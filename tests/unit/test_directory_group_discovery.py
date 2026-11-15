"""Security-group discovery uses only synthetic directory connections."""

from contextlib import contextmanager
from unittest.mock import patch

import pytest
from test_directory_management import application, login
from vg_api.directory import DirectoryUnavailable, LdapsDirectory


def test_catalog_superadmin_only_and_requires_csrf(tmp_path):
    client, provider, store, cfg = application(tmp_path)
    provider.list_groups = lambda: [{"name": "Owners", "dn": "CN=Owners,DC=test"}]
    body = {"config": cfg.model_dump(mode="json"), "revision": 0}
    login(client, "alice")
    assert client.post("/v1/directory/integration/groups", json=body).status_code == 403
    login(client)
    with patch("vg_api.directory_management.LdapsDirectory", return_value=provider):
        result = client.post("/v1/directory/integration/groups", json=body)
    assert result.status_code == 200
    assert result.json()["groups"] == [{"name": "Owners", "dn": "CN=Owners,DC=test"}]
    assert result.json()["devices"] == [{"id": "one", "name": "One"}]
    assert result.headers["cache-control"] == "no-store"
    assert store.data is None
    assert "synthetic-reader" not in result.text
    del client.headers["X-CSRF-Token"]
    assert client.post("/v1/directory/integration/groups", json=body).status_code == 403


def test_catalog_failure_sanitized_and_stale_revision_rejected(tmp_path):
    client, provider, store, cfg = application(tmp_path)
    login(client)
    body = {"config": cfg.model_dump(mode="json"), "revision": 1}
    assert client.post("/v1/directory/integration/groups", json=body).status_code == 409
    body["revision"] = 0

    def fail():
        raise ValueError("SECRET LDAP DETAILS")

    provider.list_groups = fail
    with patch("vg_api.directory_management.LdapsDirectory", return_value=provider):
        result = client.post("/v1/directory/integration/groups", json=body)
    assert result.status_code == 503 and "SECRET" not in result.text
    assert store.data is None


class Reader:
    def __init__(self, failure=False, repeating=False):
        self.calls = []
        self.failure = failure
        self.repeating = repeating

    def search(self, base, query, **kwargs):
        self.calls.append(kwargs)
        assert "objectClass=group" in query
        assert "2147483648" in query
        cookie = b"next" if len(self.calls) == 1 or self.repeating else b""
        self.result = {
            "result": 4 if self.failure else 0,
            "controls": {"1.2.840.113556.1.4.319": {"value": {"cookie": cookie}}},
        }
        self.response = [
            {
                "type": "searchResEntry",
                "dn": "CN=" + str(len(self.calls)) + ",DC=test",
                "attributes": {"cn": ["Group " + str(len(self.calls))]},
            }
        ]


def test_paged_group_discovery_and_fail_closed(tmp_path):
    _, _, _, cfg = application(tmp_path)
    directory = LdapsDirectory(cfg)
    reader = Reader()

    @contextmanager
    def connection():
        yield reader

    directory._reader = connection
    assert len(directory.list_groups()) == 2
    assert reader.calls[1]["paged_cookie"] == b"next"
    reader.failure = True
    with pytest.raises(DirectoryUnavailable):
        directory.list_groups()
    reader.failure = False
    reader.repeating = True
    with pytest.raises(DirectoryUnavailable):
        directory.list_groups()


def test_saved_mapping_changes_effective_login_roles_and_devices(tmp_path):
    client, provider, _, cfg = application(tmp_path)
    login(client)
    body = {"config": cfg.model_dump(mode="json"), "revision": 0}
    body["config"]["group_mappings"][0]["roles"] = ["approver"]
    body["config"]["group_mappings"][0]["device_ids"] = []
    with patch("vg_api.directory_management.LdapsDirectory", return_value=provider):
        assert client.put("/v1/directory/integration", json=body).status_code == 200
    assert client.get("/auth/me").status_code == 401
    login(client, "alice")
    assert client.get("/auth/me").json()["roles"] == ["approver"]
    assert client.get("/v1/devices").json() == []
    assert client.post("/auth/role", json={"role": "technician"}).status_code == 403


class PagedReader:
    def __init__(self, pages):
        self.pages = iter(pages)
        self.calls = []

    def search(self, base, query, **kwargs):
        self.calls.append((base, query, kwargs))
        assert kwargs["paged_size"] == 500
        assert kwargs["paged_criticality"] is True
        self.result, self.response = next(self.pages)


def page_result(start, count, cookie=b"", code=0):
    result = {
        "result": code,
        "controls": {
            "1.2.840.113556.1.4.319": {"value": {"cookie": cookie}},
        },
    }
    entries = [
        {
            "type": "searchResEntry",
            "dn": f"CN=Group{i:05},DC=test",
            "attributes": {"cn": [f"Group{i:05}"]},
        }
        for i in range(start, start + count)
    ]
    return result, entries


def paged_directory(tmp_path, pages):
    _, _, _, cfg = application(tmp_path)
    directory = LdapsDirectory(cfg)
    reader = PagedReader(pages)

    @contextmanager
    def connection():
        yield reader

    directory._reader = connection
    return directory, reader


def test_catalog_exceeds_ad_default_max_page_size_without_truncation(tmp_path):
    directory, reader = paged_directory(
        tmp_path,
        [
            page_result(0, 500, b"page2"),
            page_result(500, 500, b"page3"),
            page_result(1000, 500, b"page4"),
            page_result(1500, 1),
        ],
    )
    groups = directory.list_groups()
    assert len(groups) == 1501
    assert groups[0]["name"] == "Group00000"
    assert groups[-1]["name"] == "Group01500"
    assert [call[2]["paged_cookie"] for call in reader.calls] == [
        None,
        b"page2",
        b"page3",
        b"page4",
    ]
    # The same base, filter, attributes and connection are retained across pages.
    assert len({(call[0], call[1]) for call in reader.calls}) == 1


@pytest.mark.parametrize("code", [3, 4, 11, 12, 50, 51, 80])
def test_later_page_error_rejects_previously_collected_groups(tmp_path, code):
    directory, _ = paged_directory(
        tmp_path,
        [
            page_result(0, 500, b"page2"),
            page_result(500, 10, code=code),
        ],
    )
    with pytest.raises(DirectoryUnavailable, match="incomplete"):
        directory.list_groups()


@pytest.mark.parametrize(
    "controls",
    [
        {},
        {"1.2.840.113556.1.4.319": {}},
        {"1.2.840.113556.1.4.319": {"value": {}}},
        {"1.2.840.113556.1.4.319": {"value": {"cookie": None}}},
        {"1.2.840.113556.1.4.319": {"value": {"cookie": 7}}},
    ],
)
def test_missing_or_invalid_paging_response_is_not_completion(tmp_path, controls):
    bad, entries = page_result(500, 1)
    bad["controls"] = controls
    directory, _ = paged_directory(tmp_path, [page_result(0, 500, b"next"), (bad, entries)])
    with pytest.raises(DirectoryUnavailable):
        directory.list_groups()


def test_referral_in_later_page_rejects_catalog(tmp_path):
    result, entries = page_result(500, 1)
    entries.append({"type": "searchResRef", "uri": ["ldaps://other.invalid"]})
    directory, _ = paged_directory(tmp_path, [page_result(0, 500, b"next"), (result, entries)])
    with pytest.raises(DirectoryUnavailable, match="incomplete"):
        directory.list_groups()


def test_group_catalog_exact_limit_and_over_limit(tmp_path):
    pages = [page_result(i * 500, 500, str(i + 1).encode()) for i in range(20)]
    pages[-1][0]["controls"]["1.2.840.113556.1.4.319"]["value"]["cookie"] = b""
    directory, _ = paged_directory(tmp_path, pages)
    assert len(directory.list_groups()) == 10000
    pages[-1][0]["controls"]["1.2.840.113556.1.4.319"]["value"]["cookie"] = b"more"
    directory, _ = paged_directory(tmp_path, pages + [page_result(10000, 1)])
    with pytest.raises(DirectoryUnavailable, match="maximum 10000"):
        directory.list_groups()


def test_changing_cookies_without_progress_are_bounded(tmp_path):
    # A misbehaving server can otherwise evade the repeated-cookie guard forever.
    directory, reader = paged_directory(
        tmp_path, [page_result(0, 1, str(i).encode()) for i in range(101)]
    )
    with pytest.raises(DirectoryUnavailable, match="paging limit"):
        directory.list_groups()
    assert len(reader.calls) == 100


def test_empty_catalog_is_complete_only_with_empty_server_cookie(tmp_path):
    directory, _ = paged_directory(tmp_path, [page_result(0, 0)])
    assert directory.list_groups() == []
