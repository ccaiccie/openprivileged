import ssl
from contextlib import contextmanager
from types import SimpleNamespace
from uuid import UUID

import pytest
from pydantic import ValidationError
from vg_api.directory import (
    DirectoryConfig,
    DirectoryDenied,
    DirectoryUnavailable,
    LdapsDirectory,
    escape_filter,
)

GUID = "12345678-1234-5678-9012-123456789012"
GROUP = "CN=Operators,DC=example,DC=test"


def config(**overrides):
    return DirectoryConfig(
        **(
            dict(
                host="dc.example.test",
                ca_file="/test/ca.pem",
                bind_dn="CN=Reader,DC=example,DC=test",
                bind_password_env="VG_AD_READER_PASSWORD",
                user_base_dn="DC=example,DC=test",
                group_base_dn="DC=example,DC=test",
                org_id="org",
                tenant_ids=["tenant"],
                group_mappings=[
                    dict(group_dn=GROUP, roles=["technician", "auditor"], device_ids=["router"])
                ],
            )
            | overrides
        )
    )


def entry(**overrides):
    return dict(
        type="searchResEntry",
        dn="CN=Alice,DC=example,DC=test",
        attributes=dict(
            objectGUID=GUID,
            sAMAccountName="alice",
            displayName="Alice",
            mail="alice@example.test",
            memberOf=[GROUP],
            userAccountControl=512,
            accountExpires=0,
            lockoutTime=0,
        )
        | overrides,
    )


class FakeConnection:
    def __init__(self, entries=None, code=0):
        self.response = entries if entries is not None else [entry()]
        self.result = {"result": code}
        self.queries = []

    def search(self, base, query, **kwargs):
        self.queries.append((base, query, kwargs))


class FakeDirectory(LdapsDirectory):
    def __init__(self, settings=None, entries=None, code=0):
        super().__init__(settings or config())
        self.reader = FakeConnection(entries, code)
        self.bound = []

    @contextmanager
    def _reader(self):
        yield self.reader

    @contextmanager
    def _connection(self, dn, password):
        self.bound.append(dn)
        if password != "test-password":
            raise DirectoryDenied("Authentication failed")
        yield FakeConnection()


def test_record_and_group_mapping():
    provider = FakeDirectory()
    user = provider.authenticate("alice", "test-password")
    assert user.id == GUID
    assert provider.config.roles_for(user) == ("technician", "auditor")
    assert provider.config.devices_for(user) == frozenset({"router"})
    assert provider.bound == ["CN=Alice,DC=example,DC=test"]


def test_injection_is_escaped_and_guid_lookup_binary():
    provider = FakeDirectory()
    provider.authenticate("a*)(foo=*)\x00\\", "test-password")
    query = provider.reader.queries[-1][1]
    assert "a\\2a\\29\\28foo=\\2a\\29\\00\\5c" in query
    provider.lookup(GUID)
    assert "".join(f"\\{b:02x}" for b in UUID(GUID).bytes_le) in provider.reader.queries[-1][1]
    assert escape_filter("a(b)") == r"a\28b\29"


@pytest.mark.parametrize(
    "attributes", [dict(userAccountControl=514), dict(lockoutTime=1), dict(accountExpires=1)]
)
def test_disabled_locked_expired_fail_closed(attributes):
    with pytest.raises(DirectoryDenied):
        FakeDirectory(entries=[entry(**attributes)]).lookup(GUID)


@pytest.mark.parametrize("code", [3, 4, 10, 50])
def test_partial_searches_never_authorize(code):
    with pytest.raises(DirectoryUnavailable):
        FakeDirectory(code=code).authenticate("alice", "test-password")


def test_ambiguous_and_missing_users_denied():
    for entries in ([], [entry(), entry()]):
        with pytest.raises(DirectoryDenied):
            FakeDirectory(entries=entries).authenticate("alice", "test-password")


def test_bad_password_denied():
    with pytest.raises(DirectoryDenied):
        FakeDirectory().authenticate("alice", "wrong")


def test_import_skips_disabled_and_unmapped():
    provider = FakeDirectory(entries=[entry(), entry(userAccountControl=514), entry(memberOf=[])])
    assert len(provider.list_users()) == 1


def test_nested_group_query_uses_ad_matching_rule():
    provider = FakeDirectory(config(nested_groups=True))
    provider.lookup(GUID)
    assert "member:1.2.840.113556.1.4.1941:=" in provider.reader.queries[-1][1]


def test_configuration_rejects_unknown_insecure_options():
    with pytest.raises(ValidationError):
        config(verify_tls=False)
    with pytest.raises(ValidationError):
        config(host="ldap://example.test")


def test_tls_options_and_bind_error_sanitized(monkeypatch):
    seen = {}

    def tls(**kwargs):
        seen["tls"] = kwargs
        return object()

    def server(*args, **kwargs):
        seen["server"] = kwargs
        return object()

    def connection(*args, **kwargs):
        seen["connection"] = kwargs
        return SimpleNamespace(bind=lambda: False, result={"result": 49}, unbind=lambda: None)

    fake = SimpleNamespace(
        Tls=tls, Server=server, Connection=connection, SIMPLE="SIMPLE", NONE="NONE"
    )
    monkeypatch.setattr("vg_api.directory.importlib.import_module", lambda _: fake)
    with pytest.raises(DirectoryDenied):
        with LdapsDirectory(config())._connection("test", "test-password"):
            pass
    assert seen["tls"]["validate"] == ssl.CERT_REQUIRED
    assert seen["tls"]["valid_names"] == ["dc.example.test"]
    assert seen["tls"]["version"] == ssl.PROTOCOL_TLS_CLIENT
    assert seen["server"]["use_ssl"] is True
    assert seen["connection"]["auto_referrals"] is False


def test_reader_password_missing(monkeypatch):
    monkeypatch.delenv("VG_AD_READER_PASSWORD", raising=False)
    with pytest.raises(DirectoryUnavailable):
        LdapsDirectory(config()).lookup(GUID)


def test_schemaless_ldap_attributes_are_normalized():
    record = entry()
    record["attributes"] = {
        k: v if isinstance(v, list) else [v] for k, v in record["attributes"].items()
    }
    record["raw_attributes"] = {"objectGUID": [UUID(GUID).bytes_le]}
    user = FakeDirectory(entries=[record]).lookup(GUID)
    assert user.id == GUID
    assert user.username == "alice"
    assert user.groups == (GROUP,)


def test_computed_account_flags_allow_auto_unlocked_account():
    provider = FakeDirectory(
        entries=[entry(lockoutTime=1, **{"msDS-User-Account-Control-Computed": 0})]
    )
    assert provider.lookup(GUID).id == GUID
    provider = FakeDirectory(entries=[entry(**{"msDS-User-Account-Control-Computed": 16})])
    with pytest.raises(DirectoryDenied):
        provider.lookup(GUID)
