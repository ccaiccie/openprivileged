"""AD authentication/entitlements with an in-memory directory. Never contacts a DC."""

from dataclasses import replace

from fastapi.testclient import TestClient
from vg_api.directory import DirectoryConfig, DirectoryDenied, DirectoryUnavailable, DirectoryUser
from vg_api.main import create_app
from vg_core.domain import ControlPlane, Device, Policy


class FakeDirectory:
    def __init__(self):
        self.rows = {
            "a": DirectoryUser(
                "a", "alice", "Alice Test", "alice@example.invalid", ("CN=Tech,DC=test",)
            ),
            "b": DirectoryUser("b", "boss", "Boss Test", "", ("CN=Owners,DC=test",)),
        }
        self.down = False

    def lookup(self, identity):
        if self.down:
            raise DirectoryUnavailable()
        if identity not in self.rows:
            raise DirectoryDenied()
        return self.rows[identity]

    def authenticate(self, username, password):
        for row in self.rows.values():
            if row.username == username and password == "test-only-password":
                return self.lookup(row.id)
        raise DirectoryDenied()

    def list_users(self):
        if self.down:
            raise DirectoryUnavailable()
        return tuple(self.rows.values())


def setup():
    config = DirectoryConfig(
        host="dc.example.invalid",
        ca_file="/tmp/not-used-by-fake.pem",
        bind_dn="CN=Reader,DC=test",
        bind_password_env="VG_TEST_BIND_PASSWORD",
        user_base_dn="DC=test",
        group_base_dn="DC=test",
        org_id="org",
        tenant_ids=["tenant"],
        group_mappings=[
            {
                "group_dn": "CN=Tech,DC=test",
                "roles": ["technician", "auditor"],
                "device_ids": ["one"],
            },
            {"group_dn": "CN=Owners,DC=test", "roles": ["superadmin"], "device_ids": []},
        ],
    )
    provider = FakeDirectory()
    plane = ControlPlane(
        tuple(Device(n, "org", "tenant", n, "linux", "direct") for n in ("one", "two")),
        {("org", "tenant"): Policy()},
    )
    app = create_app(plane, demo_ui=True, directory_config=config, directory_provider=provider)
    client = TestClient(app, base_url="http://localhost", client=("127.0.0.1", 50000))
    return client, provider


def login(client, username="alice"):
    response = client.post(
        "/auth/login", json={"username": username, "password": "test-only-password"}
    )
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
    return response.json()


def test_directory_login_roles_profile_and_device_authority():
    client, _ = setup()
    identity = login(client)
    assert identity["id"] == "ad:a"
    assert identity["display_name"] == "Alice Test"
    assert set(identity["roles"]) == {"technician", "auditor"}
    assert identity["directory_managed"]
    assert [d["id"] for d in client.get("/v1/devices").json()] == ["one"]
    body = {"device_id": "one", "reason": "Offline test", "minutes": 5}
    assert client.post("/v1/direct-access", json=body).status_code == 201
    assert client.post("/v1/direct-access", json={**body, "device_id": "two"}).status_code == 404
    assert client.post("/auth/role", json={"role": "superadmin"}).status_code == 403
    assert client.post("/auth/role", json={"role": "auditor"}).status_code == 200
    assert client.post("/v1/direct-access", json=body).status_code == 403


def test_membership_removal_and_outage_invalidate_sessions():
    client, provider = setup()
    login(client)
    provider.rows["a"] = replace(provider.rows["a"], groups=())
    assert client.get("/auth/me").status_code in (401, 403)
    assert client.get("/v1/devices").status_code == 401
    client, provider = setup()
    login(client)
    provider.down = True
    assert client.get("/auth/me").status_code == 401
    provider.down = False
    assert client.get("/auth/me").status_code == 401


def test_account_disabled_deleted_and_changed_role_require_new_login():
    client, provider = setup()
    login(client)
    provider.rows["a"] = replace(provider.rows["a"], groups=("CN=Owners,DC=test",))
    assert client.get("/auth/me").status_code == 401
    assert login(client)["roles"] == ["superadmin"]
    del provider.rows["a"]
    assert client.get("/auth/me").status_code == 401


def test_sync_superadmin_only_and_read_only_ad_membership():
    client, _ = setup()
    login(client)
    assert client.post("/v1/directory/sync").status_code == 403
    client, _ = setup()
    login(client, "boss")
    assert client.post("/v1/directory/sync").json()["imported"] == 2
    rows = client.get("/v1/users").json()
    assert all(r["directory_managed"] and r["protected"] for r in rows)
    assert (
        client.put("/v1/users/ad:a/groups", json={"groups": ["administrators"]}).status_code == 403
    )
    assert (
        client.post("/v1/users", json={"username": "local", "groups": ["technicians"]}).status_code
        == 403
    )


def test_no_demo_fallback_or_client_supplied_roles():
    client, provider = setup()
    assert (
        client.post(
            "/auth/login", json={"username": "superadmin", "password": "test-only-password"}
        ).status_code
        == 401
    )
    provider.down = True
    assert (
        client.post(
            "/auth/login", json={"username": "alice", "password": "test-only-password"}
        ).status_code
        == 503
    )
    assert (
        client.post(
            "/auth/login",
            json={"username": "alice", "password": "test-only-password", "role": "admin"},
        ).status_code
        == 422
    )
