"""Isolated configuration tests. No real directory or credentials."""

from unittest.mock import patch

from fastapi.testclient import TestClient
from test_directory_auth import setup
from vg_api.directory_management import saved_settings
from vg_api.main import create_app
from vg_api.rotation_store import EncryptedRotationStore


class MemoryStore:
    data = None
    fail = False

    def load(self):
        return self.data

    def save(self, data):
        if self.fail:
            raise ValueError("DO NOT RETURN INTERNAL SECRET")
        self.data = data


def application(tmp_path, rotation_service=None):
    original, provider = setup()
    # Reuse synthetic directory/config from the test fixture's known values.
    from vg_api.directory import DirectoryConfig
    from vg_core.domain import ControlPlane, Device, Policy

    cfg = DirectoryConfig(
        host="dc.example.invalid",
        ca_file="/mock/ca.pem",
        bind_dn="CN=Reader,DC=test",
        bind_password_env="VG_TEST_BIND_PASSWORD",
        user_base_dn="DC=test",
        group_base_dn="DC=test",
        org_id="org",
        tenant_ids=["tenant"],
        group_mappings=[
            {"group_dn": "CN=Tech,DC=test", "roles": ["technician"], "device_ids": ["one"]},
            {"group_dn": "CN=Owners,DC=test", "roles": ["superadmin"]},
        ],
    )
    store = MemoryStore()
    plane = ControlPlane(
        (Device("one", "org", "tenant", "One", "linux", "direct"),), {("org", "tenant"): Policy()}
    )
    app = create_app(
        plane,
        demo_ui=True,
        directory_config=cfg,
        directory_provider=provider,
        directory_settings_store=store,
        directory_bind_password="synthetic-reader",
        rotation_service=rotation_service,
    )
    client = TestClient(app, base_url="http://localhost", client=("127.0.0.1", 50000))
    return client, provider, store, cfg


def login(client, name="boss"):
    r = client.post("/auth/login", json={"username": name, "password": "test-only-password"})
    assert r.status_code == 200
    client.headers["X-CSRF-Token"] = r.json()["csrf_token"]


def test_superadmin_config_view_test_and_save_revokes_sessions(tmp_path):
    client, provider, store, cfg = application(tmp_path)
    login(client)
    view = client.get("/v1/directory/integration")
    assert view.status_code == 200
    assert "synthetic-reader" not in view.text
    assert view.headers["cache-control"] == "no-store"
    body = {"config": cfg.model_dump(mode="json"), "revision": 0}
    with patch("vg_api.directory_management.LdapsDirectory", return_value=provider):
        assert client.post("/v1/directory/integration/test", json=body).status_code == 200
        assert store.data is None
        assert client.put("/v1/directory/integration", json=body).status_code == 200
    assert client.get("/auth/me").status_code == 401
    saved, password, revision = saved_settings(store)
    assert saved == cfg and password == "synthetic-reader" and revision == 1
    login(client)
    assert client.put("/v1/directory/integration", json=body).status_code == 409


def test_config_forbidden_to_technician_and_csrf_protected(tmp_path):
    client, provider, store, cfg = application(tmp_path)
    login(client, "alice")
    assert client.get("/v1/directory/integration").status_code == 403
    body = {"config": cfg.model_dump(mode="json"), "revision": 0}
    assert client.put("/v1/directory/integration", json=body).status_code == 403
    login(client)
    del client.headers["X-CSRF-Token"]
    assert client.put("/v1/directory/integration", json=body).status_code == 403
    assert store.data is None


def test_invalid_scope_device_destination_and_lockout_fail_closed(tmp_path):
    client, provider, store, cfg = application(tmp_path)
    login(client)
    body = {"config": cfg.model_dump(mode="json"), "revision": 0}
    body["config"]["org_id"] = "other"
    assert client.put("/v1/directory/integration", json=body).status_code == 403
    body["config"]["org_id"] = "org"
    body["config"]["group_mappings"][0]["device_ids"] = ["unknown"]
    assert client.put("/v1/directory/integration", json=body).status_code == 400
    body["config"]["group_mappings"][0]["device_ids"] = ["one"]
    body["config"]["host"] = "other.example.invalid"
    assert client.put("/v1/directory/integration", json=body).status_code == 400
    body["config"]["host"] = cfg.host
    body["config"]["group_mappings"][1]["roles"] = ["technician"]
    with patch("vg_api.directory_management.LdapsDirectory", return_value=provider):
        assert client.put("/v1/directory/integration", json=body).status_code == 400
    assert store.data is None
    assert client.get("/auth/me").status_code == 200


def test_storage_failure_never_activates_and_error_is_generic(tmp_path):
    client, provider, store, cfg = application(tmp_path)
    login(client)
    store.fail = True
    body = {"config": cfg.model_dump(mode="json"), "revision": 0}
    with patch("vg_api.directory_management.LdapsDirectory", return_value=provider):
        result = client.put("/v1/directory/integration", json=body)
    assert result.status_code == 503 and "INTERNAL SECRET" not in result.text
    assert client.get("/auth/me").status_code == 200
    assert client.get("/v1/directory/integration").json()["revision"] == 0


def test_encrypted_settings_roundtrip(tmp_path):
    root = tmp_path / "settings"
    root.mkdir(mode=0o700)
    _, _, _, cfg = application(tmp_path)
    import json

    with_store = EncryptedRotationStore(root, b"x" * 32)
    with_store.save(
        json.dumps(
            {
                "version": 1,
                "config": cfg.model_dump(mode="json"),
                "password": "synthetic-reader",
                "revision": 4,
            }
        ).encode()
    )
    assert b"synthetic-reader" not in (root / "rotation.enc").read_bytes()
    with_store.close()
    reopened = EncryptedRotationStore(root, b"x" * 32)
    assert saved_settings(reopened) == (cfg, "synthetic-reader", 4)
    reopened.close()


def test_integration_save_suspends_managed_runtime_before_persist(tmp_path):
    from unittest.mock import Mock

    runtime = Mock()
    client, provider, store, cfg = application(tmp_path, rotation_service=runtime)
    login(client)
    body = {"config": cfg.model_dump(mode="json"), "revision": 0}
    with patch("vg_api.directory_management.LdapsDirectory", return_value=provider):
        response = client.put("/v1/directory/integration", json=body)
    assert response.status_code == 200
    assert response.json()["rotation_restart_required"]
    runtime.suspend.assert_called_once()


def test_failed_settings_persist_still_leaves_rotation_suspended(tmp_path):
    from unittest.mock import Mock

    runtime = Mock()
    client, provider, store, cfg = application(tmp_path, rotation_service=runtime)
    login(client)
    store.fail = True
    body = {"config": cfg.model_dump(mode="json"), "revision": 0}
    with patch("vg_api.directory_management.LdapsDirectory", return_value=provider):
        assert client.put("/v1/directory/integration", json=body).status_code == 503
    runtime.suspend.assert_called_once()
