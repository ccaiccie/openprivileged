from datetime import UTC, datetime, timedelta
from threading import Event

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from vg_api.rotation_app import install_worker_lifecycle
from vg_api.rotation_store import EncryptedRotationStore
from vg_core.rotation import AccountBinding, RotationService


class Adapter:
    password = "synthetic-only"

    def __init__(self):
        self.changed = Event()

    def change(self, binding, password):
        self.password = password
        self.changed.set()

    def verify(self, binding, password):
        return password == self.password


def test_combined_lifespan_single_owner_due_rotation_and_shutdown(tmp_path):
    tmp_path.chmod(0o700)
    adapter = Adapter()
    now = [datetime(2026, 11, 13, tzinfo=UTC)]
    store = EncryptedRotationStore(tmp_path, bytes(32))
    service = RotationService(adapter, lambda: now[0], store)
    service.enroll(
        AccountBinding("vg-tech-admin", "o", "t", "tech", "priv", "ad", frozenset({"d"})),
        adapter.password,
    )
    now[0] += timedelta(hours=4)
    app = FastAPI()
    worker = install_worker_lifecycle(app, service)
    with TestClient(app) as client:
        assert adapter.changed.wait(3)
        health = client.get("/healthz/rotation").json()
        assert health["ready"] is True
        assert health["worker"]["alive"] is True
        assert health["worker"]["cycles"] >= 1
        assert health["generation"] == 2
        assert health["account_state"] == "ready"
        assert adapter.password not in str(health)
        assert service.status("vg-tech-admin").generation == 2
        with pytest.raises(ValueError, match="already in use"):
            EncryptedRotationStore(tmp_path, bytes(32))
    assert worker._thread is not None and not worker._thread.is_alive()
    # ASGI shutdown doesn't release the parent-owned vault prematurely.
    with pytest.raises(ValueError, match="already in use"):
        EncryptedRotationStore(tmp_path, bytes(32))
    store.close()
    reopened = EncryptedRotationStore(tmp_path, bytes(32))
    assert (
        RotationService(adapter, lambda: now[0], reopened).status("vg-tech-admin").generation == 2
    )
    reopened.close()


def test_reader_secret_can_stay_out_of_process_environment(monkeypatch):
    from vg_api.directory import DirectoryConfig, LdapsDirectory

    config = DirectoryConfig(
        host="dc.example.com",
        ca_file="ca.pem",
        bind_dn="CN=reader",
        bind_password_env="TEST_PW",
        user_base_dn="OU=users",
        group_base_dn="OU=groups",
        org_id="o",
        tenant_ids={"t"},
        group_mappings=[{"group_dn": "CN=tech", "roles": ["technician"]}],
    )
    provider = LdapsDirectory(config, bind_password="synthetic-reader")
    monkeypatch.delenv("TEST_PW", raising=False)
    assert provider._bind_password == "synthetic-reader"
    import os

    assert "TEST_PW" not in os.environ


def test_worker_health_proves_polling_and_stopped_state(tmp_path):
    import time

    from vg_core.rotation import RotationWorker

    tmp_path.chmod(0o700)
    store = EncryptedRotationStore(tmp_path, bytes(32))
    service = RotationService(Adapter(), store=store)
    service.enroll(
        AccountBinding("vg-tech-admin", "o", "t", "tech", "priv", "ad", frozenset({"d"})),
        "synthetic-only",
    )
    worker = RotationWorker(service, interval_seconds=0.01)
    assert worker.health()["healthy"] is False
    assert worker.health()["cycles"] == 0
    worker.start()
    try:
        for _ in range(100):
            if worker.health()["cycles"] >= 2:
                break
            time.sleep(0.01)
        assert worker.health()["cycles"] >= 2
        assert worker.health()["healthy"] is True
    finally:
        worker.stop()
        store.close()
    assert worker.health()["healthy"] is False
    assert worker.health()["alive"] is False
