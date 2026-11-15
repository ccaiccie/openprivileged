import json
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest
from vg_api.rotation_runner import health, private_read, run_loop
from vg_api.rotation_store import EncryptedRotationStore
from vg_core.rotation import AccountBinding, RotationService


class Adapter:
    def __init__(self):
        self.password = "synthetic-only"
        self.calls = 0
        self.fail = False

    def change(self, binding, password):
        self.calls += 1
        if self.fail:
            raise RuntimeError("SECRET-error-must-not-appear")
        self.password = password

    def verify(self, binding, password):
        return password == self.password


def test_resume_due_rotation_stop_and_reopen(tmp_path):
    tmp_path.chmod(0o700)
    adapter = Adapter()
    now = [datetime(2026, 11, 13, tzinfo=UTC)]
    binding = AccountBinding("a", "o", "t", "tech", "priv", "ad", frozenset({"d"}))
    store = EncryptedRotationStore(tmp_path, bytes(32))
    service = RotationService(adapter, lambda: now[0], store)
    service.enroll(binding, adapter.password)
    store.close()
    now[0] += timedelta(hours=5)
    store = EncryptedRotationStore(tmp_path, bytes(32))
    service = RotationService(adapter, lambda: now[0], store)
    stop = Event()
    rows = []

    def emit(row):
        rows.append(row)
        stop.set()

    assert run_loop(service, "a", stop, emit) == 0
    assert adapter.calls == 1
    assert rows[0]["generation"] == 2
    assert adapter.password not in json.dumps(rows)
    store.close()
    store = EncryptedRotationStore(tmp_path, bytes(32))
    service = RotationService(adapter, lambda: now[0], store)
    assert health(service, "a") == rows[0]
    stop.clear()
    assert run_loop(service, "a", stop, emit) == 0
    assert adapter.calls == 1  # Restart never rotates early.
    store.close()


def test_uncertain_reset_exits_without_retry(tmp_path):
    tmp_path.chmod(0o700)
    adapter = Adapter()
    now = [datetime(2026, 11, 13, tzinfo=UTC)]
    store = EncryptedRotationStore(tmp_path, bytes(32))
    service = RotationService(adapter, lambda: now[0], store)
    service.enroll(
        AccountBinding("a", "o", "t", "tech", "priv", "ad", frozenset({"d"})), "synthetic-only"
    )
    now[0] += timedelta(hours=4)
    adapter.fail = True
    rows = []
    assert run_loop(service, "a", Event(), rows.append) == 2
    assert rows[0]["state"] == "recovery_required"
    assert "SECRET" not in json.dumps(rows)
    assert run_loop(service, "a", Event(), rows.append) == 2
    assert adapter.calls == 1
    store.close()


def test_private_file_rejects_public_symlink_and_hardlink(tmp_path):
    path = tmp_path / "key"
    path.write_bytes(b"synthetic")
    path.chmod(0o644)
    with pytest.raises(ValueError):
        private_read(path)
    path.chmod(0o600)
    assert private_read(path) == b"synthetic"
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        private_read(link)
    link.unlink()
    link.hardlink_to(path)
    with pytest.raises(ValueError):
        private_read(path)


@pytest.mark.parametrize("username", ["Administrator", "vg-other@example.local"])
def test_runner_rejects_other_identity_before_io(username):
    from vg_api.rotation_runner import open_runtime

    config = {
        "binding": {
            "id": "vg-tech-admin",
            "org_id": "org",
            "tenant_id": "tenant",
            "technician_id": "tech",
            "privileged_username": username,
            "authority_id": "DC1.example.local",
            "device_ids": ["vg-ubuntu-rdp"],
        }
    }
    with pytest.raises(ValueError, match="restricted"):
        open_runtime(config)
