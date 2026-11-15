import os
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest
from vg_api.rotation_store import EncryptedRotationStore
from vg_core.domain import Actor, DomainError
from vg_core.rotation import AccountBinding, RotationService, RotationWorker

SECRET = "synthetic-canary-never-real"
KEY = bytes(range(32))  # Synthetic test key, never use outside tests.


class Adapter:
    def __init__(self):
        self.password = SECRET
        self.crash = False
        self.changed = Event()
        self.calls = 0

    def change(self, binding, password):
        self.calls += 1
        self.password = password
        self.changed.set()
        if self.crash:
            raise SystemExit("simulated process death")

    def verify(self, binding, password):
        return password == self.password


@pytest.fixture
def setup(tmp_path):
    directory = tmp_path / "vault"
    directory.mkdir(mode=0o700)
    now = [datetime(2026, 11, 13, tzinfo=UTC)]
    adapter = Adapter()
    binding = AccountBinding(
        "a", "org", "tenant", "tech", "tech-admin", "ad", frozenset({"device"})
    )
    store = EncryptedRotationStore(directory, KEY)
    service = RotationService(adapter, lambda: now[0], store)
    service.enroll(binding, SECRET)
    yield directory, now, adapter, binding, store, service
    store.close()


def test_encryption_restart_and_exclusive_lock(setup):
    directory, now, adapter, binding, store, service = setup
    assert SECRET.encode() not in (directory / "rotation.enc").read_bytes()
    assert (directory / "rotation.enc").stat().st_mode & 0o077 == 0
    with pytest.raises(ValueError, match="already in use"):
        EncryptedRotationStore(directory, KEY)
    expected = service.status("a")
    store.close()
    reopened = EncryptedRotationStore(directory, KEY)
    try:
        assert RotationService(adapter, lambda: now[0], reopened).status("a") == expected
    finally:
        reopened.close()


def test_crash_after_target_change_recovers_durable_pending(setup):
    directory, now, adapter, _, store, service = setup
    now[0] += timedelta(hours=4)
    adapter.crash = True
    with pytest.raises(SystemExit):
        service.rotate_due()
    accepted = adapter.password
    assert accepted.encode() not in (directory / "rotation.enc").read_bytes()
    store.close()
    reopened = EncryptedRotationStore(directory, KEY)
    try:
        restored = RotationService(adapter, lambda: now[0], reopened)
        assert restored.status("a").state == "recovery_required"
        assert restored.recover("a").state == "ready"
        assert adapter.calls == 1
        assert adapter.password == accepted
    finally:
        reopened.close()


@pytest.mark.parametrize("fail_at", [1, 2])
def test_persistence_failure_blocks_before_mutation_or_recovers_after(setup, fail_at):
    directory, now, adapter, _, store, service = setup
    original = store.save
    calls = 0

    def failing(data):
        nonlocal calls
        calls += 1
        if calls == fail_at:
            raise OSError("synthetic failure")
        original(data)

    store.save = failing
    now[0] += timedelta(hours=4)
    try:
        service.rotate_due()
    except DomainError:
        pass
    assert adapter.calls == fail_at - 1
    assert service.status("a").state == "storage_failed"
    actor = Actor("tech", "org", frozenset({"tenant"}), "technician")
    with pytest.raises(DomainError):
        service.connect(actor, "device", lambda: None, lambda u, p: pytest.fail("injected"))
    with pytest.raises(DomainError):
        service.recover("a")
    store.close()
    reopened = EncryptedRotationStore(directory, KEY)
    try:
        restored = RotationService(adapter, lambda: now[0], reopened)
        if fail_at == 2:
            assert restored.recover("a").state == "ready"
            assert adapter.calls == 1
        else:
            assert restored.status("a").state == "overdue"
    finally:
        reopened.close()


@pytest.mark.parametrize("damage", ["key", "tamper", "truncate"])
def test_corruption_fails_closed(setup, damage):
    directory, now, adapter, _, store, _ = setup
    store.close()
    path = directory / "rotation.enc"
    if damage == "tamper":
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)
    if damage == "truncate":
        path.write_bytes(b"truncated")
    reopened = EncryptedRotationStore(directory, b"X" * 32 if damage == "key" else KEY)
    try:
        with pytest.raises(DomainError, match="storage unavailable"):
            RotationService(adapter, lambda: now[0], reopened)
    finally:
        reopened.close()


def test_worker_runs_only_when_explicitly_started(setup):
    _, now, adapter, _, _, service = setup
    worker = RotationWorker(service, interval_seconds=0.01)
    now[0] += timedelta(hours=4)
    assert adapter.calls == 0
    worker.start()
    try:
        assert adapter.changed.wait(3)
    finally:
        worker.stop()
    assert service.status("a").generation == 2
    with pytest.raises(RuntimeError):
        worker.start()


def test_unsafe_storage_and_closed_store(tmp_path):
    directory = tmp_path / "vault"
    directory.mkdir(mode=0o755)
    with pytest.raises(ValueError, match="owner-only"):
        EncryptedRotationStore(directory, KEY)
    os.chmod(directory, 0o700)
    store = EncryptedRotationStore(directory, KEY)
    store.close()
    with pytest.raises(ValueError, match="closed"):
        store.save(b"no")
    with pytest.raises(ValueError, match="closed"):
        store.load()
    with pytest.raises(ValueError, match="durable"):
        RotationWorker(RotationService(Adapter()))


def test_closed_store_blocks_existing_broker_instance(setup):
    _, _, _, _, store, service = setup
    store.close()
    actor = Actor("tech", "org", frozenset({"tenant"}), "technician")
    with pytest.raises(DomainError, match="unavailable"):
        service.connect(actor, "device", lambda: None, lambda u, p: pytest.fail("injected"))


def test_promoted_state_survives_restart(setup):
    directory, now, adapter, _, store, service = setup
    now[0] += timedelta(hours=4)
    service.rotate_due()
    expected = service.status("a")
    store.close()
    reopened = EncryptedRotationStore(directory, KEY)
    try:
        restored = RotationService(adapter, lambda: now[0], reopened)
        assert restored.status("a") == expected
        actor = Actor("tech", "org", frozenset({"tenant"}), "technician")
        received = []
        restored.connect(actor, "device", lambda: None, lambda u, p: received.append(p))
        assert received == [adapter.password]
    finally:
        reopened.close()


def test_closed_store_blocks_recovery_target_mutation(setup):
    _, now, adapter, _, store, service = setup
    now[0] += timedelta(hours=4)
    adapter.crash = True
    with pytest.raises(SystemExit):
        service.rotate_due()
    calls = adapter.calls
    store.close()
    with pytest.raises(DomainError, match="storage unavailable"):
        service.recover("a")
    assert adapter.calls == calls
