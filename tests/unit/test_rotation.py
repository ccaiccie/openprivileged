from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta

import pytest
from vg_core.domain import Actor, DomainError
from vg_core.rotation import AccountBinding, RotationService

CANARY = "synthetic-only-secret"


class Adapter:
    def __init__(self):
        self.password = CANARY
        self.fail = ""
        self.changes = 0

    def change(self, binding, password):
        self.changes += 1
        if self.fail == "before":
            raise RuntimeError(password)
        self.password = password
        if self.fail == "after":
            raise RuntimeError(password)

    def verify(self, binding, password):
        if self.fail == "offline":
            raise RuntimeError(password)
        return password == self.password


@pytest.fixture
def setup():
    now = [datetime(2026, 11, 13, tzinfo=UTC)]
    adapter = Adapter()
    service = RotationService(adapter, lambda: now[0])
    binding = AccountBinding(
        "a", "org", "tenant", "tech", "tech-admin", "directory", frozenset({"device"})
    )
    service.enroll(binding, CANARY)
    actor = Actor("tech", "org", frozenset({"tenant"}), "technician")
    return service, adapter, now, binding, actor


def test_boundary_and_injection(setup):
    service, adapter, now, _, actor = setup
    now[0] += timedelta(hours=4) - timedelta(microseconds=1)
    assert service.rotate_due()[0].generation == 1
    now[0] += timedelta(microseconds=1)
    assert service.status("a").state == "overdue"
    with pytest.raises(DomainError):
        service.connect(actor, "device", lambda: None, lambda u, p: None)
    status = service.rotate_due()[0]
    assert status.generation == 2 and status.state == "ready"
    assert status.due_at == now[0] + timedelta(hours=4)
    assert adapter.password != CANARY
    assert CANARY not in str(asdict(status))
    assert adapter.password not in repr(service)
    received = []
    assert (
        service.connect(actor, "device", lambda: None, lambda u, p: received.append((u, p))) is None
    )
    assert received == [("tech-admin", adapter.password)]


@pytest.mark.parametrize("failure", ["before", "after", "offline"])
def test_failure_recovery(setup, failure):
    service, adapter, now, _, actor = setup
    now[0] += timedelta(hours=4)
    adapter.fail = failure
    assert service.rotate_due()[0].state == "recovery_required"
    calls = adapter.changes
    service.rotate_due()
    assert adapter.changes == calls
    with pytest.raises(DomainError):
        service.connect(actor, "device", lambda: None, lambda u, p: None)
    adapter.fail = ""
    assert service.recover("a").state == "ready"
    assert service.status("a").generation == 2
    if failure in {"after", "offline"}:
        assert adapter.changes == calls


def test_concurrency(setup):
    service, adapter, now, _, _ = setup
    now[0] += timedelta(hours=4)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: service.rotate_due(), range(20)))
    assert adapter.changes == 1


@pytest.mark.parametrize(
    "change",
    [
        {"id": "other"},
        {"org_id": "other"},
        {"tenant_ids": frozenset({"other"})},
        {"role": "admin"},
        {"device_ids": frozenset()},
    ],
)
def test_ownership(setup, change):
    service, _, _, _, actor = setup
    with pytest.raises(DomainError):
        service.connect(
            replace(actor, **change),
            "device",
            lambda: None,
            lambda u, p: pytest.fail("credential injected"),
        )


def test_grant_denial_and_error_redaction(setup):
    service, _, _, _, actor = setup

    def deny():
        raise DomainError("Grant expired", 403)

    with pytest.raises(DomainError, match="Grant expired"):
        service.connect(actor, "device", deny, lambda u, p: pytest.fail("credential injected"))

    def bad_backend(username, password):
        raise RuntimeError(password)

    with pytest.raises(DomainError) as error:
        service.connect(actor, "device", lambda: None, bad_backend)
    assert CANARY not in str(error.value)
    assert error.value.__suppress_context__


def test_duplicate_mapping(setup):
    service, _, _, binding, _ = setup
    with pytest.raises(ValueError, match="already assigned"):
        service.enroll(replace(binding, id="b", technician_id="other"), CANARY)
    with pytest.raises(ValueError, match="Ambiguous"):
        service.enroll(replace(binding, id="b", privileged_username="another-admin"), CANARY)
    with pytest.raises(ValueError, match="distinct"):
        replace(binding, privileged_username="TECH")


def test_unknown_password_stays_blocked(setup):
    service, adapter, now, _, _ = setup
    now[0] += timedelta(hours=4)
    adapter.fail = "before"
    service.rotate_due()
    adapter.fail = ""
    adapter.password = "externally changed synthetic value"
    assert service.recover("a").state == "recovery_required"
