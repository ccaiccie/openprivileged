from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from vg_core.domain import Actor, ControlPlane, Device, DomainError, Policy, verify_chain


@pytest.fixture
def direct_setup():
    now = [datetime(2026, 1, 1, tzinfo=UTC)]
    devices = (
        Device("frr-a", "org", "a", "lab-frr-a", "frr", access_mode="direct"),
        Device("frr-b", "org", "b", "lab-frr-b", "frr", access_mode="direct"),
        Device("approval", "org", "a", "reviewed", "ios"),
    )
    source = {("tech", "frr-a"), ("admin", "frr-a"), ("tech", "frr-b"), ("tech", "approval")}
    plane = ControlPlane(
        devices,
        {("org", "a"): Policy(max_minutes=15)},
        lambda: now[0],
        direct_entitlements=source,
    )
    source.clear()  # Caller mutation cannot grant or withdraw access.
    tech = Actor("tech", "org", frozenset({"a"}), "technician")
    reviewer = Actor("reviewer", "org", frozenset({"a"}), "approver")
    return plane, tech, reviewer, now


def test_direct_no_request_and_audited_connection(direct_setup):
    plane, tech, reviewer, _ = direct_setup
    grant = plane.direct_grant(tech, "frr-a", "  Lab inspection  ", 10)
    assert grant.status == "active" and grant.request_id == ""
    assert grant.requester_id == "tech" and grant.reason == "Lab inspection"
    assert plane.requests(tech) == ()
    assert plane.authorize_connection(tech, grant.id).id == "frr-a"
    events = plane.audit(reviewer, "a")
    assert [e.action for e in events] == ["grant.direct_activated", "connection.authorized"]
    assert verify_chain(events)


@pytest.mark.parametrize(
    ("actor", "device", "status"),
    [
        (Actor("other", "org", frozenset({"a"}), "technician"), "frr-a", 403),
        (Actor("tech", "other-org", frozenset({"a"}), "technician"), "frr-a", 404),
        (Actor("tech", "org", frozenset({"b"}), "technician"), "frr-a", 404),
        (Actor("tech", "org", frozenset({"a"}), "auditor"), "frr-a", 403),
        (Actor("tech", "org", frozenset({"a"}), "approver"), "frr-a", 403),
        (Actor("tech", "org", frozenset({"a"}), "superadmin"), "frr-a", 403),
        (Actor("tech", "org", frozenset({"a"}), "technician"), "frr-b", 404),
        (Actor("tech", "org", frozenset({"a"}), "technician"), "approval", 403),
        (Actor("tech", "org", frozenset({"a"}), "technician"), "missing", 404),
    ],
)
def test_direct_requires_scope_entitlement_mode_role(direct_setup, actor, device, status):
    plane, _, _, _ = direct_setup
    with pytest.raises(DomainError) as exc:
        plane.direct_grant(actor, device, "Lab", 1)
    assert exc.value.status == status
    assert plane.grants(actor) == ()


@pytest.mark.parametrize("minutes", [0, -1, 16, True, 1.1])
def test_direct_duration_policy(direct_setup, minutes):
    plane, tech, _, _ = direct_setup
    with pytest.raises(DomainError):
        plane.direct_grant(tech, "frr-a", "Lab", minutes)


@pytest.mark.parametrize("reason", ["", " ", "a" * 1001])
def test_direct_reason_required(direct_setup, reason):
    plane, tech, _, _ = direct_setup
    with pytest.raises(DomainError):
        plane.direct_grant(tech, "frr-a", reason, 1)


def test_direct_missing_policy_fails_closed():
    tech = Actor("tech", "org", frozenset({"a"}), "technician")
    plane = ControlPlane(
        (Device("frr", "org", "a", "lab", "frr", access_mode="direct"),),
        {},
        direct_entitlements=frozenset({("tech", "frr")}),
    )
    with pytest.raises(DomainError, match="No access policy"):
        plane.direct_grant(tech, "frr", "Lab", 1)


def test_admin_needs_explicit_entitlement_and_cannot_borrow_grant(direct_setup):
    plane, tech, _, _ = direct_setup
    admin = replace(tech, id="admin", role="admin")
    own = plane.direct_grant(admin, "frr-a", "Lab", 1)
    assert plane.authorize_connection(admin, own.id).id == "frr-a"
    foreign = plane.direct_grant(tech, "frr-a", "Lab", 1)
    for actor in (admin, replace(tech, id="other")):
        with pytest.raises(DomainError) as exc:
            plane.authorize_connection(actor, foreign.id)
        assert exc.value.status == 404
    with pytest.raises(DomainError, match="not entitled"):
        plane.direct_grant(replace(admin, id="unassigned-admin"), "frr-a", "Lab", 1)


def test_connection_rechecks_role_scope_expiry_and_revocation(direct_setup):
    plane, tech, reviewer, now = direct_setup
    grant = plane.direct_grant(tech, "frr-a", "Lab", 1)
    for actor in (
        replace(tech, role="auditor"),
        replace(tech, role="approver"),
        replace(tech, tenant_ids=frozenset({"b"})),
        replace(tech, org_id="other"),
    ):
        with pytest.raises(DomainError):
            plane.authorize_connection(actor, grant.id)
    plane.revoke(tech, grant.id)
    with pytest.raises(DomainError, match="not active"):
        plane.authorize_connection(tech, grant.id)
    expired = plane.direct_grant(tech, "frr-a", "Lab", 1)
    now[0] += timedelta(minutes=1)
    with pytest.raises(DomainError, match="not active"):
        plane.authorize_connection(tech, expired.id)
    assert plane.grants(tech)[-1].status == "expired"
    assert verify_chain(plane.audit(reviewer, "a"))


def test_connection_rechecks_direct_entitlement(direct_setup):
    plane, tech, _, _ = direct_setup
    grant = plane.direct_grant(tech, "frr-a", "Lab", 1)
    # Model a trusted policy reload, not a client-settable field.
    plane._direct_entitlements = frozenset()
    with pytest.raises(DomainError, match="not entitled"):
        plane.authorize_connection(tech, grant.id)


def test_approval_workflow_still_required_for_approval_device(direct_setup):
    plane, tech, reviewer, _ = direct_setup
    req = plane.request(tech, "approval", "Lab", "T-1", 1)
    assert req.status == "pending"
    assert plane.grants(tech) == ()
    plane.decide(reviewer, req.id, True)
    grant = plane.grants(tech)[0]
    assert grant.request_id == req.id
    assert plane.authorize_connection(tech, grant.id).id == "approval"


@pytest.mark.parametrize("protocol", ["ssh", "rdp", "vnc"])
def test_device_protocol_metadata(protocol):
    assert Device("d", "org", "a", "lab", "linux", protocol=protocol).protocol == protocol


def test_device_rejects_unknown_mode_or_protocol():
    with pytest.raises(ValueError, match="access mode"):
        Device("d", "org", "a", "lab", "linux", access_mode="skip-checks")
    with pytest.raises(ValueError, match="protocol"):
        Device("d", "org", "a", "lab", "linux", protocol="shell")


def test_standing_access_has_no_duration_and_reuses_active_grant(direct_setup):
    plane, tech, _, now = direct_setup
    grant = plane.direct_grant(tech, "frr-a", "Assigned device access")
    assert grant.expires_at is None
    assert plane.direct_grant(tech, "frr-a", "Repeated click").id == grant.id
    now[0] += timedelta(days=100)
    assert plane.expire() == 0
    assert plane.authorize_connection(tech, grant.id).id == "frr-a"
    plane.revoke(tech, grant.id)
    with pytest.raises(DomainError, match="not active"):
        plane.authorize_connection(tech, grant.id)
    replacement = plane.direct_grant(tech, "frr-a", "Reconnect")
    assert replacement.id != grant.id


def test_standing_access_rechecks_assignment_scope_and_role(direct_setup):
    plane, tech, _, _ = direct_setup
    assigned = replace(tech, device_ids=frozenset({"frr-a"}))
    grant = plane.direct_grant(assigned, "frr-a", "Assigned device access")
    for denied in (
        replace(assigned, device_ids=frozenset()),
        replace(assigned, role="auditor"),
        replace(assigned, id="other"),
        replace(assigned, tenant_ids=frozenset({"b"})),
    ):
        with pytest.raises(DomainError):
            plane.authorize_connection(denied, grant.id)
    with pytest.raises(DomainError, match="not entitled"):
        plane.direct_grant(tech, "approval", "No approval bypass")
