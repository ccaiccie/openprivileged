from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from vg_api.main import create_app
from vg_core.domain import Actor, ControlPlane, Device, DomainError, Policy, verify_chain


@pytest.fixture
def setup():
    now = [datetime(2026, 1, 1, tzinfo=UTC)]
    plane = ControlPlane(
        (Device("a", "org", "a", "router", "ios"), Device("b", "org", "b", "other", "linux")),
        {("org", "a"): Policy()},
        lambda: now[0],
    )
    tech = Actor("tech", "org", frozenset({"a"}), "technician")
    reviewer = Actor("reviewer", "org", frozenset({"a"}), "approver")
    return plane, tech, reviewer, now


def test_full_lifecycle_and_expiry(setup):
    plane, tech, reviewer, now = setup
    req = plane.request(tech, "a", "Maintenance", "CHG1", 10)
    assert plane.decide(reviewer, req.id, True).status == "approved"
    grant = plane.grants(tech)[0]
    assert grant.status == "active"
    now[0] += timedelta(minutes=10)
    assert plane.grants(tech)[0].status == "expired"
    assert plane.expire() == 0
    events = plane.audit(reviewer, "a")
    assert [e.action for e in events] == [
        "request.created",
        "request.approval_recorded",
        "grant.activated",
        "grant.expired",
    ]
    assert verify_chain(events)
    assert not verify_chain((replace(events[0], action="tampered"), *events[1:]))
    assert not verify_chain(events[1:])


@pytest.mark.parametrize("minutes", [0, -1, 61, True, 1.5])
def test_duration_policy(setup, minutes):
    plane, tech, _, _ = setup
    with pytest.raises(DomainError):
        plane.request(tech, "a", "Reason", "CHG1", minutes)


@pytest.mark.parametrize("reason,ticket", [(" ", "CHG1"), ("Reason", " ")])
def test_required_fields(setup, reason, ticket):
    plane, tech, _, _ = setup
    with pytest.raises(DomainError):
        plane.request(tech, "a", reason, ticket, 10)


def test_isolation_and_role_enforcement(setup):
    plane, tech, reviewer, _ = setup
    assert [d.id for d in plane.devices(tech)] == ["a"]
    with pytest.raises(DomainError, match="not found"):
        plane.request(tech, "b", "Reason", "CHG1", 10)
    req = plane.request(tech, "a", "Reason", "CHG1", 10)
    outsiders = [replace(reviewer, tenant_ids=frozenset({"b"})), replace(reviewer, org_id="other")]
    for outsider in outsiders:
        assert plane.requests(outsider) == ()
        with pytest.raises(DomainError, match="not found"):
            plane.decide(outsider, req.id, True)
    with pytest.raises(DomainError):
        plane.decide(tech, req.id, True)
    with pytest.raises(DomainError):
        plane.decide(replace(tech, role="admin"), req.id, True)
    with pytest.raises(DomainError):
        plane.audit(tech, "a")


def test_two_reviewers_and_replay():
    plane = ControlPlane(
        (Device("d", "o", "t", "r", "ios"),), {("o", "t"): Policy(approvals_required=2)}
    )
    tech = Actor("t", "o", frozenset({"t"}), "technician")
    reviewer = replace(tech, id="r1", role="approver")
    req = plane.request(tech, "d", "Reason", "CHG", 10)
    assert plane.decide(reviewer, req.id, True).status == "pending"
    assert not plane.grants(tech)
    with pytest.raises(DomainError):
        plane.decide(reviewer, req.id, True)
    plane.decide(replace(reviewer, id="r2"), req.id, True)
    assert len(plane.grants(tech)) == 1
    with pytest.raises(DomainError):
        plane.decide(replace(reviewer, id="r3"), req.id, True)


def test_deny_and_revoke(setup):
    plane, tech, reviewer, _ = setup
    req = plane.request(tech, "a", "Reason", "CHG", 10)
    assert plane.decide(reviewer, req.id, False).status == "denied"
    with pytest.raises(DomainError):
        plane.decide(reviewer, req.id, True)
    assert not plane.grants(tech)
    req = plane.request(tech, "a", "Reason", "CHG", 10)
    plane.decide(reviewer, req.id, True)
    grant = plane.grants(tech)[0]
    with pytest.raises(DomainError):
        plane.revoke(replace(tech, id="other-tech"), grant.id)
    assert plane.revoke(tech, grant.id).status == "revoked"
    with pytest.raises(DomainError):
        plane.revoke(tech, grant.id)


def test_concurrent_approval_creates_one_grant(setup):
    plane, tech, reviewer, _ = setup
    req = plane.request(tech, "a", "Reason", "CHG", 10)

    def decide(_):
        try:
            plane.decide(reviewer, req.id, True)
            return True
        except DomainError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(decide, range(8))) == 1
    assert len(plane.grants(tech)) == 1


def test_api_auth_validation_and_flow(setup):
    plane, tech, reviewer, _ = setup
    client = TestClient(create_app(plane, {"test-tech": tech, "test-reviewer": reviewer}))
    tech_headers = {"Authorization": "Bearer test-tech"}
    reviewer_headers = {"Authorization": "Bearer test-reviewer"}
    assert client.get("/health").status_code == 200
    assert client.get("/v1/devices").status_code == 401
    assert client.get("/v1/devices", headers={"X-Role": "admin"}).status_code == 401
    assert len(client.get("/v1/devices", headers=tech_headers).json()) == 1
    body = {"device_id": "a", "reason": "Maintenance", "ticket_ref": "CHG", "minutes": 10}
    assert (
        client.post(
            "/v1/access-requests", headers=tech_headers, json={**body, "minutes": True}
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/v1/access-requests", headers=tech_headers, json={**body, "org_id": "other"}
        ).status_code
        == 422
    )
    response = client.post("/v1/access-requests", headers=tech_headers, json=body)
    assert response.status_code == 201
    req_id = response.json()["id"]
    assert (
        client.post(f"/v1/access-requests/{req_id}/approve", headers=tech_headers).status_code
        == 403
    )
    assert (
        client.post(f"/v1/access-requests/{req_id}/approve", headers=reviewer_headers).status_code
        == 200
    )
    grant = client.get("/v1/grants", headers=tech_headers).json()[0]
    assert client.post(f"/v1/grants/{grant['id']}/revoke", headers=tech_headers).status_code == 200
    assert client.get("/v1/audit/a/verify", headers=reviewer_headers).json()["valid"]


def test_default_api_fails_closed():
    client = TestClient(create_app())
    assert (
        client.get("/v1/devices", headers={"Authorization": "Bearer anything"}).status_code == 401
    )


def test_missing_policy_fails_closed(setup):
    _, tech, _, _ = setup
    plane = ControlPlane((Device("a", "org", "a", "router", "ios"),), {})
    with pytest.raises(DomainError, match="No access policy"):
        plane.request(tech, "a", "Reason", "CHG", 10)


def test_cross_tenant_grant_and_audit_are_hidden(setup):
    plane, tech, reviewer, _ = setup
    req = plane.request(tech, "a", "Reason", "CHG", 10)
    plane.decide(reviewer, req.id, True)
    grant = plane.grants(tech)[0]
    outsider = replace(reviewer, tenant_ids=frozenset({"b"}))
    assert plane.grants(outsider) == ()
    with pytest.raises(DomainError, match="not found"):
        plane.revoke(outsider, grant.id)
    with pytest.raises(DomainError, match="not found"):
        plane.audit(outsider, "a")
    assert plane.audit(outsider, "b") == ()


def test_demo_ui_is_opt_in_and_local(setup):
    plane, tech, reviewer, _ = setup
    tokens = {"test-tech": tech, "test-reviewer": reviewer}
    assert TestClient(create_app(plane, tokens)).get("/demo/identities").status_code == 404
    client = TestClient(
        create_app(plane, tokens, demo_ui=True),
        base_url="http://127.0.0.1",
        client=("127.0.0.1", 50000),
    )
    page = client.get("/")
    assert page.status_code == 200 and "OpenPrivileged" in page.text
    assert "test-tech" not in page.text
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/demo/identities").status_code == 404
    assert client.get("/auth/me").status_code == 401
    assert client.get("/auth/me", headers={"Origin": "https://evil.test"}).status_code == 403
    assert client.get("/", headers={"Host": "evil.test"}).status_code == 400


def test_role_portals_and_api_permissions():
    from vg_api.main import demo

    plane, tokens = demo()
    client = TestClient(
        create_app(plane, tokens, demo_ui=True),
        base_url="http://localhost",
        client=("127.0.0.1", 50000),
    )
    headers = {a.role: {"Authorization": f"Bearer {t}"} for t, a in tokens.items()}
    for role in headers:
        assert client.get(f"/{role}").status_code == 200
        assert TestClient(create_app()).get(f"/{role}").status_code == 404
    client = TestClient(create_app(plane, tokens))
    body = {"device_id": "router-a", "reason": "Test", "ticket_ref": "T-1", "minutes": 10}
    assert (
        client.post("/v1/access-requests", json=body, headers=headers["auditor"]).status_code == 403
    )
    request = client.post("/v1/access-requests", json=body, headers=headers["technician"]).json()
    path = f"/v1/access-requests/{request['id']}/approve"
    assert client.post(path, headers=headers["technician"]).status_code == 403
    assert client.post(path, headers=headers["auditor"]).status_code == 403
    assert client.post(path, headers=headers["admin"]).status_code == 200
    grant = client.get("/v1/grants", headers=headers["admin"]).json()[0]
    assert (
        client.post(f"/v1/grants/{grant['id']}/revoke", headers=headers["auditor"]).status_code
        == 403
    )
    assert client.get("/v1/audit/customer-a", headers=headers["technician"]).status_code == 403
    for auth in headers.values():
        assert client.get("/v1/audit/customer-b", headers=auth).status_code == 404
        assert (
            client.post(
                "/v1/access-requests", json={**body, "device_id": "linux-b"}, headers=auth
            ).status_code
            == 404
        )
    own = client.post("/v1/access-requests", json=body, headers=headers["admin"]).json()
    assert (
        client.post(
            f"/v1/access-requests/{own['id']}/approve", headers=headers["admin"]
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/v1/access-requests/{own['id']}/approve", headers=headers["approver"]
        ).status_code
        == 200
    )
