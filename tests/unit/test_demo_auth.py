"""Local demo login authorization regressions; fictional fixture passwords only."""

import pytest
from fastapi.testclient import TestClient
from vg_api.main import create_app, demo

PASSWORDS = {
    "tech": "fixture-tech-password",
    "reviewer": "fixture-reviewer-password",
    "auditor": "fixture-auditor-password",
    "admin": "fixture-admin-password",
    "multi": "fixture-multi-password",
    "superadmin": "fixture-superadmin-password",
}
BODY = {"device_id": "router-a", "reason": "Auth test", "ticket_ref": "T-1", "minutes": 10}


@pytest.fixture
def app():
    plane, tokens = demo()
    return create_app(plane, tokens, demo_ui=True, demo_passwords=PASSWORDS)


def client_for(app):
    return TestClient(app, base_url="http://localhost", client=("127.0.0.1", 50000))


def login(client, username):
    response = client.post(
        "/auth/login", json={"username": username, "password": PASSWORDS[username]}
    )
    assert response.status_code == 200, response.text
    identity = response.json()
    assert identity["id"] == username
    return identity, {"X-CSRF-Token": identity["csrf_token"]}


def test_login_session_and_invalid_credentials(app):
    client = client_for(app)
    assert client.get("/auth/me").status_code == 401
    assert client.get("/v1/devices").status_code == 401
    for username, password in (("tech", "wrong"), ("missing", "wrong")):
        assert (
            client.post(
                "/auth/login", json={"username": username, "password": password}
            ).status_code
            == 401
        )
    response = client.post("/auth/login", json={"username": "tech", "password": PASSWORDS["tech"]})
    assert response.status_code == 200
    assert "httponly" in response.headers["set-cookie"].lower()
    assert "samesite=strict" in response.headers["set-cookie"].lower()
    assert response.json()["roles"] == ["technician"]
    assert client.get("/auth/me").json()["role"] == "technician"
    assert client.get("/v1/devices").status_code == 200
    assert client_for(app).get("/v1/devices").status_code == 401


def test_no_identity_endpoint_or_bearer_bypass(app):
    plane, tokens = demo()
    bearer_client = client_for(create_app(plane, tokens, demo_ui=True, demo_passwords=PASSWORDS))
    for token in tokens:
        assert (
            bearer_client.get(
                "/v1/devices", headers={"Authorization": f"Bearer {token}"}
            ).status_code
            == 401
        )
    client = client_for(app)
    assert client.get("/demo/identities", headers={"X-VaultGate-Demo": "local"}).status_code == 404
    assert (
        client.get(
            "/v1/devices", headers={"Authorization": "Bearer invalid", "X-Role": "admin"}
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/auth/login",
            json={"username": "tech", "password": PASSWORDS["tech"], "role": "admin"},
        ).status_code
        == 422
    )
    login(client, "tech")
    for path in ("/admin", "/auditor", "/?role=admin"):
        client.get(path)
        assert client.get("/auth/me").json()["role"] == "technician"


def test_csrf_and_origin_protection(app):
    client = client_for(app)
    _, csrf = login(client, "tech")
    assert client.post("/v1/access-requests", json=BODY).status_code == 403
    assert (
        client.post("/v1/access-requests", json=BODY, headers={"X-CSRF-Token": "wrong"}).status_code
        == 403
    )
    assert (
        client.post(
            "/v1/access-requests", json=BODY, headers={**csrf, "Origin": "https://evil.example"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/auth/login",
            json={"username": "admin", "password": PASSWORDS["admin"]},
            headers={"Origin": "https://evil.example"},
        ).status_code
        == 403
    )
    assert client.post("/v1/access-requests", json=BODY, headers=csrf).status_code == 201


def test_single_and_multi_role_selection(app):
    client = client_for(app)
    identity, csrf = login(client, "tech")
    assert identity["roles"] == ["technician"]
    assert client.post("/auth/role", json={"role": "admin"}, headers=csrf).status_code == 403
    assert client.get("/auth/me").json()["role"] == "technician"
    identity, csrf = login(client, "multi")
    assert set(identity["roles"]) == {"technician", "approver"}
    assert client.post("/auth/role", json={"role": "admin"}, headers=csrf).status_code == 403
    response = client.post("/auth/role", json={"role": "approver"}, headers=csrf)
    assert response.status_code == 200
    assert client.get("/auth/me").json()["role"] == "approver"
    assert client.get("/auth/me").json()["id"] == "multi"


def test_multi_role_cannot_approve_own_request(app):
    client = client_for(app)
    _, csrf = login(client, "multi")
    response = client.post("/auth/role", json={"role": "technician"}, headers=csrf)
    assert response.status_code == 200
    csrf = {"X-CSRF-Token": client.get("/auth/me").json()["csrf_token"]}
    request = client.post("/v1/access-requests", json=BODY, headers=csrf)
    assert request.status_code == 201
    request_id = request.json()["id"]
    assert client.post("/auth/role", json={"role": "approver"}, headers=csrf).status_code == 200
    csrf = {"X-CSRF-Token": client.get("/auth/me").json()["csrf_token"]}
    assert client.post(f"/v1/access-requests/{request_id}/approve", headers=csrf).status_code == 403
    assert client.post(f"/v1/access-requests/{request_id}/deny", headers=csrf).status_code == 403
    reviewer = client_for(app)
    _, review_csrf = login(reviewer, "reviewer")
    assert (
        reviewer.post(f"/v1/access-requests/{request_id}/approve", headers=review_csrf).status_code
        == 200
    )


def test_auditor_read_only_and_tenant_isolation(app):
    tech = client_for(app)
    _, csrf = login(tech, "tech")
    request = tech.post("/v1/access-requests", json=BODY, headers=csrf).json()
    reviewer = client_for(app)
    _, review_csrf = login(reviewer, "reviewer")
    assert (
        reviewer.post(
            f"/v1/access-requests/{request['id']}/approve", headers=review_csrf
        ).status_code
        == 200
    )
    auditor = client_for(app)
    _, audit_csrf = login(auditor, "auditor")
    grant = auditor.get("/v1/grants").json()[0]
    assert auditor.get("/v1/audit/customer-a").status_code == 200
    assert auditor.post("/v1/access-requests", json=BODY, headers=audit_csrf).status_code == 403
    assert auditor.post(f"/v1/grants/{grant['id']}/revoke", headers=audit_csrf).status_code == 403
    for client, headers in ((tech, csrf), (reviewer, review_csrf), (auditor, audit_csrf)):
        assert client.get("/v1/audit/customer-b").status_code == 404
        assert (
            client.post(
                "/v1/access-requests", json={**BODY, "device_id": "linux-b"}, headers=headers
            ).status_code
            == 404
        )
    assert tech.get("/v1/audit/customer-a").status_code == 403


def test_logout_invalidates_copied_session_and_audits_role_changes(app):
    client = client_for(app)
    _, csrf = login(client, "multi")
    assert client.post("/auth/role", json={"role": "approver"}, headers=csrf).status_code == 200
    copied = client_for(app)
    copied.cookies.update(client.cookies)
    csrf = {"X-CSRF-Token": client.get("/auth/me").json()["csrf_token"]}
    assert client.post("/auth/logout", headers=csrf).status_code in (200, 204)
    assert client.get("/auth/me").status_code == 401
    assert copied.get("/auth/me").status_code == 401
    assert copied.get("/v1/devices").status_code == 401
    auditor = client_for(app)
    login(auditor, "auditor")
    actions = [event["action"] for event in auditor.get("/v1/audit/customer-a").json()]
    assert {"auth.login", "auth.role_changed", "auth.logout"} <= set(actions)


def test_remote_clients_and_foreign_hosts_cannot_login(app):
    remote = TestClient(app, base_url="http://localhost", client=("203.0.113.9", 50000))
    assert (
        remote.post(
            "/auth/login", json={"username": "tech", "password": PASSWORDS["tech"]}
        ).status_code
        == 403
    )
    client = client_for(app)
    assert (
        client.post(
            "/auth/login",
            json={"username": "tech", "password": PASSWORDS["tech"]},
            headers={"Host": "evil.example"},
        ).status_code
        == 400
    )


def test_superadmin_management_is_separate_from_operations(app):
    client = client_for(app)
    identity, csrf = login(client, "superadmin")
    assert identity["roles"] == ["superadmin"]
    assert client.get("/v1/users").status_code == 200
    assert {g["id"] for g in client.get("/v1/groups").json()} == {
        "administrators",
        "technicians",
        "approvers",
        "auditors",
    }
    for path in ("/v1/devices", "/v1/access-requests", "/v1/grants", "/v1/audit/customer-a"):
        assert client.get(path).status_code == 403
    assert client.post("/v1/access-requests", json=BODY, headers=csrf).status_code == 403
    assert client.post("/auth/role", json={"role": "admin"}, headers=csrf).status_code == 403
    operational = client_for(app)
    _, op_csrf = login(operational, "admin")
    for path in ("/v1/users", "/v1/groups"):
        assert operational.get(path).status_code == 403
    assert (
        operational.post(
            "/v1/users", json={"username": "newtech", "groups": ["technicians"]}, headers=op_csrf
        ).status_code
        == 403
    )
    assert (
        operational.put(
            "/v1/users/tech/groups", json={"groups": ["auditors"]}, headers=op_csrf
        ).status_code
        == 403
    )


def test_user_creation_validation_and_assigned_scope(app):
    admin = client_for(app)
    _, csrf = login(admin, "superadmin")
    body = {"username": "newtech", "groups": ["technicians"]}
    for field, value in (("role", "admin"), ("org_id", "other"), ("tenant_ids", ["customer-b"])):
        assert admin.post("/v1/users", json={**body, field: value}, headers=csrf).status_code == 422
    for groups in (["unknown"], ["superadmins"], ["technicians", "technicians"]):
        assert (
            admin.post("/v1/users", json={**body, "groups": groups}, headers=csrf).status_code
            == 400
        )
    assert admin.post("/v1/users", json={**body, "groups": []}, headers=csrf).status_code == 422
    created = admin.post("/v1/users", json=body, headers=csrf)
    assert created.status_code == 201
    assert created.json()["id"] == "newtech"
    password = created.json()["demo_password"]
    assert password
    assert admin.post("/v1/users", json=body, headers=csrf).status_code == 409
    new_user = client_for(app)
    response = new_user.post("/auth/login", json={"username": "newtech", "password": password})
    assert response.status_code == 200
    assert response.json()["roles"] == ["technician"]
    new_csrf = {"X-CSRF-Token": response.json()["csrf_token"]}
    assert [device["id"] for device in new_user.get("/v1/devices").json()] == ["router-a"]
    assert (
        new_user.post(
            "/v1/access-requests", json={**BODY, "device_id": "linux-b"}, headers=new_csrf
        ).status_code
        == 404
    )
    assert new_user.post("/v1/access-requests", json=BODY, headers=new_csrf).status_code == 201
    users = admin.get("/v1/users").json()
    assert all("demo_password" not in user and "digest" not in user for user in users)


def test_group_change_invalidates_sessions_and_audits(app):
    admin = client_for(app)
    _, admin_csrf = login(admin, "superadmin")
    tech = client_for(app)
    login(tech, "tech")
    second = client_for(app)
    login(second, "tech")
    assert (
        admin.put(
            "/v1/users/superadmin/groups", json={"groups": ["technicians"]}, headers=admin_csrf
        ).status_code
        == 403
    )
    assert (
        admin.put(
            "/v1/users/missing/groups", json={"groups": ["technicians"]}, headers=admin_csrf
        ).status_code
        == 404
    )
    assert (
        admin.put(
            "/v1/users/tech/groups", json={"groups": ["unknown"]}, headers=admin_csrf
        ).status_code
        == 400
    )
    assert tech.get("/auth/me").status_code == 200
    assert (
        admin.put(
            "/v1/users/tech/groups", json={"groups": ["auditors", "approvers"]}, headers=admin_csrf
        ).status_code
        == 200
    )
    assert tech.get("/auth/me").status_code == 401
    assert second.get("/auth/me").status_code == 401
    identity, csrf = login(tech, "tech")
    assert set(identity["roles"]) == {"auditor", "approver"}
    assert tech.post("/auth/role", json={"role": "technician"}, headers=csrf).status_code == 403
    assert (
        admin.post(
            "/v1/users", json={"username": "auditnew", "groups": ["auditors"]}, headers=admin_csrf
        ).status_code
        == 201
    )
    auditor = client_for(app)
    login(auditor, "auditor")
    actions = [event["action"] for event in auditor.get("/v1/audit/customer-a").json()]
    assert {"identity.user_created", "identity.groups_changed"} <= set(actions)


def test_session_expiry_and_login_rotation(app, monkeypatch):
    from types import SimpleNamespace

    from vg_api import demo_auth

    now = demo_auth.time.monotonic()
    monkeypatch.setattr(demo_auth, "time", SimpleNamespace(monotonic=lambda: now))
    client = client_for(app)
    login(client, "tech")
    old = client_for(app)
    old.cookies.update(client.cookies)
    login(client, "auditor")
    assert old.get("/auth/me").status_code == 401
    assert client.get("/auth/me").json()["role"] == "auditor"
    now += 3601
    assert client.get("/auth/me").status_code == 401
    assert client.get("/v1/devices").status_code == 401


def test_provisioning_help_requires_activation_before_enrollment(app):
    """Setup guidance must match the managed runner's enabled-account precondition."""
    client = client_for(app)
    login(client, "superadmin")
    response = client.get("/admin")
    assert response.status_code == 200
    assert "Enrollment requires an already-enabled account" in response.text
    assert "this form does not perform activation or enrollment" in response.text
    assert "enrollment before enabling the account" not in response.text
