"""Exercise the real demo launcher over HTTP on an unused localhost port.

Run: uv run --no-sync python tests/integration/http_demo_smoke.py
Uses only fictional demo data, prints no passwords or session tokens, stops only its own server.
"""

import http.cookiejar
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from uuid import UUID

from vg_core.domain import AuditEvent, verify_chain

ROOT = Path(__file__).resolve().parents[2]
checks = 0


def main() -> None:
    global checks
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    launcher = str(Path(sys.executable).parent / "vg-api")
    process = subprocess.Popen(
        [launcher, "--demo", "--port", str(port)],
        cwd=ROOT,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )
    passwords: dict[str, str] = {}
    usernames = {
        "admin": "admin",
        "technician": "tech",
        "approver": "reviewer",
        "auditor": "auditor",
    }
    openers = {
        role: urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        for role in usernames
    }
    csrf_tokens: dict[str, str] = {}
    try:
        assert process.stdout is not None
        for _ in range(8):
            line = process.stdout.readline().strip()
            if " demo password: " in line:
                username, password = line.split(" demo password: ", 1)
                passwords[username] = password
        assert set(passwords) == {"admin", "tech", "reviewer", "auditor", "multi", "superadmin"}
        base = f"http://127.0.0.1:{port}"

        def call(
            method: str,
            path: str,
            role: str | None = None,
            body: dict[str, object] | None = None,
            expected: int = 200,
            extra_headers: dict[str, str] | None = None,
        ) -> object:
            global checks
            headers = {"Content-Type": "application/json"}
            if role in csrf_tokens:
                headers["X-CSRF-Token"] = csrf_tokens[role]
            if role == "invalid":
                headers["Authorization"] = "Bearer invalid"
            headers.update(extra_headers or {})
            request = urllib.request.Request(
                base + path,
                method=method,
                headers=headers,
                data=json.dumps(body).encode() if body else None,
            )
            try:
                opener = openers.get(role) if role else None
                send = opener.open if opener else urllib.request.urlopen
                with send(request, timeout=5) as response:
                    status, raw = response.status, response.read()
            except urllib.error.HTTPError as exc:
                status, raw = exc.code, exc.read()
            assert status == expected, (method, path, role, status, expected)
            checks += 1
            return json.loads(raw)

        for _ in range(100):
            try:
                call("GET", "/health")
                break
            except urllib.error.URLError:
                time.sleep(0.1)
        else:
            raise RuntimeError("Demo server did not start")
        for role in (None, "invalid"):
            call("GET", "/v1/devices", role, expected=401)
        call("GET", "/demo/identities", expected=404)
        call("POST", "/auth/login", body={"username": "tech", "password": "wrong"}, expected=401)
        for role, username in usernames.items():
            identity = call(
                "POST",
                "/auth/login",
                role,
                {"username": username, "password": passwords[username]},
            )
            assert isinstance(identity, dict) and identity["role"] == role
            csrf_tokens[role] = identity["csrf_token"]
        call("POST", "/auth/role", "technician", {"role": "admin"}, 403)
        identity = call("GET", "/auth/me?role=admin", "technician")
        assert isinstance(identity, dict) and identity["role"] == "technician"
        for role in usernames:
            devices = call("GET", "/v1/devices", role)
            assert isinstance(devices, list) and [d["id"] for d in devices] == ["router-a"]
        body = {
            "device_id": "router-a",
            "reason": "HTTP smoke test",
            "ticket_ref": "LAB-HTTP",
            "minutes": 1,
        }
        call(
            "POST",
            "/v1/access-requests",
            "technician",
            body,
            403,
            extra_headers={"X-CSRF-Token": "wrong"},
        )
        call(
            "POST",
            "/v1/access-requests",
            "technician",
            body,
            403,
            extra_headers={"Origin": "https://evil.example"},
        )
        call("POST", "/v1/access-requests", "auditor", body, 403)
        call("POST", "/v1/access-requests", "approver", body, 403)
        for extra, code in [
            ({"device_id": "linux-b"}, 404),
            ({"minutes": 61}, 400),
            ({"minutes": True}, 422),
            ({"ticket_ref": " "}, 400),
            ({"org_id": "forged"}, 422),
            ({"reason": " "}, 400),
        ]:
            call("POST", "/v1/access-requests", "technician", {**body, **extra}, code)
        req = call("POST", "/v1/access-requests", "technician", body, 201)
        assert isinstance(req, dict)
        request_id = req["id"]
        assert str(UUID(request_id)) == request_id
        endpoint = f"/v1/access-requests/{request_id}/approve"
        call("POST", endpoint, "technician", expected=403)
        call("POST", endpoint, "auditor", expected=403)
        call("POST", "/v1/access-requests/unknown/approve", "approver", expected=404)
        call("POST", endpoint, "approver")
        call("POST", endpoint, "approver", expected=409)
        grants = call("GET", "/v1/grants", "technician")
        assert isinstance(grants, list) and len(grants) == 1 and grants[0]["status"] == "active"
        expiry_id = grants[0]["id"]
        expiry_start = time.monotonic()
        second = call("POST", "/v1/access-requests", "technician", body, 201)
        assert isinstance(second, dict)
        call("POST", f"/v1/access-requests/{second['id']}/deny", "approver")
        call("POST", f"/v1/access-requests/{second['id']}/approve", "approver", expected=409)
        third = call("POST", "/v1/access-requests", "technician", body, 201)
        assert isinstance(third, dict)
        call("POST", f"/v1/access-requests/{third['id']}/approve", "approver")
        grants = call("GET", "/v1/grants", "approver")
        assert isinstance(grants, list)
        revoke_id = next(g["id"] for g in grants if g["request_id"] == third["id"])
        call("POST", f"/v1/grants/{revoke_id}/revoke", "auditor", expected=403)
        call("POST", f"/v1/grants/{revoke_id}/revoke", "technician")
        call("POST", f"/v1/grants/{revoke_id}/revoke", "approver", expected=409)
        call("GET", "/v1/audit/customer-a", "technician", expected=403)
        call("GET", "/v1/audit/customer-b", "auditor", expected=404)
        call("GET", "/v1/audit/customer-a/verify", "auditor")
        print(
            "Inventory, RBAC, approval, denial, revoke, isolation and input validation passed.",
            flush=True,
        )
        # Exercise real wall-clock expiry through the unmodified demo's one-minute grant.
        time.sleep(max(0, 61 - (time.monotonic() - expiry_start)))
        grants = call("GET", "/v1/grants", "technician")
        assert isinstance(grants, list)
        assert next(g for g in grants if g["id"] == expiry_id)["status"] == "expired"
        call("POST", f"/v1/grants/{expiry_id}/revoke", "approver", expected=409)
        events = call("GET", "/v1/audit/customer-a", "auditor")
        assert isinstance(events, list)
        assert verify_chain(tuple(AuditEvent(**event) for event in events))
        assert sum(e["action"] == "grant.expired" for e in events) == 1
        result = call("GET", "/v1/audit/customer-a/verify", "auditor")
        assert isinstance(result, dict) and result["valid"] is True
        assert result["count"] == len(events)
        assert sum(e["action"] == "auth.login" for e in events) == len(usernames)
        for role in usernames:
            requests = call("GET", "/v1/access-requests", role)
            assert isinstance(requests, list) and len(requests) == 3
        call("POST", "/auth/logout", "technician")
        call("GET", "/auth/me", "technician", expected=401)
        call("GET", "/v1/devices", "technician", expected=401)
        events = call("GET", "/v1/audit/customer-a", "auditor")
        assert isinstance(events, list)
        assert verify_chain(tuple(AuditEvent(**event) for event in events))
        assert any(e["action"] == "auth.logout" for e in events)
        print(f"PASS: {checks} HTTP checks; expiry and {len(events)}-event audit chain verified.")
        print("Request IDs are UUID strings, not URLs.")
    finally:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=10)
        print("Isolated test server stopped; existing user process untouched.")


if __name__ == "__main__":
    main()
