import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from vg_api.demo_auth import DemoAuth
from vg_api.lab_access import SSHTarget
from vg_api.ssh_sessions import SSHProcess, install_sessions, parse_message, ssh_command
from vg_core.domain import Actor, ControlPlane, Device, DomainError


class FakeProcess:
    instances = []

    def __init__(self, target):
        self.target = target
        self.inputs = []
        self.sizes = []
        self.closed = False
        self.output = [b"FRR lab terminal\r\n"]
        self.instances.append(self)

    def read(self):
        return self.output.pop(0) if self.output else None

    def write(self, data):
        self.inputs.append(data)

    def resize(self, cols, rows):
        self.sizes.append((cols, rows))

    def close(self):
        self.closed = True


@pytest.fixture
def socket_setup(monkeypatch):
    now = [datetime.now(UTC)]
    from vg_core.domain import Policy

    store = ControlPlane(
        (
            Device("frr", "demo-msp", "customer-a", "lab", "frr", "direct"),
            Device("vnc", "demo-msp", "customer-a", "desktop", "ubuntu", "direct", "vnc"),
        ),
        {("demo-msp", "customer-a"): Policy()},
        lambda: now[0],
        direct_entitlements=frozenset({("tech", "frr"), ("tech", "vnc"), ("multi", "frr")}),
    )
    tech = Actor("tech", "demo-msp", frozenset({"customer-a"}), "technician")
    tokens = {"t": tech, "a": replace(tech, id="auditor", role="auditor")}
    passwords = {"tech": "test-password", "auditor": "audit-password", "multi": "multi-password"}
    auth = DemoAuth(store, tokens, passwords)
    app = FastAPI()

    @app.exception_handler(DomainError)
    async def error(request: Request, exc: DomainError):
        return JSONResponse({"detail": str(exc)}, status_code=exc.status)

    auth.install(app)
    target = SSHTarget("127.0.0.1", 2222, "lab", "/tmp/key", "/tmp/known_hosts")
    FakeProcess.instances = []
    monkeypatch.setattr("vg_api.ssh_sessions.SSHProcess", FakeProcess)
    install_sessions(app, store, auth, {"frr": target})
    client = TestClient(app, base_url="http://localhost", client=("127.0.0.1", 50000))
    user = client.post("/auth/login", json={"username": "tech", "password": "test-password"}).json()
    grant = store.direct_grant(tech, "frr", "Interactive lab", 5)
    return client, store, auth, user, grant, now, tech, target


def connect(client, ident, origin="http://localhost"):
    headers = {"Origin": origin} if origin is not None else {}
    return client.websocket_connect(
        f"ws://localhost/v1/grants/{ident}/ssh-session", headers=headers
    )


def handshake(ws, user):
    ws.send_json({"type": "auth", "csrf_token": user["csrf_token"]})
    message = ws.receive_json()
    assert message["type"] == "ready"
    assert message["recording"] is False
    assert ws.receive_bytes() == b"FRR lab terminal\r\n"
    return message


def test_interactive_input_resize_and_cleanup(socket_setup):
    client, store, auth, user, grant, _, tech, target = socket_setup
    with connect(client, grant.id) as ws:
        hello = handshake(ws, user)
        ws.send_json({"type": "input", "data": "show version\r"})
        ws.send_json({"type": "resize", "cols": 100, "rows": 30})
        # Invalid final input synchronizes prior queue processing and closes safely.
        ws.send_json({"type": "command", "command": "local host command"})
        assert ws.receive_json()["type"] == "error"
        with pytest.raises(WebSocketDisconnect):
            ws.receive_json()
    proc = FakeProcess.instances[0]
    assert proc.target == target
    assert proc.inputs == [b"show version\r"] and proc.sizes == [(100, 30)]
    assert proc.closed
    auditor = replace(tech, id="audit", role="auditor")
    events = store.audit(auditor, "customer-a")
    starts = [e for e in events if e.action == "session.ssh_started"]
    ends = [e for e in events if e.action == "session.ssh_ended"]
    assert len(starts) == len(ends) == 1
    assert hello["session_id"] in starts[0].target and hello["session_id"] in ends[0].target
    assert not any("show version" in e.target for e in events)


@pytest.mark.parametrize("origin", [None, "http://evil.test", "https://localhost"])
def test_exact_origin_required_before_ssh(socket_setup, origin):
    client, _, _, _, grant, _, _, _ = socket_setup
    with pytest.raises(WebSocketDisconnect):
        with connect(client, grant.id, origin):
            pass
    assert FakeProcess.instances == []


@pytest.mark.parametrize(
    "hello",
    [
        {"type": "auth", "csrf_token": "wrong"},
        {"type": "auth", "csrf_token": "wrong", "host": "8.8.8.8"},
        {"type": "input", "data": "whoami"},
    ],
)
def test_csrf_and_auth_message_required(socket_setup, hello):
    client, _, _, _, grant, _, _, _ = socket_setup
    with connect(client, grant.id) as ws:
        ws.send_json(hello)
        assert ws.receive_json()["type"] == "error"
    assert FakeProcess.instances == []


@pytest.mark.parametrize(
    "case", ["owner", "tenant", "role", "expired", "revoked", "no_cookie", "vnc"]
)
def test_authorization_before_spawn(socket_setup, case):
    client, store, auth, user, grant, now, tech, _ = socket_setup
    ident = grant.id
    if case == "owner":
        auth.users["tech"].actor = replace(tech, id="other")
    elif case == "tenant":
        auth.users["tech"].actor = replace(tech, tenant_ids=frozenset({"other"}))
    elif case == "role":
        client.post("/auth/login", json={"username": "auditor", "password": "audit-password"})
    elif case == "expired":
        now[0] += timedelta(minutes=6)
    elif case == "revoked":
        store.revoke(tech, grant.id)
    elif case == "no_cookie":
        client.cookies.clear()
    else:
        ident = store.direct_grant(tech, "vnc", "Desktop", 1).id
    with pytest.raises(WebSocketDisconnect):
        with connect(client, ident):
            pass
    assert FakeProcess.instances == []


@pytest.mark.parametrize("event", ["logout", "revoke", "expiry", "entitlement", "role"])
def test_live_session_rechecked_on_input(socket_setup, event):
    client, store, auth, user, grant, now, tech, _ = socket_setup
    if event == "role":
        user = client.post(
            "/auth/login", json={"username": "multi", "password": "multi-password"}
        ).json()
        tech = replace(tech, id="multi")
        grant = store.direct_grant(tech, "frr", "Lab", 1)
    with connect(client, grant.id) as ws:
        handshake(ws, user)
        if event == "logout":
            assert (
                client.post(
                    "/auth/logout", headers={"X-CSRF-Token": user["csrf_token"]}
                ).status_code
                == 200
            )
        elif event == "revoke":
            store.revoke(tech, grant.id)
        elif event == "expiry":
            now[0] += timedelta(minutes=6)
        elif event == "entitlement":
            store._direct_entitlements = frozenset()
        else:
            assert (
                client.post(
                    "/auth/role",
                    json={"role": "approver"},
                    headers={"X-CSRF-Token": user["csrf_token"]},
                ).status_code
                == 200
            )
        ws.send_json({"type": "input", "data": "must not reach SSH\r"})
        assert ws.receive_json()["type"] == "error"
    assert FakeProcess.instances[0].inputs == []
    assert FakeProcess.instances[0].closed


def test_idle_revocation_guard(socket_setup):
    client, store, _, user, grant, _, tech, _ = socket_setup
    with connect(client, grant.id) as ws:
        handshake(ws, user)
        store.revoke(tech, grant.id)
        # No further user input: periodic watcher must close this terminal.
        assert ws.receive_json()["type"] == "error"
    assert FakeProcess.instances[0].closed


def test_per_user_session_limit(socket_setup):
    client, _, _, user, grant, _, _, _ = socket_setup
    with connect(client, grant.id) as first:
        handshake(first, user)
        with connect(client, grant.id) as second:
            handshake(second, user)
            with pytest.raises(WebSocketDisconnect):
                with connect(client, grant.id):
                    pass
    assert len(FakeProcess.instances) == 2 and all(p.closed for p in FakeProcess.instances)


@pytest.mark.parametrize(
    "message",
    [
        {"type": "resize", "cols": True, "rows": 24},
        {"type": "resize", "cols": 1000, "rows": 24},
        {"type": "input", "data": "x" * 4097},
        {"type": "input", "data": "ls", "host": "8.8.8.8"},
    ],
)
def test_terminal_message_bounds(socket_setup, message):
    client, _, _, user, grant, _, _, _ = socket_setup
    with connect(client, grant.id) as ws:
        handshake(ws, user)
        ws.send_json(message)
        assert ws.receive_json()["type"] == "error"
    assert FakeProcess.instances[0].closed


def test_ssh_command_disables_host_escape_forwarding_and_passwords():
    command = ssh_command(SSHTarget("127.0.0.1", 2222, "lab", "/tmp/key", "/tmp/known"))
    assert command[:4] == ["/usr/bin/ssh", "-F", "/dev/null", "-tt"]
    assert command[-1] == "lab@127.0.0.1"
    assert "EscapeChar=none" in command and "PermitLocalCommand=no" in command
    assert "ClearAllForwardings=yes" in command and "ForwardAgent=no" in command
    assert "IdentityAgent=none" in command and "StrictHostKeyChecking=yes" in command
    assert "PasswordAuthentication=no" in command and "ControlPath=none" in command


def test_pty_child_cleanup(monkeypatch):
    child = Mock()
    child.pid = 999999
    child.poll.return_value = None
    child.wait.side_effect = [subprocess.TimeoutExpired("ssh", 1), 0]
    spawn = Mock(return_value=child)
    kill = Mock()
    monkeypatch.setattr("vg_api.ssh_sessions.subprocess.Popen", spawn)
    monkeypatch.setattr("vg_api.ssh_sessions.os.killpg", kill)
    process = SSHProcess(SSHTarget("127.0.0.1", 22, "lab", "/tmp/key", "/tmp/known"))
    assert spawn.call_args.kwargs["start_new_session"]
    assert spawn.call_args.kwargs.get("shell", False) is False
    assert "SSH_AUTH_SOCK" not in spawn.call_args.kwargs["env"]
    process.resize(100, 30)
    process.close()
    assert kill.call_count == 3


def test_malformed_or_oversized_json_rejected():
    for raw in ("[]", "{bad", '"' + "x" * 20000 + '"'):
        with pytest.raises(DomainError):
            parse_message(raw)


def test_real_pty_round_trip_and_cleanup(monkeypatch):
    import sys
    import time

    # Exercise actual PTY/subprocess plumbing without any network or device access.
    monkeypatch.setattr(
        "vg_api.ssh_sessions.ssh_command",
        lambda target: [
            sys.executable,
            "-u",
            "-c",
            "print('LAB READY', flush=True); "
            "line=input(); print('RECEIVED:'+line, flush=True); input()",
        ],
    )
    process = SSHProcess(SSHTarget("127.0.0.1", 22, "lab", "/tmp/key", "/tmp/known"))
    try:
        process.resize(120, 40)
        process.write(b"hello-lab\n")
        received = b""
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            chunk = process.read()
            if chunk:
                received += chunk
            if b"RECEIVED:hello-lab" in received:
                break
            time.sleep(0.01)
        assert b"LAB READY" in received and b"RECEIVED:hello-lab" in received
    finally:
        process.close()
    assert process.process.poll() is not None


def test_binary_input_rejected_and_cleaned_up(socket_setup):
    client, _, _, user, grant, _, _, _ = socket_setup
    with connect(client, grant.id) as ws:
        handshake(ws, user)
        ws.send_bytes(b"not a supported input frame")
        assert ws.receive_json()["type"] == "error"
    assert FakeProcess.instances[0].inputs == [] and FakeProcess.instances[0].closed
