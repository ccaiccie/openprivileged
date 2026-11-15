"""RFB desktop bridge protocol/security tests; all credentials are fictional."""

import asyncio
import json
from dataclasses import FrozenInstanceError

import pytest
from vg_api.desktop_bridge import (
    DesktopProtocolError,
    DesktopTarget,
    authenticate_vnc,
    load_desktop_target,
    proxy_vnc,
    vnc_challenge_response,
)

BANNER = b"RFB 003.008\n"
CHALLENGE = bytes(range(16))
RESPONSE = bytes.fromhex("b866924125c8eebb9debc1db61c538e2")


class FakeWriter:
    def __init__(self):
        self.output = bytearray()
        self.closed = False

    def write(self, data):
        self.output.extend(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def backend(monkeypatch, payload):
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    writer = FakeWriter()
    calls = []

    async def connect(host, port, **kwargs):
        calls.append((host, port))
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", connect)
    return reader, writer, calls


def test_challenge_known_des_vector():
    # Independent reference: OpenSSL DES-ECB key0e86ceceeef64e26, no padding.
    assert vnc_challenge_response("password", CHALLENGE) == RESPONSE


def test_target_does_not_print_password_and_is_immutable():
    target = DesktopTarget(host="10.78.0.21", port=5901, password="testpass")
    assert "testpass" not in repr(target)
    with pytest.raises(FrozenInstanceError):
        target.host = "127.0.0.1"


def test_backend_authenticates_before_client_init(monkeypatch):
    async def scenario():
        reader, writer, calls = backend(
            monkeypatch, BANNER + b"\x02\x01\x02" + CHALLENGE + b"\x00\x00\x00\x00"
        )
        actual_reader, actual_writer = await authenticate_vnc(
            DesktopTarget(host="10.78.0.21", port=5901, password="password")
        )
        assert actual_reader is reader and actual_writer is writer
        assert calls == [("10.78.0.21", 5901)]
        assert bytes(writer.output) == BANNER + b"\x02" + RESPONSE
        assert not writer.closed

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "payload",
    [
        b"RFB 003.007\n",
        b"INVALID DATA",
        BANNER + b"\x01\x01",  # Do not accept backend NoAuth.
        BANNER + b"\x01\x13",  # Unsupported security scheme.
        BANNER + b"\x00" + (6).to_bytes(4, "big") + b"denied",
        BANNER
        + b"\x01\x02"
        + CHALLENGE
        + (1).to_bytes(4, "big")
        + (6).to_bytes(4, "big")
        + b"denied",
    ],
)
def test_invalid_backend_handshakes_fail_closed(monkeypatch, payload):
    async def scenario():
        _, writer, _ = backend(monkeypatch, payload)
        with pytest.raises(DesktopProtocolError):
            await authenticate_vnc(DesktopTarget(host="10.78.0.21", port=5901, password="password"))
        assert writer.closed

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "host,port", [("127.0.0.1", 5901), ("10.78.0.22", 5901), ("10.78.0.21", 22)]
)
def test_only_fixed_lab_target_can_connect(monkeypatch, host, port):
    async def scenario():
        _, _, calls = backend(monkeypatch, b"")
        with pytest.raises(DesktopProtocolError):
            await authenticate_vnc(DesktopTarget(host=host, port=port, password="password"))
        assert calls == []

    asyncio.run(scenario())


def test_load_private_credentials_without_exposing_other_values(tmp_path):
    path = tmp_path / "desktop.json"
    path.write_text(
        json.dumps(
            {
                "address": "10.78.0.21",
                "username": "tester",
                "vnc_password": "testpass",
                "rdp_password": "unrelated-fixture-value",
            }
        )
    )
    path.chmod(0o600)
    target = load_desktop_target(path)
    assert target.host == "10.78.0.21" and target.port == 5901
    assert target.password == "testpass"
    assert "unrelated-fixture-value" not in repr(target)


@pytest.mark.parametrize(
    "overrides",
    [
        {"address": "127.0.0.1"},
        {"vnc_password": ""},
        {"vnc_password": "ninechars"},
        {"vnc_password": "snow\u2603"},
    ],
)
def test_load_rejects_wrong_address_or_invalid_password(tmp_path, overrides):
    path = tmp_path / "desktop.json"
    path.write_text(json.dumps({"address": "10.78.0.21", "vnc_password": "testpass", **overrides}))
    path.chmod(0o600)
    with pytest.raises(ValueError):
        load_desktop_target(path)


def test_load_rejects_world_readable_file_and_symlink(tmp_path):
    path = tmp_path / "desktop.json"
    path.write_text(json.dumps({"address": "10.78.0.21", "vnc_password": "testpass"}))
    path.chmod(0o644)
    with pytest.raises(ValueError):
        load_desktop_target(path)
    path.chmod(0o600)
    linked = tmp_path / "link.json"
    linked.symlink_to(path)
    with pytest.raises(OSError):
        load_desktop_target(linked)


class FakeWebSocket:
    def __init__(self, frames=()):
        self.frames = list(frames)
        self.sent = []
        self.close_code = None

    async def receive_bytes(self):
        if self.frames:
            return self.frames.pop(0)
        await asyncio.Future()

    async def send_bytes(self, data):
        self.sent.append(data)

    async def close(self, code=1000, reason=None):
        self.close_code = code


def test_unauthorized_websocket_never_connects_backend(monkeypatch):
    async def scenario():
        _, _, calls = backend(monkeypatch, b"")
        ws = FakeWebSocket()

        async def denied():
            return False

        await proxy_vnc(ws, DesktopTarget("10.78.0.21", 5901, "testpass"), denied)
        assert calls == []
        assert ws.close_code == 1008
        assert not ws.sent

    asyncio.run(scenario())


def desktop_init():
    import struct

    name = b"fixture desktop"
    return (
        struct.pack(">HHBBBBHHHBBBxxxI", 1, 1, 32, 24, 0, 1, 255, 255, 255, 16, 8, 0, len(name))
        + name
    )


def test_fragmented_browser_handshake_and_live_revocation(monkeypatch):
    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data(BANNER + b"\x01\x02" + CHALLENGE + b"\x00" * 4 + desktop_init())
        writer = FakeWriter()

        async def connect(host, port):
            return reader, writer

        monkeypatch.setattr(asyncio, "open_connection", connect)
        # Fragmented banner; pipeline selection, exclusive-init and first key event.
        key_event = b"\x04\x01\x00\x00\x00\x00\x00A"
        ws = FakeWebSocket([BANNER[:4], BANNER[4:], b"\x01\x00" + key_event])
        allowed = True

        async def authorize():
            return allowed

        proxy = asyncio.create_task(
            proxy_vnc(ws, DesktopTarget("10.78.0.21", 5901, "password"), authorize)
        )
        try:
            for _ in range(200):
                if bytes(writer.output).endswith(key_event):
                    break
                await asyncio.sleep(0.005)
            assert bytes(writer.output) == BANNER + b"\x02" + RESPONSE + b"\x01" + key_event
            assert ws.sent[:4] == [BANNER, b"\x01\x01", b"\x00" * 4, desktop_init()]
            assert CHALLENGE not in b"".join(ws.sent)
            assert RESPONSE not in b"".join(ws.sent)
            assert b"password" not in b"".join(ws.sent)
            allowed = False  # Same callback state used when logout/grant revoke occurs.
            await asyncio.wait_for(proxy, timeout=2)
            assert writer.closed
            assert ws.close_code == 1008
        finally:
            proxy.cancel()
            await asyncio.gather(proxy, return_exceptions=True)

    asyncio.run(scenario())


def test_revoked_input_is_not_forwarded(monkeypatch):
    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data(BANNER + b"\x01\x02" + CHALLENGE + b"\x00" * 4 + desktop_init())
        writer = FakeWriter()

        async def connect(host, port):
            return reader, writer

        monkeypatch.setattr(asyncio, "open_connection", connect)
        allowed = True
        key_event = b"\x04\x01\x00\x00\x00\x00\x00B"

        class RevokeOnInput(FakeWebSocket):
            async def receive_bytes(self):
                nonlocal allowed
                if self.frames:
                    return self.frames.pop(0)
                allowed = False
                return key_event

        ws = RevokeOnInput([BANNER, b"\x01", b"\x01"])

        async def authorize():
            return allowed

        await asyncio.wait_for(
            proxy_vnc(ws, DesktopTarget("10.78.0.21", 5901, "password"), authorize), timeout=2
        )
        assert key_event not in writer.output
        assert writer.closed and ws.close_code == 1008

    asyncio.run(scenario())


def test_oversized_browser_frame_closes_backend(monkeypatch):
    async def scenario():
        _, writer, _ = backend(monkeypatch, BANNER + b"\x01\x02" + CHALLENGE + b"\x00" * 4)
        ws = FakeWebSocket([b"x" * (1024 * 1024 + 1)])

        async def authorize():
            return True

        await proxy_vnc(ws, DesktopTarget("10.78.0.21", 5901, "password"), authorize)
        assert writer.closed and ws.close_code == 1011

    asyncio.run(scenario())


def test_revocation_interrupts_stalled_browser_handshake(monkeypatch):
    async def scenario():
        _, writer, _ = backend(monkeypatch, BANNER + b"\x01\x02" + CHALLENGE + b"\x00" * 4)
        ws = FakeWebSocket()  # Client never sends its version banner.
        allowed = True

        async def authorize():
            return allowed

        proxy = asyncio.create_task(
            proxy_vnc(ws, DesktopTarget("10.78.0.21", 5901, "password"), authorize)
        )
        try:
            for _ in range(200):
                if ws.sent:
                    break
                await asyncio.sleep(0.005)
            assert ws.sent == [BANNER]
            allowed = False
            await asyncio.wait_for(proxy, timeout=2)
            assert writer.closed and ws.close_code == 1008
        finally:
            proxy.cancel()
            await asyncio.gather(proxy, return_exceptions=True)

    asyncio.run(scenario())


def test_revocation_interrupts_stalled_backend_handshake(monkeypatch):
    async def scenario():
        reader = asyncio.StreamReader()  # Backend never sends its version banner.
        writer = FakeWriter()
        connected = asyncio.Event()

        async def connect(host, port):
            connected.set()
            return reader, writer

        monkeypatch.setattr(asyncio, "open_connection", connect)
        ws = FakeWebSocket()
        allowed = True

        async def authorize():
            return allowed

        proxy = asyncio.create_task(
            proxy_vnc(ws, DesktopTarget("10.78.0.21", 5901, "password"), authorize)
        )
        try:
            await asyncio.wait_for(connected.wait(), timeout=1)
            allowed = False
            await asyncio.wait_for(proxy, timeout=2)
            assert writer.closed and ws.close_code == 1008
            assert not ws.sent
        finally:
            proxy.cancel()
            await asyncio.gather(proxy, return_exceptions=True)

    asyncio.run(scenario())


@pytest.fixture
def desktop_route_setup():
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    from vg_api.demo_auth import DemoAuth
    from vg_api.desktop_bridge import install_vnc_routes
    from vg_core.domain import Actor, ControlPlane, Device, DomainError, Policy

    actors = {
        name: Actor(name, "demo-msp", frozenset({"customer-a"}), role)
        for name, role in (("tech", "technician"), ("other", "technician"), ("auditor", "auditor"))
    }
    plane = ControlPlane(
        (
            Device("vg-ubuntu-vnc", "demo-msp", "customer-a", "VNC", "ubuntu", "direct", "vnc"),
            Device("vg-ubuntu-rdp", "demo-msp", "customer-a", "RDP", "ubuntu", "direct", "rdp"),
        ),
        {("demo-msp", "customer-a"): Policy()},
        direct_entitlements=frozenset(
            (name, device)
            for name in ("tech", "multi")
            for device in ("vg-ubuntu-vnc", "vg-ubuntu-rdp")
        ),
    )
    app = FastAPI()

    @app.exception_handler(DomainError)
    async def domain_error(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=exc.status)

    passwords = {name: "fixture-pass" for name in (*actors, "multi")}
    auth = DemoAuth(plane, actors, passwords)
    auth.install(app)
    install_vnc_routes(
        app, plane, auth, {"vg-ubuntu-vnc": DesktopTarget("10.78.0.21", 5901, "testpass")}
    )
    actors["multi"] = Actor("multi", "demo-msp", frozenset({"customer-a"}), "technician")
    return app, plane, actors


def route_client(app, username="tech"):
    from fastapi.testclient import TestClient

    client = TestClient(app, base_url="http://localhost", client=("127.0.0.1", 50000))
    response = client.post("/auth/login", json={"username": username, "password": "fixture-pass"})
    assert response.status_code == 200
    return client, response.json()["csrf_token"]


@pytest.mark.parametrize(
    "case",
    [
        "no-login",
        "no-origin",
        "foreign-origin",
        "wrong-csrf",
        "no-binary",
        "duplicate-csrf",
        "other-user",
        "auditor",
        "rdp-target",
        "revoked",
    ],
)
def test_websocket_route_rejects_invalid_authorization(monkeypatch, desktop_route_setup, case):
    from starlette.websockets import WebSocketDisconnect
    from vg_api import desktop_bridge

    app, plane, actors = desktop_route_setup
    invoked = []

    async def should_not_proxy(*args):
        invoked.append(True)

    monkeypatch.setattr(desktop_bridge, "proxy_vnc", should_not_proxy)
    username = "other" if case == "other-user" else "auditor" if case == "auditor" else "tech"
    client, csrf = route_client(app, username)
    device = "vg-ubuntu-rdp" if case == "rdp-target" else "vg-ubuntu-vnc"
    grant = plane.direct_grant(actors["tech"], device, "Route test", 1)
    if case == "revoked":
        plane.revoke(actors["tech"], grant.id)
    if case == "no-login":
        client.cookies.clear()
    headers = {"Origin": "http://localhost"}
    if case == "no-origin":
        headers = {}
    if case == "foreign-origin":
        headers = {"Origin": "https://evil.example"}
    protocols = ["binary", "vaultgate-csrf." + ("wrong" if case == "wrong-csrf" else csrf)]
    if case == "no-binary":
        protocols.remove("binary")
    if case == "duplicate-csrf":
        protocols.append("vaultgate-csrf.duplicate")
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(
            f"ws://localhost/v1/grants/{grant.id}/vnc-session",
            headers=headers,
            subprotocols=protocols,
        ):
            pass
    assert exc.value.code == 1008
    assert not invoked


@pytest.mark.parametrize("change", ["revoke", "logout", "role-switch"])
def test_accepted_route_rechecks_session_and_grant(monkeypatch, desktop_route_setup, change):
    from vg_api import desktop_bridge

    app, plane, actors = desktop_route_setup

    async def mock_proxy(socket, target, authorize):
        assert await authorize()
        await socket.send_text("ready")
        await socket.receive_text()
        permitted = await authorize()
        await socket.send_json({"permitted": permitted})
        await socket.close(code=1008 if not permitted else 1000)

    monkeypatch.setattr(desktop_bridge, "proxy_vnc", mock_proxy)
    client, csrf = route_client(app, "multi")
    grant = plane.direct_grant(actors["multi"], "vg-ubuntu-vnc", "Route test", 1)
    with client.websocket_connect(
        f"ws://localhost/v1/grants/{grant.id}/vnc-session",
        headers={"Origin": "http://localhost"},
        subprotocols=["binary", "vaultgate-csrf." + csrf],
    ) as socket:
        assert socket.accepted_subprotocol == "binary"
        assert socket.receive_text() == "ready"
        if change == "revoke":
            plane.revoke(actors["multi"], grant.id)
        elif change == "logout":
            assert client.post("/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
        else:
            assert (
                client.post(
                    "/auth/role", json={"role": "approver"}, headers={"X-CSRF-Token": csrf}
                ).status_code
                == 200
            )
        socket.send_text("recheck")
        assert socket.receive_json() == {"permitted": False}
    events = plane.audit(actors["auditor"], "customer-a")
    assert "desktop.session_requested" in [event.action for event in events]
    assert "desktop.session_closed" in [event.action for event in events]
