"""Guacamole protocol constraints and fail-closed certificate configuration."""

import asyncio
import json

import pytest
from vg_api import rdp_bridge as rdp

PIN = ":".join(["ab"] * 32)


class Writer:
    def __init__(self):
        self.data = bytearray()
        self.closed = False

    def write(self, value):
        self.data.extend(value)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def test_loader_requires_fixed_target_and_private_credentials(tmp_path):
    secret = tmp_path / "credentials.json"
    manifest = tmp_path / "manifest.json"
    secret.write_text(
        json.dumps({"address": "10.78.0.21", "username": "vgdesktop", "rdp_password": "fictional"})
    )
    secret.chmod(0o600)
    manifest.write_text(json.dumps({"desktop": {"rdp_certificate_sha256": PIN}}))
    target = rdp.load_rdp_target(secret, manifest)
    assert target.fingerprint == PIN
    assert "fictional" not in repr(target)
    secret.chmod(0o644)
    with pytest.raises(ValueError, match="permissions"):
        rdp.load_rdp_target(secret, manifest)
    secret.chmod(0o600)
    secret.write_text(secret.read_text().replace("10.78.0.21", "127.0.0.1"))
    with pytest.raises(ValueError, match="approved"):
        rdp.load_rdp_target(secret, manifest)


@pytest.mark.parametrize("value", ["", "1.x", "999999.a;", "1.x!", "1.x,99999.x;", "a.x;"])
def test_invalid_browser_frames(value):
    with pytest.raises(ValueError):
        rdp.parse_client(value)


def test_client_roundtrip_and_multiple_instructions():
    assert rdp.parse_client(
        (rdp.instruction("key", "65", "1") + rdp.instruction("sync", "123")).decode()
    ) == [["key", "65", "1"], ["sync", "123"]]
    assert not {"connect", "select", "clipboard", "file", "blob"} & rdp.ALLOWED_INPUT


@pytest.mark.parametrize("supports_pin", [True, False])
def test_guacd_pin_and_server_only_credentials(monkeypatch, supports_pin):
    async def scenario():
        reader = asyncio.StreamReader()
        args = ["hostname", "port", "username", "password", "ignore-cert", "cert-tofu"]
        if supports_pin:
            args.append("cert-fingerprints")
        reader.feed_data(rdp.instruction("args", *args) + rdp.instruction("ready", "uuid"))
        reader.feed_eof()
        writer = Writer()

        async def connect(host, port):
            assert (host, port) == ("127.0.0.1", 4823)
            return reader, writer

        monkeypatch.setattr(asyncio, "open_connection", connect)
        target = rdp.RDPTarget("10.78.0.21", "vgdesktop", "fictional", PIN)
        if not supports_pin:
            with pytest.raises(ValueError, match="pinning"):
                await rdp.connect_rdp(target)
            assert writer.closed
            assert b"fictional" not in writer.data
        else:
            await rdp.connect_rdp(target)
            frames = rdp.parse_client(writer.data.decode())
            values = dict(zip(args, frames[-1][1:], strict=True))
            assert values["ignore-cert"] == "false"
            assert values["cert-tofu"] == "false"
            assert values["cert-fingerprints"] == "sha256:" + PIN
            assert values["password"] == "fictional"

    asyncio.run(scenario())


def test_unapproved_target_fails_before_network():
    async def scenario():
        with pytest.raises(ValueError, match="Unapproved"):
            await rdp.connect_rdp(rdp.RDPTarget("example.com", "vgdesktop", "fictional", PIN))

    asyncio.run(scenario())


def test_revocation_cancels_stalled_connection(monkeypatch):
    async def scenario():
        cancelled = asyncio.Event()

        async def connect(target):
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        monkeypatch.setattr(rdp, "connect_rdp", connect)
        calls = 0

        async def authorized():
            nonlocal calls
            calls += 1
            return calls == 1

        class Socket:
            async def close(self, code):
                self.code = code

        socket = Socket()
        await asyncio.wait_for(
            rdp.proxy_rdp(
                socket, rdp.RDPTarget("10.78.0.21", "vgdesktop", "fictional", PIN), authorized
            ),
            3,
        )
        assert cancelled.is_set()
        assert socket.code == 1008

    asyncio.run(scenario())


@pytest.fixture
def rdp_route_setup():
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    from vg_api.demo_auth import DemoAuth
    from vg_api.rdp_bridge import install_rdp_routes
    from vg_core.domain import Actor, ControlPlane, Device, DomainError, Policy

    actors = {
        name: Actor(name, "demo-msp", frozenset({"customer-a"}), role)
        for name, role in (("tech", "technician"), ("other", "technician"), ("auditor", "auditor"))
    }
    plane = ControlPlane(
        (
            Device("vg-ubuntu-rdp", "demo-msp", "customer-a", "RDP", "ubuntu", "direct", "rdp"),
            Device("vg-ubuntu-vnc", "demo-msp", "customer-a", "VNC", "ubuntu", "direct", "vnc"),
        ),
        {("demo-msp", "customer-a"): Policy()},
        direct_entitlements=frozenset(
            (name, device)
            for name in ("tech", "multi")
            for device in ("vg-ubuntu-rdp", "vg-ubuntu-vnc")
        ),
    )
    app = FastAPI()

    @app.exception_handler(DomainError)
    async def domain_error(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=exc.status)

    passwords = {name: "fixture-pass" for name in (*actors, "multi")}
    auth = DemoAuth(plane, actors, passwords)
    auth.install(app)
    install_rdp_routes(
        app,
        plane,
        auth,
        {"vg-ubuntu-rdp": rdp.RDPTarget("10.78.0.21", "vgdesktop", "testpass", PIN)},
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
        "no-guacamole",
        "duplicate-csrf",
        "other-user",
        "auditor",
        "vnc-target",
        "revoked",
    ],
)
def test_websocket_route_rejects_invalid_authorization(monkeypatch, rdp_route_setup, case):
    from starlette.websockets import WebSocketDisconnect
    from vg_api import rdp_bridge

    app, plane, actors = rdp_route_setup
    invoked = []

    async def should_not_proxy(*args):
        invoked.append(True)

    monkeypatch.setattr(rdp_bridge, "proxy_rdp", should_not_proxy)
    username = "other" if case == "other-user" else "auditor" if case == "auditor" else "tech"
    client, csrf = route_client(app, username)
    device = "vg-ubuntu-vnc" if case == "vnc-target" else "vg-ubuntu-rdp"
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
    protocols = ["guacamole", "vaultgate-csrf." + ("wrong" if case == "wrong-csrf" else csrf)]
    if case == "no-guacamole":
        protocols.remove("guacamole")
    if case == "duplicate-csrf":
        protocols.append("vaultgate-csrf.duplicate")
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(
            f"ws://localhost/v1/grants/{grant.id}/rdp-session",
            headers=headers,
            subprotocols=protocols,
        ):
            pass
    assert exc.value.code == 1008
    assert not invoked


@pytest.mark.parametrize("change", ["revoke", "logout", "role-switch"])
def test_accepted_route_rechecks_session_and_grant(monkeypatch, rdp_route_setup, change):
    from vg_api import rdp_bridge

    app, plane, actors = rdp_route_setup

    async def mock_proxy(socket, target, authorize):
        assert await authorize()
        await socket.send_text("ready")
        await socket.receive_text()
        permitted = await authorize()
        await socket.send_json({"permitted": permitted})
        await socket.close(code=1008 if not permitted else 1000)

    monkeypatch.setattr(rdp_bridge, "proxy_rdp", mock_proxy)
    client, csrf = route_client(app, "multi")
    grant = plane.direct_grant(actors["multi"], "vg-ubuntu-rdp", "Route test", 1)
    with client.websocket_connect(
        f"ws://localhost/v1/grants/{grant.id}/rdp-session",
        headers={"Origin": "http://localhost"},
        subprotocols=["guacamole", "vaultgate-csrf." + csrf],
    ) as socket:
        assert socket.accepted_subprotocol == "guacamole"
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
    assert "rdp.session_requested" in [event.action for event in events]
    assert "rdp.session_closed" in [event.action for event in events]


@pytest.mark.parametrize(
    "parts",
    [
        ["size", "99999999", "800"],
        ["size", "4096", "4096"],
        ["size", "1280", "800", "99999"],
        ["size", "1280"],
        ["key", "65", "2"],
        ["mouse", "0", "0", "999"],
        ["sync", "NaN"],
        ["touch", "0", "0", "0", "0", "0", "NaN", "1"],
        ["disconnect", "extra"],
        ["ack", "0", "ok", "-1"],
    ],
)
def test_client_instruction_argument_bounds(parts):
    with pytest.raises(ValueError):
        rdp.validate_client(parts)


@pytest.mark.parametrize(
    "parts",
    [
        ["size", "1280", "800"],
        ["size", "1920", "1080", "96"],
        ["key", "65", "1"],
        ["mouse", "-1", "800", "1"],
        ["sync", "123"],
        ["sync", "123", "0"],
        ["ack", "0", "OK", "0"],
        ["disconnect"],
        ["touch", "0", "1", "1", "1", "1", "0", "0.5"],
    ],
)
def test_client_instruction_valid_arguments(parts):
    rdp.validate_client(parts)


def test_loader_rejects_symlink_and_oversized_config(tmp_path):
    secret = tmp_path / "credentials.json"
    manifest = tmp_path / "manifest.json"
    secret.write_text("{}")
    secret.chmod(0o600)
    manifest.write_text("{}")
    link = tmp_path / "link.json"
    link.symlink_to(secret)
    with pytest.raises(ValueError, match="safely open"):
        rdp.load_rdp_target(link, manifest)
    secret.write_bytes(b" " * 65537)
    with pytest.raises(ValueError, match="too large"):
        rdp.load_rdp_target(secret, manifest)


def test_nop_keepalive_has_no_arguments():
    rdp.validate_client(["nop"])
    with pytest.raises(ValueError):
        rdp.validate_client(["nop", "extra"])


def test_fragmented_display_is_not_interleaved_with_ping(monkeypatch):
    async def scenario():
        reader = asyncio.StreamReader()
        writer = Writer()
        ping_sent = asyncio.Event()
        sent = []

        async def connect(target):
            return reader, writer

        async def authorized():
            return True

        class Socket:
            async def send_text(self, text):
                sent.append(text)
                if "4.ping" in text:
                    ping_sent.set()

            async def receive_text(self):
                if not ping_sent.is_set():
                    await asyncio.sleep(0.01)
                    return "0.,4.ping,3.123;"
                await asyncio.Event().wait()

            async def close(self, code):
                pass

        monkeypatch.setattr(rdp, "connect_rdp", connect)
        task = asyncio.create_task(
            rdp.proxy_rdp(
                Socket(), rdp.RDPTarget("10.78.0.21", "vgdesktop", "fictional", PIN), authorized
            )
        )
        reader.feed_data(b"4.blob,1.0,8.abcd")
        await asyncio.wait_for(ping_sent.wait(), 1)
        reader.feed_data(b"efgh;")
        await asyncio.sleep(0.02)
        reader.feed_eof()
        await asyncio.wait_for(task, 1)
        assert sent[1:] == ["0.,4.ping,3.123;", "4.blob,1.0,8.abcdefgh;"]

    asyncio.run(scenario())


def test_managed_route_injects_current_secret_without_browser_exposure(monkeypatch):
    from datetime import UTC, datetime, timedelta

    from vg_api.main import create_app
    from vg_core.domain import Actor, ControlPlane, Device, Policy
    from vg_core.rotation import AccountBinding, RotationService

    actor = Actor("tech", "demo-msp", frozenset({"customer-a"}), "technician")
    plane = ControlPlane(
        (Device("vg-ubuntu-rdp", "demo-msp", "customer-a", "RDP", "ubuntu", "direct", "rdp"),),
        {("demo-msp", "customer-a"): Policy()},
        direct_entitlements=frozenset({("tech", "vg-ubuntu-rdp")}),
    )
    now = [datetime(2026, 11, 13, tzinfo=UTC)]

    class Adapter:
        password = "synthetic-original-secret"

        def change(self, binding, password):
            self.password = password

        def verify(self, binding, password):
            return self.password == password

    adapter = Adapter()
    service = RotationService(adapter, lambda: now[0])
    service.enroll(
        AccountBinding(
            "a",
            "demo-msp",
            "customer-a",
            "tech",
            "vg-tech-admin",
            "lab",
            frozenset({"vg-ubuntu-rdp"}),
        ),
        adapter.password,
    )
    app = create_app(
        plane,
        {"tech": actor},
        demo_ui=True,
        demo_passwords={"tech": "fixture-pass"},
        rdp_targets={
            "vg-ubuntu-rdp": rdp.RDPTarget("10.78.0.21", "vgdesktop", "unused-static-password", PIN)
        },
        rotation_service=service,
    )
    observed = []

    async def connect(target, *, approved_username):
        assert target.username == approved_username == "vg-tech-admin"
        assert target.password == adapter.password
        observed.append(target.password)
        return asyncio.StreamReader(), Writer()

    async def proxy(socket, target, authorize, opener=None):
        assert opener is not None and await authorize()
        reader, writer = await opener()
        await socket.send_text("session-open")
        writer.close()
        await socket.close()

    monkeypatch.setattr(rdp, "connect_rdp", connect)
    monkeypatch.setattr(rdp, "proxy_rdp", proxy)
    client, csrf = route_client(app)
    grant = plane.direct_grant(actor, "vg-ubuntu-rdp", "Managed rotation test", 1)
    for iteration in range(2):
        if iteration:
            now[0] += timedelta(hours=4)
            service.rotate_due()
        with client.websocket_connect(
            f"ws://localhost/v1/grants/{grant.id}/rdp-session",
            subprotocols=["guacamole", f"vaultgate-csrf.{csrf}"],
            headers={"origin": "http://localhost"},
        ) as socket:
            assert socket.receive_text() == "session-open"
    assert len(observed) == 2 and observed[0] != observed[1]
    assert "synthetic-original-secret" not in client.get("/openapi.json").text
