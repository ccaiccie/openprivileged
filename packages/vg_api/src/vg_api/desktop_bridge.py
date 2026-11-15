"""Fixed isolated-lab VNC bridge. Backend credentials never enter the browser.

The frontend sees NoAuth only inside a session/CSRF/grant-authorized WebSocket.
The backend authenticates with the private VNC password over the isolated lab leg.
This is not TLS protection for the backend leg or a session recorder.
"""

import asyncio
import contextlib
import json
import os
import stat
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path

from Crypto.Cipher import DES
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from vg_core.domain import ControlPlane, DomainError

from vg_api.demo_auth import DemoAuth

VERSION = b"RFB 003.008\n"
MAX_FRAME = 1024 * 1024
TIMEOUT = 10.0
Authorize = Callable[[], Awaitable[bool]]


class DesktopProtocolError(ValueError):
    """Deliberately generic protocol/authentication failure without secret values."""


@dataclass(frozen=True)
class DesktopTarget:
    host: str
    port: int
    password: str = field(repr=False)


def load_desktop_target(path: Path) -> DesktopTarget:
    if not path.is_absolute():
        raise ValueError("Desktop credentials require an absolute owner-only path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Desktop credentials must be an owner-only regular file")
        if info.st_size > 4096:
            raise ValueError("Desktop credentials file exceeds size limit")
        data = json.load(stream)
    password = data.get("vnc_password")
    if (
        data.get("address") != "10.78.0.21"
        or not isinstance(password, str)
        or not 1 <= len(password) <= 8
        or not password.isascii()
    ):
        raise ValueError("Expected isolated lab address and a valid VNC password")
    return DesktopTarget("10.78.0.21", 5901, password)


def vnc_challenge_response(password: str, challenge: bytes) -> bytes:
    if len(challenge) != 16 or not password or not password.isascii():
        raise DesktopProtocolError("Invalid VNC challenge or credential format")
    # RFB's legacy VNC security reverses the bits of each DES password-key byte.
    raw = password.encode("ascii")[:8].ljust(8, b"\0")
    key = bytes(int(f"{byte:08b}"[::-1], 2) for byte in raw)
    return DES.new(key, DES.MODE_ECB).encrypt(challenge)


async def authenticate_vnc(
    target: DesktopTarget,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    if target.host != "10.78.0.21" or target.port != 5901:
        raise DesktopProtocolError("Only the fixed isolated desktop endpoint is permitted")
    writer: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(TIMEOUT):
            reader, writer = await asyncio.open_connection(target.host, target.port)
            if await reader.readexactly(12) != VERSION:
                raise DesktopProtocolError("Unsupported backend RFB version")
            writer.write(VERSION)
            await writer.drain()
            count = (await reader.readexactly(1))[0]
            if count == 0:
                raise DesktopProtocolError("Backend rejected connection")
            offered = await reader.readexactly(count)
            if 2 not in offered:
                raise DesktopProtocolError("Backend VNC password authentication required")
            writer.write(b"\x02")
            await writer.drain()
            challenge = await reader.readexactly(16)
            writer.write(vnc_challenge_response(target.password, challenge))
            await writer.drain()
            if await reader.readexactly(4) != b"\0\0\0\0":
                raise DesktopProtocolError("Backend authentication failed")
            return reader, writer
    except BaseException:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        raise


async def proxy_vnc(socket: WebSocket, target: DesktopTarget, authorize: Authorize) -> None:
    """Proxy an already accepted socket; recheck the session/grant for every input."""
    writer: asyncio.StreamWriter | None = None
    tasks: list[asyncio.Task[None]] = []
    buffer = bytearray()

    async def permitted() -> None:
        if not await authorize():
            raise PermissionError("Desktop access ended")

    async def receive() -> bytes:
        data = await socket.receive_bytes()
        if not data or len(data) > MAX_FRAME:
            raise DesktopProtocolError("Invalid WebSocket frame size")
        await permitted()
        return data

    async def exact(count: int) -> bytes:
        while len(buffer) < count:
            buffer.extend(await receive())
            if len(buffer) > MAX_FRAME:
                raise DesktopProtocolError("Handshake size exceeded")
        result = bytes(buffer[:count])
        del buffer[:count]
        return result

    async def heartbeat() -> None:
        while True:
            await asyncio.sleep(1)
            await permitted()

    close_code = 1000
    try:
        await permitted()
        # Start checks before backend handshake, so logout/revoke also interrupts setup.
        monitor = asyncio.create_task(heartbeat())
        tasks.append(monitor)
        backend = asyncio.create_task(authenticate_vnc(target))
        try:
            done, _ = await asyncio.wait([backend, monitor], return_when=asyncio.FIRST_COMPLETED)
            if backend in done:
                reader, writer = backend.result()
            if monitor in done:
                monitor.result()
            reader, writer = await backend
        finally:
            if not backend.done():
                backend.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await backend

        async def initialize() -> None:
            assert writer is not None
            async with asyncio.timeout(TIMEOUT):
                await socket.send_bytes(VERSION)
                if await exact(12) != VERSION:
                    raise DesktopProtocolError("Unsupported client RFB version")
                await socket.send_bytes(b"\x01\x01")
                if await exact(1) != b"\x01":
                    raise DesktopProtocolError("Unsupported client security selection")
                await socket.send_bytes(b"\0\0\0\0")
                shared = await exact(1)
                if shared not in (b"\0", b"\x01"):
                    raise DesktopProtocolError("Invalid client initialization")
                await permitted()
                # Always share the lab display; one browser must not evict other sessions.
                writer.write(b"\x01")
                await writer.drain()
                initial = await reader.readexactly(24)
                name_length = int.from_bytes(initial[20:24], "big")
                if name_length > 4096:
                    raise DesktopProtocolError("Invalid backend desktop name length")
                await socket.send_bytes(initial + await reader.readexactly(name_length))
                if buffer:
                    await permitted()
                    writer.write(buffer)
                    buffer.clear()
                    await writer.drain()

        handshake = asyncio.create_task(initialize())
        try:
            done, _ = await asyncio.wait([handshake, monitor], return_when=asyncio.FIRST_COMPLETED)
            if monitor in done:
                monitor.result()
            await handshake
        finally:
            if not handshake.done():
                handshake.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await handshake

        async def to_backend() -> None:
            assert writer is not None
            while True:
                data = await receive()
                writer.write(data)
                await writer.drain()

        async def to_browser() -> None:
            while True:
                data = await reader.read(65536)
                if not data:
                    return
                await permitted()
                await socket.send_bytes(data)

        tasks.extend([asyncio.create_task(to_backend()), asyncio.create_task(to_browser())])
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    except (PermissionError, DomainError):
        close_code = 1008
    except WebSocketDisconnect:
        pass
    except (OSError, ValueError, RuntimeError, TimeoutError, asyncio.IncompleteReadError):
        close_code = 1011
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        with contextlib.suppress(RuntimeError, OSError):
            await socket.close(code=close_code)


def install_vnc_routes(
    app: FastAPI, store: ControlPlane, auth: DemoAuth, targets: dict[str, DesktopTarget]
) -> None:
    active: set[str] = set()

    @app.websocket("/v1/grants/{grant_id}/vnc-session")
    async def vnc_session(socket: WebSocket, grant_id: str) -> None:
        protocols = socket.scope.get("subprotocols", [])
        csrf_values = [
            p.removeprefix("vaultgate-csrf.") for p in protocols if p.startswith("vaultgate-csrf.")
        ]
        try:
            if len(csrf_values) != 1 or "binary" not in protocols:
                raise DomainError("Browser desktop handshake required", 403)
            csrf = csrf_values[0]
            original = await auth.async_socket_actor(socket, csrf)
            device = store.authorize_connection(original, grant_id, audit=False)
            if device.id != "vg-ubuntu-vnc" or device.protocol != "vnc" or device.id not in targets:
                raise DomainError("Desktop target unavailable", 403)
            if grant_id in active or len(active) >= 8:
                raise DomainError("Desktop session limit reached", 409)
        except DomainError:
            await socket.close(code=1008)
            return
        active.add(grant_id)

        async def authorized() -> bool:
            try:
                current = await auth.async_socket_actor(socket, csrf)
                if current != original:
                    return False
                target_device = store.authorize_connection(current, grant_id, audit=False)
                return target_device.id == device.id and target_device.protocol == "vnc"
            except DomainError:
                return False

        try:
            await socket.accept(subprotocol="binary")
            store.authorize_connection(original, grant_id)
            store.record_identity_event(original, "desktop.session_requested", grant_id)
            await proxy_vnc(socket, targets[device.id], authorized)
        except DomainError:
            with contextlib.suppress(RuntimeError, OSError):
                await socket.close(code=1008)
        finally:
            active.discard(grant_id)
            store.record_identity_event(original, "desktop.session_closed", grant_id)
