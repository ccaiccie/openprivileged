"""Grant-bound Guacamole RDP tunnel for one explicitly approved isolated desktop."""

import asyncio
import contextlib
import json
import logging
import math
import os
import re
import stat
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from vg_core.domain import ControlPlane, DomainError
from vg_core.rotation import RotationService

from vg_api.demo_auth import DemoAuth
from vg_api.rotation_gateway import open_managed_session

Authorize = Callable[[], Awaitable[bool]]
TIMEOUT = 20
MAX_INPUT = 16384
GUACD = ("127.0.0.1", 4823)
ALLOWED_INPUT = {"sync", "mouse", "key", "size", "ack", "disconnect", "touch", "nop"}


@dataclass(frozen=True)
class RDPTarget:
    host: str
    username: str
    password: str = field(repr=False)
    fingerprint: str


def load_rdp_target(credentials: Path, manifest: Path) -> RDPTarget:
    def read_config(path: Path, secret: bool) -> dict[str, Any]:
        if not path.is_absolute():
            raise ValueError("RDP configuration requires an absolute path")
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError as exc:
            raise ValueError("Cannot safely open RDP configuration") from exc
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise ValueError("RDP configuration must be an operator-owned regular file")
            if metadata.st_mode & (0o077 if secret else 0o022):
                raise ValueError("RDP configuration permissions are unsafe")
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError("RDP configuration too large")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("RDP configuration must be an object")
        return value

    data = read_config(credentials, True)
    config = read_config(manifest, False)

    # The immutable public pin may be nested in the non-secret operator manifest.
    def find_pin(value: object) -> str | None:
        if isinstance(value, dict):
            if "rdp_certificate_sha256" in value:
                return str(value["rdp_certificate_sha256"])
            for child in value.values():
                found = find_pin(child)
                if found:
                    return found
        return None

    pin = find_pin(config)
    if data.get("address") != "10.78.0.21" or data.get("username") != "vgdesktop":
        raise ValueError("Only the approved isolated Ubuntu desktop is permitted")
    password = data.get("rdp_password")
    if not isinstance(password, str) or not 1 <= len(password) <= 200:
        raise ValueError("Invalid operator-held RDP password")
    if not pin or re.fullmatch(r"(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}", pin) is None:
        raise ValueError("Explicit SHA256 RDP certificate pin required")
    return RDPTarget("10.78.0.21", "vgdesktop", password, pin.lower())


def instruction(*parts: str) -> bytes:
    return (",".join(f"{len(p)}.{p}" for p in parts) + ";").encode("utf-8")


async def read_instruction(reader: asyncio.StreamReader) -> list[str]:
    parts: list[str] = []
    total = 0
    while len(parts) < 256:
        digits = await reader.readuntil(b".")
        if len(digits) > 8 or not digits[:-1].isdigit():
            raise ValueError("Invalid guacd instruction")
        size = int(digits[:-1])
        total += size
        if size > 65536 or total > 131072:
            raise ValueError("Guacd handshake too large")
        text = (await reader.readexactly(size)).decode("utf-8")
        parts.append(text)
        separator = await reader.readexactly(1)
        if separator == b";":
            return parts
        if separator != b",":
            raise ValueError("Invalid guacd separator")
    raise ValueError("Too many guacd handshake arguments")


def parse_client(text: str) -> list[list[str]]:
    if not text or len(text.encode()) > MAX_INPUT:
        raise ValueError("Invalid client frame size")
    output: list[list[str]] = []
    cursor = 0
    while cursor < len(text):
        parts: list[str] = []
        while len(parts) < 32:
            dot = text.find(".", cursor)
            if dot < 0 or dot - cursor > 6 or not text[cursor:dot].isdigit():
                raise ValueError("Malformed client instruction")
            length = int(text[cursor:dot])
            if length > 8192:
                raise ValueError("Client argument too long")
            start, end = dot + 1, dot + 1 + length
            if end >= len(text):
                raise ValueError("Incomplete client instruction")
            parts.append(text[start:end])
            separator = text[end]
            cursor = end + 1
            if separator == ";":
                break
            if separator != ",":
                raise ValueError("Malformed client separator")
        else:
            raise ValueError("Too many client arguments")
        if not parts:
            raise ValueError("Missing opcode")
        output.append(parts)
    return output


def validate_client(parts: list[str]) -> None:
    """Constrain untrusted browser instructions before sending to guacd."""
    opcode, *args = parts
    counts = {
        "sync": {1, 2},
        "mouse": {3},
        "key": {2},
        "size": {2, 3},
        "ack": {3},
        "disconnect": {0},
        "nop": {0},
        "touch": {7},
    }
    if opcode not in counts or len(args) not in counts[opcode]:
        raise ValueError("Invalid RDP client operation")

    def integer(value: str, low: int, high: int) -> int:
        if re.fullmatch(r"-?[0-9]{1,16}", value) is None:
            raise ValueError("Invalid RDP numeric argument")
        result = int(value)
        if not low <= result <= high:
            raise ValueError("RDP numeric argument out of range")
        return result

    if opcode == "size":
        width = integer(args[0], 1, 4096)
        height = integer(args[1], 1, 4096)
        if width * height > 8388608:
            raise ValueError("RDP framebuffer too large")
        if len(args) == 3:
            integer(args[2], 48, 384)
    elif opcode == "key":
        integer(args[0], 0, 0xFFFFFFFF)
        integer(args[1], 0, 1)
    elif opcode == "mouse":
        integer(args[0], -4096, 8192)
        integer(args[1], -4096, 8192)
        integer(args[2], 0, 31)
    elif opcode == "sync":
        for value in args:
            integer(value, 0, 2**53 - 1)
    elif opcode == "ack":
        integer(args[0], 0, 65535)
        if len(args[1]) > 1024:
            raise ValueError("RDP acknowledgment too long")
        integer(args[2], 0, 65535)
    elif opcode == "touch":
        integer(args[0], 0, 65535)
        for value in args[1:5]:
            integer(value, -4096, 8192)
        for value, low, high in ((args[5], -360, 360), (args[6], 0, 1)):
            number = float(value)
            if not math.isfinite(number) or not low <= number <= high:
                raise ValueError("Invalid RDP touch argument")


async def connect_rdp(
    target: RDPTarget, *, approved_username: str = "vgdesktop"
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    # approved_username is server-only and supplied by the assigned credential binding.
    if target.host != "10.78.0.21" or target.username != approved_username:
        raise ValueError("Unapproved RDP target")
    writer = None
    try:
        async with asyncio.timeout(TIMEOUT):
            reader, writer = await asyncio.open_connection(*GUACD)
            writer.write(instruction("select", "rdp"))
            await writer.drain()
            args = await read_instruction(reader)
            if not args or args[0] != "args" or "cert-fingerprints" not in args:
                raise ValueError("Guacd must support explicit certificate pinning")
            parameters = {
                "hostname": target.host,
                "port": "3389",
                "username": target.username,
                "password": target.password,
                "security": "tls",
                "ignore-cert": "false",
                "cert-tofu": "false",
                "cert-fingerprints": "sha256:" + target.fingerprint,
                "disable-auth": "false",
                "width": "1280",
                "height": "800",
                "dpi": "96",
                "color-depth": "24",
                "disable-audio": "true",
                "enable-audio-input": "false",
                "enable-printing": "false",
                "enable-drive": "false",
                "enable-sftp": "false",
                "disable-copy": "true",
                "disable-paste": "true",
                "disable-upload": "true",
                "disable-download": "true",
                "resize-method": "display-update",
                "timezone": "UTC",
                "client-name": "VaultGate-isolated-lab",
            }
            writer.write(instruction("size", "1280", "800", "96"))
            writer.write(instruction("audio"))
            writer.write(instruction("video"))
            writer.write(instruction("image", "image/png", "image/jpeg"))
            writer.write(instruction("timezone", "UTC"))
            writer.write(
                instruction(
                    "connect",
                    *[
                        name if name.startswith("VERSION_") else parameters.get(name, "")
                        for name in args[1:]
                    ],
                )
            )
            await writer.drain()
            ready = await read_instruction(reader)
            if not ready or ready[0] != "ready":
                raise ValueError("RDP initialization failed")
            return reader, writer
    except BaseException:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        raise


async def proxy_rdp(
    socket: WebSocket,
    target: RDPTarget,
    authorize: Authorize,
    opener: Callable[[], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]
    | None = None,
) -> None:
    writer: asyncio.StreamWriter | None = None
    tasks: list[asyncio.Task[None]] = []
    code = 1000

    async def permitted() -> None:
        if not await authorize():
            raise PermissionError("RDP session authorization ended")

    async def heartbeat() -> None:
        while True:
            await asyncio.sleep(1)
            await permitted()

    try:
        await permitted()
        monitor = asyncio.create_task(heartbeat())
        tasks.append(monitor)
        connection = asyncio.ensure_future(opener() if opener else connect_rdp(target))
        try:
            done, _ = await asyncio.wait([monitor, connection], return_when=asyncio.FIRST_COMPLETED)
            if connection in done:
                reader, writer = connection.result()
            if monitor in done:
                monitor.result()
            reader, writer = await connection
        finally:
            if not connection.done():
                connection.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await connection
        await permitted()
        await socket.send_text(instruction("", str(uuid4())).decode())

        async def to_server() -> None:
            assert writer is not None
            while True:
                message = await socket.receive_text()
                await permitted()
                for parts in parse_client(message):
                    if parts[0] == "":
                        if len(parts) != 3 or parts[1] != "ping" or not parts[2].isdigit():
                            raise ValueError("Invalid tunnel ping")
                        await socket.send_text(instruction(*parts).decode())
                        continue
                    if parts[0] not in ALLOWED_INPUT:
                        raise PermissionError("Unsupported RDP client operation")
                    validate_client(parts)
                    writer.write(instruction(*parts))
                await writer.drain()

        async def to_browser() -> None:
            while True:
                # Keep each instruction intact: tunnel ping replies must never be
                # inserted between fragments of a guacd display instruction.
                parts = await read_instruction(reader)
                await permitted()
                await socket.send_text(instruction(*parts).decode("utf-8"))

        tasks.extend([asyncio.create_task(to_server()), asyncio.create_task(to_browser())])
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    except WebSocketDisconnect:
        pass
    except (DomainError, PermissionError) as exc:
        logging.getLogger(__name__).info("RDP denied: %s", type(exc).__name__)
        code = 1008
    except (OSError, ValueError, RuntimeError, TimeoutError, asyncio.IncompleteReadError) as exc:
        logging.getLogger(__name__).warning("RDP transport ended: %s", type(exc).__name__)
        code = 1011
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        with contextlib.suppress(OSError, RuntimeError, WebSocketDisconnect):
            await socket.close(code=code)


def install_rdp_routes(
    app: FastAPI,
    store: ControlPlane,
    auth: DemoAuth,
    targets: dict[str, RDPTarget],
    rotation_service: RotationService | None = None,
) -> None:
    active: set[str] = set()

    @app.websocket("/v1/grants/{grant_id}/rdp-session")
    async def rdp_session(socket: WebSocket, grant_id: str) -> None:
        protocols = socket.scope.get("subprotocols", [])
        csrf_values = [
            p.removeprefix("vaultgate-csrf.") for p in protocols if p.startswith("vaultgate-csrf.")
        ]
        try:
            if len(csrf_values) != 1 or "guacamole" not in protocols:
                raise DomainError("Authenticated RDP handshake required", 403)
            csrf = csrf_values[0]
            original = await auth.async_socket_actor(socket, csrf)
            device = store.authorize_connection(original, grant_id, audit=False)
            if device.id != "vg-ubuntu-rdp" or device.protocol != "rdp" or device.id not in targets:
                raise DomainError("RDP target unavailable", 403)
            if grant_id in active or len(active) >= 8:
                raise DomainError("RDP session limit reached", 409)
        except DomainError:
            await socket.close(code=1008)
            return
        active.add(grant_id)

        async def authorized() -> bool:
            try:
                current = await auth.async_socket_actor(socket, csrf)
                if current != original:
                    return False
                current_device = store.authorize_connection(current, grant_id, audit=False)
                return current_device.id == device.id and current_device.protocol == "rdp"
            except DomainError:
                return False

        try:
            await socket.accept(subprotocol="guacamole")
            store.authorize_connection(original, grant_id)
            store.record_identity_event(original, "rdp.session_requested", grant_id)
            if rotation_service is None:
                await proxy_rdp(socket, targets[device.id], authorized)
            else:

                async def open_rotated() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
                    async def connect(
                        username: str, password: str
                    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
                        target = replace(targets[device.id], username=username, password=password)
                        return await connect_rdp(target, approved_username=username)

                    async def close(
                        connection: tuple[asyncio.StreamReader, asyncio.StreamWriter],
                    ) -> None:
                        connection[1].close()
                        with contextlib.suppress(Exception):
                            await connection[1].wait_closed()

                    return await open_managed_session(
                        rotation_service, original, device.id, authorized, connect, close
                    )

                await proxy_rdp(socket, targets[device.id], authorized, opener=open_rotated)
        except DomainError:
            with contextlib.suppress(RuntimeError, OSError):
                await socket.close(code=1008)
        finally:
            active.discard(grant_id)
            store.record_identity_event(original, "rdp.session_closed", grant_id)
