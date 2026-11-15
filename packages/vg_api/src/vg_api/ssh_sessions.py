"""Local-demo interactive SSH: server-pinned targets, scoped live authorization, no recording."""

import asyncio
import contextlib
import fcntl
import json
import os
import pty
import signal
import struct
import subprocess
import termios
import time
from collections import Counter
from typing import Any
from uuid import uuid4

import asyncssh
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from vg_core.domain import Actor, ControlPlane, DomainError
from vg_core.rotation import RotationService

from vg_api.demo_auth import DemoAuth
from vg_api.lab_access import SSHTarget
from vg_api.managed_ssh import ManagedSSHProcess, ManagedSSHTarget, connect_managed_ssh
from vg_api.rotation_gateway import open_managed_session


def ssh_command(target: SSHTarget) -> list[str]:
    return [
        "/usr/bin/ssh",
        "-F",
        "/dev/null",
        "-tt",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={target.known_hosts}",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "EscapeChar=none",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "ServerAliveInterval=10",
        "-o",
        "ServerAliveCountMax=2",
        "-i",
        target.private_key,
        "-p",
        str(target.port),
        f"{target.username}@{target.host}",
    ]


class SSHProcess:
    def __init__(self, target: SSHTarget):
        self.master, slave = pty.openpty()
        self.closed = False
        self.process: subprocess.Popen[bytes] | None = None
        try:
            os.set_blocking(self.master, False)
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
            env = os.environ.copy()
            env.pop("SSH_AUTH_SOCK", None)
            env["TERM"] = "xterm-256color"
            self.process = subprocess.Popen(
                ssh_command(target),
                stdin=slave,
                stdout=slave,
                stderr=slave,
                env=env,
                close_fds=True,
                start_new_session=True,
            )
        except BaseException:
            os.close(self.master)
            raise
        finally:
            os.close(slave)

    def read(self) -> bytes | None:
        try:
            return os.read(self.master, 16384)
        except BlockingIOError:
            return None
        except OSError:
            return b""

    def write(self, data: bytes) -> None:
        written = os.write(self.master, data)
        if written != len(data):
            raise DomainError("Terminal input buffer full", 429)

    def resize(self, cols: int, rows: int) -> None:
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        # The child is deliberately in its own session, not our controlling TTY.
        # Notify OpenSSH explicitly so it forwards the updated PTY size remotely.
        if self.process is not None and self.process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.process.pid, signal.SIGWINCH)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        process = self.process
        try:
            if process is not None and process.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=1)
        finally:
            with contextlib.suppress(OSError):
                os.close(self.master)


def ws_request(ws: WebSocket, csrf: str | None = None) -> Request:
    """Adapt transport metadata only; DemoAuth remains authority for identity and session."""
    scheme = "https" if ws.url.scheme == "wss" else "http"
    host = ws.headers.get("host", "")
    if (
        not ws.client
        or ws.client.host not in {"127.0.0.1", "::1"}
        or ws.headers.get("origin") != f"{scheme}://{host}"
        or ws.url.query
    ):
        raise DomainError("Local same-origin browser session required", 403)
    scope = dict(ws.scope)
    scope.update(type="http", method="POST" if csrf is not None else "GET", scheme=scheme)
    headers = [(k, v) for k, v in ws.scope["headers"] if k.lower() != b"x-csrf-token"]
    if csrf is not None:
        headers.append((b"x-csrf-token", csrf.encode("ascii")))
    scope["headers"] = headers
    return Request(scope)


def parse_message(raw: str) -> dict[str, Any]:
    if len(raw.encode("utf-8")) > 16384:
        raise DomainError("Terminal message too large", 400)
    try:
        data: Any = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise DomainError("Invalid terminal message", 400) from exc
    if not isinstance(data, dict):
        raise DomainError("Invalid terminal message", 400)
    return data


def install_sessions(
    app: FastAPI,
    store: ControlPlane,
    auth: DemoAuth | None,
    ssh_targets: dict[str, SSHTarget] | None,
    rotation_service: RotationService | None = None,
    managed_targets: dict[str, ManagedSSHTarget] | None = None,
) -> None:
    targets = (ssh_targets or {}).copy()
    managed = (managed_targets or {}).copy()
    if managed.keys() & targets.keys() or (managed and rotation_service is None):
        raise ValueError("Managed SSH requires rotation service and distinct targets")
    slots: Counter[str] = Counter()

    @app.websocket("/v1/grants/{grant_id}/ssh-session")
    async def session(ws: WebSocket, grant_id: str) -> None:
        process: SSHProcess | ManagedSSHProcess | None = None
        actor: Actor | None = None
        slot_key: str | None = None
        started = False
        session_id = str(uuid4())
        tasks: list[asyncio.Task[None]] = []
        reason = "disconnected"
        try:
            if auth is None:
                raise DomainError("Session login required", 401)
            actor = await auth.async_actor(ws_request(ws))
            device = store.authorize_connection(actor, grant_id, audit=False)
            if device.protocol != "ssh" or device.id not in targets.keys() | managed.keys():
                raise DomainError("Interactive SSH endpoint is not configured", 403)
            slot_key = actor.org_id + ":" + actor.id
            if sum(slots.values()) >= 8 or slots[slot_key] >= 2:
                slot_key = None
                raise DomainError("Terminal session limit reached", 429)
            slots[slot_key] += 1
            await ws.accept()
            hello = parse_message(await asyncio.wait_for(ws.receive_text(), timeout=5))
            csrf = hello.get("csrf_token")
            if (
                set(hello) != {"type", "csrf_token"}
                or hello.get("type") != "auth"
                or not isinstance(csrf, str)
                or not 1 <= len(csrf) <= 128
                or not csrf.isascii()
            ):
                raise DomainError("Terminal authentication required", 403)
            original_actor = actor

            async def check() -> None:
                assert auth is not None
                current = await auth.async_socket_actor(ws, csrf)
                if current != original_actor:
                    raise DomainError("Identity or active role changed; reconnect", 403)
                store.authorize_connection(current, grant_id, audit=False)

            await check()
            if device.id in managed:
                assert rotation_service is not None

                async def authorized() -> bool:
                    await check()
                    return True

                async def connect(username: str, password: str) -> ManagedSSHProcess:
                    return await connect_managed_ssh(managed[device.id], username, password)

                async def close_managed(opened: ManagedSSHProcess) -> None:
                    await opened.close()

                process = await open_managed_session(
                    rotation_service, actor, device.id, authorized, connect, close_managed
                )
            else:
                process = SSHProcess(targets[device.id])
            store.record_identity_event(
                actor, "session.ssh_started", f"{session_id}:{grant_id}:{device.id}"
            )
            started = True
            await ws.send_json({"type": "ready", "session_id": session_id, "recording": False})

            async def read_output() -> None:
                assert process is not None
                while True:
                    chunk = (
                        await process.read()
                        if isinstance(process, ManagedSSHProcess)
                        else process.read()
                    )
                    if chunk == b"":
                        return
                    if chunk is None:
                        await asyncio.sleep(0.02)
                        continue
                    await asyncio.wait_for(ws.send_bytes(chunk), timeout=2)

            async def guard() -> None:
                while True:
                    await asyncio.sleep(1)
                    await check()

            async def read_input() -> None:
                assert process is not None
                window, total = time.monotonic(), 0
                while True:
                    message = parse_message(await ws.receive_text())
                    await check()
                    if time.monotonic() - window >= 1:
                        window, total = time.monotonic(), 0
                    if message.get("type") == "input" and set(message) == {"type", "data"}:
                        text = message["data"]
                        if not isinstance(text, str) or len(text) > 4096:
                            raise DomainError("Terminal input too large", 400)
                        encoded = text.encode("utf-8")
                        total += len(encoded)
                        if total > 65536:
                            raise DomainError("Terminal input rate exceeded", 429)
                        process.write(encoded)
                    elif message.get("type") == "resize" and set(message) == {
                        "type",
                        "cols",
                        "rows",
                    }:
                        cols, rows = message["cols"], message["rows"]
                        if type(cols) is not int or type(rows) is not int:
                            raise DomainError("Invalid terminal size", 400)
                        if not 20 <= cols <= 300 or not 5 <= rows <= 120:
                            raise DomainError("Invalid terminal size", 400)
                        process.resize(cols, rows)
                    else:
                        raise DomainError("Invalid terminal message", 400)

            tasks = [asyncio.create_task(fn()) for fn in (read_output, read_input, guard)]
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
            reason = "closed"
        except DomainError as exc:
            reason = "authorization_or_input_rejected"
            with contextlib.suppress(Exception):
                await asyncio.wait_for(ws.send_json({"type": "error", "message": str(exc)}), 1)
        except (WebSocketDisconnect, RuntimeError):
            reason = "disconnected"
        except (
            TimeoutError,
            OSError,
            UnicodeError,
            ValueError,
            KeyError,
            TypeError,
            asyncssh.Error,
        ):
            reason = "transport_failed"
            with contextlib.suppress(Exception):
                await asyncio.wait_for(
                    ws.send_json(
                        {"type": "error", "message": "SSH terminal unavailable or timed out"}
                    ),
                    1,
                )
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            if process:
                with contextlib.suppress(Exception):
                    if isinstance(process, ManagedSSHProcess):
                        await process.close()
                    else:
                        await asyncio.to_thread(process.close)
            if slot_key is not None:
                slots[slot_key] -= 1
                if not slots[slot_key]:
                    del slots[slot_key]
            if started and actor:
                store.record_identity_event(actor, "session.ssh_ended", f"{session_id}:{reason}")
            with contextlib.suppress(Exception):
                await asyncio.wait_for(ws.close(code=1000 if reason == "closed" else 1008), 1)
