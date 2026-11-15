"""Pinned, password-only backend SSH. Secrets never enter argv, environment or browser."""

import asyncio
import contextlib
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import asyncssh
from vg_core.domain import Device, DomainError


@dataclass(frozen=True)
class ManagedSSHTarget:
    host: str
    port: int
    known_hosts: str


class ManagedSSHProcess:
    def __init__(
        self, connection: asyncssh.SSHClientConnection, process: asyncssh.SSHClientProcess[bytes]
    ):
        self.connection = connection
        self.process = process

    async def read(self) -> bytes:
        return await self.process.stdout.read(16384)

    def write(self, data: bytes) -> None:
        self.process.stdin.write(data)

    def resize(self, cols: int, rows: int) -> None:
        self.process.change_terminal_size(cols, rows)

    async def close(self) -> None:
        self.connection.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self.connection.wait_closed(), 2)


async def connect_managed_ssh(
    target: ManagedSSHTarget, username: str, password: str
) -> ManagedSSHProcess:
    """Return only after host verification, password authentication and PTY creation.

    No local SSH config, agent, private key, GSSAPI or keyboard-interactive fallback.
    Fixed vtysh command: this is intentional read/write FRR access, not a sandbox.
    """
    connection: asyncssh.SSHClientConnection | None = None
    try:
        async with asyncio.timeout(15):
            connection = await asyncssh.connect(
                target.host,
                port=target.port,
                username=username,
                password=password,
                known_hosts=target.known_hosts,
                config=None,
                client_keys=[],
                agent_path=None,
                agent_forwarding=False,
                preferred_auth=["password"],
                public_key_auth=False,
                kbdint_auth=False,
                host_based_auth=False,
                gss_auth=False,
                gss_kex=False,
                password_auth=True,
                connect_timeout=5,
                login_timeout=10,
                keepalive_interval=10,
                keepalive_count_max=2,
            )
            process = await connection.create_process(
                "vtysh",
                term_type="xterm-256color",
                term_size=(80, 24),
                encoding=None,
                stderr=asyncssh.STDOUT,
            )
            return ManagedSSHProcess(connection, process)
    except BaseException as exc:
        if connection:
            connection.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(connection.wait_closed(), 2)
        if isinstance(exc, asyncio.CancelledError):
            raise
        raise DomainError(
            "Managed SSH unavailable; check authorization and pinned host identity", 502
        ) from None


def load_managed_targets(
    config: dict[str, Any],
) -> tuple[tuple[Device, ...], dict[str, ManagedSSHTarget]]:
    # Local import avoids runner/adapter/session import cycle.
    from vg_api.rotation_runner import private_read

    path = config.get("managed_ssh_inventory_file")
    if path is None:
        return (), {}
    if not isinstance(path, str) or not Path(path).is_absolute():
        raise ValueError("Managed SSH inventory requires an absolute private path")
    payload = json.loads(private_read(Path(path)))
    binding = config["binding"]
    targets: dict[str, ManagedSSHTarget] = {}
    devices = []
    for row in payload["devices"]:
        device_id = row["id"]
        if device_id not in {"vg-frr-1", "vg-frr-2", "vg-frr-3"} or device_id in targets:
            raise ValueError("Only distinct approved FRR IDs allowed")
        if device_id not in binding["device_ids"]:
            raise ValueError("Managed target is outside enrolled device scope")
        target = ManagedSSHTarget(**row["ssh"])
        address = ipaddress.ip_address(target.host)
        if (
            not (
                address.is_loopback
                or any(
                    address in net
                    for net in (
                        ipaddress.ip_network("10.0.0.0/8"),
                        ipaddress.ip_network("172.16.0.0/12"),
                        ipaddress.ip_network("192.168.0.0/16"),
                    )
                )
            )
            or type(target.port) is not int
        ):
            raise ValueError("Invalid managed SSH address")
        if not 1 <= target.port <= 65535:
            raise ValueError("Invalid managed SSH port")
        hosts = Path(target.known_hosts)
        if not hosts.is_absolute():
            raise ValueError("Absolute pinned known_hosts required")
        pins = private_read(hosts).decode()
        expected = target.host if target.port == 22 else f"[{target.host}]:{target.port}"
        if not any(
            len(parts := line.split()) >= 3
            and expected in parts[0].split(",")
            and parts[1].startswith(("ssh-", "ecdsa-", "sk-"))
            for line in pins.splitlines()
        ):
            raise ValueError("Exact managed SSH host and port pin required")
        targets[device_id] = target
        devices.append(
            Device(
                device_id,
                binding["org_id"],
                binding["tenant_id"],
                row["name"],
                "frr",
                "direct",
                "ssh",
            )
        )
    if not targets:
        raise ValueError("Managed SSH inventory cannot be empty")
    return tuple(devices), targets
