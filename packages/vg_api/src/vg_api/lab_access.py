"""Explicit operator-supplied lab inventory; no target or command comes from a browser."""

import ipaddress
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vg_core.domain import Device, DomainError


@dataclass(frozen=True)
class SSHTarget:
    host: str
    port: int
    username: str
    private_key: str
    known_hosts: str


def load_inventory(
    path: Path,
) -> tuple[tuple[Device, ...], frozenset[tuple[str, str]], dict[str, SSHTarget]]:
    data: Any = json.loads(path.read_text())
    devices: list[Device] = []
    entitlements: set[tuple[str, str]] = set()
    targets: dict[str, SSHTarget] = {}
    for entry in data["devices"]:
        device = Device(
            entry["id"],
            "demo-msp",
            "customer-a",
            entry["name"],
            entry["platform"],
            access_mode="direct",
            protocol=entry["protocol"],
        )
        if any(d.id == device.id for d in devices):
            raise ValueError("Duplicate device ID")
        devices.append(device)
        for username in entry.get("entitled_users", []):
            entitlements.add((username, device.id))
        if "ssh" in entry:
            if device.protocol != "ssh":
                raise ValueError("SSH target requires SSH protocol")
            target = SSHTarget(**entry["ssh"])
            address = ipaddress.ip_address(target.host)
            if not (
                address.is_loopback
                or any(
                    address in n
                    for n in (
                        ipaddress.ip_network("10.0.0.0/8"),
                        ipaddress.ip_network("172.16.0.0/12"),
                        ipaddress.ip_network("192.168.0.0/16"),
                    )
                )
            ):
                raise ValueError("Only explicit private lab or loopback addresses allowed")
            if (
                type(target.port) is not int
                or not 1 <= target.port <= 65535
                or not isinstance(target.username, str)
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", target.username) is None
            ):
                raise ValueError("Invalid SSH target")
            key, hosts = Path(target.private_key), Path(target.known_hosts)
            if not key.is_absolute() or not hosts.is_absolute():
                raise ValueError("Use absolute operator-owned SSH credential paths")
            if not key.is_file() or key.stat().st_uid != os.getuid():
                raise ValueError("SSH key must be a regular file owned by the current user")
            if key.stat().st_mode & 0o077:
                raise ValueError("SSH key must be owner-only (0600), outside the shared repo mount")
            if not hosts.is_file() or not hosts.read_text().strip():
                raise ValueError("Pinned known_hosts file is required")
            if hosts.stat().st_mode & 0o022 or hosts.stat().st_uid != os.getuid():
                raise ValueError(
                    "Pinned known_hosts must be owner-controlled, not writable by others"
                )
            if any(c in str(key) + str(hosts) for c in "\r\n"):
                raise ValueError("Invalid credential path")
            expected_host = target.host if target.port == 22 else f"[{target.host}]:{target.port}"
            pinned = False
            for line in hosts.read_text().splitlines():
                parts = line.split()
                if (
                    len(parts) >= 3
                    and not parts[0].startswith(("#", "@"))
                    and expected_host in parts[0].split(",")
                    and parts[1].startswith(("ssh-", "ecdsa-", "sk-"))
                ):
                    pinned = True
                    break
            if not pinned:
                raise ValueError("known_hosts must explicitly pin this exact host and port")
            targets[device.id] = target
    return tuple(devices), frozenset(entitlements), targets


def ssh_probe(target: SSHTarget, timeout: float = 10) -> dict[str, str]:
    """Fixed read-only FRR probe; no shell, arbitrary command, password or target input."""
    if timeout <= 0:
        raise DomainError("Grant expired", 403)
    try:
        result = subprocess.run(
            [
                "ssh",
                "-F",
                "/dev/null",
                "-T",
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
                "ForwardAgent=no",
                "-o",
                "ClearAllForwardings=yes",
                "-o",
                "ConnectTimeout=5",
                "-i",
                target.private_key,
                "-p",
                str(target.port),
                f"{target.username}@{target.host}",
                "vtysh -c 'show version'",
            ],
            capture_output=True,
            text=True,
            timeout=min(timeout, 10),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DomainError("Lab SSH test unavailable or timed out", 502) from exc
    if result.returncode:
        # Do not return stderr, paths, credentials or unbounded remote data.
        raise DomainError(
            "SSH test failed. Check lab reachability, pinned host key and authorized key.", 502
        )
    return {"status": "connected", "protocol": "ssh", "output": result.stdout[:4096]}
