"""Optional existing key-based SSH targets for the combined rotation application.

This does not enroll routers in AD or rotate SSH credentials. Directory device
mappings remain the authorization authority; demo inventory usernames are ignored.
"""

from dataclasses import replace
from pathlib import Path
from typing import Any

from vg_core.domain import Device

from vg_api.lab_access import SSHTarget, load_inventory
from vg_api.rotation_runner import private_read


def load_ssh_inventory(
    config: dict[str, Any],
) -> tuple[tuple[Device, ...], dict[str, SSHTarget]]:
    path = config.get("ssh_inventory_file")
    if path is None:
        return (), {}
    if not isinstance(path, str) or not Path(path).is_absolute():
        raise ValueError("SSH inventory requires an absolute operator-owned path")
    # Same ownership/permissions contract as the main private runtime config.
    private_read(Path(path))
    devices, _demo_entitlements, targets = load_inventory(Path(path))
    if not devices or any(d.protocol != "ssh" or d.id not in targets for d in devices):
        raise ValueError("Combined SSH inventory requires configured SSH targets only")
    if any(d.id == "vg-ubuntu-rdp" for d in devices):
        raise ValueError("SSH inventory must not replace the managed desktop")
    binding = config["binding"]
    scoped = tuple(
        replace(d, org_id=binding["org_id"], tenant_id=binding["tenant_id"]) for d in devices
    )
    return scoped, targets
