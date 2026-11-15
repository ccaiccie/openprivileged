"""Explicit offline migration of approved lab device scope, never password rotation.

Caller must stop the owning worker, retain current config for rollback, hold the
exclusive encrypted store and approve exact old/new device scope. Use latest vault;
never restore an old snapshot. This function is not exposed to HTTP/browser users.
"""

import json
from dataclasses import asdict, replace

from vg_core.rotation import AccountBinding, StateStore

LAB_DEVICES = frozenset({"vg-ubuntu-rdp", "vg-frr-1", "vg-frr-2", "vg-frr-3"})


def migrate_device_scope(
    store: StateStore, expected: AccountBinding, devices: frozenset[str]
) -> AccountBinding:
    if (
        expected.id != "vg-tech-admin"
        or expected.privileged_username != "vg-tech-admin@example.local"
        or expected.authority_id != "DC1.example.local"
        or "vg-ubuntu-rdp" not in devices
        or not devices <= LAB_DEVICES
        or "vg-ubuntu-rdp" not in expected.device_ids
        or not expected.device_ids <= LAB_DEVICES
    ):
        raise ValueError("Only approved lab device scope may be migrated")
    payload = json.loads(store.load() or b"null")
    expected_row = asdict(expected)
    expected_row["device_ids"] = sorted(expected.device_ids)
    if (
        not isinstance(payload, dict)
        or payload.get("version") != 1
        or len(payload.get("records", [])) != 1
    ):
        raise ValueError("Unexpected vault contents")
    row = payload["records"][0]
    actual = {**row["binding"], "device_ids": sorted(row["binding"]["device_ids"])}
    if actual != expected_row or row["state"] != "ready" or row["pending"] is not None:
        raise ValueError("Expected ready account scope does not match")
    updated = replace(expected, device_ids=devices)
    # The only changed field. current/pending, generation, due time and identity survive.
    row["binding"]["device_ids"] = sorted(devices)
    store.save(json.dumps(payload).encode())
    return updated
