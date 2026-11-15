import json
import tempfile
from pathlib import Path

import pytest
from vg_api.rotation_inventory import load_ssh_inventory


@pytest.fixture
def inventory():
    with tempfile.TemporaryDirectory(prefix="vg-ssh-inventory-", dir="/tmp") as folder:
        root = Path(folder)
        key = root / "key"
        key.write_text("SYNTHETIC-KEY-NOT-A-CREDENTIAL")
        key.chmod(0o600)
        hosts = root / "known_hosts"
        hosts.write_text("10.78.0.11 ssh-ed25519 AAAATEST\n")
        hosts.chmod(0o600)
        entry = {
            "id": "vg-frr-1",
            "name": "FRR",
            "platform": "frr",
            "protocol": "ssh",
            "entitled_users": ["tech", "admin"],
            "ssh": {
                "host": "10.78.0.11",
                "port": 22,
                "username": "vgoperator",
                "private_key": str(key),
                "known_hosts": str(hosts),
            },
        }
        path = root / "inventory.json"
        config = {
            "binding": {"org_id": "actual-org", "tenant_id": "actual-tenant"},
            "ssh_inventory_file": str(path),
        }

        def write():
            path.write_text(json.dumps({"devices": [entry]}))
            path.chmod(0o600)
            return config

        yield entry, write


def test_optional_inventory_is_off_by_default():
    assert load_ssh_inventory({}) == ((), {})


def test_scoped_existing_key_targets_without_demo_entitlements(inventory):
    _, write = inventory
    devices, targets = load_ssh_inventory(write())
    assert devices[0].org_id == "actual-org"
    assert devices[0].tenant_id == "actual-tenant"
    assert devices[0].protocol == "ssh"
    assert targets["vg-frr-1"].username == "vgoperator"
    # This interface intentionally does not return demo user grants.
    assert len(load_ssh_inventory(write())) == 2


@pytest.mark.parametrize("change", ["desktop_collision", "nonssh", "unconfigured"])
def test_reject_invalid_inventory(inventory, change):
    entry, write = inventory
    if change == "desktop_collision":
        entry["id"] = "vg-ubuntu-rdp"
    elif change == "nonssh":
        entry["protocol"] = "rdp"
        del entry["ssh"]
    else:
        del entry["ssh"]
    with pytest.raises(ValueError):
        load_ssh_inventory(write())


def test_reject_world_readable_inventory(inventory):
    _, write = inventory
    config = write()
    Path(config["ssh_inventory_file"]).chmod(0o644)
    with pytest.raises(ValueError):
        load_ssh_inventory(config)


def test_reject_relative_inventory():
    with pytest.raises(ValueError):
        load_ssh_inventory({"ssh_inventory_file": "inventory.json"})


def test_combined_app_keeps_explicit_directory_mappings_and_installs_ssh(inventory, monkeypatch):
    from unittest.mock import Mock

    from fastapi import FastAPI
    from vg_api import rotation_app

    _, write = inventory
    config = write()
    config.update(
        {
            "reader_password_file": "/synthetic/reader",
            "rdp_fingerprint": ":".join(["aa"] * 32),
            "directory": {
                "host": "dc.example.com",
                "ca_file": "ca.pem",
                "bind_dn": "CN=reader",
                "bind_password_env": "TEST_PASSWORD",
                "user_base_dn": "OU=users",
                "group_base_dn": "OU=groups",
                "org_id": "actual-org",
                "tenant_ids": ["actual-tenant"],
                "group_mappings": [
                    {"group_dn": "CN=tech", "roles": ["technician"], "device_ids": ["vg-frr-1"]}
                ],
            },
        }
    )
    config["binding"]["technician_id"] = "ad:synthetic"
    store, service = Mock(), Mock()
    monkeypatch.setattr(rotation_app, "open_runtime", lambda _: (store, service))
    monkeypatch.setattr(rotation_app, "private_read", lambda _: b"synthetic-reader")
    captured = {}

    def create(plane, **kwargs):
        captured.update(plane=plane, **kwargs)
        return FastAPI()

    monkeypatch.setattr(rotation_app, "create_app", create)
    with rotation_app.managed_application(config):
        assert "vg-frr-1" in captured["ssh_targets"]
        mapping = captured["directory_config"].group_mappings[0]
        assert mapping.device_ids == frozenset({"vg-frr-1"})
        assert {d.id for d in captured["plane"]._devices.values()} == {"vg-frr-1", "vg-ubuntu-rdp"}
    store.close.assert_called_once()
