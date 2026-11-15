import json
import subprocess
import tempfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from vg_api.lab_access import SSHTarget, load_inventory, ssh_probe
from vg_api.main import create_app
from vg_core.domain import Actor, ControlPlane, Device, DomainError, Policy


@pytest.fixture
def lab_api(monkeypatch):
    now = [datetime.now(UTC)]
    devices = (
        Device("frr", "org", "a", "frr-lab", "frr", access_mode="direct"),
        Device("desktop", "org", "a", "desktop-lab", "ubuntu", "direct", "vnc"),
        Device("unentitled", "org", "a", "other-lab", "frr", access_mode="direct"),
        Device("foreign", "org", "b", "foreign-lab", "frr", access_mode="direct"),
    )
    plane = ControlPlane(
        devices,
        {("org", "a"): Policy()},
        lambda: now[0],
        direct_entitlements=frozenset({("tech", "frr"), ("tech", "desktop")}),
    )
    tech = Actor("tech", "org", frozenset({"a"}), "technician")
    actors = {
        "tech": tech,
        "other": replace(tech, id="other"),
        "auditor": replace(tech, id="auditor", role="auditor"),
        "reviewer": replace(tech, id="reviewer", role="approver"),
        "admin": replace(tech, id="admin", role="admin"),
        "tenant-b": replace(tech, tenant_ids=frozenset({"b"})),
        "org-b": replace(tech, org_id="other-org"),
    }
    target = SSHTarget("127.0.0.1", 2201, "lab", "/tmp/test-key", "/tmp/test-known")
    probe = Mock(return_value={"status": "connected", "protocol": "ssh", "output": "FRR"})
    monkeypatch.setattr("vg_api.main.ssh_probe", probe)
    client = TestClient(create_app(plane, actors, ssh_targets={"frr": target}))
    return client, plane, tech, now, probe, target, actors


def auth(role="tech"):
    return {"Authorization": "Bearer " + role}


def grant(client, device="frr"):
    response = client.post(
        "/v1/direct-access",
        headers=auth(),
        json={"device_id": device, "reason": "Lab test", "minutes": 1},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_direct_api_and_fixed_target_call(lab_api):
    client, plane, tech, _, probe, target, _ = lab_api
    ident = grant(client)
    assert plane.requests(tech) == ()
    response = client.post(f"/v1/grants/{ident}/ssh-test", headers=auth())
    assert response.status_code == 200
    assert response.json()["output"] == "FRR"
    probe.assert_called_once()
    assert probe.call_args.args[0] == target
    assert 0 < probe.call_args.args[1] <= 60


@pytest.mark.parametrize(
    "role,status",
    [
        ("other", 404),
        ("admin", 404),
        ("auditor", 403),
        ("reviewer", 403),
        ("tenant-b", 404),
        ("org-b", 404),
    ],
)
def test_no_probe_for_other_identity_role_scope(lab_api, role, status):
    client, _, _, _, probe, _, _ = lab_api
    ident = grant(client)
    response = client.post(f"/v1/grants/{ident}/ssh-test", headers=auth(role))
    assert response.status_code == status
    probe.assert_not_called()


@pytest.mark.parametrize("state", ["revoked", "expired", "unentitled"])
def test_no_probe_for_inactive_or_withdrawn_entitlement(lab_api, state):
    client, plane, tech, now, probe, _, _ = lab_api
    ident = grant(client)
    if state == "revoked":
        plane.revoke(tech, ident)
    elif state == "expired":
        now[0] += timedelta(minutes=2)
    else:
        plane._direct_entitlements = frozenset()
    assert client.post(f"/v1/grants/{ident}/ssh-test", headers=auth()).status_code == 403
    probe.assert_not_called()


def test_no_probe_for_unknown_grant_or_unauthenticated(lab_api):
    client, _, _, _, probe, _, _ = lab_api
    assert client.post("/v1/grants/missing/ssh-test", headers=auth()).status_code == 404
    assert client.post("/v1/grants/missing/ssh-test").status_code == 401
    probe.assert_not_called()


def test_missing_transport_and_endpoint(lab_api):
    client, plane, _, _, probe, _, actors = lab_api
    nonssh = grant(client, "desktop")
    assert client.post(f"/v1/grants/{nonssh}/ssh-test", headers=auth()).status_code == 501
    ssh = grant(client)
    unconfigured = TestClient(create_app(plane, actors))
    assert unconfigured.post(f"/v1/grants/{ssh}/ssh-test", headers=auth()).status_code == 503
    probe.assert_not_called()


@pytest.mark.parametrize(
    "extra",
    [
        {"host": "8.8.8.8"},
        {"command": "whoami"},
        {"username": "root"},
        {"private_key": "/tmp/evil"},
    ],
)
def test_client_cannot_supply_target_or_command(lab_api, extra):
    client, _, _, _, probe, _, _ = lab_api
    ident = grant(client)
    assert (
        client.post(f"/v1/grants/{ident}/ssh-test", headers=auth(), json=extra).status_code == 422
    )
    assert (
        client.post(
            "/v1/direct-access",
            headers=auth(),
            json={"device_id": "frr", "reason": "Lab", "minutes": 1, **extra},
        ).status_code
        == 422
    )
    probe.assert_not_called()


@pytest.mark.parametrize("device,status", [("unentitled", 403), ("foreign", 404)])
def test_direct_endpoint_checks_entitlement_and_scope(lab_api, device, status):
    client, _, _, _, probe, _, _ = lab_api
    response = client.post(
        "/v1/direct-access",
        headers=auth(),
        json={"device_id": device, "reason": "Lab", "minutes": 1},
    )
    assert response.status_code == status
    probe.assert_not_called()


def test_probe_command_is_fixed_and_pins_host(monkeypatch):
    run = Mock(return_value=subprocess.CompletedProcess([], 0, stdout="X" * 5000, stderr=""))
    monkeypatch.setattr("vg_api.lab_access.subprocess.run", run)
    target = SSHTarget("10.20.30.40", 2222, "labuser", "/tmp/test-key", "/tmp/test-hosts")
    result = ssh_probe(target, timeout=60)
    args, kwargs = run.call_args
    command = args[0]
    assert command[0] == "ssh" and command[-1] == "vtysh -c 'show version'"
    assert command[-2] == "labuser@10.20.30.40"
    for option in (
        "StrictHostKeyChecking=yes",
        "UserKnownHostsFile=/tmp/test-hosts",
        "GlobalKnownHostsFile=/dev/null",
        "IdentitiesOnly=yes",
        "ForwardAgent=no",
        "ClearAllForwardings=yes",
        "BatchMode=yes",
    ):
        assert option in command
    assert command[1:3] == ["-F", "/dev/null"]
    assert kwargs.get("shell", False) is False and kwargs["timeout"] == 10
    assert len(result["output"]) == 4096


@pytest.mark.parametrize("failure", ["exit", "timeout", "os"])
def test_probe_sanitizes_errors(monkeypatch, failure):
    run = Mock()
    if failure == "exit":
        run.return_value = subprocess.CompletedProcess([], 1, "", "secret diagnostic")
    elif failure == "timeout":
        run.side_effect = subprocess.TimeoutExpired("secret diagnostic", 1)
    else:
        run.side_effect = OSError("secret diagnostic")
    monkeypatch.setattr("vg_api.lab_access.subprocess.run", run)
    with pytest.raises(DomainError) as exc:
        ssh_probe(SSHTarget("127.0.0.1", 22, "lab", "/tmp/key", "/tmp/known"))
    assert exc.value.status == 502 and "secret" not in str(exc.value)


@pytest.fixture
def inventory_files():
    # Repository lives on fuseblk and does not preserve restrictive chmod.
    with tempfile.TemporaryDirectory(prefix="vg-inventory-", dir="/tmp") as folder:
        root = Path(folder)
        key = root / "key"
        key.write_text("TEST KEY PLACEHOLDER")
        key.chmod(0o600)
        hosts = root / "known_hosts"
        hosts.write_text("[10.1.2.3]:2222 ssh-ed25519 AAAATESTKEY\n")
        hosts.chmod(0o600)
        entry = {
            "id": "frr",
            "name": "Lab FRR",
            "platform": "frr",
            "protocol": "ssh",
            "entitled_users": ["tech"],
            "ssh": {
                "host": "10.1.2.3",
                "port": 2222,
                "username": "lab",
                "private_key": str(key),
                "known_hosts": str(hosts),
            },
        }
        path = root / "inventory.json"

        def write(entries=None):
            path.write_text(json.dumps({"devices": [entry] if entries is None else entries}))
            return path

        yield entry, key, hosts, write


def test_inventory_valid_scoped_and_entitled(inventory_files):
    _, _, _, write = inventory_files
    devices, entitlements, targets = load_inventory(write())
    assert len(devices) == 1
    assert devices[0].org_id == "demo-msp" and devices[0].tenant_id == "customer-a"
    assert devices[0].access_mode == "direct"
    assert entitlements == frozenset({("tech", "frr")})
    assert targets["frr"].host == "10.1.2.3"


@pytest.mark.parametrize("host", ["8.8.8.8", "169.254.169.254", "0.0.0.0", "example.com"])
def test_inventory_rejects_nonlab_addresses(inventory_files, host):
    entry, _, _, write = inventory_files
    entry["ssh"]["host"] = host
    with pytest.raises(ValueError):
        load_inventory(write())


@pytest.mark.parametrize(
    "bad",
    [
        "key_permissions",
        "hosts_writable",
        "empty_hosts",
        "wrong_host",
        "relative_key",
        "duplicate_id",
        "port_bool",
        "username_options",
        "key_directory",
        "nonssh",
    ],
)
def test_inventory_rejects_unsafe_configuration(inventory_files, bad):
    entry, key, hosts, write = inventory_files
    if bad == "key_permissions":
        key.chmod(0o644)
    elif bad == "hosts_writable":
        hosts.chmod(0o666)
    elif bad == "empty_hosts":
        hosts.write_text("")
    elif bad == "wrong_host":
        hosts.write_text("10.1.2.4 ssh-ed25519 AAAATESTKEY\n")
    elif bad == "relative_key":
        entry["ssh"]["private_key"] = "key"
    elif bad == "port_bool":
        entry["ssh"]["port"] = True
    elif bad == "username_options":
        entry["ssh"]["username"] = "-oProxyCommand=evil"
    elif bad == "key_directory":
        entry["ssh"]["private_key"] = str(key.parent)
    elif bad == "nonssh":
        entry["protocol"] = "vnc"
    path = write([entry, entry] if bad == "duplicate_id" else None)
    with pytest.raises(ValueError):
        load_inventory(path)


def test_probe_does_not_extend_short_grant_timeout(monkeypatch):
    run = Mock(return_value=subprocess.CompletedProcess([], 0, stdout="FRR", stderr=""))
    monkeypatch.setattr("vg_api.lab_access.subprocess.run", run)
    target = SSHTarget("127.0.0.1", 22, "lab", "/tmp/key", "/tmp/known")
    ssh_probe(target, timeout=0.01)
    assert run.call_args.kwargs["timeout"] == 0.01
    run.reset_mock()
    with pytest.raises(DomainError) as exc:
        ssh_probe(target, timeout=0)
    assert exc.value.status == 403
    run.assert_not_called()


def test_standing_direct_api_and_bounded_probe(lab_api):
    client, plane, tech, now, probe, target, _ = lab_api
    payload = {"device_id": "frr", "reason": "Assigned device access"}
    response = client.post("/v1/direct-access", headers=auth(), json=payload)
    assert response.status_code == 201
    grant = response.json()
    assert grant["expires_at"] is None
    assert (
        client.post("/v1/direct-access", headers=auth(), json=payload).json()["id"] == grant["id"]
    )
    now[0] += timedelta(days=100)
    assert client.post(f"/v1/grants/{grant['id']}/ssh-test", headers=auth()).status_code == 200
    probe.assert_called_once_with(target, 30.0)
    plane.revoke(tech, grant["id"])
    assert client.post(f"/v1/grants/{grant['id']}/ssh-test", headers=auth()).status_code == 403
    assert client.post("/v1/direct-access", headers=auth("other"), json=payload).status_code == 403
