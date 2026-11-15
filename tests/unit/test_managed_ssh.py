import asyncio
import json
from dataclasses import asdict, replace
from datetime import UTC, datetime

import asyncssh
import pytest
from vg_api.managed_ssh import ManagedSSHTarget, connect_managed_ssh, load_managed_targets
from vg_api.rotation_gateway import open_managed_session
from vg_api.rotation_scope import migrate_device_scope
from vg_api.rotation_store import EncryptedRotationStore
from vg_core.domain import Actor, DomainError
from vg_core.rotation import AccountBinding, RotationService


class Adapter:
    def verify(self, binding, password):
        return True

    def change(self, binding, password):
        pytest.fail("scope migration must not rotate")


def test_real_password_ssh_pin_before_credential_and_no_fallback(tmp_path):
    async def scenario():
        key = asyncssh.generate_private_key("ssh-ed25519")
        wrong_key = asyncssh.generate_private_key("ssh-ed25519")
        auth_calls = []
        commands = []

        class Server(asyncssh.SSHServer):
            def begin_auth(self, username):
                return True

            def password_auth_supported(self):
                return True

            def validate_password(self, username, password):
                auth_calls.append((username, password))
                return username == "vg-tech-admin@example.local" and password == "synthetic-secret"

        async def shell(proc):
            commands.append(proc.command)
            proc.stdout.write(b"FRR test ready\r\n")
            while True:
                try:
                    data = await proc.stdin.read(4)
                    break
                except asyncssh.TerminalSizeChanged:
                    pass
            proc.stdout.write(data)
            proc.exit(0)

        server = await asyncssh.create_server(
            Server,
            "127.0.0.1",
            0,
            server_host_keys=[key],
            process_factory=shell,
            encoding=None,
            line_editor=False,
        )
        port = server.get_port()
        hosts = tmp_path / "hosts"
        hosts.write_text(f"[127.0.0.1]:{port} " + wrong_key.export_public_key().decode())
        target = ManagedSSHTarget("127.0.0.1", port, str(hosts))
        try:
            with pytest.raises(DomainError) as error:
                await connect_managed_ssh(target, "vg-tech-admin@example.local", "synthetic-secret")
            assert auth_calls == []  # Wrong key fails before sending any password.
            assert "synthetic-secret" not in str(error.value)
            hosts.write_text(f"[127.0.0.1]:{port} " + key.export_public_key().decode())
            process = await connect_managed_ssh(
                target, "vg-tech-admin@example.local", "synthetic-secret"
            )
            assert commands == ["vtysh"]
            assert await process.read() == b"FRR test ready\r\n"
            process.resize(100, 30)
            process.write(b"test")
            assert await process.read() == b"test"
            await process.close()
            with pytest.raises(DomainError):
                await connect_managed_ssh(target, "vg-tech-admin@example.local", "wrong")
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


def binding():
    return AccountBinding(
        "vg-tech-admin",
        "org",
        "tenant",
        "tech-guid",
        "vg-tech-admin@example.local",
        "DC1.example.local",
        frozenset({"vg-ubuntu-rdp"}),
    )


def test_device_scope_migration_retains_secret_deadline_and_identity(tmp_path):
    tmp_path.chmod(0o700)
    store = EncryptedRotationStore(tmp_path, bytes(32))
    service = RotationService(Adapter(), lambda: datetime(2026, 11, 14, tzinfo=UTC), store)
    old = binding()
    service.enroll(old, "synthetic-secret")
    before = json.loads(store.load())
    new = migrate_device_scope(store, old, old.device_ids | {"vg-frr-1", "vg-frr-2", "vg-frr-3"})
    after = json.loads(store.load())
    expected = json.loads(json.dumps(before))
    expected["records"][0]["binding"]["device_ids"] = sorted(new.device_ids)
    assert after == expected
    with pytest.raises(ValueError):
        migrate_device_scope(store, old, old.device_ids)
    migrate_device_scope(store, new, old.device_ids)  # Rollback scope on latest vault only.
    assert json.loads(store.load()) == before
    store.close()


@pytest.mark.parametrize(
    "devices",
    [
        frozenset({"other"}),
        frozenset({"vg-frr-1"}),
        frozenset({"vg-ubuntu-rdp", "production-router"}),
    ],
)
def test_reject_scope_widening_outside_lab(devices):
    with pytest.raises(ValueError):
        migrate_device_scope(None, binding(), devices)


def test_inventory_requires_scope_and_private_exact_pins(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text("10.78.0.11 ssh-ed25519 synthetic\n")
    hosts.chmod(0o600)
    inventory = tmp_path / "inventory"
    inventory.write_text(
        json.dumps(
            {
                "devices": [
                    {
                        "id": "vg-frr-1",
                        "name": "VG-FRR-1",
                        "ssh": {"host": "10.78.0.11", "port": 22, "known_hosts": str(hosts)},
                    }
                ]
            }
        )
    )
    inventory.chmod(0o600)
    config = {
        "binding": {**asdict(binding()), "device_ids": ["vg-ubuntu-rdp", "vg-frr-1"]},
        "managed_ssh_inventory_file": str(inventory),
    }
    devices, targets = load_managed_targets(config)
    assert devices[0].id == "vg-frr-1" and devices[0].org_id == "org"
    assert targets["vg-frr-1"].host == "10.78.0.11"
    hosts.write_text("10.78.0.12 ssh-ed25519 synthetic\n")
    with pytest.raises(ValueError):
        load_managed_targets(config)
    hosts.chmod(0o666)
    with pytest.raises(ValueError):
        load_managed_targets(config)


def test_gateway_refuses_unmapped_actor_and_overdue_before_password_injection():
    async def scenario():
        service = RotationService(Adapter())
        service.enroll(replace(binding(), device_ids=frozenset({"vg-frr-1"})), "synthetic-secret")
        actor = Actor("wrong-tech", "org", frozenset({"tenant"}), "technician")

        async def authorize():
            return True

        async def connect(username, password):
            pytest.fail("unmapped actor must not receive connection")

        async def close(connection):
            pass

        with pytest.raises(DomainError):
            await open_managed_session(service, actor, "vg-frr-1", authorize, connect, close)

    asyncio.run(scenario())


def test_managed_websocket_uses_vault_and_revokes_without_secret_exposure(monkeypatch):
    from fastapi.testclient import TestClient
    from vg_api.main import create_app
    from vg_api.managed_ssh import ManagedSSHProcess
    from vg_core.domain import ControlPlane, Device, Policy

    class Stream:
        def __init__(self):
            self.first = True

        async def read(self, size):
            if self.first:
                self.first = False
                return b"FRR managed prompt"
            await asyncio.Event().wait()

        def write(self, data):
            pass

    class Connection:
        closed = False

        def close(self):
            self.closed = True

        async def wait_closed(self):
            pass

    class Process:
        stdout = Stream()
        stdin = Stream()

        def change_terminal_size(self, cols, rows):
            pass

    plane = ControlPlane(
        (Device("vg-frr-1", "org", "tenant", "router", "frr", "direct", "ssh"),),
        {("org", "tenant"): Policy()},
        direct_entitlements=frozenset({("tech-guid", "vg-frr-1")}),
    )
    actor = Actor("tech-guid", "org", frozenset({"tenant"}), "technician")
    service = RotationService(Adapter())
    service.enroll(replace(binding(), device_ids=frozenset({"vg-frr-1"})), "hidden-privileged")
    connection = Connection()
    calls = []

    async def connect(target, username, password):
        assert username == "vg-tech-admin@example.local"
        assert password == "hidden-privileged"
        calls.append(target)
        return ManagedSSHProcess(connection, Process())

    monkeypatch.setattr("vg_api.ssh_sessions.connect_managed_ssh", connect)
    app = create_app(
        plane,
        {"t": actor},
        demo_ui=True,
        demo_passwords={"tech-guid": "regular-secret"},
        rotation_service=service,
        managed_ssh_targets={"vg-frr-1": ManagedSSHTarget("10.78.0.11", 22, "/pin")},
    )
    client = TestClient(app, base_url="http://localhost", client=("127.0.0.1", 50000))
    login = client.post(
        "/auth/login", json={"username": "tech-guid", "password": "regular-secret"}
    ).json()
    devices = client.get("/v1/devices").json()
    assert devices[0]["connection_ready"] and devices[0]["interactive_ssh"]
    assert not devices[0]["ssh_probe_ready"]
    grant = plane.direct_grant(actor, "vg-frr-1", "assigned", None)
    with client.websocket_connect(
        f"ws://localhost/v1/grants/{grant.id}/ssh-session", headers={"Origin": "http://localhost"}
    ) as ws:
        ws.send_json({"type": "auth", "csrf_token": login["csrf_token"]})
        assert ws.receive_json()["type"] == "ready"
        assert ws.receive_bytes() == b"FRR managed prompt"
        # Invalid input forces cleanup; no arbitrary username/password accepted.
        ws.send_json({"type": "input", "data": "show version", "password": "injected"})
        assert ws.receive_json()["type"] == "error"
    assert len(calls) == 1 and connection.closed
    assert "hidden-privileged" not in json.dumps(devices)


def test_scope_migration_rejects_uncertain_state_and_identity_change(tmp_path):
    tmp_path.chmod(0o700)
    store = EncryptedRotationStore(tmp_path, bytes(32))
    service = RotationService(Adapter(), store=store)
    service.enroll(binding(), "synthetic-secret")
    with pytest.raises(ValueError):
        migrate_device_scope(
            store,
            replace(binding(), technician_id="other"),
            frozenset({"vg-ubuntu-rdp", "vg-frr-1"}),
        )
    payload = json.loads(store.load())
    payload["records"][0]["state"] = "recovery_required"
    payload["records"][0]["pending"] = "synthetic-pending"
    store.save(json.dumps(payload).encode())
    with pytest.raises(ValueError):
        migrate_device_scope(store, binding(), frozenset({"vg-ubuntu-rdp", "vg-frr-1"}))
    assert json.loads(store.load()) == payload
    store.close()
