"""Generalized managed AD uses synthetic, in-memory directory and subprocess mocks."""

import json
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import UUID

import pytest
from vg_api.directory import DirectoryConfig, DirectoryUser
from vg_api.directory_provisioning import ProvisioningConfig
from vg_api.lab_access import SSHTarget
from vg_api.rotation_managed_ad import ManagedAdAccount, ManagedAdRotationAdapter
from vg_core.domain import Actor
from vg_core.rotation import AccountBinding, RotationService

TECH = "00000000-0000-0000-0000-000000000001"
ADMIN = "00000000-0000-0000-0000-000000000002"


def fixture():
    config = DirectoryConfig(
        host="dc.example.invalid",
        ca_file="/not/used",
        bind_dn="reader",
        bind_password_env="TEST",
        user_base_dn="DC=test",
        group_base_dn="DC=test",
        org_id="org",
        tenant_ids=["tenant"],
        group_mappings=[
            {"group_dn": "CN=Tech,DC=test", "roles": ["technician"], "device_ids": ["router"]}
        ],
    )
    row = DirectoryUser(TECH, "joe.bloe", "", "", ("CN=Tech,DC=test",))
    connection = Mock()
    connection.result = {"result": 0}
    connection.response = [
        {
            "type": "searchResEntry",
            "attributes": {"sAMAccountName": ["a.joe.bloe"], "userAccountControl": ["512"]},
            "raw_attributes": {"objectGUID": [UUID(ADMIN).bytes_le]},
        }
    ]

    @contextmanager
    def connect(dn, password):
        assert dn == "CN=a.joe.bloe,OU=Managed,DC=test"
        yield connection

    directory = SimpleNamespace(config=config, lookup=Mock(return_value=row), _connection=connect)
    binding = AccountBinding(
        "managed-joe",
        "org",
        "tenant",
        "ad:" + TECH,
        "a.joe.bloe",
        "dc.example.invalid",
        frozenset({"router"}),
    )
    account = ManagedAdAccount(binding, ADMIN, "joe.bloe", "CN=a.joe.bloe,OU=Managed,DC=test")
    authority = SSHTarget("dc.example.invalid", 22, "delegate", "/not/used/key", "/not/used/pins")
    adapter = ManagedAdRotationAdapter(
        authority,
        directory,
        ProvisioningConfig(domain_base_dn="DC=test", target_ou_dn="OU=Managed,DC=test"),
        (account,),
    )
    return adapter, account, directory, connection


def test_guid_identity_enabled_status_and_owner_checked():
    adapter, account, directory, connection = fixture()
    assert adapter.verify(account.binding, "synthetic-password")
    connection.response[0]["raw_attributes"]["objectGUID"] = [UUID(TECH).bytes_le]
    assert not adapter.verify(account.binding, "synthetic-password")
    connection.response[0]["raw_attributes"]["objectGUID"] = [UUID(ADMIN).bytes_le]
    connection.response[0]["attributes"]["userAccountControl"] = ["514"]
    assert not adapter.verify(account.binding, "synthetic-password")
    directory.lookup.return_value = replace(directory.lookup.return_value, username="someoneelse")
    with pytest.raises(ValueError):
        adapter.verify(account.binding, "synthetic-password")


def test_reset_guid_targeted_secret_stdin_no_argument_or_output_leak():
    adapter, account, _, _ = fixture()
    secret = "OnlySyntheticSecret!" * 3
    result = SimpleNamespace(returncode=0, stdout="VG_ROTATED", stderr="")
    with patch("vg_api.rotation_managed_ad.subprocess.run", return_value=result) as run:
        adapter.change(account.binding, secret)
        args, kwargs = run.call_args
        assert secret not in " ".join(args[0])
        data = json.loads(kwargs["input"])
        assert data["guid"] == ADMIN and data["technician_guid"] == TECH
        assert data["password"] == secret
    with patch("vg_api.rotation_managed_ad.subprocess.run", side_effect=ValueError(secret)):
        with pytest.raises(RuntimeError) as error:
            adapter.change(account.binding, secret)
        assert secret not in str(error.value)


def test_allowlist_rejects_wrong_name_ou_authority_and_owner():
    adapter, account, directory, _ = fixture()
    for invalid in [
        replace(account, distinguished_name="CN=a.joe.bloe,OU=Other,DC=test"),
        replace(account, object_guid=TECH),
        replace(account, binding=replace(account.binding, privileged_username="a.other")),
        replace(account, binding=replace(account.binding, authority_id="wrong.invalid")),
    ]:
        with pytest.raises(ValueError):
            ManagedAdRotationAdapter(adapter.authority, directory, adapter.scope, (invalid,))
    with pytest.raises(ValueError):
        adapter.verify(replace(account.binding, device_ids=frozenset({"other"})), "password")


def test_core_enroll_hidden_ssh_mapping_and_four_hour_rotation_with_adapter():
    adapter, account, _, _ = fixture()
    now = [datetime(2026, 11, 14, tzinfo=UTC)]
    service = RotationService(adapter, clock=lambda: now[0])
    status = service.enroll(account.binding, "synthetic-initial-password")
    assert status.state == "ready"
    assert status.due_at == now[0] + timedelta(hours=4)
    actor = Actor("ad:" + TECH, "org", frozenset({"tenant"}), "technician", frozenset({"router"}))
    seen = []
    service.connect(actor, "router", lambda: None, lambda username, password: seen.append(username))
    assert seen == ["a.joe.bloe"]
    now[0] += timedelta(hours=4)
    with patch(
        "vg_api.rotation_managed_ad.subprocess.run",
        return_value=SimpleNamespace(returncode=0, stdout="VG_ROTATED"),
    ):
        assert service.rotate_due()[0].state == "ready"
    assert service.status("managed-joe").generation == 2


def test_staged_enrollment_exact_guids_and_no_enable_or_reset(tmp_path):
    from dataclasses import asdict

    from vg_api.rotation_managed_ad import enroll_staged

    adapter, account, _, _ = fixture()
    binding = asdict(account.binding)
    binding["device_ids"] = list(binding["device_ids"])
    config = {
        "managed_accounts": [
            {
                "binding": binding,
                "object_guid": ADMIN,
                "regular_username": "joe.bloe",
                "distinguished_name": account.distinguished_name,
            }
        ],
        "directory": {"host": "dc.example.invalid"},
        "managed_scope": {"target_ou_dn": "OU=Managed,DC=test"},
        "account_provisioning": {
            "journal_directory": str(tmp_path),
            "journal_key_file": str(tmp_path / "key"),
        },
    }
    row = {
        "state": "disabled_pending_enrollment",
        "object_guid": ADMIN,
        "source_guid": TECH,
        "username": "a.joe.bloe",
        "target_ou_dn": "OU=Managed,DC=test",
        "password": "fake-initial",
    }
    journal = Mock()
    journal.load.side_effect = lambda: json.dumps(
        {"accounts": {"dc.example.invalid:a.joe.bloe": row}}
    ).encode()
    service = RotationService(adapter)
    vault = Mock()
    with (
        patch("vg_api.rotation_store.EncryptedRotationStore", return_value=journal),
        patch("vg_api.rotation_runner.private_read", return_value=b"x" * 32),
        patch("vg_api.rotation_managed_ad.open_managed_runtime", return_value=(vault, service)),
        patch.object(adapter, "change") as reset,
    ):
        assert enroll_staged(config, "managed-joe").state == "ready"
        reset.assert_not_called()
        saved = json.loads(journal.save.call_args.args[0])["accounts"][
            "dc.example.invalid:a.joe.bloe"
        ]
        assert saved["state"] == "enrolled" and "password" not in saved
        row["object_guid"] = TECH
        with pytest.raises(ValueError):
            enroll_staged(config, "managed-joe")


def test_generalized_runtime_requires_exact_persisted_allowlist(tmp_path):
    from dataclasses import asdict

    from vg_api.rotation_managed_ad import open_managed_runtime

    _, account, directory, _ = fixture()
    binding = asdict(account.binding)
    binding["device_ids"] = list(binding["device_ids"])
    config = {
        "managed_accounts": [
            {
                "binding": binding,
                "object_guid": ADMIN,
                "regular_username": "joe.bloe",
                "distinguished_name": account.distinguished_name,
            }
        ],
        "directory": directory.config.model_dump(mode="json"),
        "managed_scope": {"domain_base_dn": "DC=test", "target_ou_dn": "OU=Managed,DC=test"},
        "ssh": {
            "host": "dc.example.invalid",
            "port": 22,
            "username": "delegate",
            "private_key": "/unused/key",
            "known_hosts": "/unused/pins",
        },
        "reader_password_file": str(tmp_path / "reader"),
        "key_file": str(tmp_path / "key"),
        "vault_directory": str(tmp_path / "vault"),
    }
    (tmp_path / "vault").mkdir(mode=0o700)
    (tmp_path / "reader").write_text("synthetic-reader")
    (tmp_path / "reader").chmod(0o600)
    (tmp_path / "key").write_bytes(b"k" * 32)
    (tmp_path / "key").chmod(0o600)
    with pytest.raises(ValueError):
        open_managed_runtime(config)
    store, service = open_managed_runtime(config, enrollment=True)
    try:
        store.save(
            json.dumps(
                {
                    "version": 1,
                    "records": [{"binding": {**binding, "technician_id": "ad:" + ADMIN}}],
                }
            ).encode()
        )
    finally:
        store.close()
    with pytest.raises(ValueError):
        open_managed_runtime(config, enrollment=True)


def test_persisted_metadata_rejects_guid_dn_or_regular_name_changes():
    from test_directory_management import MemoryStore
    from vg_api.rotation_managed_ad import ManagedRotationState

    adapter, account, _, _ = fixture()
    backing = MemoryStore()
    state = ManagedRotationState(backing, (account,), adapter.scope)
    state.save(
        json.dumps({"version": 1, "records": [{"binding": {"id": account.binding.id}}]}).encode()
    )
    assert state.load() is not None
    for altered in [
        replace(account, object_guid="00000000-0000-0000-0000-000000000003"),
        replace(account, regular_username="renamed"),
        replace(account, distinguished_name="CN=a.joe.bloe,OU=Other,DC=test"),
    ]:
        with pytest.raises(ValueError):
            ManagedRotationState(backing, (altered,), adapter.scope).load()
    backing.data = json.dumps({"version": 1, "records": []}).encode()
    with pytest.raises(ValueError):
        state.load()


def test_connect_revalidates_source_rename_and_target_disabled_or_replaced():
    from vg_core.domain import DomainError

    adapter, account, directory, connection = fixture()
    service = RotationService(adapter)
    service.enroll(account.binding, "synthetic-initial")
    actor = Actor("ad:" + TECH, "org", frozenset({"tenant"}), "technician", frozenset({"router"}))
    inject = Mock()
    original = directory.lookup.return_value
    directory.lookup.return_value = replace(original, username="renamed")
    with pytest.raises(DomainError):
        service.connect(actor, "router", lambda: None, inject)
    directory.lookup.return_value = original
    connection.response[0]["attributes"]["userAccountControl"] = ["514"]
    with pytest.raises(DomainError):
        service.connect(actor, "router", lambda: None, inject)
    connection.response[0]["attributes"]["userAccountControl"] = ["512"]
    connection.response[0]["raw_attributes"]["objectGUID"] = [UUID(TECH).bytes_le]
    with pytest.raises(DomainError):
        service.connect(actor, "router", lambda: None, inject)
    inject.assert_not_called()


def test_suspension_blocks_connect_and_rotation_even_during_verification():
    from vg_core.domain import DomainError

    adapter, account, _, _ = fixture()
    now = [datetime(2026, 11, 14, tzinfo=UTC)]
    service = RotationService(adapter, clock=lambda: now[0])
    service.enroll(account.binding, "synthetic-initial")
    actor = Actor("ad:" + TECH, "org", frozenset({"tenant"}), "technician", frozenset({"router"}))

    def verifying(*args):
        service.suspend()
        return True

    inject = Mock()
    with patch.object(adapter, "validate_connect", side_effect=verifying):
        with pytest.raises(DomainError):
            service.connect(actor, "router", lambda: None, inject)
    assert service.status(account.binding.id).state == "suspended"
    now[0] += timedelta(hours=5)
    with patch.object(adapter, "change") as change:
        assert service.rotate_due()[0].state == "suspended"
        change.assert_not_called()
    inject.assert_not_called()


def test_suspended_recovery_never_verifies_or_resets():
    adapter, account, _, _ = fixture()
    service = RotationService(adapter)
    service.enroll(account.binding, "synthetic-initial")
    service.suspend()
    with patch.object(adapter, "verify") as verify, patch.object(adapter, "change") as change:
        assert service.recover(account.binding.id).state == "suspended"
        verify.assert_not_called()
        change.assert_not_called()


def test_recovery_suspended_during_verification_does_not_reset():
    adapter, account, _, _ = fixture()
    now = [datetime(2026, 11, 14, tzinfo=UTC)]
    service = RotationService(adapter, clock=lambda: now[0])
    service.enroll(account.binding, "synthetic-initial")
    now[0] += timedelta(hours=4)
    with patch.object(adapter, "change", side_effect=RuntimeError("synthetic timeout")):
        assert service.rotate_due()[0].state == "recovery_required"
    calls = [0]

    def verifying(*args):
        calls[0] += 1
        if calls[0] == 1:
            return False
        service.suspend()
        return True

    with (
        patch.object(adapter, "verify", side_effect=verifying),
        patch.object(adapter, "change") as change,
    ):
        assert service.recover(account.binding.id).state == "suspended"
        change.assert_not_called()
