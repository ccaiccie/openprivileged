import base64
import json
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace
from uuid import UUID

import pytest
from vg_api.directory import DirectoryDenied
from vg_api.lab_access import SSHTarget
from vg_api.rotation_ad import AdLabRotationAdapter, AdRotationAccount
from vg_core.rotation import AccountBinding

GUID = "12345678-1234-5678-1234-567812345678"
DN = "CN=vg-tech-admin,OU=Users,OU=VaultGate Lab,DC=example,DC=local"


class Directory:
    config = SimpleNamespace(host="DC1.example.local")
    fail = False
    guid = GUID

    @contextmanager
    def _connection(self, dn, password):
        if self.fail:
            raise DirectoryDenied("synthetic")
        assert dn == DN
        response = [
            {"type": "searchResEntry", "raw_attributes": {"objectGUID": [UUID(self.guid).bytes_le]}}
        ]
        yield SimpleNamespace(search=lambda *a, **kw: True, response=response)


def fixture():
    binding = AccountBinding("a", "o", "t", "tech", "vg-tech-admin", "ad", frozenset({"d"}))
    directory = Directory()
    adapter = AdLabRotationAdapter(
        SSHTarget("192.0.2.116", 22, "Administrator", "/private/key", "/private/hosts"),
        directory,
        (AdRotationAccount(binding, GUID, DN),),
    )
    return binding, directory, adapter


def test_reset_uses_stdin_not_command_or_environment(monkeypatch):
    binding, _, adapter = fixture()
    secret = "synthetic-password-for-test-only-Aa1!"

    def run(command, **kwargs):
        assert secret not in str(command)
        assert "env" not in kwargs and "shell" not in kwargs
        assert "-T" in command and "-tt" not in command
        assert "StrictHostKeyChecking=yes" in command
        data = json.loads(kwargs["input"])
        assert data == {"guid": GUID, "dn": DN, "username": "vg-tech-admin", "password": secret}
        script = base64.b64decode(command[-1]).decode("utf-16le")
        assert "Set-ADAccountPassword" in script and "ObjectGUID" in script
        assert secret not in script
        return SimpleNamespace(returncode=0, stdout="VG_ROTATED")

    monkeypatch.setattr("vg_api.rotation_ad.subprocess.run", run)
    adapter.change(binding, secret)


def test_reset_scope_and_secret_safe_errors(monkeypatch):
    binding, _, adapter = fixture()
    with pytest.raises(ValueError, match="allowlisted"):
        adapter.change(replace(binding, privileged_username="Administrator"), "X" * 40)

    def run(*args, **kwargs):
        raise RuntimeError("synthetic-secret")

    monkeypatch.setattr("vg_api.rotation_ad.subprocess.run", run)
    with pytest.raises(RuntimeError) as exc:
        adapter.change(binding, "X" * 40)
    assert "synthetic-secret" not in str(exc.value)
    assert exc.value.__suppress_context__


def test_verify_authentication_and_immutable_identity():
    binding, directory, adapter = fixture()
    assert adapter.verify(binding, "synthetic")
    directory.guid = "00000000-0000-0000-0000-000000000000"
    assert not adapter.verify(binding, "synthetic")
    directory.fail = True
    assert not adapter.verify(binding, "synthetic")


def test_no_accounts_outside_lab():
    binding, _, _ = fixture()
    with pytest.raises(ValueError, match="VaultGate Lab"):
        AdRotationAccount(binding, GUID, "CN=Administrator,CN=Users,DC=example,DC=local")


def test_upn_is_used_for_gateway_but_sam_for_reset(monkeypatch):
    binding, directory, _ = fixture()
    binding = replace(binding, privileged_username="vg-tech-admin@example.local")
    adapter = AdLabRotationAdapter(
        SSHTarget("192.0.2.116", 22, "Administrator", "/private/key", "/private/hosts"),
        directory,
        (AdRotationAccount(binding, GUID, DN),),
    )

    def run(command, **kwargs):
        assert json.loads(kwargs["input"])["username"] == "vg-tech-admin"
        return SimpleNamespace(returncode=0, stdout="VG_ROTATED")

    monkeypatch.setattr("vg_api.rotation_ad.subprocess.run", run)
    adapter.change(binding, "X" * 40)
    assert adapter.verify(binding, "synthetic")


def test_same_guid_cannot_be_allowlisted_under_multiple_bindings():
    binding, directory, _ = fixture()
    with pytest.raises(ValueError, match="Duplicate"):
        AdLabRotationAdapter(
            SSHTarget("192.0.2.116", 22, "Administrator", "/private/key", "/private/hosts"),
            directory,
            (
                AdRotationAccount(binding, GUID, DN),
                AdRotationAccount(replace(binding, id="second"), GUID, DN),
            ),
        )
