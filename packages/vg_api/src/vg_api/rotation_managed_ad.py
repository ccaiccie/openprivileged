"""Opt-in GUID-pinned a.username rotation. Does not create/enable accounts or grant rights.

Each account and technician/device binding must be explicitly operator allowlisted.
The SSH authority uses preconfigured delegated credentials, not browser input.
"""

import base64
import json
import subprocess
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from vg_core.rotation import AccountBinding, RotationService, RotationStatus

from vg_api.directory import DirectoryDenied, LdapsDirectory
from vg_api.directory_provisioning import ProvisioningConfig, privileged_username
from vg_api.lab_access import SSHTarget
from vg_api.rotation_store import EncryptedRotationStore
from vg_api.ssh_sessions import ssh_command


@dataclass(frozen=True)
class ManagedAdAccount:
    binding: AccountBinding
    object_guid: str
    regular_username: str
    distinguished_name: str


RESET = r"""
$ErrorActionPreference = 'Stop'
try {
  Import-Module ActiveDirectory -ErrorAction Stop
  $p = [Console]::In.ReadToEnd() | ConvertFrom-Json
  $u = Get-ADUser -Server $p.server -Identity ([Guid]$p.guid) `
    -Properties DistinguishedName,SamAccountName,Enabled
  if ($u.DistinguishedName -ine $p.dn -or $u.SamAccountName -cne $p.username -or
      -not $u.Enabled) { throw 'scope' }
  $t = Get-ADUser -Server $p.server -Identity ([Guid]$p.technician_guid) `
    -Properties SamAccountName,Enabled
  if ($t.SamAccountName -cne $p.regular_username -or -not $t.Enabled) { throw 'owner' }
  $secure = ConvertTo-SecureString -String $p.password -AsPlainText -Force
  Set-ADAccountPassword -Server $p.server -Identity $u.ObjectGUID -Reset `
    -NewPassword $secure -ErrorAction Stop
  [Console]::Out.Write('VG_ROTATED')
} catch { [Console]::Out.Write('VG_FAILED'); exit 1 }
"""


class ManagedAdRotationAdapter:
    def __init__(
        self,
        authority: SSHTarget,
        directory: LdapsDirectory,
        scope: ProvisioningConfig,
        accounts: tuple[ManagedAdAccount, ...],
    ):
        self.authority, self.directory, self.scope = authority, directory, scope
        self.accounts = {a.binding.id: a for a in accounts}
        if not accounts or len(self.accounts) != len(accounts):
            raise ValueError("Distinct managed accounts required")
        if len({UUID(a.object_guid) for a in accounts}) != len(accounts):
            raise ValueError("Duplicate managed GUID")
        for account in accounts:
            binding = account.binding
            technician = binding.technician_id.removeprefix("ad:")
            if binding.technician_id != "ad:" + str(UUID(technician)):
                raise ValueError("Canonical AD technician GUID required")
            if UUID(account.object_guid) == UUID(technician):
                raise ValueError("Separate privileged GUID required")
            username = privileged_username(account.regular_username)
            if binding.privileged_username != username:
                raise ValueError("Managed account must be a. plus regular sAMAccountName")
            if (
                account.distinguished_name.casefold()
                != ("CN=" + username + "," + scope.target_ou_dn).casefold()
            ):
                raise ValueError("Managed account must be in the explicitly delegated OU")
            if (
                binding.authority_id.casefold() != directory.config.host.casefold()
                or binding.org_id != directory.config.org_id
                or binding.tenant_id not in directory.config.tenant_ids
            ):
                raise ValueError("Directory authority and organization scope must match")

    def _account(self, binding: AccountBinding) -> ManagedAdAccount:
        account = self.accounts.get(binding.id)
        if account is None or binding != account.binding:
            raise ValueError("Account is not allowlisted")
        regular = self.directory.lookup(binding.technician_id.removeprefix("ad:"))
        if (
            regular.username != account.regular_username
            or "technician" not in self.directory.config.roles_for(regular)
        ):
            raise ValueError("Technician ownership or role changed")
        if not binding.device_ids <= self.directory.config.devices_for(regular):
            raise ValueError("Managed binding exceeds current device entitlement")
        return account

    def change(self, binding: AccountBinding, password: str) -> None:
        account = self._account(binding)
        if not 32 <= len(password) <= 200:
            raise ValueError("Invalid managed password")
        command = ssh_command(self.authority)
        command[command.index("-tt")] = "-T"
        command += [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            base64.b64encode(RESET.encode("utf-16le")).decode(),
        ]
        payload = {
            "server": self.directory.config.host,
            "guid": account.object_guid,
            "dn": account.distinguished_name,
            "username": binding.privileged_username,
            "technician_guid": binding.technician_id.removeprefix("ad:"),
            "regular_username": account.regular_username,
            "password": password,
        }
        try:
            result = subprocess.run(
                command,
                input=json.dumps(payload),
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0 or result.stdout.strip() != "VG_ROTATED":
                raise ValueError("Reset not confirmed")
        except Exception:
            raise RuntimeError("Managed AD rotation uncertain; reconcile before reuse") from None

    def validate_connect(self, binding: AccountBinding, password: str) -> bool:
        """Fresh source/target identity check immediately before broker injection."""
        return self.verify(binding, password)

    def verify(self, binding: AccountBinding, password: str) -> bool:
        account = self._account(binding)
        try:
            with self.directory._connection(account.distinguished_name, password) as connection:
                connection.search(
                    account.distinguished_name,
                    "(objectClass=user)",
                    search_scope="BASE",
                    attributes=["objectGUID", "sAMAccountName", "userAccountControl"],
                )
                rows = [e for e in connection.response if e.get("type") == "searchResEntry"]
                if connection.result.get("result") != 0 or len(rows) != 1:
                    raise ValueError("Identity not verified")
                attrs = rows[0]["attributes"]
                username = attrs.get("sAMAccountName")
                flags = attrs.get("userAccountControl")
                if isinstance(username, list):
                    username = username[0] if len(username) == 1 else None
                if isinstance(flags, list):
                    flags = flags[0] if len(flags) == 1 else None
                return (
                    UUID(bytes_le=rows[0]["raw_attributes"]["objectGUID"][0])
                    == UUID(account.object_guid)
                    and username == binding.privileged_username
                    and flags is not None
                    and not int(flags) & 2
                )
        except DirectoryDenied:
            return False
        except Exception:
            raise RuntimeError("Managed AD verification unavailable") from None


class ManagedRotationState:
    """Encrypted backing-store envelope binding each core record to AD metadata."""

    def __init__(
        self, store: Any, accounts: tuple[ManagedAdAccount, ...], scope: ProvisioningConfig
    ):
        self.store = store
        self.metadata = {
            a.binding.id: {
                "object_guid": str(UUID(a.object_guid)),
                "distinguished_name": a.distinguished_name.casefold(),
                "regular_username": a.regular_username,
                "target_ou_dn": scope.target_ou_dn.casefold(),
                "domain_base_dn": scope.domain_base_dn.casefold(),
            }
            for a in accounts
        }

    def load(self) -> bytes | None:
        raw = self.store.load()
        if raw is None:
            return None
        envelope = json.loads(raw)
        if envelope.get("managed_version") != 1:
            raise ValueError("Unbound managed state requires explicit reenrollment")
        payload = envelope["rotation"]
        ids = [r["binding"]["id"] for r in payload["records"]]
        if len(ids) != len(set(ids)) or set(envelope["identities"]) != set(ids):
            raise ValueError("Managed identity metadata mismatch")
        for account_id in ids:
            if (
                account_id not in self.metadata
                or envelope["identities"][account_id] != self.metadata[account_id]
            ):
                raise ValueError("Managed identity changed; explicit reenrollment required")
        return json.dumps(payload).encode()

    def save(self, data: bytes) -> None:
        payload = json.loads(data)
        ids = [r["binding"]["id"] for r in payload["records"]]
        if len(ids) != len(set(ids)) or any(i not in self.metadata for i in ids):
            raise ValueError("Managed identity not approved")
        self.store.save(
            json.dumps(
                {
                    "managed_version": 1,
                    "identities": {i: self.metadata[i] for i in ids},
                    "rotation": payload,
                }
            ).encode()
        )


def configured_accounts(config: dict[str, Any]) -> tuple[ManagedAdAccount, ...]:
    """Parse operator-only allowlist; browser input never reaches this interface."""
    result = []
    for row in config["managed_accounts"]:
        binding = AccountBinding(
            **{**row["binding"], "device_ids": frozenset(row["binding"]["device_ids"])}
        )
        result.append(
            ManagedAdAccount(
                binding, row["object_guid"], row["regular_username"], row["distinguished_name"]
            )
        )
    return tuple(result)


def open_managed_runtime(
    config: dict[str, Any], *, enrollment: bool = False
) -> tuple[EncryptedRotationStore, RotationService]:
    """Separate opt-in runtime; never widens the existing synthetic lab adapter."""
    from dataclasses import asdict
    from pathlib import Path

    from vg_core.rotation import RotationService

    from vg_api.directory import DirectoryConfig
    from vg_api.rotation_runner import private_read
    from vg_api.rotation_store import EncryptedRotationStore

    accounts = configured_accounts(config)
    selected = DirectoryConfig.model_validate(config["directory"])
    password = private_read(Path(config["reader_password_file"])).decode()
    if config.get("directory_settings_directory"):
        from vg_api.directory_management import saved_settings

        settings = EncryptedRotationStore(
            Path(config["directory_settings_directory"]),
            private_read(Path(config["directory_settings_key_file"])),
        )
        try:
            saved = saved_settings(settings)
            if saved is not None:
                current, password, _ = saved
                if current.org_id != selected.org_id or current.tenant_ids != selected.tenant_ids:
                    raise ValueError("Saved directory scope differs from approved configuration")
                selected = current
        finally:
            settings.close()
    directory = LdapsDirectory(selected, bind_password=password)
    adapter = ManagedAdRotationAdapter(
        SSHTarget(**config["ssh"]),
        directory,
        ProvisioningConfig.model_validate(config["managed_scope"]),
        accounts,
    )
    store = EncryptedRotationStore(
        Path(config["vault_directory"]), private_read(Path(config["key_file"]))
    )
    try:
        state = ManagedRotationState(store, accounts, adapter.scope)
        raw = state.load()
        payload: dict[str, Any] = json.loads(raw) if raw else {"version": 1, "records": []}
        allowed = {}
        for account in accounts:
            data = asdict(account.binding)
            data["device_ids"] = sorted(data["device_ids"])
            allowed[account.binding.id] = data
        saved = payload.get("records", [])
        ids = set()
        for row in saved:
            data = dict(row["binding"])
            data["device_ids"] = sorted(data["device_ids"])
            if data != allowed.get(data["id"]) or data["id"] in ids:
                raise ValueError("Vault bindings do not match approved scope")
            ids.add(data["id"])
        if not enrollment and ids != set(allowed):
            raise ValueError("Every configured account must be enrolled before serving")
        return store, RotationService(adapter, store=state)
    except BaseException:
        store.close()
        raise


def enroll_staged(config: dict[str, Any], account_id: str) -> RotationStatus:
    """Operator-invoked enrollment of an ALREADY enabled staged identity.

    Does not reset, enable, assign groups, install a task, or start a worker.
    Requires explicit approved allowlist + encrypted staging record + successful
    credential/GUID/technician/device validation before persisting the binding.
    """
    from pathlib import Path

    from vg_api.rotation_runner import private_read
    from vg_api.rotation_store import EncryptedRotationStore

    account = next((a for a in configured_accounts(config) if a.binding.id == account_id), None)
    if account is None:
        raise ValueError("Account is not allowlisted")
    staging = config["account_provisioning"]
    journal = EncryptedRotationStore(
        Path(staging["journal_directory"]), private_read(Path(staging["journal_key_file"]))
    )
    store = None
    try:
        payload = json.loads(journal.load() or b"null")
        key = (
            config["directory"]["host"].casefold()
            + ":"
            + account.binding.privileged_username.casefold()
        )
        row = payload["accounts"][key]
        if (
            row["state"] != "disabled_pending_enrollment"
            or UUID(row["object_guid"]) != UUID(account.object_guid)
            or row["source_guid"] != account.binding.technician_id.removeprefix("ad:")
            or row["username"] != account.binding.privileged_username
            or row["target_ou_dn"].casefold() != config["managed_scope"]["target_ou_dn"].casefold()
        ):
            raise ValueError("Staged identity does not match approved enrollment")
        store, service = open_managed_runtime(config, enrollment=True)
        # Enabled state and password are verified. A disabled account cannot pass.
        status = service.enroll(account.binding, row["password"])
        # Vault now owns the password; scrub it from the current journal snapshot.
        row["state"] = "enrolled"
        row.pop("password", None)
        journal.save(json.dumps(payload).encode())
        return status
    finally:
        if store is not None:
            store.close()
        journal.close()
