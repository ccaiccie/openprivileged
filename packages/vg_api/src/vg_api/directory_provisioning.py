"""Explicit staged AD account creation. Never enables accounts or grants privileges.

The operator configures one OU and encrypted journal; browser users cannot expand
that scope. Writer credentials are used for one call and are never persisted.
"""

import json
import re
import secrets
from typing import Any, Literal, Protocol
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator
from vg_core.domain import DomainError

from vg_api.directory import LdapsDirectory, escape_filter
from vg_api.directory_auth import DirectoryAuth
from vg_api.directory_management import SettingsStore


class ProvisioningConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    domain_base_dn: str = Field(min_length=1)
    target_ou_dn: str = Field(min_length=1)

    @model_validator(mode="after")
    def scope(self) -> "ProvisioningConfig":
        # Deliberately disallow escaped/composite OU names in this prototype.
        if not re.fullmatch(
            r"OU=[A-Za-z0-9 _-]+(?:,OU=[A-Za-z0-9 _-]+)*,DC=[A-Za-z0-9-]+(?:,DC=[A-Za-z0-9-]+)*",
            self.target_ou_dn,
            re.I,
        ):
            raise ValueError("Use a dedicated OU with simple names")
        if not re.fullmatch(r"DC=[A-Za-z0-9-]+(?:,DC=[A-Za-z0-9-]+)*", self.domain_base_dn, re.I):
            raise ValueError("A domain naming context is required")
        if not self.target_ou_dn.casefold().endswith("," + self.domain_base_dn.casefold()):
            raise ValueError("Target OU must be inside the domain")
        return self


def privileged_username(username: str) -> str:
    """No truncation, UPN rewriting, collisions or double prefixing."""
    if username.casefold().startswith("a.") or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,17}", username
    ):
        raise DomainError("Regular username must be 1–18 safe characters and not start with a.")
    return "a." + username


class PreviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: UUID


class CreateInput(PreviewInput):
    confirmed_username: str
    consent: Literal[True]
    writer_dn: str
    writer_password: SecretStr


class Provisioner(Protocol):
    def inspect(self, username: str) -> bool: ...
    def create(self, username: str, password: str, writer_dn: str, writer_password: str) -> str: ...


class LdapsProvisioner:
    def __init__(self, directory: LdapsDirectory, config: ProvisioningConfig):
        self.directory = directory
        self.config = config

    def _scope(self, connection: Any) -> None:
        connection.search(
            "", "(objectClass=*)", search_scope="BASE", attributes=["defaultNamingContext"]
        )
        entries = [e for e in connection.response if e.get("type") == "searchResEntry"]
        if connection.result.get("result") != 0 or len(entries) != 1:
            raise ValueError("Unverified naming context")
        base = entries[0]["attributes"].get("defaultNamingContext")
        if isinstance(base, list):
            base = base[0] if len(base) == 1 else None
        if not isinstance(base, str) or base.casefold() != self.config.domain_base_dn.casefold():
            raise ValueError("Wrong naming context")
        connection.search(
            self.config.target_ou_dn,
            "(objectClass=organizationalUnit)",
            search_scope="BASE",
            attributes=["objectGUID"],
        )
        if (
            connection.result.get("result") != 0
            or len([e for e in connection.response if e.get("type") == "searchResEntry"]) != 1
        ):
            raise ValueError("Unverified OU")

    def _exists(self, connection: Any, username: str) -> bool:
        return bool(
            self.directory._search(
                connection,
                self.config.domain_base_dn,
                "(sAMAccountName=" + escape_filter(username) + ")",
                ["objectGUID"],
                2,
            )
        )

    def inspect(self, username: str) -> bool:
        with self.directory._reader() as connection:
            self._scope(connection)
            return self._exists(connection, username)

    def create(self, username: str, password: str, writer_dn: str, writer_password: str) -> str:
        # Repeat collision/scope checks with the writer, after preview and under lock.
        with self.directory._connection(writer_dn, writer_password) as connection:
            self._scope(connection)
            if self._exists(connection, username):
                raise ValueError("Account already exists")
            dn = "CN=" + username + "," + self.config.target_ou_dn
            if not connection.add(
                dn,
                ["top", "person", "organizationalPerson", "user"],
                {
                    "sAMAccountName": username,
                    "displayName": username,
                    "userAccountControl": 514,
                },
            ):
                raise ValueError("Create failed")
            # Account stays disabled if any subsequent operation or storage fails.
            if not connection.extend.microsoft.modify_password(dn, password):
                raise ValueError("Initial password failed")
            connection.search(
                dn,
                "(objectClass=user)",
                search_scope="BASE",
                attributes=["objectGUID", "userAccountControl"],
            )
            entries = [e for e in connection.response if e.get("type") == "searchResEntry"]
            if connection.result.get("result") != 0 or len(entries) != 1:
                raise ValueError("Verification failed")
            attrs = entries[0]["attributes"]
            flags = attrs.get("userAccountControl")
            if isinstance(flags, list):
                flags = flags[0] if len(flags) == 1 else None
            if int(flags or 0) != 514:
                raise ValueError("Account not disabled")
            return str(UUID(bytes_le=entries[0]["raw_attributes"]["objectGUID"][0]))


class DirectoryProvisioning:
    def __init__(
        self,
        auth: DirectoryAuth,
        config: ProvisioningConfig | None = None,
        store: SettingsStore | None = None,
        password: str | None = None,
        provider: Provisioner | None = None,
    ):
        self.auth, self.config, self.store = auth, config, store
        self.password, self.provider = password, provider

    def _provider(self) -> Provisioner:
        if self.config is None or self.store is None:
            raise DomainError(
                "Provisioning is disabled; configure a dedicated OU and encrypted journal first",
                503,
            )
        if self.provider is not None:
            return self.provider
        if not isinstance(self.auth.provider, LdapsDirectory):
            raise DomainError("Provisioning requires a verified LDAPS directory", 503)
        return LdapsProvisioner(self.auth.provider, self.config)

    def _target(self, user_id: UUID) -> str:
        try:
            record = self.auth.provider.lookup(str(user_id))
        except Exception:
            raise DomainError("Technician identity cannot be verified", 503) from None
        if "technician" not in self.auth.config.roles_for(record):
            raise DomainError("Only a currently mapped technician can have a managed account", 403)
        return privileged_username(record.username)

    def install(self, app: FastAPI) -> None:
        @app.get("/v1/directory/provisioning")
        def capabilities(request: Request) -> JSONResponse:
            with self.auth.lock:
                self.auth.admin(request)
                return JSONResponse(
                    {
                        "enabled": self.config is not None and self.store is not None,
                        "prefix": "a.",
                        "target_ou_dn": self.config.target_ou_dn if self.config else None,
                        "creation_state": "disabled_pending_enrollment",
                        "permissions": (
                            "Read domain users/groups; Create User objects and Reset Password "
                            "only in the dedicated OU. "
                            "No Domain Admin or domain-wide write required."
                        ),
                    },
                    headers={"Cache-Control": "no-store"},
                )

        @app.post("/v1/directory/provisioning/preview")
        def preview(body: PreviewInput, request: Request) -> dict[str, Any]:
            with self.auth.lock:
                self.auth.admin(request)
                username = self._target(body.user_id)
                try:
                    exists = self._provider().inspect(username)
                except DomainError:
                    raise
                except Exception:
                    raise DomainError(
                        "Directory verification failed; nothing changed", 503
                    ) from None
                return {
                    "username": username,
                    "exists": exists,
                    "target_ou_dn": self.config.target_ou_dn if self.config else None,
                    "creation_state": "disabled_pending_enrollment",
                }

        @app.post("/v1/directory/provisioning/create")
        def create(body: CreateInput, request: Request) -> dict[str, str]:
            with self.auth.lock:
                actor = self.auth.admin(request)
                username = self._target(body.user_id)
                if username != body.confirmed_username:
                    raise DomainError("Username changed; preview and confirm again", 409)
                secret = body.writer_password.get_secret_value()
                if not body.writer_dn.strip() or not secret or len(secret) > 1024:
                    raise DomainError("A delegated writer identity and password are required")
                provider = self._provider()
                assert self.store is not None and self.config is not None
                # Persist intent + secret BEFORE the remote write. Any uncertain result
                # blocks retries until operator reconciliation; never reset an existing user.
                try:
                    raw = self.store.load()
                    journal: dict[str, Any] = (
                        json.loads(raw) if raw else {"version": 1, "accounts": {}}
                    )
                    key = self.auth.config.host.casefold() + ":" + username.casefold()
                    if key in journal["accounts"] or provider.inspect(username):
                        raise DomainError(
                            "Account exists or has a pending attempt; "
                            "reconcile manually, do not retry",
                            409,
                        )
                    generated = "Vg!9" + secrets.token_urlsafe(36)
                    journal["accounts"][key] = {
                        "source_guid": str(body.user_id),
                        "username": username,
                        "password": generated,
                        "state": "pending",
                        "target_ou_dn": self.config.target_ou_dn,
                    }
                    self.store.save(json.dumps(journal).encode())
                except DomainError:
                    raise
                except Exception:
                    raise DomainError(
                        "Provisioning storage or directory unavailable; no create attempted", 503
                    ) from None
                try:
                    guid = provider.create(username, generated, body.writer_dn, secret)
                    journal["accounts"][key].update(
                        {"object_guid": guid, "state": "disabled_pending_enrollment"}
                    )
                    self.store.save(json.dumps(journal).encode())
                except Exception:
                    self.auth.audit(actor, "directory.account_creation_uncertain", username)
                    raise DomainError(
                        "Creation outcome requires reconciliation. Any created account remains "
                        "disabled; do not retry automatically.",
                        503,
                    ) from None
                self.auth.audit(actor, "directory.account_created_disabled", username)
                return {
                    "username": username,
                    "object_guid": guid,
                    "state": "disabled_pending_enrollment",
                }
