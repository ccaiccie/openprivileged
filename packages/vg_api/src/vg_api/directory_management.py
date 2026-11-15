"""Superadmin-only, encrypted single-directory settings. No AD writes."""

import json
from collections.abc import Callable
from typing import Any, Protocol

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from vg_core.domain import Actor, DomainError

from vg_api.directory import DirectoryConfig, DirectoryProvider, LdapsDirectory
from vg_api.directory_auth import DirectoryAuth


class SettingsStore(Protocol):
    def load(self) -> bytes | None: ...
    def save(self, data: bytes) -> None: ...


class IntegrationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    config: DirectoryConfig
    bind_password: SecretStr | None = None
    revision: int = Field(ge=0)


def saved_settings(store: SettingsStore) -> tuple[DirectoryConfig, str, int] | None:
    raw = store.load()
    if raw is None:
        return None
    saved = json.loads(raw)
    if saved["version"] != 1 or not saved["password"]:
        raise ValueError("Invalid directory settings")
    return (
        DirectoryConfig.model_validate(saved["config"]),
        saved["password"],
        int(saved["revision"]),
    )


class DirectoryManagement:
    def __init__(
        self,
        auth: DirectoryAuth,
        store: SettingsStore | None,
        password: str | None,
        revision: int = 0,
        factory: Callable[[DirectoryConfig, str], DirectoryProvider] | None = None,
        on_settings_change: Callable[[], None] | None = None,
    ):
        self.on_settings_change = on_settings_change
        self.auth = auth
        self.store = store
        self.password = password
        self.revision = revision
        self.factory = factory or (
            lambda config, secret: LdapsDirectory(config, bind_password=secret)
        )

    def reader_candidate(
        self, body: IntegrationInput, identity: str
    ) -> tuple[DirectoryProvider, str]:
        old = self.auth.config
        cfg = body.config
        if body.revision != self.revision:
            raise DomainError("Integration changed; reload before saving", 409)
        if cfg.org_id != old.org_id or cfg.tenant_ids != old.tenant_ids:
            raise DomainError("Organization and customer scope cannot be changed here", 403)
        devices = {
            d.id
            for d in self.auth.store.devices(
                Actor(identity, old.org_id, old.tenant_ids, "superadmin")
            )
        }
        if any(d not in devices for m in cfg.group_mappings for d in m.device_ids):
            raise DomainError("Group mappings must reference configured device IDs")
        secret = body.bind_password.get_secret_value() if body.bind_password else None
        if secret is None:
            if (cfg.host, cfg.port, cfg.bind_dn) != (old.host, old.port, old.bind_dn):
                raise DomainError("Enter a reader password for the new directory destination")
            secret = self.password
        if not secret or len(secret) > 1024:
            raise DomainError("A nonempty reader password is required")
        return self.factory(cfg, secret), secret

    def candidate(self, body: IntegrationInput, identity: str) -> tuple[DirectoryProvider, str]:
        provider, secret = self.reader_candidate(body, identity)
        cfg = body.config
        try:
            # Prove that the CURRENT immutable identity retains authority before switching.
            current = provider.lookup(identity.removeprefix("ad:"))
            if "ad:" + current.id != identity or "superadmin" not in cfg.roles_for(current):
                raise ValueError("No superadmin mapping")
        except Exception:
            raise DomainError(
                "Verification failed. Check LDAPS trust, reader access, search bases, and a "
                "superadmin mapping for your current AD identity. Nothing was changed.",
                400,
            ) from None
        return provider, secret

    def install(self, app: FastAPI) -> None:
        @app.get("/v1/directory/integration")
        def view(request: Request) -> JSONResponse:
            with self.auth.lock:
                self.auth.admin(request)
                return JSONResponse(
                    {
                        "configured": True,
                        "editable": self.store is not None,
                        "config": self.auth.config.model_dump(mode="json"),
                        "revision": self.revision,
                        "reader_password_set": bool(self.password),
                    },
                    headers={"Cache-Control": "no-store"},
                )

        @app.post("/v1/directory/integration/groups")
        def groups(body: IntegrationInput, request: Request) -> JSONResponse:
            with self.auth.lock:
                actor = self.auth.admin(request)
                provider, _ = self.reader_candidate(body, actor.id)
                try:
                    catalog = provider.list_groups()
                except Exception:
                    raise DomainError(
                        "Cannot load groups. Check LDAPS, reader access and group search base.",
                        503,
                    ) from None
                return JSONResponse(
                    {
                        "groups": catalog,
                        "devices": [
                            {"id": d.id, "name": d.hostname}
                            for d in self.auth.store.devices(
                                Actor(actor.id, actor.org_id, actor.tenant_ids, "superadmin")
                            )
                        ],
                    },
                    headers={"Cache-Control": "no-store"},
                )

        @app.post("/v1/directory/integration/test")
        def test(body: IntegrationInput, request: Request) -> dict[str, bool]:
            with self.auth.lock:
                actor = self.auth.admin(request)
                self.candidate(body, actor.id)
                self.auth.audit(actor, "directory.integration_tested", "verified")
                return {"verified": True}

        @app.put("/v1/directory/integration")
        def save(body: IntegrationInput, request: Request) -> dict[str, Any]:
            with self.auth.lock:
                actor = self.auth.admin(request)
                if self.store is None:
                    raise DomainError("Encrypted integration storage is not configured", 503)
                provider, secret = self.candidate(body, actor.id)
                revision = self.revision + 1
                serialized = json.dumps(
                    {
                        "version": 1,
                        "config": body.config.model_dump(mode="json"),
                        "password": secret,
                        "revision": revision,
                    }
                ).encode()
                if self.on_settings_change is not None:
                    # Suspend before persistence/activation, even if persistence fails.
                    self.on_settings_change()
                try:
                    self.store.save(serialized)
                except Exception:
                    raise DomainError(
                        (
                            "Could not persist integration; nothing activated. "
                            "Managed rotation is paused; "
                            "a controlled restart is required."
                            if self.on_settings_change
                            else "Could not persist integration; nothing activated"
                        ),
                        503,
                    ) from None
                self.auth.audit(actor, "directory.integration_updated", str(revision))
                self.auth.config = body.config
                self.auth.provider = provider
                self.password = secret
                self.revision = revision
                # Existing sessions and cached identities cannot retain previous mappings.
                self.auth.sessions.clear()
                self.auth.users.clear()
                return {
                    "saved": True,
                    "sign_in_required": True,
                    "revision": revision,
                    "rotation_restart_required": self.on_settings_change is not None,
                }
