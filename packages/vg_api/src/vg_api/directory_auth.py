"""Local-only LDAPS integration prototype. No offline/cached authorization fallback."""

import asyncio
from dataclasses import replace

from fastapi import FastAPI, Request, WebSocket
from vg_core.domain import Actor, ControlPlane, DomainError

from vg_api.demo_auth import DemoAuth, User
from vg_api.directory import (
    DirectoryConfig,
    DirectoryDenied,
    DirectoryProvider,
    DirectoryUnavailable,
    DirectoryUser,
)


class DirectoryAuth(DemoAuth):
    def __init__(self, store: ControlPlane, config: DirectoryConfig, provider: DirectoryProvider):
        # Directory mode deliberately excludes local demo users and bearer credentials.
        super().__init__(store, {}, {})
        self._async_checks = asyncio.Semaphore(8)
        self.config = config
        self.provider = provider

    async def async_actor(self, request: Request) -> Actor:
        async with self._async_checks:
            return await asyncio.to_thread(self.actor, request)

    async def async_socket_actor(self, socket: WebSocket, csrf: str) -> Actor:
        async with self._async_checks:
            return await asyncio.to_thread(self.socket_actor, socket, csrf)

    def invalidate(self, identity: str) -> None:
        self.sessions = {k: v for k, v in self.sessions.items() if v.username != identity}
        self.users.pop(identity, None)

    def provision(self, record: DirectoryUser) -> User:
        roles = tuple(self.config.roles_for(record))
        identity = "ad:" + record.id
        if not roles:
            self.invalidate(identity)
            raise DomainError("Directory account has no mapped access", 403)
        user = User(
            Actor(
                identity,
                self.config.org_id,
                frozenset(self.config.tenant_ids),
                roles[0],
                frozenset(self.config.devices_for(record)),
            ),
            list(record.groups),
            b"",
            b"",
            roles,
            record.display_name,
            record.email,
        )
        old = self.users.get(identity)
        if old and (
            old.actor != user.actor
            or old.directory_roles != user.directory_roles
            or old.groups != user.groups
        ):
            self.invalidate(identity)
            self.audit(user.actor, "directory.access_changed", identity)
        if not old:
            self.audit(user.actor, "directory.user_imported", identity)
        self.users[identity] = user
        return user

    def authenticate(self, username: str, password: str) -> User:
        try:
            return self.provision(self.provider.authenticate(username, password))
        except DirectoryDenied:
            raise DomainError("Invalid username or password", 401) from None
        except DirectoryUnavailable:
            raise DomainError("Directory unavailable; access denied", 503) from None

    def refresh(self, username: str) -> None:
        try:
            self.provision(self.provider.lookup(username.removeprefix("ad:")))
        except (DirectoryDenied, DirectoryUnavailable):
            self.invalidate(username)
            raise DomainError(
                "Directory access could not be verified; sign in again", 401
            ) from None

    def group_catalog(self) -> list[dict[str, str]]:
        return [{"id": m.group_dn, "role": ", ".join(m.roles)} for m in self.config.group_mappings]

    def validate_groups(self, groups: list[str]) -> list[str]:
        raise DomainError("Directory membership is managed in Active Directory", 403)

    def install(self, app: FastAPI) -> None:
        super().install(app)

        @app.post("/v1/directory/sync")
        def sync(request: Request) -> dict[str, int]:
            with self.lock:
                actor = self.admin(request)
                try:
                    # Fetch a complete snapshot before changes; reject partial LDAP results.
                    records = self.provider.list_users()
                except (DirectoryDenied, DirectoryUnavailable):
                    raise DomainError(
                        "Directory sync unavailable; no import performed", 503
                    ) from None
                present = {"ad:" + r.id for r in records}
                imported = 0
                for record in records:
                    try:
                        self.provision(record)
                        imported += 1
                    except DomainError:
                        pass  # Unmapped users are deliberately not provisioned.
                for identity in set(self.users) - present:
                    self.invalidate(identity)
                self.audit(replace(actor, role="superadmin"), "directory.sync", str(imported))
                return {"imported": imported}
