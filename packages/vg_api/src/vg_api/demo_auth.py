"""Ephemeral localhost demonstration, not a production identity provider."""

import hashlib
import secrets
import time
from dataclasses import dataclass, replace
from threading import RLock
from typing import Any

from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from vg_core.domain import Actor, ControlPlane, DomainError, Role

COOKIE = "vg_demo_session"
GROUPS: dict[str, Role] = {
    "administrators": "admin",
    "technicians": "technician",
    "approvers": "approver",
    "auditors": "auditor",
}


class Login(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=200)


class SelectRole(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    role: str


class Membership(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    groups: list[str] = Field(min_length=1, max_length=4)


class NewUser(Membership):
    username: str = Field(pattern=r"^[a-z][a-z0-9_-]{2,31}$")


@dataclass
class User:
    actor: Actor
    groups: list[str]
    salt: bytes
    digest: bytes
    directory_roles: tuple[Role, ...] | None = None
    display_name: str = ""
    email: str = ""


@dataclass
class Session:
    username: str
    role: Role
    csrf: str
    expires: float


class DemoAuth:
    def __init__(
        self, store: ControlPlane, identities: dict[str, Actor], passwords: dict[str, str]
    ):
        self.store = store
        self.lock = RLock()
        self.users: dict[str, User] = {}
        self.sessions: dict[str, Session] = {}
        self.failures: dict[str, list[float]] = {}
        actors = {a.id: a for a in identities.values()}
        actors["multi"] = Actor("multi", "demo-msp", frozenset({"customer-a"}), "technician")
        actors["superadmin"] = Actor(
            "superadmin", "demo-msp", frozenset({"customer-a"}), "superadmin"
        )
        for name, actor in actors.items():
            if name not in passwords:
                continue
            groups = [g for g, r in GROUPS.items() if r == actor.role]
            if name == "multi":
                groups = ["technicians", "approvers"]
            salt = secrets.token_bytes(16)
            self.users[name] = User(actor, groups, salt, self.hash(passwords[name], salt))

    @staticmethod
    def hash(password: str, salt: bytes) -> bytes:
        return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)

    def authenticate(self, username: str, password: str) -> User:
        user = self.users.get(username)
        digest = self.hash(password, user.salt if user else b"demo-invalid-user")
        if not user or not secrets.compare_digest(digest, user.digest):
            raise DomainError("Invalid username or password", 401)
        return user

    def refresh(self, username: str) -> None:
        """Directory providers override to validate current authority."""

    def roles(self, user: User) -> list[Role]:
        if user.directory_roles is not None:
            return list(user.directory_roles)
        return (
            ["superadmin"] if user.actor.role == "superadmin" else [GROUPS[g] for g in user.groups]
        )

    def audit(self, actor: Actor, action: str, target: str) -> None:
        self.store.record_identity_event(actor, action, target)

    def local(self, request: Request) -> None:
        origin = request.headers.get("origin")
        if (
            not request.client
            or request.client.host not in {"127.0.0.1", "::1"}
            or (origin and origin != f"{request.url.scheme}://{request.headers.get('host')}")
            or request.headers.get("sec-fetch-site") == "cross-site"
        ):
            raise DomainError("Local same-origin demo required", 403)

    def session(self, request: Request) -> tuple[str, Session, User]:
        self.local(request)
        sid = request.cookies.get(COOKIE, "")
        session = self.sessions.get(sid)
        if not session or session.expires <= time.monotonic():
            self.sessions.pop(sid, None)
            raise DomainError("Sign in required", 401)
        self.refresh(session.username)
        if sid not in self.sessions:
            raise DomainError("Directory access changed; sign in again", 401)
        user = self.users[session.username]
        if session.role not in self.roles(user):
            self.sessions.pop(sid, None)
            raise DomainError("Session role no longer assigned; sign in again", 401)
        if request.method not in {"GET", "HEAD", "OPTIONS"} and not secrets.compare_digest(
            request.headers.get("x-csrf-token", ""), session.csrf
        ):
            raise DomainError("Valid CSRF token required", 403)
        return sid, session, user

    def actor(self, request: Request) -> Actor:
        with self.lock:
            _, session, user = self.session(request)
            return replace(user.actor, role=session.role)

    async def async_actor(self, request: Request) -> Actor:
        return self.actor(request)

    async def async_socket_actor(self, socket: WebSocket, csrf: str) -> Actor:
        return self.socket_actor(socket, csrf)

    def socket_actor(self, socket: WebSocket, csrf: str) -> Actor:
        scheme = "https" if socket.url.scheme == "wss" else "http"
        origin = socket.headers.get("origin")
        if origin != f"{scheme}://{socket.headers.get('host')}":
            raise DomainError("Same-origin browser session required", 403)
        headers = [(k, v) for k, v in socket.scope["headers"] if k != b"x-csrf-token"]
        headers.append((b"x-csrf-token", csrf.encode("ascii", errors="ignore")))
        scope = {
            **socket.scope,
            "type": "http",
            "method": "POST",
            "scheme": scheme,
            "headers": headers,
        }
        return self.actor(Request(scope))

    def payload(self, session: Session, user: User) -> dict[str, Any]:
        return {
            "id": user.actor.id,
            "tenant_ids": sorted(user.actor.tenant_ids),
            "role": session.role,
            "roles": self.roles(user),
            "csrf_token": session.csrf,
            "display_name": user.display_name,
            "email": user.email,
            "directory_managed": user.directory_roles is not None,
        }

    def admin(self, request: Request) -> Actor:
        actor = self.actor(request)
        if actor.role != "superadmin":
            raise DomainError("Superadmin role required", 403)
        return actor

    def group_catalog(self) -> list[dict[str, str]]:
        return [{"id": group, "role": role} for group, role in GROUPS.items()]

    def validate_groups(self, groups: list[str]) -> list[str]:
        if any(g not in GROUPS for g in groups) or len(groups) != len(set(groups)):
            raise DomainError("Choose distinct existing operational groups")
        return groups.copy()

    def install(self, app: FastAPI) -> None:
        @app.post("/auth/login")
        def login(body: Login, request: Request) -> JSONResponse:
            self.local(request)
            with self.lock:
                # Global local-demo limit prevents username-spraying memory growth.
                now = time.monotonic()
                attempts = [t for t in self.failures.get("local", []) if now - t < 60]
                if len(attempts) >= 10:
                    raise DomainError("Too many failed attempts; wait one minute", 429)
                try:
                    user = self.authenticate(body.username, body.password)
                except DomainError:
                    self.failures["local"] = [*attempts, now]
                    raise
                self.sessions.pop(request.cookies.get(COOKIE, ""), None)
                self.sessions = {k: v for k, v in self.sessions.items() if v.expires > now}
                if len(self.sessions) >= 100:
                    raise DomainError("Demo session limit reached", 429)
                session = Session(
                    user.actor.id, self.roles(user)[0], secrets.token_urlsafe(32), now + 3600
                )
                sid = secrets.token_urlsafe(32)
                self.sessions[sid] = session
                self.audit(replace(user.actor, role=session.role), "auth.login", body.username)
                response = JSONResponse(
                    self.payload(session, user), headers={"Cache-Control": "no-store"}
                )
                response.set_cookie(
                    COOKIE,
                    sid,
                    httponly=True,
                    samesite="strict",
                    secure=False,
                    max_age=3600,
                    path="/",
                )
                return response

        @app.get("/auth/me")
        def me(request: Request) -> JSONResponse:
            with self.lock:
                _, session, user = self.session(request)
                return JSONResponse(
                    self.payload(session, user), headers={"Cache-Control": "no-store"}
                )

        @app.post("/auth/role")
        def select(body: SelectRole, request: Request) -> JSONResponse:
            with self.lock:
                _, session, user = self.session(request)
                permitted = self.roles(user)
                if body.role not in permitted:
                    raise DomainError("Role is not assigned to this user", 403)
                selected = next(role for role in permitted if role == body.role)
                session.role = selected
                self.audit(replace(user.actor, role=selected), "auth.role_changed", selected)
                return JSONResponse(
                    self.payload(session, user), headers={"Cache-Control": "no-store"}
                )

        @app.post("/auth/logout")
        def logout(request: Request) -> JSONResponse:
            with self.lock:
                sid, session, user = self.session(request)
                self.audit(replace(user.actor, role=session.role), "auth.logout", user.actor.id)
                del self.sessions[sid]
                response = JSONResponse({"ok": True})
                response.delete_cookie(COOKIE, path="/")
                return response

        @app.get("/v1/users")
        def users(request: Request) -> Any:
            with self.lock:
                actor = self.admin(request)
                return [
                    {
                        "id": u.actor.id,
                        "groups": u.groups,
                        "roles": self.roles(u),
                        "protected": u.actor.role == "superadmin" or u.directory_roles is not None,
                        "display_name": u.display_name,
                        "email": u.email,
                        "directory_managed": u.directory_roles is not None,
                    }
                    for u in self.users.values()
                    if u.actor.org_id == actor.org_id and u.actor.tenant_ids <= actor.tenant_ids
                ]

        @app.get("/v1/groups")
        def groups(request: Request) -> Any:
            self.admin(request)
            return self.group_catalog()

        @app.post("/v1/users", status_code=201)
        def create(body: NewUser, request: Request) -> Any:
            with self.lock:
                actor = self.admin(request)
                groups = self.validate_groups(body.groups)
                if body.username in self.users:
                    raise DomainError("Username unavailable", 409)
                if len(self.users) >= 100:
                    raise DomainError("Demo user limit reached", 409)
                password, salt = secrets.token_urlsafe(18), secrets.token_bytes(16)
                self.users[body.username] = User(
                    Actor(body.username, actor.org_id, actor.tenant_ids, GROUPS[groups[0]]),
                    groups,
                    salt,
                    self.hash(password, salt),
                )
                self.audit(actor, "identity.user_created", body.username + ":" + ",".join(groups))
                return {"id": body.username, "groups": groups, "demo_password": password}

        @app.put("/v1/users/{username}/groups")
        def membership(username: str, body: Membership, request: Request) -> Any:
            with self.lock:
                actor = self.admin(request)
                user = self.users.get(username)
                if (
                    not user
                    or user.actor.org_id != actor.org_id
                    or not user.actor.tenant_ids <= actor.tenant_ids
                ):
                    raise DomainError("User not found", 404)
                if (
                    username == actor.id
                    or user.actor.role == "superadmin"
                    or user.directory_roles is not None
                ):
                    raise DomainError("Protected superadmin membership cannot be changed", 403)
                user.groups = self.validate_groups(body.groups)
                self.sessions = {k: v for k, v in self.sessions.items() if v.username != username}
                self.audit(actor, "identity.groups_changed", username + ":" + ",".join(user.groups))
                return {"id": username, "groups": user.groups}
