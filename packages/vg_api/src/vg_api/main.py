"""Explicitly opted-in local demo. Production authentication is deliberately absent."""

import argparse
import secrets
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import uvicorn
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware
from vg_core.domain import Actor, ControlPlane, Device, DomainError, Policy, verify_chain
from vg_core.rotation import RotationService

from vg_api.demo_auth import DemoAuth
from vg_api.desktop_bridge import DesktopTarget, install_vnc_routes, load_desktop_target
from vg_api.directory import DirectoryConfig, DirectoryProvider, LdapsDirectory
from vg_api.directory_auth import DirectoryAuth
from vg_api.directory_management import DirectoryManagement, SettingsStore
from vg_api.directory_provisioning import DirectoryProvisioning, ProvisioningConfig
from vg_api.lab_access import SSHTarget, load_inventory, ssh_probe
from vg_api.managed_ssh import ManagedSSHTarget
from vg_api.rdp_bridge import RDPTarget, install_rdp_routes, load_rdp_target
from vg_api.ssh_sessions import install_sessions

bearer = HTTPBearer(auto_error=False)


class RequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    device_id: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=1000)
    ticket_ref: str = Field(max_length=100)
    minutes: int = Field(ge=1, le=480)


class SSHTestBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class DirectRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    device_id: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=1000)
    minutes: int | None = Field(default=None, ge=1, le=60)


def create_app(
    plane: ControlPlane | None = None,
    tokens: dict[str, Actor] | None = None,
    *,
    demo_ui: bool = False,
    demo_passwords: dict[str, str] | None = None,
    ssh_targets: dict[str, SSHTarget] | None = None,
    desktop_targets: dict[str, DesktopTarget] | None = None,
    rdp_targets: dict[str, RDPTarget] | None = None,
    directory_config: DirectoryConfig | None = None,
    directory_provider: DirectoryProvider | None = None,
    rotation_service: RotationService | None = None,
    managed_ssh_targets: dict[str, ManagedSSHTarget] | None = None,
    directory_settings_store: SettingsStore | None = None,
    directory_bind_password: str | None = None,
    directory_revision: int = 0,
    directory_provisioning_config: ProvisioningConfig | None = None,
    directory_provisioning_store: SettingsStore | None = None,
) -> FastAPI:
    app = FastAPI(title="OpenPrivileged local control-plane prototype", version="0.1.0")
    store = plane or ControlPlane((), {})
    identities = (tokens or {}).copy()
    auth = DemoAuth(store, identities, demo_passwords or {}) if demo_ui else None
    if directory_config:
        if not demo_ui:
            raise ValueError("Directory prototype requires local browser session mode")
        auth = DirectoryAuth(
            store, directory_config, directory_provider or LdapsDirectory(directory_config)
        )
    if auth:
        auth.install(app)
        if isinstance(auth, DirectoryAuth):
            DirectoryManagement(
                auth,
                directory_settings_store,
                directory_bind_password,
                directory_revision,
                on_settings_change=rotation_service.suspend if rotation_service else None,
            ).install(app)
            DirectoryProvisioning(
                auth, directory_provisioning_config, directory_provisioning_store
            ).install(app)
        install_sessions(app, store, auth, ssh_targets or {}, rotation_service, managed_ssh_targets)
        install_vnc_routes(app, store, auth, desktop_targets or {})
        install_rdp_routes(app, store, auth, rdp_targets or {}, rotation_service)
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]"])
        static = Path(__file__).parent / "static"
        app.mount("/static", StaticFiles(directory=static), name="static")

        @app.get("/admin", include_in_schema=False)
        @app.get("/technician", include_in_schema=False)
        @app.get("/approver", include_in_schema=False)
        @app.get("/auditor", include_in_schema=False)
        @app.get("/", include_in_schema=False)
        def dashboard() -> HTMLResponse:
            nonce = secrets.token_urlsafe(24)
            page = (static / "index.html").read_text().replace("__STYLE_NONCE__", nonce)
            if directory_config:
                page = page.replace(
                    "Use the username and generated demo password shown when the server starts. "
                    "Never enter a real password.",
                    "Configured test Active Directory only. Sign in with your AD username and "
                    "password over verified LDAPS.",
                ).replace("Demo password", "AD password")
            return HTMLResponse(
                page,
                headers={
                    "Cache-Control": "no-store",
                    "Content-Security-Policy": (
                        "default-src 'self'; script-src 'self'; "
                        f"style-src 'self' 'nonce-{nonce}'; img-src 'self' data: blob:; "
                        "connect-src 'self'; frame-ancestors 'none'; "
                        "base-uri 'none'; form-action 'self'"
                    ),
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                },
            )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Pydantic error inputs can contain credentials, including unknown extra fields.
        return JSONResponse(
            {
                "detail": [
                    {"loc": error["loc"], "type": error["type"], "msg": "Invalid value"}
                    for error in exc.errors()
                ]
            },
            status_code=422,
            headers={"Cache-Control": "no-store"},
        )

    @app.exception_handler(DomainError)
    async def domain_error(request: Request, exc: DomainError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=exc.status)

    def actor(
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ) -> Actor:
        if auth:
            session_actor = auth.actor(request)
            if session_actor.role == "superadmin":
                raise DomainError("Select an operational account for operational APIs", 403)
            return session_actor
        identity = identities.get(credentials.credentials) if credentials else None
        if identity is None:
            raise DomainError("Valid bearer token required", 401)
        return identity

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": "local-prototype", "storage": "ephemeral"}

    @app.get("/v1/devices")
    def devices(user: Annotated[Actor, Depends(actor)]) -> Any:
        return [
            {
                **asdict(d),
                "connection_ready": (
                    d.id in (ssh_targets or {}) or d.id in (managed_ssh_targets or {})
                ),
                "ssh_probe_ready": d.id in (ssh_targets or {}),
                "interactive_ssh": bool(auth)
                and (d.id in (ssh_targets or {}) or d.id in (managed_ssh_targets or {})),
                "desktop_ready": bool(auth) and d.id in (desktop_targets or {}),
                "rdp_ready": bool(auth) and d.id in (rdp_targets or {}),
            }
            for d in store.devices(user)
        ]

    @app.post("/v1/direct-access", status_code=201)
    def direct_access(body: DirectRequestBody, user: Annotated[Actor, Depends(actor)]) -> Any:
        return store.direct_grant(user, body.device_id, body.reason, body.minutes)

    @app.post("/v1/grants/{grant_id}/ssh-test")
    def test_ssh(
        grant_id: str, user: Annotated[Actor, Depends(actor)], body: SSHTestBody | None = None
    ) -> Any:
        device = store.authorize_connection(user, grant_id)
        if device.protocol != "ssh":
            raise DomainError("RDP/VNC transport is not implemented yet", 501)
        target = (ssh_targets or {}).get(device.id)
        if target is None:
            raise DomainError("No verified SSH lab endpoint configured for this device", 503)
        grant = next(g for g in store.grants(user) if g.id == grant_id)
        # A standing grant has no expiry, but a one-shot probe remains bounded.
        remaining = (
            (grant.expires_at - datetime.now(UTC)).total_seconds()
            if grant.expires_at is not None
            else 30.0
        )
        if remaining <= 0:
            raise DomainError("Grant expired", 403)
        result = ssh_probe(target, remaining)
        store.authorize_connection(user, grant_id)
        store.record_identity_event(user, "connection.ssh_test_succeeded", device.id)
        return result

    @app.get("/v1/access-requests")
    def requests(user: Annotated[Actor, Depends(actor)]) -> Any:
        return store.requests(user)

    @app.post("/v1/access-requests", status_code=201)
    def create_request(body: RequestBody, user: Annotated[Actor, Depends(actor)]) -> Any:
        return store.request(user, body.device_id, body.reason, body.ticket_ref, body.minutes)

    @app.post("/v1/access-requests/{request_id}/approve")
    def approve(request_id: str, user: Annotated[Actor, Depends(actor)]) -> Any:
        return store.decide(user, request_id, True)

    @app.post("/v1/access-requests/{request_id}/deny")
    def deny(request_id: str, user: Annotated[Actor, Depends(actor)]) -> Any:
        return store.decide(user, request_id, False)

    @app.get("/v1/grants")
    def grants(user: Annotated[Actor, Depends(actor)]) -> Any:
        return store.grants(user)

    @app.post("/v1/grants/{grant_id}/revoke")
    def revoke(grant_id: str, user: Annotated[Actor, Depends(actor)]) -> Any:
        return store.revoke(user, grant_id)

    @app.get("/v1/audit/{tenant_id}")
    def audit(tenant_id: str, user: Annotated[Actor, Depends(actor)]) -> Any:
        return store.audit(user, tenant_id)

    @app.get("/v1/audit/{tenant_id}/verify")
    def verify(tenant_id: str, user: Annotated[Actor, Depends(actor)]) -> dict[str, Any]:
        events = store.audit(user, tenant_id)
        return {
            "valid": verify_chain(events),
            "count": len(events),
            "head": events[-1].hash if events else None,
        }

    return app


def demo(inventory: Path | None = None) -> tuple[ControlPlane, dict[str, Actor]]:
    devices: tuple[Device, ...] = (
        Device("router-a", "demo-msp", "customer-a", "lab-router", "ios"),
        Device("linux-b", "demo-msp", "customer-b", "lab-linux", "linux"),
    )
    tokens = {
        secrets.token_urlsafe(32): Actor("admin", "demo-msp", frozenset({"customer-a"}), "admin"),
        secrets.token_urlsafe(32): Actor(
            "tech", "demo-msp", frozenset({"customer-a"}), "technician"
        ),
        secrets.token_urlsafe(32): Actor(
            "reviewer", "demo-msp", frozenset({"customer-a"}), "approver"
        ),
        secrets.token_urlsafe(32): Actor(
            "auditor", "demo-msp", frozenset({"customer-a"}), "auditor"
        ),
    }
    entitlements: frozenset[tuple[str, str]] = frozenset()
    if inventory:
        lab_devices, entitlements, _ = load_inventory(inventory)
        if any(d.id in {x.id for x in devices} for d in lab_devices):
            raise ValueError("Lab device IDs must not collide with demo devices")
        devices = (*devices, *lab_devices)
    return ControlPlane(
        devices, {("demo-msp", "customer-a"): Policy()}, direct_entitlements=entitlements
    ), tokens


def run() -> None:
    parser = argparse.ArgumentParser(
        description="Local-only OpenPrivileged prototype; optional isolated lab access"
    )
    parser.add_argument(
        "--demo", action="store_true", help="Seed fictional devices and demo identities"
    )
    parser.add_argument("--port", type=int, default=8792)
    parser.add_argument(
        "--lab-inventory", type=Path, help="Operator-owned isolated lab inventory JSON"
    )
    parser.add_argument(
        "--desktop-credentials", type=Path, help="Owner-only approved lab VNC credentials"
    )
    parser.add_argument(
        "--rdp-manifest", type=Path, help="Lab manifest with explicit RDP certificate pin"
    )
    parser.add_argument(
        "--directory-config", type=Path, help="LDAPS JSON settings; no secrets in JSON"
    )
    args = parser.parse_args()
    directory_config = (
        DirectoryConfig.model_validate_json(args.directory_config.read_text())
        if args.directory_config
        else None
    )
    if args.rdp_manifest and not args.desktop_credentials:
        parser.error("--rdp-manifest requires --desktop-credentials")
    if not args.demo:
        parser.error("Pass --demo. Production authentication and persistence are not implemented.")
    plane, tokens = demo(args.lab_inventory)
    ssh_targets = load_inventory(args.lab_inventory)[2] if args.lab_inventory else {}
    desktop_targets = (
        {"vg-ubuntu-vnc": load_desktop_target(args.desktop_credentials)}
        if args.desktop_credentials
        else {}
    )
    print("LOCAL DEMO ONLY. State is lost on exit. Do not expose via tunnel or load real secrets.")
    passwords = {a.id: secrets.token_urlsafe(18) for a in tokens.values()}
    passwords.update({name: secrets.token_urlsafe(18) for name in ("multi", "superadmin")})
    print(f"Open http://127.0.0.1:{args.port}/ and sign in. Demo-only passwords:")
    if directory_config:
        print("LDAPS mode: demo passwords are disabled; use an explicitly mapped AD account.")
        passwords = {}
    for name, password in passwords.items():
        print(f"{name} demo password: {password}", flush=True)
    uvicorn.run(
        create_app(
            plane,
            tokens,
            demo_ui=True,
            demo_passwords=passwords,
            directory_config=directory_config,
            ssh_targets=ssh_targets,
            desktop_targets=desktop_targets,
            rdp_targets={
                "vg-ubuntu-rdp": load_rdp_target(
                    args.desktop_credentials.absolute(), args.rdp_manifest.absolute()
                )
            }
            if args.rdp_manifest
            else {},
        ),
        host="127.0.0.1",
        port=args.port,
        access_log=False,
        ws_max_size=16384,
        ws_max_queue=8,
    )
