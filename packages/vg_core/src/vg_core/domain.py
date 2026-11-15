"""In-memory authorization reference. Transports must separately enforce active grants."""

import json
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import RLock
from typing import Literal
from uuid import uuid4

Role = Literal["admin", "approver", "technician", "auditor", "superadmin"]


class DomainError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Actor:
    id: str
    org_id: str
    tenant_ids: frozenset[str]
    role: Role
    device_ids: frozenset[str] | None = None

    def require_device(self, device_id: str) -> None:
        if self.device_ids is not None and device_id not in self.device_ids:
            raise DomainError("Resource not found", 404)

    def require(self, org_id: str, tenant_id: str, roles: set[str]) -> None:
        if self.org_id != org_id or tenant_id not in self.tenant_ids:
            raise DomainError("Resource not found", 404)
        if self.role not in roles:
            raise DomainError("Role is not permitted", 403)


@dataclass(frozen=True)
class Device:
    id: str
    org_id: str
    tenant_id: str
    hostname: str
    platform: str
    access_mode: Literal["approval", "direct"] = "approval"
    protocol: Literal["ssh", "rdp", "vnc"] = "ssh"

    def __post_init__(self) -> None:
        if self.access_mode not in {"approval", "direct"}:
            raise ValueError("Invalid device access mode")
        if self.protocol not in {"ssh", "rdp", "vnc"}:
            raise ValueError("Invalid device protocol")


@dataclass(frozen=True)
class Policy:
    max_minutes: int = 60
    approvals_required: int = 1
    require_ticket: bool = True

    def __post_init__(self) -> None:
        if not 1 <= self.max_minutes <= 480 or not 1 <= self.approvals_required <= 5:
            raise ValueError("Invalid policy limits")


@dataclass(frozen=True)
class AccessRequest:
    id: str
    org_id: str
    tenant_id: str
    device_id: str
    requester_id: str
    reason: str
    ticket_ref: str
    minutes: int
    approvals_required: int
    approvers: tuple[str, ...] = ()
    status: str = "pending"


@dataclass(frozen=True)
class Grant:
    id: str
    request_id: str
    org_id: str
    tenant_id: str
    device_id: str
    requester_id: str
    starts_at: datetime
    expires_at: datetime | None
    status: str = "active"
    reason: str = ""


@dataclass(frozen=True)
class AuditEvent:
    seq: int
    org_id: str
    tenant_id: str
    ts: str
    actor_id: str
    action: str
    target: str
    prev_hash: str
    hash: str


def event_hash(event: AuditEvent) -> str:
    data = asdict(event)
    data.pop("hash")
    return sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify_chain(events: tuple[AuditEvent, ...]) -> bool:
    previous = "0" * 64
    scope = (events[0].org_id, events[0].tenant_id) if events else None
    for seq, event in enumerate(events, 1):
        if (
            (event.org_id, event.tenant_id) != scope
            or event.seq != seq
            or event.prev_hash != previous
            or event.hash != event_hash(event)
        ):
            return False
        previous = event.hash
    return True


class ControlPlane:
    """Serialized transitions; callers receive immutable snapshots, not mutable storage."""

    def __init__(
        self,
        devices: tuple[Device, ...],
        policies: dict[tuple[str, str], Policy],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        *,
        direct_entitlements: frozenset[tuple[str, str]] = frozenset(),
    ):
        self._devices = {d.id: d for d in devices}
        self._direct_entitlements = frozenset(direct_entitlements)
        self._policies = policies.copy()
        self._requests: dict[str, AccessRequest] = {}
        self._grants: dict[str, Grant] = {}
        self._events: dict[tuple[str, str], list[AuditEvent]] = {}
        self._clock = clock
        self._lock = RLock()

    def _audit(self, org: str, tenant: str, actor: str, action: str, target: str) -> None:
        events = self._events.setdefault((org, tenant), [])
        event = AuditEvent(
            len(events) + 1,
            org,
            tenant,
            self._clock().isoformat(),
            actor,
            action,
            target,
            events[-1].hash if events else "0" * 64,
            "",
        )
        events.append(replace(event, hash=event_hash(event)))

    def record_identity_event(self, actor: Actor, action: str, target: str) -> None:
        with self._lock:
            for tenant in sorted(actor.tenant_ids):
                self._audit(actor.org_id, tenant, actor.id, action, target)

    def devices(self, actor: Actor) -> tuple[Device, ...]:
        return tuple(
            d
            for d in self._devices.values()
            if d.org_id == actor.org_id
            and d.tenant_id in actor.tenant_ids
            and (actor.device_ids is None or d.id in actor.device_ids)
        )

    def request(
        self, actor: Actor, device_id: str, reason: str, ticket: str, minutes: int
    ) -> AccessRequest:
        with self._lock:
            device = self._devices.get(device_id)
            if device is None:
                raise DomainError("Resource not found", 404)
            actor.require_device(device.id)
            actor.require(device.org_id, device.tenant_id, {"technician", "admin"})
            policy = self._policies.get((device.org_id, device.tenant_id))
            if policy is None:
                raise DomainError("No access policy configured", 403)
            if not reason.strip() or len(reason) > 1000 or len(ticket) > 100:
                raise DomainError("Reason required; reason/ticket length limit exceeded")
            if type(minutes) is not int or not 1 <= minutes <= policy.max_minutes:
                raise DomainError("Duration exceeds policy limits")
            if policy.require_ticket and not ticket.strip():
                raise DomainError("Ticket reference required")
            request = AccessRequest(
                str(uuid4()),
                device.org_id,
                device.tenant_id,
                device.id,
                actor.id,
                reason.strip(),
                ticket.strip(),
                minutes,
                policy.approvals_required,
            )
            self._requests[request.id] = request
            self._audit(request.org_id, request.tenant_id, actor.id, "request.created", request.id)
            return request

    def direct_grant(
        self, actor: Actor, device_id: str, reason: str, minutes: int | None = None
    ) -> Grant:
        """Issue only a scoped, explicitly entitled grant; never connects a device."""
        with self._lock:
            device = self._devices.get(device_id)
            if device is None:
                raise DomainError("Resource not found", 404)
            actor.require_device(device.id)
            actor.require(device.org_id, device.tenant_id, {"technician", "admin"})
            if device.access_mode != "direct" or (
                (
                    actor.device_ids is None
                    and (actor.id, device.id) not in self._direct_entitlements
                )
                or (actor.device_ids is not None and device.id not in actor.device_ids)
            ):
                raise DomainError("Direct access is not entitled", 403)
            policy = self._policies.get((device.org_id, device.tenant_id))
            if policy is None:
                raise DomainError("No access policy configured", 403)
            if not reason.strip() or len(reason) > 1000:
                raise DomainError("Reason required; maximum 1000 characters")
            if minutes is not None and (
                type(minutes) is not int or not 1 <= minutes <= policy.max_minutes
            ):
                raise DomainError("Duration exceeds policy limits")
            # Standing entitlement is rechecked on every connection. Repeated clicks
            # reuse only the caller's active standing grant, never a revoked one.
            if minutes is None:
                for existing in self._grants.values():
                    if (
                        existing.requester_id == actor.id
                        and existing.device_id == device.id
                        and existing.org_id == device.org_id
                        and existing.tenant_id == device.tenant_id
                        and not existing.request_id
                        and existing.expires_at is None
                        and existing.status == "active"
                    ):
                        return existing
            now = self._clock()
            grant = Grant(
                str(uuid4()),
                "",
                device.org_id,
                device.tenant_id,
                device.id,
                actor.id,
                now,
                now + timedelta(minutes=minutes) if minutes is not None else None,
                reason=reason.strip(),
            )
            self._grants[grant.id] = grant
            self._audit(
                device.org_id, device.tenant_id, actor.id, "grant.direct_activated", grant.id
            )
            return grant

    def authorize_connection(self, actor: Actor, grant_id: str, *, audit: bool = True) -> Device:
        """Re-check every connection attempt; this is authorization, not an SSH broker."""
        with self._lock:
            self.expire()
            grant = self._grants.get(grant_id)
            if grant is None:
                raise DomainError("Resource not found", 404)
            actor.require_device(grant.device_id)
            actor.require(grant.org_id, grant.tenant_id, {"technician", "admin"})
            if grant.requester_id != actor.id:
                raise DomainError("Resource not found", 404)
            if grant.status != "active":
                raise DomainError("Grant is not active", 403)
            device = self._devices.get(grant.device_id)
            if device is None:
                raise DomainError("Resource not found", 404)
            actor.require_device(device.id)
            actor.require(device.org_id, device.tenant_id, {"technician", "admin"})
            if device.org_id != grant.org_id or device.tenant_id != grant.tenant_id:
                raise DomainError("Resource not found", 404)
            if not grant.request_id and (
                device.access_mode != "direct"
                or (
                    (
                        actor.device_ids is None
                        and (actor.id, device.id) not in self._direct_entitlements
                    )
                    or (actor.device_ids is not None and device.id not in actor.device_ids)
                )
            ):
                raise DomainError("Direct access is not entitled", 403)
            if audit:
                self._audit(
                    device.org_id, device.tenant_id, actor.id, "connection.authorized", grant.id
                )
            return device

    def requests(self, actor: Actor) -> tuple[AccessRequest, ...]:
        with self._lock:
            return tuple(
                r
                for r in self._requests.values()
                if r.org_id == actor.org_id
                and r.tenant_id in actor.tenant_ids
                and (actor.device_ids is None or r.device_id in actor.device_ids)
                and (actor.role != "technician" or r.requester_id == actor.id)
            )

    def decide(self, actor: Actor, request_id: str, approve: bool) -> AccessRequest:
        with self._lock:
            request = self._requests.get(request_id)
            if request is None:
                raise DomainError("Resource not found", 404)
            actor.require_device(request.device_id)
            actor.require(request.org_id, request.tenant_id, {"admin", "approver"})
            if actor.id == request.requester_id:
                raise DomainError("Self-approval or denial is not permitted", 403)
            if request.status != "pending" or actor.id in request.approvers:
                raise DomainError("Request already decided or reviewer already voted", 409)
            approvers = (*request.approvers, actor.id) if approve else request.approvers
            status = "approved" if len(approvers) >= request.approvals_required else "pending"
            request = replace(request, approvers=approvers, status=status if approve else "denied")
            self._requests[request.id] = request
            self._audit(
                request.org_id,
                request.tenant_id,
                actor.id,
                "request.approval_recorded" if approve else "request.denied",
                request.id,
            )
            if request.status == "approved":
                now = self._clock()
                grant = Grant(
                    str(uuid4()),
                    request.id,
                    request.org_id,
                    request.tenant_id,
                    request.device_id,
                    request.requester_id,
                    now,
                    now + timedelta(minutes=request.minutes),
                )
                self._grants[grant.id] = grant
                self._audit(grant.org_id, grant.tenant_id, actor.id, "grant.activated", grant.id)
            return request

    def expire(self) -> int:
        with self._lock:
            count = 0
            for grant in tuple(self._grants.values()):
                if (
                    grant.status == "active"
                    and grant.expires_at is not None
                    and self._clock() >= grant.expires_at
                ):
                    self._grants[grant.id] = replace(grant, status="expired")
                    self._audit(grant.org_id, grant.tenant_id, "system", "grant.expired", grant.id)
                    count += 1
            return count

    def grants(self, actor: Actor) -> tuple[Grant, ...]:
        with self._lock:
            self.expire()
            return tuple(
                g
                for g in self._grants.values()
                if g.org_id == actor.org_id
                and g.tenant_id in actor.tenant_ids
                and (actor.device_ids is None or g.device_id in actor.device_ids)
                and (actor.role != "technician" or g.requester_id == actor.id)
            )

    def revoke(self, actor: Actor, grant_id: str) -> Grant:
        with self._lock:
            self.expire()
            grant = self._grants.get(grant_id)
            if grant is None:
                raise DomainError("Resource not found", 404)
            actor.require_device(grant.device_id)
            actor.require(grant.org_id, grant.tenant_id, {"admin", "approver", "technician"})
            if actor.role == "technician" and grant.requester_id != actor.id:
                raise DomainError("Resource not found", 404)
            if grant.status != "active":
                raise DomainError("Grant is not active", 409)
            grant = replace(grant, status="revoked")
            self._grants[grant.id] = grant
            self._audit(grant.org_id, grant.tenant_id, actor.id, "grant.revoked", grant.id)
            return grant

    def audit(self, actor: Actor, tenant_id: str) -> tuple[AuditEvent, ...]:
        actor.require(actor.org_id, tenant_id, {"admin", "approver", "auditor"})
        with self._lock:
            return tuple(self._events.get((actor.org_id, tenant_id), []))
