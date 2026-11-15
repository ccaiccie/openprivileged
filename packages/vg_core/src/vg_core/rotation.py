"""Single-process rotation reference with optional durable encrypted state.

Only trusted backend code may construct this service or call ``connect``. No API
routes expose it. Never serialize this service outside its trusted StateStore.
Real target adapters are injected by explicitly configured trusted backends.
"""

import json
import secrets
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from threading import Event, RLock, Thread
from typing import Protocol

from vg_core.domain import Actor, DomainError

ROTATION_INTERVAL = timedelta(hours=4)


@dataclass(frozen=True)
class AccountBinding:
    id: str
    org_id: str
    tenant_id: str
    technician_id: str
    privileged_username: str
    authority_id: str
    device_ids: frozenset[str]

    def __post_init__(self) -> None:
        if not all(
            (
                self.id,
                self.org_id,
                self.tenant_id,
                self.technician_id,
                self.privileged_username,
                self.authority_id,
                self.device_ids,
            )
        ):
            raise ValueError("Binding fields must be nonempty")
        if self.technician_id.casefold() == self.privileged_username.casefold():
            raise ValueError("Regular and privileged accounts must be distinct")


@dataclass(frozen=True)
class RotationStatus:
    account_id: str
    state: str
    generation: int
    due_at: datetime


class TargetAdapter(Protocol):
    """Trusted adapter: scope to one password authority, pin TLS/SSH, bound timeouts.

    ``verify`` must authenticate without changing state. AD rotation occurs once
    at its authority, not independently on every domain-joined device.
    """

    def change(self, binding: AccountBinding, password: str) -> None: ...

    def verify(self, binding: AccountBinding, password: str) -> bool: ...


class _Record:
    def __init__(self, binding: AccountBinding, password: str, now: datetime):
        self.binding = binding
        self.current = password
        self.pending: str | None = None
        self.state = "ready"
        self.generation = 1
        self.due_at = now + ROTATION_INTERVAL


class StateStore(Protocol):
    """Exclusive trusted persistence; implementations must encrypt and durably commit."""

    def load(self) -> bytes | None: ...

    def save(self, data: bytes) -> None: ...


class RotationService:
    """Local prototype with optional durable state; use synthetic passwords ONLY.

    No timers start automatically: an opt-in worker invokes ``rotate_due``. Overdue,
    uncertain and rotating accounts cannot start sessions. ``recover`` requires
    an explicit operator call, preventing automatic repeated authentication.
    """

    def __init__(
        self,
        adapter: TargetAdapter,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        store: StateStore | None = None,
    ):
        self._adapter = adapter
        self._clock = clock
        self._records: dict[str, _Record] = {}
        self._lock = RLock()
        self._store = store
        self._storage_failed = False
        self._suspended = Event()
        if store is not None:
            try:
                data = store.load()
                if data is not None:
                    payload = json.loads(data)
                    if payload["version"] != 1:
                        raise ValueError("Unsupported state version")
                    for row in payload["records"]:
                        binding = AccountBinding(
                            **{
                                **row["binding"],
                                "device_ids": frozenset(row["binding"]["device_ids"]),
                            }
                        )
                        record = _Record(binding, row["current"], self._now())
                        record.pending = row["pending"]
                        record.state = row["state"]
                        record.generation = row["generation"]
                        record.due_at = datetime.fromisoformat(row["due_at"])
                        if (
                            record.state not in {"ready", "recovery_required"}
                            or (record.state == "ready") != (record.pending is None)
                            or record.due_at.tzinfo is None
                            or not isinstance(record.current, str)
                            or not record.current
                            or record.generation < 1
                            or binding.id in self._records
                        ):
                            raise ValueError("Invalid persisted state")
                        self._records[binding.id] = record
            except Exception:
                raise DomainError("Rotation storage unavailable", 503) from None

    def _persist(self) -> None:
        if self._storage_failed:
            raise DomainError("Rotation storage unavailable", 503)
        if self._store is None:
            return
        try:
            rows = []
            for record in self._records.values():
                binding = asdict(record.binding)
                binding["device_ids"] = sorted(record.binding.device_ids)
                rows.append(
                    {
                        "binding": binding,
                        "current": record.current,
                        "pending": record.pending,
                        "state": record.state,
                        "generation": record.generation,
                        "due_at": record.due_at.isoformat(),
                    }
                )
            self._store.save(json.dumps({"version": 1, "records": rows}).encode())
        except Exception:
            # Even an uncertain local fsync poisons this instance. Reopen/reconcile
            # from durable state before further connections or target mutations.
            self._storage_failed = True
            raise DomainError("Rotation storage unavailable", 503) from None

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("Clock must be timezone-aware")
        return now

    def enroll(self, binding: AccountBinding, password: str) -> RotationStatus:
        """Trusted setup only; initial secret must already authenticate."""
        with self._lock:
            if self._storage_failed:
                raise DomainError("Rotation storage unavailable", 503)
            if self._suspended.is_set():
                raise DomainError("Rotation configuration suspended", 503)
            if not password or binding.id in self._records:
                raise ValueError("Invalid or duplicate enrollment")
            for record in self._records.values():
                other = record.binding
                # Authority IDs identify actual authorities globally, not tenant aliases.
                if (other.authority_id.casefold(), other.privileged_username.casefold()) == (
                    binding.authority_id.casefold(),
                    binding.privileged_username.casefold(),
                ):
                    raise ValueError("Privileged account already assigned")
                if (other.org_id, other.tenant_id, other.technician_id) == (
                    binding.org_id,
                    binding.tenant_id,
                    binding.technician_id,
                ) and other.device_ids & binding.device_ids:
                    raise ValueError("Ambiguous technician-device mapping")
            try:
                valid = self._adapter.verify(binding, password)
            except Exception:
                valid = False
            if not valid or self._suspended.is_set():
                raise DomainError("Initial credential could not be verified", 503)
            self._records[binding.id] = _Record(binding, password, self._now())
            self._persist()
            return self.status(binding.id)

    def suspend(self) -> None:
        """Fail closed after directory changes; deliberately no lock inversion.

        Already-started target operations may finish, but new sessions/rotation
        cannot start. Only a new explicitly configured runtime can resume.
        """
        self._suspended.set()

    def status(self, account_id: str) -> RotationStatus:
        with self._lock:
            record = self._records[account_id]
            state = "storage_failed" if self._storage_failed else record.state
            if self._suspended.is_set():
                state = "suspended"
            if state == "ready" and self._now() >= record.due_at:
                state = "overdue"
            return RotationStatus(account_id, state, record.generation, record.due_at)

    def rotate_due(self) -> tuple[RotationStatus, ...]:
        with self._lock:
            if self._storage_failed:
                raise DomainError("Rotation storage unavailable", 503)
            if self._suspended.is_set():
                return tuple(self.status(key) for key in self._records)
            for record in self._records.values():
                if self._suspended.is_set():
                    break
                if record.state != "ready" or self._now() < record.due_at:
                    continue
                # Retain pending before target mutation; durable mode commits the
                # encrypted snapshot before invoking the adapter.
                record.pending = secrets.token_urlsafe(32) + "Aa1!"
                record.state = "recovery_required"
                self._persist()  # Must commit BEFORE any remote mutation.
                try:
                    if self._suspended.is_set():
                        break
                    self._adapter.change(record.binding, record.pending)
                    if self._adapter.verify(record.binding, record.pending):
                        self._promote(record)
                except Exception:
                    # Never propagate arbitrary adapter exceptions (may contain secrets).
                    # Keep both versions: a timeout does NOT mean change failed.
                    pass
            return tuple(self.status(key) for key in self._records)

    def _promote(self, record: _Record) -> None:
        assert record.pending is not None
        now = self._now()
        record.current = record.pending
        record.pending = None
        record.generation += 1
        record.due_at = now + ROTATION_INTERVAL
        record.state = "ready"
        self._persist()

    def recover(self, account_id: str) -> RotationStatus:
        """Reconcile pending first. Never silently generate a second new password."""
        with self._lock:
            if self._storage_failed:
                raise DomainError("Rotation storage unavailable", 503)
            record = self._records[account_id]
            if self._suspended.is_set():
                return self.status(account_id)
            if record.state != "recovery_required" or record.pending is None:
                return self.status(account_id)
            if self._store is not None:
                try:
                    if self._store.load() is None:
                        raise ValueError("Missing state")
                except Exception:
                    self._storage_failed = True
                    raise DomainError("Rotation storage unavailable", 503) from None
            try:
                if self._adapter.verify(record.binding, record.pending):
                    self._promote(record)
                elif self._adapter.verify(record.binding, record.current):
                    if self._suspended.is_set():
                        return self.status(account_id)
                    self._adapter.change(record.binding, record.pending)
                    if self._adapter.verify(record.binding, record.pending):
                        self._promote(record)
            except Exception:
                pass
            return self.status(account_id)

    def connect(
        self,
        actor: Actor,
        device_id: str,
        authorize: Callable[[], None],
        inject: Callable[[str, str], None],
    ) -> None:
        """Trusted broker callback only, never a password-returning/reveal API.

        ``authorize`` must revalidate the live grant/session for this actor/device.
        ``inject`` opens a backend connection, not a client-side command. Both are
        trusted server closures, never user-supplied callbacks or request values.
        """
        with self._lock:
            actor.require_device(device_id)
            matches = [
                r
                for r in self._records.values()
                if r.binding.org_id == actor.org_id
                and r.binding.tenant_id in actor.tenant_ids
                and r.binding.technician_id == actor.id
                and device_id in r.binding.device_ids
            ]
            if actor.role != "technician" or len(matches) != 1:
                raise DomainError("Resource not found", 404)
            record = matches[0]
            authorize()
            if self._store is not None:
                try:
                    if self._store.load() is None:
                        raise ValueError("Missing state")
                except Exception:
                    self._storage_failed = True
            if self.status(record.binding.id).state != "ready":
                raise DomainError("Privileged credential unavailable", 503)
            try:
                validate = getattr(self._adapter, "validate_connect", None)
                if validate is not None and validate(record.binding, record.current) is not True:
                    raise DomainError("Managed identity unavailable", 503)
                # Settings may have changed while directory verification ran.
                if self._suspended.is_set():
                    raise DomainError("Rotation configuration suspended", 503)
                inject(record.binding.privileged_username, record.current)
            except Exception:
                raise DomainError("Backend connection failed", 502) from None


class RotationWorker:
    """Opt-in in-process polling worker; never installs an OS task.

    Start only with an exclusive durable store and bounded target adapters.
    Recovery-required accounts stay quarantined for operator reconciliation.
    """

    def __init__(self, service: RotationService, interval_seconds: float = 30):
        if not 0 < interval_seconds <= 60:
            raise ValueError("Polling interval must be between zero and 60 seconds")
        if service._store is None:
            raise ValueError("Worker requires durable storage")
        self._service = service
        self._interval = interval_seconds
        self._stop = Event()
        self._thread: Thread | None = None
        self._lock = RLock()
        self.failed = False
        self._cycles = 0
        self._last_cycle: float | None = None

    def health(self) -> dict[str, bool | int | float | None]:
        """Secret-free polling liveness, separate from account readiness."""
        with self._lock:
            alive = self._thread is not None and self._thread.is_alive()
            age = (
                None if self._last_cycle is None else max(0.0, time.monotonic() - self._last_cycle)
            )
            return {
                "alive": alive,
                "cycles": self._cycles,
                "last_cycle_age_seconds": None if age is None else round(age, 3),
                "poll_interval_seconds": self._interval,
                "healthy": (
                    alive
                    and not self._stop.is_set()
                    and not self.failed
                    and age is not None
                    and age <= self._interval + 90
                ),
            }

    def start(self) -> None:
        with self._lock:
            if self._thread is not None:
                raise RuntimeError("Worker already started")
            self._thread = Thread(target=self._run, name="credential-rotation", daemon=True)
            self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                statuses = self._service.rotate_due()
                failed = any(s.state != "ready" for s in statuses)
            except Exception:
                failed = True
            with self._lock:
                self.failed = failed
                self._cycles += 1
                self._last_cycle = time.monotonic()
            if self._stop.wait(self._interval):
                return

    def stop(self, timeout: float = 5) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
            if self._thread.is_alive():
                raise RuntimeError("Rotation worker still stopping")
