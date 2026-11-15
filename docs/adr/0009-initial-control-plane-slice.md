# ADR 0009: Implement an isolated control-plane slice first

Date: 2026-11-12. Status: initial implementation decision.

The owner requested starting code from the existing OpenPrivileged plans. Begin with the
request/approval/grant domain and API, rather than device mutation or a pretend credential
vault. This makes tenant boundaries, separation of duties, time limits and transitions
executable before coupling them to real privilege.

Use dependency-free immutable Python domain records and a serialized in-memory repository
for the first runnable example. FastAPI supplies strict request validation and OpenAPI.
Scopes come from trusted identity mappings, never caller-provided tenant/role headers.
The demo launcher binds localhost only, requires explicit `--demo`, seeds fictional devices
and generates ephemeral opaque tokens. No secrets are stored and no outbound device calls occur.

Consequences: not W1 complete (OIDC/Postgres/RLS absent), not W3 complete (durable scheduler
absent), and not production-ready. Grant activation is explicitly simulated. A subsequent
transactional repository must atomically persist transitions, approvals and audit entries;
it must also re-evaluate policy and identity revocation before broker authorization. The
in-process lock is not a distributed concurrency control mechanism. Keep API and domain tests
when adding those adapters, and add real Postgres cross-tenant and concurrency tests.
