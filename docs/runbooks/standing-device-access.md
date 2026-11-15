# Assigned technician device access

Technicians open the Devices view immediately after login. Devices marked `direct`
are explicitly assigned through the operator inventory or current AD device-group
mapping. Their Connect button creates or reuses an active standing grant and opens
the configured SSH, RDP, or VNC transport. No duration or approval request is needed.

Standing grants have `expires_at: null`; this is not a large artificial timeout.
Time-bounded direct grants remain compatible with clients supplying `minutes`.
Approval-required devices still require the original reason, ticket, duration and
independent approval. An absent assignment is never inferred from a visible button.

Every transport continues to validate current identity, role, customer/device
scope, grant ownership and revocation. Logout, role changes and revoked grants
still close active sessions through the existing transport checks. Revoking a grant
ends that grant; to withdraw continuing access, remove the underlying device
assignment. A technician still assigned to a device can establish a new grant.
Password rotation remains independent of access-grant duration.

Standing grants are held in the prototype's in-memory control plane and do not
survive restart. Device assignments are loaded from operator configuration; a new
Connect recreates a grant only after authorization succeeds. This change does not
add an idle timeout, persistence for authorization/audit, or production session
recording. An unconfigured transport is shown honestly and cannot connect.

Validation: unit/API tests cover no-expiry access, repeated-click reuse, revoke,
withdrawn assignment, scope/role/ownership checks, bounded SSH probes and unchanged
approval workflow. `tests/integration/browser_direct_smoke.py` checks the default
Devices view, no duration dialog, repeated Connect, unconfigured transport,
revocation, approval-dialog cancellation and narrow-screen layout using only a
synthetic local server.
