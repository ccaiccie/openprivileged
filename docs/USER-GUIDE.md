# User and role guide

[Documentation home](README.md) · [AD setup](AD-INTEGRATION.md) · [Troubleshooting](TROUBLESHOOTING.md)

Use fictional data in the local demo. For an explicitly configured isolated lab,
use your normal AD identity to sign in, not the hidden equipment account. The role
selector contains only assigned roles. Switching roles does not change your identity
and cannot bypass the independent-review requirement.

## Roles

| Selected role | Operational permissions in this prototype |
| --- | --- |
| Technician | Request access, connect using own active grants, revoke own grants; lists own requests/grants within assigned scope. |
| Admin | Request access, independently approve/deny, revoke scoped grants, and inspect audit. Connection still requires a grant owned by that identity. |
| Approver | Approve/deny others' scoped requests, revoke scoped grants, inspect audit. Does not connect as the requester. |
| Auditor | Inspect scoped audit and verify its hash chain; no approval or connection authority. |
| Superadmin | Manage application identity setup and AD configuration/provisioning workflows. Not an automatic operational admin; assign/select another role for operational work. |

Organization, customer and device restrictions apply regardless of role. Cross-scope
resources may appear as “Resource not found” rather than disclosing their existence.
AD role-group membership remains managed in AD; local demo group management is not
an AD-write feature.

## Approval-required access

1. Open **Devices**, choose an available device and request access.
2. Enter a meaningful reason, change-ticket reference and requested duration. Do not
   enter passwords or sensitive customer data in reason/ticket fields.
3. A separate admin or approver reviews the pending request and approves or denies.
   The same identity cannot approve or deny its own request, even after a role switch.
   Repeated votes from one reviewer do not count twice.
4. When the configured approval count is met, a grant activates. Its duration starts
   at activation, not when the technician opens the connection.
5. Connect while the grant remains active. A configured transport is required; a
   successful request alone does not prove network reachability or target credentials.
6. Disconnect when finished, or revoke the grant when access is no longer needed.

Policy is configured in code/runtime, not by an end-user duration setting. The demo
uses a maximum of 60 minutes and one approval; core policy supports 1–480 minutes
and 1–5 independent approvals. Denial closes the pending request. Submit a new
request if the work changes; do not reuse an expired/revoked grant.

## Assigned direct access

A device marked `direct` requires explicit assignment. **Connect** creates or reuses
an active standing grant without a duration/approval dialog. Standing grants have
`expires_at: null`; they are not short-lived access windows. API callers may request
a time-bounded direct grant where policy allows it.

Revocation ends that grant, but an assigned technician can establish a new one.
To withdraw continuing direct access, remove the underlying device entitlement as
well. Password rotation is independent of grant duration. Read
[standing device access](runbooks/standing-device-access.md) for enforcement details.

## Sessions and credentials

SSH, RDP and VNC are optional lab transports. A device with no configured transport
cannot connect. The browser does not receive the managed AD password. Generalized
managed SSH derives the equipment identity from the exact enrolled technician/device
binding; it does not use any account merely because its name begins with `a.`.

Logout, role changes, grant expiry/revocation and changed entitlements are checked
by transport authorization and close unauthorized sessions. This is not a guarantee
that detached/background jobs on the remote machine terminate. Do not treat a closed
browser tab as a remote-process cleanup mechanism.

Local browser sessions expire after one hour; a restart loses them. A new sign-in
may be required after directory configuration or role membership changes. There is
no production MFA/SSO implementation in this snapshot.

## Audit review

Use **Audit trail** and **Verify chain** from an authorized operational role. Events
cover authorization and session lifecycle. The demo does not record keystrokes,
terminal transcripts or desktop video. Chain verification checks ordering/linkage
within the current in-memory stream, not completeness or an independent trusted
record. Restart discards the control plane's requests, grants and audit events.

The [operations guide](OPERATIONS.md) distinguishes durable rotation state from
this ephemeral application state.
