# Troubleshooting

[Documentation home](README.md) · [Operations](OPERATIONS.md) · [AD integration](AD-INTEGRATION.md)

Start with the exact command, runtime mode, code revision, HTTP status and sanitized
error. Do not include credentials, runtime files or vault contents in public reports.
Use synthetic reproduction wherever possible. Never fix a denial by widening domain
permissions, removing a GUID check, disabling TLS, or disabling a certificate pin.

| Symptom | Check and safe next step |
| --- | --- |
| Local login fails after restart | Demo credentials are generated per launch. Use the current local launch output privately; old passwords are not a permanent default. |
| Demo password fails in directory mode | AD mode disables demo fallback. Sign in with the mapped normal AD identity and verify directory reachability. |
| “Directory unavailable” / access cannot be verified | Check DNS, DC availability, service network path, trusted CA path inside the container, certificate hostname/validity and reader access. No cached authorization fallback is expected. |
| Valid AD user has no access | Verify enabled identity and explicit security-group membership under the configured bases; primary group is not used. Check nested-group setting and assigned roles. |
| Can't see Setup AD / permission denied | Select an assigned superadmin role. Operational admin is not superadmin. |
| Load domain groups fails | Verify read/search access and group base. Failed/partial searches, paging-control faults and safety limits reject the entire catalog; narrow the base. Do not raise domain-wide limits as a first response. |
| Save unavailable | Configure a separate encrypted directory-settings store. A successful connection test alone does not make settings editable. |
| Save would remove access | Preserve current immutable identity's superadmin mapping and test another recovery identity. Don't remove the lockout check. |
| Signed out after save/group change | Expected session invalidation. Sign in again. Managed rotation additionally needs a controlled restart after a settings save. |
| Devices missing / “Resource not found” | Check organization/customer and device assignment. Cross-scope resources are intentionally concealed. |
| Request rejected | Check selected role, device scope, required reason/ticket, duration and current policy. |
| Cannot approve own request | Independent identity required; changing roles is not independent review. |
| Direct access immediately reappears after revocation | Revoke ends one grant. Remove the standing device assignment to withdraw continuing access. |
| Device lists but Connect is unavailable | A catalog entry is not a configured transport. Verify the approved inventory and protocol target; default demo does not connect to real equipment. |
| SSH/RDP/VNC fails | Check approved target, network, host/certificate pin, target account privileges and gateway dependency. Do not use insecure host-key or TLS bypasses. |
| Staged `a.*` account cannot log in | Creation deliberately produces a disabled, unenrolled account with no equipment groups. Follow reviewed activation and enrollment steps; do not distribute its password. |
| Provisioning preview rejects username | `a.` plus regular name must satisfy the naming helper (18-character regular-name limit). No truncation or double prefix. Renaming requires deliberate identity migration. |
| Creation collision or pending journal | Another security principal can hold the name anywhere in the domain; uncertain writes may already have created a user. Reconcile GUID and intent, never delete/recreate automatically. |
| Rotation state says recovery/storage/suspended | Use the state-specific response in [Operations](OPERATIONS.md). Health checks are safe; recovery/reset are not read-only. |
| Runner reports `runner_failed` during live service | The live owner holds the exclusive lock. Use HTTP health, not a competing runner. After shutdown, verify private-file ownership, key, exact scope and paths without printing secrets. |
| Restart rejects generalized account binding | Persisted GUID/DN/name/domain/OU and exact allowlist must match. A recreated same-name AD user is a different principal. Reconcile and explicitly re-enroll; do not remove identity metadata. |
| Audit/history disappeared | The control plane is in memory. Rotation persistence does not provide durable request/grant/audit storage. |

## Distinguish failures before acting

- HTTP 401 usually requires a fresh sign-in or current identity verification.
- HTTP 403 is an authorization denial; adding broad AD permissions is not a fix.
- HTTP 404 can deliberately hide an out-of-scope resource.
- HTTP 409 can indicate a conflicting/already-decided state; refresh before retrying.
- HTTP 503 can indicate a failed dependency, unconfigured encrypted storage or
  fail-closed suspension. Inspect sanitized status rather than repeatedly submitting.

Detailed errors are deliberately suppressed around credential-handling code because
raw library exceptions can contain secrets. A generic failure is not proof that a
remote mutation did not occur. Preserve state and investigate with the domain owner.

## Minimal useful bug report

Include code revision, OS/Python/runtime mode, synthetic steps to reproduce,
expected versus actual result, sanitized HTTP status/error and relevant test result.
State whether the problem occurs in the local demo or only in a separately configured
lab. Replace internal hostnames, DNs and GUIDs consistently with placeholders. Use
private vulnerability reporting for security-sensitive findings; see [SECURITY](../SECURITY.md).
