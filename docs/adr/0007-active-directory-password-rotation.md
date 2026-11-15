# ADR-0007: Active Directory account vaulting and password rotation (CPM-style)

Status: Proposed

## Context
Windows estates are managed through AD service, admin and break-glass accounts, plus local administrator accounts on member servers. CyberArk's Central Policy Manager (CPM) handles these with platform policies that verify, change and reconcile passwords on a schedule, after each use, or on demand. MSP buyers expect the same, and RDP brokering (ADR-0008) is only valuable if the password it injects is vaulted and rotated.

## Decision
Add an `ad` credential family to the vault (ADR-0004) with a `vg_directory` driver package. The driver runs **inside the customer's collector** (ADR-0003), never in the cloud, so domain controllers need no inbound exposure.

**Operations (mirrors CPM):**
- **verify**: bind or Kerberos-authenticate as the account with the vaulted password; report drift.
- **change**: set a new password for the account using the vaulted *manager account* (a delegated service account, not Domain Admin).
- **reconcile**: if verify fails, use the manager account to reset the password and re-sync the vault.
- **logon / dependent accounts**: update the password wherever it is consumed (Windows services, scheduled tasks, IIS app pools) via WinRM; list of dependents is stored on the credential.

**Mechanics:**
- Protocol: LDAPS (636) for AD password set (`unicodePwd`) with the `ldap3` library (LGPL-3.0, imported as an unmodified library, to be cleared in LICENSES.md) or `msldap` (MIT, check). Kerberos via `gssapi` is only needed for GSSAPI binds. Plain LDAP is refused.
- Reset vs change: managed accounts use an administrative **reset** (needs the Reset Password right on the OU); self-service **change** (old + new password) is used when a customer refuses delegated reset rights.
- Local accounts on member servers: WinRM over HTTPS using `pypsrp` (MIT) to run `Set-LocalUser`; SMB/SAMR is a later fallback.
- Password generation: policy-driven (length, charset, exclusions) and checked against the domain's fine-grained password policy before apply.
- Two-phase rotation (RISKS.md #4): write the new secret as `pending`, apply it, verify a fresh login with it, then promote to `current`. On failure the old version stays `current` and `grant.withdraw_failed` is emitted.
- Replication: after a reset, verify against the same DC that accepted the change (pin the DC for the job) and then confirm on a second DC, to avoid false drift while AD replicates.
- Triggers: after every grant/session (one-time-use), on schedule (e.g. every 30 days), on offboarding, on manual request, and on verify failure.
- Protected accounts (krbtgt, built-in Administrator, accounts in `protected_accounts[]`) are excluded by default and need an explicit policy. krbtgt rotation is out of scope.
- Delegation guide: ship a documented least-privilege setup (a dedicated OU, a delegated manager account with only Reset Password and write `pwdLastSet`, no interactive logon).

**Identity side (separate from vaulting):** technicians still sign in with OIDC (Entra ID / ADFS / Okta). AD group membership may map to OpenPrivileged roles through the IdP; direct LDAP login to OpenPrivileged is not provided.

## Consequences
+ Matches the CyberArk CPM model buyers already understand: verify, change, reconcile, and dependent accounts.
+ Runs on the customer LAN, consistent with ADR-0003; the cloud never holds a route to a domain controller.
− A bad rotation can lock out a service account or break dependents; mitigated by two-phase rotation, dry-run by default, and a dependents list.
− The customer must delegate rights on an OU; onboarding docs and a PowerShell delegation script are required.
− Replication lag and multi-DC topologies add edge cases; needs a lab with two DCs in the test topology.
