# ADR-0004: Original vault and device-native JIT credentials (no upstream vault)

Status: Accepted (planning)

## Context
The repo collection has no vault, broker or recorder. HashiCorp Vault/OpenBao could store secrets but cannot create network-device users or tie into grants, and adds an operational component and (for Vault) BSL licensing concerns. Network devices vary: some support local users with expiry, others only a shared enable secret.

## Decision
Implement a small vault module in Python: envelope encryption (AES-256-GCM data keys per tenant, wrapped by Cloud KMS), versioned credentials with `pending/current/retired` states. Grants use one of two strategies per device policy: **temp_user** (create a unique local account for the grant, verify, remove at expiry; preferred) or **shared_vault** (broker injects the vaulted credential; rotate after use). Credentials are not revealed to humans unless policy `allow_reveal` is set, and reveal is audited and forces rotation at expiry.

## Consequences
+ Tight coupling between approvals, device state and audit; no extra moving parts.
+ Per-platform command knowledge lives in `vg_devices` drivers with golden tests.
− We own cryptography-adjacent code: mitigated by using `cryptography` primitives, KMS, external review, and keeping the interface narrow.
− Platforms without user-creation support fall back to rotation, which is weaker for audit attribution (the session recording supplies attribution).
