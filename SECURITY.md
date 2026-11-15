# Security

OpenPrivileged is an experimental, local-only PAM prototype. It is **not ready
for production or real customer credentials**. Do not expose it to the Internet,
place it behind a public tunnel, or treat its demonstration controls as a
compliance certification.

## Current boundaries

- The control plane is in memory; restarts lose its operational state. It has no
  production database/RLS, OIDC/MFA, WORM audit storage or full session recording.
- Local demo passwords are generated at startup. Use fictional identities/data.
- SSH/VNC/RDP and AD integration are opt-in isolated-lab features, not a general
  production gateway. They require operator-supplied private configuration.
- AD account creation is disabled by default and requires explicit scoped writer
  configuration. Read `docs/AD-MANAGED-ACCOUNTS.md`. Never grant Domain Admin just
  to operate this application.
- Encrypted local rotation state does not provide production KMS/HSM custody.
  Vault data and keys must stay outside the repository, with restrictive access.
- Single-process operation is required. Do not scale workers or run two owners
  against the same vault. Rotation uncertainty requires reconciliation.
- Disconnect/revoke does not guarantee termination of remote background jobs.
- Hash-chained audit events do not prove completeness without trusted external
  anchors. Reasons and tickets may contain sensitive text.

## Reporting a vulnerability

Do not put passwords, keys, customer information or exploit details in a public
issue. Use GitHub private vulnerability reporting if the repository owner enables
it. Otherwise ask the maintainer for a private reporting channel before sending
sensitive details. No security email address or response-time guarantee is
currently published.

## Before public distribution

Include the Apache-2.0 LICENSE, preserve third-party notices, review dependencies and
run the release checks. An automated secret scan is not a security audit. No
support SLA, compliance certification or hosted-service security promise is made
by this source snapshot.
