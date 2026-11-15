# ADR-0008: RDP session brokering and recording (PSM-style)

Status: Proposed (Mode A first, Mode B after a lab spike)

## Context
CyberArk's Privileged Session Manager (PSM) lets a user click "Connect" and land in an RDP session on the target without ever seeing the password; the session is proxied, recorded, and can be monitored or terminated. OpenPrivileged already promises this for SSH. For Windows servers the same flow requires an RDP-capable gateway. The earlier plan deferred RDP (PLAN.md out-of-v1; TASKS.md Phase 5), and ADR-0001 and LICENSES.md require an ADR before adding a non-Python process.

## Options considered
1. **Apache Guacamole `guacd` + our own Python front end** (separate container, driven over the Guacamole protocol). Clientless HTML5 RDP in the browser, with a native recording format (`.guac`) that can be converted to video. Apache-2.0.
2. Native RDP proxy using FreeRDP in proxy mode: tighter fidelity for native `mstsc`, but C code, more fragile, no built-in browser client.
3. Jump host with RDS RemoteApp / PSM-style connection components on a Windows server (what CyberArk does): needs Windows Server licensing (RDS CALs) and a Windows fleet to operate.
4. Python RDP implementation (aardwolf, `rdp-py`): immature for production recording and NLA.

## Decision
Two access modes behind one grant, policy, recording and audit pipeline. Both run as separate processes (never imported into Python, per ADR-0001); the broker decides which mode a grant may use (`rdp_modes[]` in policy).

### Mode A: browser RDP via Guacamole (first release)
`guacd` runs as a separate container. The OpenPrivileged `broker` speaks the Guacamole protocol to `guacd`, which is the only component that talks RDP.

**Connection flow:**
1. Grant is approved and activated; for `ad` credentials the worker verifies the vaulted password (ADR-0007) before the window opens.
2. Technician opens the session in the browser; the broker validates the grant and policy.
3. The broker resolves the credential **server-side** and passes it to `guacd` in the connection parameters. The password never reaches the browser or the technician's client.
4. `guacd` connects with NLA/CredSSP to the target. For private networks the guacd instance lives next to the collector (or reaches the target through it); the collector tunnel (ADR-0003) carries the Guacamole stream, so no inbound ports are opened.
5. Recording: `guacd` writes the session stream; chunks are hashed and chained exactly like SSH recordings (SECURITY.md) and stored under the bucket retention lock. A worker job converts recordings to video for review and extracts a searchable event index (window titles are not available; we index keystroke/clipboard/file-transfer events and connect/disconnect times).
6. At expiry or early revoke, the broker closes the Guacamole connection (hard kill) and the worker rotates or resets the password (ADR-0007) so a copied credential is useless.

### Mode B: native RDP client through a reverse-proxy RDP endpoint (second release)
The technician keeps `mstsc`, Remote Desktop Manager or any RDP client. OpenPrivileged runs an RDP proxy endpoint (TCP 3389 on a TCP load balancer, same pattern as the native SSH endpoint in ADR-0003) in front of the targets.

1. When a grant activates, the portal issues a **per-grant `.rdp` file** (or connection string) pointing at the proxy, with a one-time, short-lived token as the username/password. The token is bound to the grant, user, device, and source IP and is single use.
2. The proxy terminates the client leg (TLS/NLA with the token), asks the broker to validate it, then opens a **second, independent RDP connection** to the target using the vaulted AD or local credential (ADR-0007). The client never learns the real password.
3. For private networks the target leg goes through the collector tunnel (ADR-0003): the proxy sends bytes to the collector, which dials the target on the customer LAN. Nothing inbound is opened; the collector's own connection is outbound-only. This is the "reverse" part of the reverse proxy.
4. The proxy records channel events and the graphics stream into the same hash-chained recorder; virtual channels (clipboard, drives, printers, smart cards) are blocked or allowed per policy at the proxy, not trusted to the client's settings.
5. Expiry or revoke: the proxy drops both legs; the worker rotates the password.

**Implementation candidates (to be spiked in a lab before choosing):**
- **FreeRDP `freerdp-proxy`** (Apache-2.0, C): server-side proxy with module hooks for credential substitution and channel filtering. Preferred if the hooks cover token validation and recording.
- **PyRDP** (GPL-3.0, Python): purpose-built RDP man-in-the-middle with recording and credential substitution. GPL, so it may only be used as an unmodified, arm's-length separate process under an ADR exception to the license gate; counsel must sign off first, otherwise do not use it.
- Custom Python proxy: rejected for now; implementing CredSSP/NLA, RDP6/8 graphics and channel parsing is a large effort.

Open risk to verify early: terminating NLA/CredSSP on the client leg with a token credential while presenting a valid certificate. Clients must trust the proxy certificate (a customer-installed CA or a publicly trusted name such as `rdp.<domain>`), otherwise users get warnings they will learn to click through.

### Choosing the mode
- Guacamole (A): no client install, easiest to ship, strongest for contractors and BYOD, lower fidelity (multi-monitor, audio, high DPI are limited).
- Native proxy (B): full-fidelity experience technicians expect; more fragile to build and a larger security surface (a public 3389 listener, so it needs token pre-auth, rate limiting and source-IP binding).
- Neither mode exposes a customer RDP port to the internet.

**Controls (CyberArk parity targets):**
- Clipboard, drive redirection, printing and file transfer are **off by default**; policy toggles per tenant and per device.
- Live monitoring and termination by an admin (second-approver monitoring comes later, per the existing cut line).
- Dual control: a policy may require an approver before connect, as in the existing approval flow.
- TLS to the target is verified when the target has a trusted cert; otherwise the cert fingerprint is pinned per device and changes raise an alert.
- Session timeout and idle disconnect enforced by the broker, not just by Windows.
- Prefer one-time-use AD credentials; fall back to a vaulted local administrator rotated after use.

**Not provided in either mode yet:** RemoteApp (publish-an-application-only sessions), a Microsoft RD Gateway-protocol endpoint (the Mode B proxy is not an RD Gateway; an RD Gateway front end is a later option), Kerberos delegation SSO into the target, VNC.

## Consequences
+ Delivers the PSM-style "connect without seeing the password, recorded, kill on demand" flow with permissive-licensed components.
+ Reuses the collector, grant, approval, recorder and audit pipeline unchanged.
− A new long-lived process type (guacd) with its own scaling and patching; it needs GKE Autopilot or a GCE VM (HOSTING.md), not Cloud Run.
− Mode A is lower fidelity than native; Mode B closes that gap but adds an internet-facing 3389 listener and a dependency on a C proxy whose hooks must be proven in a spike.
− RDP recordings are large (video-like). Retention costs and the conversion pipeline must be estimated before pricing.
− Guacamole's license (Apache-2.0 for guacd and the client, to be verified) and the licenses of its native libs (FreeRDP is Apache-2.0) must be confirmed in LICENSES.md before building.
