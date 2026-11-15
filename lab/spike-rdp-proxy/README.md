# Mode B spike: RDP reverse proxy for native clients (ADR-0008)

Goal: decide go / no-go on a native-client RDP proxy before building it into OpenPrivileged. Time-box: 3 working days.

## Setup
1. Lab VMs up (`lab/README.md`), `ws1` reachable at 10.77.0.21 with RDP + NLA.
2. `mkdir certs` and create a proxy certificate (use the lab CA from `02-dc1-setup.ps1` if you want clients to trust it, otherwise self-signed for the first pass).
3. `cp config.ini.example config.ini` and set the target credential.
4. `docker compose -f lab/docker/compose.yml --profile spike up --build rdp-proxy`
5. Connect with `mstsc` (or `xfreerdp`) to `localhost:3389`.

## Tests and pass criteria
| # | Test | Pass |
|---|------|------|
| T1 | Client connects to the proxy; proxy opens its own connection to ws1 with the stored credential; user reaches the desktop | Desktop visible; client never entered the target password |
| T2 | Client leg uses NLA/CredSSP (no downgrade to plain TLS/RDP security) with a certificate the client trusts | No certificate warning with the lab CA; NLA enforced |
| T3 | Clipboard, drive, printer channels blocked at the proxy while the client has them enabled | Redirection does not work from the client |
| T4 | **Token auth:** client supplies a one-time token as username/password; a hook validates it against a stub broker and selects the target credential | Valid token connects once; reused or expired token is refused; no hook means no-go for this proxy |
| T5 | Session capture: obtain a recording or event stream from the proxy usable by the hash-chained recorder | A replayable or indexable artefact is produced |
| T6 | Kill: broker drops both legs on demand | Both connections end within 5 s |
| T7 | Abuse: 200 bad-token attempts from one source | Rate limiting is possible at the proxy or in front of it (TCP LB / host firewall) |

## Decision
- **Go** (build Mode B on `freerdp-proxy`): T1, T2, T3, T4 and T6 pass, and T5 is workable.
- **No-go for this proxy**: T4 fails and no supported hook exists. Fall back to Mode A only, or evaluate PyRDP strictly as a comparison (GPL-3.0, never shipped or imported; ADR exception and counsel review needed before any real use).
- Record the outcome in `docs/adr/0008-rdp-brokering-and-recording.md` (Status line) and `TASKS.md`.
