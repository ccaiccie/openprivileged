# Interactive isolated lab access

Local development only. The lab's privileged containers are not a production isolation boundary.
The application must bind loopback; do not put this demo behind a public tunnel.

This optional workflow requires your own operator-approved private inventory,
desktop credential file and pinned RDP manifest. The machine-specific
`/path/to/private-lab/inventory.json` and `/path/to/private-lab/manifest.json` are intentionally not
included. Replace those example path references below with your private files;
these commands are not a ready-to-run lab deployment.

Launch from the repository (the launcher installs the locked dependencies):

```bash
./run-demo.sh --port 8797 \
  --lab-inventory /path/to/private-lab/inventory.json \
  --desktop-credentials /path/to/private-lab/desktop-credentials.json
```

Sign in with `tech` and the fresh password printed by this process. On Devices,
choose a configured FRR or Ubuntu VNC target, give a fictional reason and request
entitled access. On Grants choose **Open SSH** or **Open desktop**. This is actual
interactive transport, not the fixed **Test SSH** probe. FRR supports normal shell
commands and `vtysh`. Disconnect closes the browser channel; Revoke prevents
reconnection and closes the active bridge within roughly one second.

Optional RDP integration requires the separately approved, loopback-only guacd
sidecar at 127.0.0.1:4823 and `--rdp-manifest /path/to/private-lab/manifest.json`. The manifest
contains the explicit desktop certificate fingerprint. No arbitrary targets,
client-supplied credentials or certificate bypass are accepted. Browser RDP
verification status must be checked in the accompanying test report; the presence
of code alone is not proof of end-to-end operation.

## Security limits

- Login, active assigned role, own active grant, tenant scope and current entitlement
  are enforced server-side. Rechecked on input and a one-second watchdog.
- SSH pins host keys and disables local escape commands, forwarding and agents.
- VNC credentials remain server-side; the internal lab VNC leg is not encrypted.
- RDP credentials remain server-side and certificate pinning is mandatory.
- The browser sends CSRF proof without putting secrets in URLs.
- Session lifecycle is audited; keystrokes and screens are not recorded.
- Logout, role switch, revoke and expiry disconnect transport. Remote background
  processes and shared Ubuntu desktop state may remain. This is not device account
  withdrawal or per-user desktop isolation.
- State is in memory. Restarting creates new passwords and loses grants/audit data.
- Existing instances are independent and must not be silently restarted.

The legacy `lab/docker/compose.yml` exposes guacd on 4822; this optional broker
expects a separately approved sidecar on 4823. Do not assume starting the legacy
Compose project configures this integration. No sidecar is needed for the default
synthetic demo.
