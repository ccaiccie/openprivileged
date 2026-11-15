# Local browser VNC bridge

The Ubuntu VNC target can now be used interactively from the OpenPrivileged browser UI.
This is real screen/keyboard/mouse transport, not the earlier connectivity probe.
Only the explicitly configured isolated target `10.78.0.21:5901` is accepted.
Native RDP browser transport is separate and is not implemented by this module.

## Boundary

- Browser login, same-origin checks and an active owned grant are required.
- CSRF is conveyed as a WebSocket subprotocol, never in the URL.
- The backend reads the owner-only desktop credentials file and performs the VNC
  challenge-response. It never sends that password/challenge to the browser.
- The browser sees a synthetic RFB NoAuth handshake **inside the authorized
  WebSocket**, not an unauthenticated VNC server exposed on a port.
- Every input and outbound framebuffer chunk is authorized again. A one-second
  watchdog also rechecks login, active role, grant ownership, entitlement and expiry.
  Revocation/logout/role changes close both streams, including stalled handshakes.
- One session per grant, at most eight active bridge sessions per app process.
- Session-requested and session-closed audit events exist. Screen/keystroke recording
  is not implemented.

The internal VNC leg still uses classic unencrypted VNC authentication, and the
current demo browser runs on localhost HTTP/WS. Keep this strictly local. This is
not production identity, TLS transport, a multi-tenant desktop isolation system,
or a replacement for the privileged-container security warning in the lab runbook.
Different authorized grants share the dedicated lab desktop, by design.

## Integration

`vg_api.desktop_bridge.load_desktop_target(Path(...))` validates owner/mode0600,
rejects symlinks and accepts only the fixed address and ASCII VNC password format.
Install `install_vnc_routes(app, store, auth, {"vg-ubuntu-vnc": target})`.
Without explicit target configuration, the endpoint fails closed.

Official noVNC1.7.0 assets are vendored under `static/vendor/novnc`; npm tarball
SHA512 integrity and provenance are in `SOURCE.txt`, with upstream license retained.
The dashboard CSP must allow `img-src 'self' data: blob:` for TightJPEG framebuffer
decoding. Script/style restrictions remain unchanged; do not add unsafe-eval.

## Verification

`tests/unit/test_desktop_bridge.py` covers password-safe representation, DES known
vector, malformed/refused handshakes, owner-only credential loading, fixed endpoint,
fragmented frontend messages, per-input authorization and stalled-handshake revoke,
and installation-level Origin/CSRF/session/role/ownership checks.

`tests/integration/browser_vnc_smoke.py` uses a separate ephemeral app process and
the approved lab. It authenticates through the real API, obtains a direct grant,
loads official noVNC, verifies actual framebuffer and input-driven changes, then
revokes the grant and verifies disconnect. It asserts no CSP violations and stops
only its own process. The fresh-lab screenshot was visually inspected and showed
Ubuntu24.04.5 GNOME, not merely an empty canvas.
