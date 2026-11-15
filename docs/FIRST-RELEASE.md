# First GitHub revision

Upload the contents of this `openprivileged` folder, not the original working lab.
Nothing has been pushed or published automatically.

## Before publishing

- OpenPrivileged Community original code is licensed under Apache License 2.0.
  Include the root `LICENSE` when uploading or distributing this revision.
  Third-party components retain their own licenses and notices.
- Keep third-party licenses and notices under `static/vendor` intact.
- Review this snapshot yourself. Automated scans reduce risk; they cannot prove
  absence of secrets or establish ownership/licensing of every file.
- Start with the localhost-only synthetic demo. Do not expose the app publicly.
- Run `uv sync --locked --python 3.12`, then `uv run pytest -q`.

## What is intentionally absent

Runtime credentials, vault/state, SSH keys, GNS3 inventory/manifest and personal
FRR migration helpers; virtual environments/caches; operational logs, screenshots,
internal product/business plans and generated planning decks.

## Compatibility and lab-only boundaries

The Python packages, CLI (`vg-api`), VG_* configuration variables and internal
vault format identifiers retain their existing names to avoid breaking behavior.
The UI and public documentation use OpenPrivileged. No existing installation has
been renamed or modified.

The legacy single-account AD adapter is still a restrictive lab reference. Its
original private domain/address has been replaced with example.local and
192.0.2.116 (documentation-only address). It cannot operate against the original
lab as shipped. Do not weaken allowlists to make it work; review the managed AD
configuration documentation and explicitly configure/test an isolated environment.
References to GNS3 files in optional integration scripts/runbooks require an
operator-provided private inventory; these files are deliberately not shipped.

A hosted SaaS offering is separate future work. This snapshot does not claim
production readiness, HA, durable control-plane storage, MFA or session recording.
