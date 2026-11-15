# OpenPrivileged documentation

OpenPrivileged Community is a **pre-release, isolated-lab prototype**, not a
production PAM service. Start with the synthetic localhost demo; optional directory,
remote-session and rotation workflows require separate operator configuration.
Read [Security](../SECURITY.md) before connecting anything real.

## Choose your path

| Goal | Guide |
| --- | --- |
| Install prerequisites and run the demo | [Installation](INSTALLATION.md) |
| Understand components and trust boundaries | [Architecture](ARCHITECTURE.md) |
| Find configuration switches and optional integrations | [Configuration](CONFIGURATION.md) |
| Understand packaging and deployment limitations | [Deployment](DEPLOYMENT.md) |
| Use the application by role | [User guide](USER-GUIDE.md) |
| Connect an isolated AD and map groups | [AD integration](AD-INTEGRATION.md) |
| Understand `a.username` creation and delegated permissions | [Managed AD accounts](AD-MANAGED-ACCOUNTS.md) |
| Operate the prototype safely | [Operations](OPERATIONS.md) |
| Diagnose a failed workflow | [Troubleshooting](TROUBLESHOOTING.md) |
| Develop and test changes | [Developer guide](DEVELOPMENT.md), [Contributing](../CONTRIBUTING.md) |

## Detailed runbooks and references

- [Local request/approval demo](runbooks/local-demo.md)
- [Interactive lab access](runbooks/interactive-lab.md)
- [Browser VNC](runbooks/browser-vnc.md)
- [Standing device access](runbooks/standing-device-access.md)
- [Directory configuration reference](integrations/active-directory.md)
- [Technician password rotation design and limits](design/technician-password-rotation.md)
- [Combined rotation container and controlled cutover](runbooks/rotation-container.md)
- [Lab scaffolding](../lab/README.md)
- [Branding](branding/BRAND.md)
- [Release checklist](FIRST-RELEASE.md)
- [License](../LICENSE) and [third-party notices](../THIRD-PARTY-NOTICES.md)

Detailed runbooks may describe optional experiments not active in the default demo.
Private inventory, credentials and runtime state are deliberately not distributed.
Read prerequisites before executing a command; infrastructure scripts are not
required to explore the synthetic application.

## Architecture decision records

These explain decisions and future design intent. They do **not** certify that a
component is deployed or complete; use the current guides and source for behavior.

1. [Python-first stack](adr/0001-python-first-stack.md)
2. [Cloud infrastructure direction](adr/0002-gcp-cloud-run-terraform.md)
3. [Customer-network reachability](adr/0003-customer-network-reachability.md)
4. [Credential vault and just-in-time strategy](adr/0004-credential-vault-and-jit-strategy.md)
5. [UI direction](adr/0005-htmx-ui-no-spa.md)
6. [Multi-tenancy and RLS direction](adr/0006-multi-tenancy-rls.md)
7. [AD password rotation](adr/0007-active-directory-password-rotation.md)
8. [RDP brokering and recording direction](adr/0008-rdp-brokering-and-recording.md)
9. [Initial control-plane slice](adr/0009-initial-control-plane-slice.md)

## Documentation conventions

Public product branding is **OpenPrivileged**. Internal `vg_core` / `vg_api`
package names, the `vg-api` CLI and compatibility identifiers are retained.
Examples are fictional. No example credentials should be reused, and no guide
requires Domain Admin merely to operate the application. Hosted offerings are
separate from this community source; see [openprivileged.com](https://openprivileged.com)
for announcements, not a promise of currently available SaaS capabilities.
