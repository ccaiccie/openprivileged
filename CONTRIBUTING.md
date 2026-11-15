# Contributing to OpenPrivileged

OpenPrivileged Community is an experimental privileged-access-management project,
licensed under Apache 2.0. Contributions should improve the isolated development
experience without suggesting that the prototype is production-ready.

## Start here

1. Read the [documentation index](docs/README.md), [security boundaries](SECURITY.md)
   and [architecture](docs/ARCHITECTURE.md).
2. Fork the repository and create a focused branch from `main`.
3. Follow the [development guide](docs/DEVELOPMENT.md) to install dependencies and
   run the local checks.
4. Make the smallest coherent change, with tests and updated documentation.
5. Open a pull request describing the problem, behavior change, test results and
   any migration or compatibility considerations.

For substantial changes, discuss the proposed design in an issue first. Use
fictional examples. Do not include private domain names, inventories, credentials,
logs containing secrets, vault data, personal information or customer data.

## Pull request checklist

- [ ] Scope is clear and unrelated changes are excluded.
- [ ] Unit tests cover success, denial and relevant failure/retry paths.
- [ ] Formatting, lint, strict type checks and unit tests pass.
- [ ] Authorization remains server-side and tenant/device boundaries are tested.
- [ ] Secrets do not enter browser responses, logs, fixtures, screenshots or Git.
- [ ] New external writes are explicit, opt-in and fail closed on uncertain results.
- [ ] README/runbooks describe supported behavior, prerequisites and limitations.
- [ ] Dependencies and bundled third-party notices are reviewed when changed.

Never run provisioning, password resets, teardown scripts, Terraform apply or
infrastructure creation as an incidental part of a documentation or unit-test change.
Tests against an actual isolated domain or device require a separate authorized lab.

## Reporting defects and vulnerabilities

A normal issue should include the version/commit, reproduction using fictional
inputs, expected and actual behavior, and sanitized error text. Say whether the
failure affects the synthetic demo or an optional integration.

For vulnerabilities, follow [SECURITY.md](SECURITY.md). Do not publish exploit
instructions or sensitive material in a public issue. A private reporting channel
must be arranged if GitHub private vulnerability reporting is unavailable.

## Compatibility and licensing

Public branding is OpenPrivileged. Existing Python package names (`vg_core`,
`vg_api`), the `vg-api` command and compatibility identifiers remain intentionally
unchanged. Renaming them is a behavioral change, not a cosmetic cleanup.

Submit only material you have the right to contribute under the project's license.
Preserve [third-party notices](THIRD-PARTY-NOTICES.md) and vendor license files.
Do not imply that Apache 2.0 licenses separately bundled third-party components
under different terms.
