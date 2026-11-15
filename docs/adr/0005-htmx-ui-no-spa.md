# ADR-0005: Server-rendered UI (Jinja2 + HTMX) with vendored xterm.js

Status: Accepted (planning)

## Context
Python-first requirement; a solo builder; the UI is forms, tables, approval pages, and a terminal. TypeScript is allowed only if justified.

## Decision
Use Jinja2 templates with HTMX for interactivity, served by the FastAPI app. The sole front-end library with real JavaScript is xterm.js (MIT, vendored and pinned) for the terminal and a small replay player. No Node build pipeline in MVP.

## Consequences
+ Single deploy artifact, no API/UI version skew, fast to ship, easy CSP (no inline scripts, nonce'd).
− Less rich interactions; a customer-facing white-label SPA, if later needed, would need a new ADR.
− xterm.js is third-party JS: pinned with SRI hashes and listed in the SBOM.
