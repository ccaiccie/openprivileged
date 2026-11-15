# ADR-0001: Python-first stack with non-Python upstreams as separate processes

Status: Accepted (planning)

## Context
The supplied repos are Python network-automation libraries (Netmiko, Scrapli, Nornir, pynetbox, NORFAB, ntc-templates) plus Java (Netshot) and C#/.NET (NETworkManager). The owner requires Python 3.12+ for backend, workers, collector, and CLI. A solo builder needs one language across the stack.

## Decision
Write all OpenPrivileged services in Python 3.12+ (FastAPI, SQLAlchemy/Alembic, Arq, asyncssh, Typer; uv, ruff, mypy, pytest). Any non-Python upstream (Netshot, a future RDP proxy) runs as its own container/process and is driven from Python over REST or a socket. Never rewrite or fork it.

## Consequences
+ One toolchain, one hiring profile, direct use of the device libraries.
+ GPL components stay at arm's length (separate process).
− Python is weaker for high-fanout raw-socket proxies; broker concurrency must be validated (asyncssh/asyncio is adequate for hundreds of sessions per instance, estimate).
− Collector must be a lightweight Python package; shipping Python to customers requires a container or a pinned venv installer.
