#!/usr/bin/env bash
# Run from the host or the ChatGPT container without relying on /usr/bin/python3.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if ! command -v uv >/dev/null 2>&1; then
  echo 'uv is required: https://docs.astral.sh/uv/getting-started/installation/' >&2
  exit 1
fi
# Separate environments because the host and container have different system Python builds.
if [[ -n "${CONTAINER_ID:-}" || -f /.dockerenv || -f /run/.containerenv ]]; then
  export UV_PROJECT_ENVIRONMENT="$PWD/.venv-container"
else
  export UV_PROJECT_ENVIRONMENT="$PWD/.venv-host"
fi
uv sync --locked --python 3.12
exec uv run --no-sync vg-api --demo "$@"
