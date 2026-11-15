# Combined lab API/broker/rotation worker. Never run a second vault owner.
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159 AS build
RUN pip install --no-cache-dir uv==0.9.12
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY packages/vg_core/pyproject.toml packages/vg_core/pyproject.toml
COPY packages/vg_api/pyproject.toml packages/vg_api/pyproject.toml
COPY packages/vg_core/src packages/vg_core/src
COPY packages/vg_api/src packages/vg_api/src
RUN uv sync --frozen --no-dev --no-editable --python /usr/local/bin/python

FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159 AS runtime
ARG VG_UID=10001
ARG VG_GID=10001
RUN test "$VG_UID" -gt 0 && test "$VG_GID" -gt 0 \
    && apt-get update && apt-get install -y --no-install-recommends openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid "$VG_GID" vaultgate \
    && useradd --uid "$VG_UID" --gid "$VG_GID" --no-create-home --home-dir /nonexistent vaultgate
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER ${VG_UID}:${VG_GID}
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8766/healthz/rotation', timeout=3).close()"]
ENTRYPOINT ["python", "-m", "vg_api.rotation_app"]
CMD ["/run/vaultgate-secrets/config.json", "--port", "8766"]
