"""Regression checks for the opt-in deployment's security contract."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_combined_image_uses_one_app_and_installed_locked_dependencies():
    dockerfile = (ROOT / "lab/docker/rotation/Dockerfile").read_text()
    assert 'ENTRYPOINT ["python", "-m", "vg_api.rotation_app"]' in dockerfile
    assert "--frozen --no-dev --no-editable" in dockerfile
    assert "USER ${VG_UID}:${VG_GID}" in dockerfile
    assert 'test "$VG_UID" -gt 0' in dockerfile
    assert "COPY . " not in dockerfile
    assert "STOPSIGNAL SIGTERM" in dockerfile
    assert "/healthz/rotation" in dockerfile


def test_compose_preserves_original_single_owner_vault_and_secret_mounts():
    compose = (ROOT / "lab/docker/compose.rotation.yml").read_text()
    assert "target: /var/lib/vaultgate/vault" in compose
    assert "target: /run/vaultgate-secrets\n        read_only: true" in compose
    assert compose.count("create_host_path: false") == 2
    assert "stop_grace_period: 120s" in compose
    assert "restart: unless-stopped" in compose
    assert "read_only: true" in compose
    assert "no-new-privileges:true" in compose
    assert "cap_drop: [ALL]" in compose
    assert "network_mode: host" in compose  # Explicit existing Linux topology, not isolation.
    assert "ports:" not in compose
    assert "docker.sock" not in compose
    assert "privileged: true" not in compose
    assert "environment:" not in compose
    assert "VG_UID:?" in compose and "VG_GID:?" in compose


def test_context_is_allowlisted_without_private_material():
    ignore = (ROOT / ".dockerignore").read_text().splitlines()
    assert "**" in ignore
    assert "!packages/vg_api/src/**" in ignore
    assert "!packages/vg_core/src/**" in ignore
    assert not any(line.startswith("!") and "secret" in line for line in ignore)
    assert "**/__pycache__/**" in ignore
