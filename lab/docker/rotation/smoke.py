"""Network-isolated image smoke test. Uses synthetic data ONLY, no AD adapter.

Run first/restart in separate containers with the same dedicated fixture bind.
Never mount a real vault here. The marker prevents use of a non-fixture directory.
"""

import os
import signal
import subprocess
import sys
import time
import urllib.request
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI
from vg_api.rotation_app import install_worker_lifecycle
from vg_api.rotation_store import EncryptedRotationStore
from vg_core.rotation import AccountBinding, RotationService

ROOT = Path("/fixture")
KEY = bytes(range(32))  # Public synthetic test key; never deployment material.
START = datetime(2026, 1, 1, tzinfo=UTC)


class Adapter:
    def change(self, binding, password):
        (ROOT / "fake-target").write_text(password)

    def verify(self, binding, password):
        return password == (ROOT / "fake-target").read_text()


def fixture():
    assert (ROOT / "SYNTHETIC_ONLY").read_text() == "vaultgate-container-test\n"
    assert ROOT.stat().st_uid == os.getuid()
    assert ROOT.stat().st_mode & 0o077 == 0


def server():
    import uvicorn

    fixture()
    store = EncryptedRotationStore(ROOT / "vault", KEY)
    service = RotationService(Adapter(), lambda: START + timedelta(hours=4), store)
    app = FastAPI()
    worker = install_worker_lifecycle(app, service)
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def observed_lifespan(application):
        async with original_lifespan(application):
            yield
        assert worker._thread is not None and not worker._thread.is_alive()
        (ROOT / "graceful-shutdown").write_text("worker-stopped")

    app.router.lifespan_context = observed_lifespan
    try:
        uvicorn.run(app, host="127.0.0.1", port=18766, log_level="critical")
    finally:
        worker.stop(90)
        store.close()


def main():
    fixture()
    phase = sys.argv[1]
    if phase == "serve":
        server()
        return
    if phase == "first":
        (ROOT / "vault").mkdir(mode=0o700)
        (ROOT / "fake-target").write_text("synthetic-only")
        (ROOT / "fake-target").chmod(0o600)
        store = EncryptedRotationStore(ROOT / "vault", KEY)
        service = RotationService(Adapter(), lambda: START, store)
        service.enroll(
            AccountBinding("vg-tech-admin", "o", "t", "tech", "admin", "fake", frozenset({"d"})),
            "synthetic-only",
        )
        store.close()
    elif phase != "restart":
        raise ValueError("Unknown phase")
    (ROOT / "graceful-shutdown").unlink(missing_ok=True)
    process = subprocess.Popen([sys.executable, __file__, "serve"])
    try:
        for _ in range(100):
            assert process.poll() is None, "Child exited unexpectedly"
            try:
                with urllib.request.urlopen(
                    "http://127.0.0.1:18766/healthz/rotation", timeout=1
                ) as r:
                    if r.status == 200:
                        break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("Worker never became ready")
        # A second process cannot own the same vault while the server owns it.
        try:
            extra = EncryptedRotationStore(ROOT / "vault", KEY)
        except ValueError:
            pass
        else:
            extra.close()
            raise AssertionError("Second vault owner unexpectedly accepted")
    finally:
        process.terminate()
        assert process.wait(timeout=15) in (0, -signal.SIGTERM), "Graceful stop failed"
        assert (ROOT / "graceful-shutdown").read_text() == "worker-stopped"
    store = EncryptedRotationStore(ROOT / "vault", KEY)
    try:
        service = RotationService(Adapter(), lambda: START + timedelta(hours=4), store)
        status = service.status("vg-tech-admin")
        assert status.generation == 2, "Missing or duplicated rotation"
        assert status.state == "ready"
        assert status.due_at == START + timedelta(hours=8)
        assert (ROOT / "fake-target").read_bytes() not in (ROOT / "vault/rotation.enc").read_bytes()
    finally:
        store.close()
    print(f"PASS {phase}: due rotation, health, exclusive ownership, SIGTERM, durable generation")


if __name__ == "__main__":
    main()
