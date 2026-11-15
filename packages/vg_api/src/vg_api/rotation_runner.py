"""Opt-in foreground single-account lab runner, not an installed system service.

Exclusive vault ownership precludes a separate API process using this same vault.
No enrollment, recovery, security configuration, or credential export occurs here.
"""

import argparse
import json
import os
import signal
import stat
from collections.abc import Callable
from pathlib import Path
from threading import Event
from typing import Any

from vg_core.rotation import AccountBinding, RotationService

from vg_api.directory import DirectoryConfig, LdapsDirectory
from vg_api.lab_access import SSHTarget
from vg_api.rotation_ad import AdLabRotationAdapter, AdRotationAccount
from vg_api.rotation_store import EncryptedRotationStore


def private_read(path: Path) -> bytes:
    if path.absolute().resolve() != path.absolute():
        raise ValueError("Symlink paths not permitted")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or info.st_size > 1024 * 1024
        ):
            raise ValueError("Unsafe private file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return stream.read(1024 * 1024 + 1)
    finally:
        os.close(fd)


def health(service: RotationService, account_id: str) -> dict[str, str | int]:
    status = service.status(account_id)
    return {
        "account": status.account_id,
        "state": status.state,
        "generation": status.generation,
        "due_at": status.due_at.isoformat(),
    }


def run_loop(
    service: RotationService,
    account_id: str,
    stop: Event,
    emit: Callable[[dict[str, str | int]], None],
    interval: float = 30,
) -> int:
    """Exit on uncertain state; never automatically retry/recover a pending reset."""
    if not 0 < interval <= 60:
        raise ValueError("Invalid polling interval")
    while not stop.is_set():
        service.rotate_due()
        report = health(service, account_id)
        emit(report)
        if report["state"] != "ready":
            return 2
        stop.wait(interval)
    return 0


def open_runtime(config: dict[str, Any]) -> tuple[EncryptedRotationStore, RotationService]:
    if config.get("managed_accounts"):
        from vg_api.rotation_managed_ad import open_managed_runtime

        return open_managed_runtime(config)
    binding = AccountBinding(
        **{**config["binding"], "device_ids": frozenset(config["binding"]["device_ids"])}
    )
    if (
        binding.id != "vg-tech-admin"
        or binding.privileged_username != "vg-tech-admin@example.local"
        or binding.authority_id != "DC1.example.local"
        or "vg-ubuntu-rdp" not in binding.device_ids
        or not binding.device_ids
        <= frozenset({"vg-ubuntu-rdp", "vg-frr-1", "vg-frr-2", "vg-frr-3"})
    ):
        raise ValueError("Runner is restricted to the approved synthetic lab account")
    directory = LdapsDirectory(DirectoryConfig.model_validate(config["directory"]))
    account = AdRotationAccount(binding, config["object_guid"], config["distinguished_name"])
    adapter = AdLabRotationAdapter(SSHTarget(**config["ssh"]), directory, (account,))
    store = EncryptedRotationStore(
        Path(config["vault_directory"]), private_read(Path(config["key_file"]))
    )
    try:
        payload = json.loads(store.load() or b"null")
        # Exact persisted scope, including technician ownership; no new enrollment.
        if (
            not isinstance(payload, dict)
            or len(payload.get("records", [])) != 1
            or payload["records"][0]["binding"] != config["binding"]
        ):
            raise ValueError("Vault scope does not match approved account")
        service = RotationService(adapter, store=store)
        return store, service
    except BaseException:
        store.close()
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--run", action="store_true", help="Rotate due credentials until stopped")
    parser.add_argument(
        "--enroll-managed",
        metavar="ACCOUNT_ID",
        help="Enroll one approved, already enabled staged a.username; no worker",
    )
    args = parser.parse_args()
    store = None
    try:
        config = json.loads(private_read(args.config))
        if args.enroll_managed:
            if args.run:
                raise ValueError("Enrollment and rotation must be separate invocations")
            from vg_api.rotation_managed_ad import enroll_staged

            status = enroll_staged(config, args.enroll_managed)
            print(
                json.dumps(
                    {
                        "account": status.account_id,
                        "state": status.state,
                        "mode": "enrolled-no-worker",
                    }
                )
            )
            return 0
        store, service = open_runtime(config)
        if config.get("managed_accounts"):
            from vg_api.rotation_managed_ad import configured_accounts

            ids = [a.binding.id for a in configured_accounts(config)]
            stop = Event()
            signal.signal(signal.SIGTERM, lambda *_: stop.set())
            signal.signal(signal.SIGINT, lambda *_: stop.set())
            while True:
                if args.run:
                    service.rotate_due()
                rows = [health(service, account_id) for account_id in ids]
                print(
                    json.dumps({"accounts": rows, "mode": "run" if args.run else "check-only"}),
                    flush=True,
                )
                if any(row["state"] != "ready" for row in rows):
                    return 2
                if not args.run or stop.wait(30):
                    return 0
        if not args.run:
            print(json.dumps({**health(service, "vg-tech-admin"), "mode": "check-only"}))
            return 0
        stop = Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        return run_loop(
            service, "vg-tech-admin", stop, lambda row: print(json.dumps(row), flush=True)
        )
    except Exception:
        # Exception text/tracebacks may originate from secret-handling libraries.
        print('{"state":"runner_failed","action":"operator_check_required"}', flush=True)
        return 2
    finally:
        if store is not None:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
