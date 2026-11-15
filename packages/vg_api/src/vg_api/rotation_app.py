"""Opt-in single-process lab API and rotation lifecycle; no service installation."""

import argparse
import asyncio
import json
import re
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from vg_core.domain import ControlPlane, Device, Policy
from vg_core.rotation import RotationService, RotationWorker

from vg_api.directory import DirectoryConfig, LdapsDirectory
from vg_api.directory_management import saved_settings
from vg_api.directory_provisioning import ProvisioningConfig
from vg_api.main import create_app
from vg_api.managed_ssh import load_managed_targets
from vg_api.rdp_bridge import RDPTarget
from vg_api.rotation_inventory import load_ssh_inventory
from vg_api.rotation_runner import open_runtime, private_read
from vg_api.rotation_store import EncryptedRotationStore


def install_worker_lifecycle(
    app: FastAPI, service: RotationService, account_ids: tuple[str, ...] = ("vg-tech-admin",)
) -> RotationWorker:
    """Worker and session gateway MUST use this same service/store instance."""
    worker = RotationWorker(service)
    original = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        async with original(application):
            worker.start()
            try:
                yield
            finally:
                # The adapter bounds reset (30s) and verification (30s max).
                # Keep event loop alive while broker callbacks finish their lock.
                await asyncio.to_thread(worker.stop, 90)

    app.router.lifespan_context = lifespan

    @app.get("/healthz/rotation", include_in_schema=False)
    def rotation_health() -> JSONResponse:
        accounts = [service.status(account_id) for account_id in account_ids]
        account = accounts[0]
        worker_health = worker.health()
        ready = worker_health["healthy"] is True and all(a.state == "ready" for a in accounts)
        return JSONResponse(
            {
                "ready": ready,
                "accounts": [{"id": a.account_id, "state": a.state} for a in accounts],
                "worker": worker_health,
                "account_state": account.state,
                "generation": account.generation,
                "due_at": account.due_at.isoformat(),
            },
            status_code=200 if ready else 503,
        )

    return worker


@contextmanager
def managed_application(config: dict[str, Any]) -> Iterator[FastAPI]:
    """Own encrypted store until both ASGI server and worker finish shutdown."""
    store, service = open_runtime(config)
    worker: RotationWorker | None = None
    integration_store: EncryptedRotationStore | None = None
    provisioning_store: EncryptedRotationStore | None = None
    try:
        directory_config = DirectoryConfig.model_validate(config["directory"])
        inventory_config = config
        account_ids: tuple[str, ...] = ("vg-tech-admin",)
        if config.get("managed_accounts"):
            from vg_api.rotation_managed_ad import configured_accounts

            accounts = configured_accounts(config)
            account_ids = tuple(a.binding.id for a in accounts)
            # Device inventory is organization-level, but the vault maintains exact
            # technician-device bindings. Never use a union for session authorization.
            first = config["binding"]
            if any(
                a.binding.org_id != first["org_id"] or a.binding.tenant_id != first["tenant_id"]
                for a in accounts
            ):
                raise ValueError("Combined app currently supports one organization/tenant")
            inventory_config = {
                **config,
                "binding": {
                    **first,
                    "device_ids": sorted({d for a in accounts for d in a.binding.device_ids}),
                },
            }
        ssh_devices, ssh_targets = load_ssh_inventory(inventory_config)
        managed_devices, managed_targets = load_managed_targets(inventory_config)
        if managed_targets.keys() & ssh_targets.keys():
            raise ValueError("Duplicate key and managed SSH target")
        directory_config = directory_config.model_copy(
            update={
                "group_mappings": tuple(
                    m.model_copy(update={"device_ids": frozenset({"vg-ubuntu-rdp"})})
                    if "technician" in m.roles
                    and not config.get("ssh_inventory_file")
                    and not config.get("managed_ssh_inventory_file")
                    else m
                    for m in directory_config.group_mappings
                )
            }
        )
        binding = config["binding"]
        if (
            directory_config.org_id != binding["org_id"]
            or binding["tenant_id"] not in directory_config.tenant_ids
        ):
            raise ValueError("Directory scope must match vault")
        fingerprint = config["rdp_fingerprint"]
        if not isinstance(fingerprint, str) or not re.fullmatch(
            r"(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}", fingerprint
        ):
            raise ValueError("Pinned desktop certificate required")
        password = private_read(Path(config["reader_password_file"])).decode()
        directory_revision = 0
        if config.get("directory_settings_directory"):
            integration_store = EncryptedRotationStore(
                Path(config["directory_settings_directory"]),
                private_read(Path(config["directory_settings_key_file"])),
            )
            saved = saved_settings(integration_store)
            if saved:
                selected, password, directory_revision = saved
                if (
                    selected.org_id != directory_config.org_id
                    or selected.tenant_ids != directory_config.tenant_ids
                ):
                    raise ValueError("Saved directory scope must match original configuration")
                directory_config = selected
        provisioning_config = None
        if config.get("account_provisioning"):
            provisioning = config["account_provisioning"]
            provisioning_config = ProvisioningConfig.model_validate(provisioning["scope"])
            provisioning_store = EncryptedRotationStore(
                Path(provisioning["journal_directory"]),
                private_read(Path(provisioning["journal_key_file"])),
            )
        directory = LdapsDirectory(directory_config, bind_password=password)
        device = Device(
            "vg-ubuntu-rdp",
            binding["org_id"],
            binding["tenant_id"],
            "AD lab desktop",
            "ubuntu",
            "direct",
            "rdp",
        )
        plane = ControlPlane(
            (device, *ssh_devices, *managed_devices),
            {(binding["org_id"], binding["tenant_id"]): Policy()},
            direct_entitlements=frozenset({(binding["technician_id"], device.id)}),
        )
        app = create_app(
            plane,
            demo_ui=True,
            directory_config=directory_config,
            directory_provider=directory,
            directory_settings_store=integration_store,
            directory_bind_password=password,
            directory_revision=directory_revision,
            directory_provisioning_config=provisioning_config,
            directory_provisioning_store=provisioning_store,
            rotation_service=service,
            ssh_targets=ssh_targets,
            managed_ssh_targets=managed_targets,
            rdp_targets={device.id: RDPTarget("10.78.0.21", "unused", "unused", fingerprint)},
        )
        worker = install_worker_lifecycle(app, service, account_ids)
        yield app
    finally:
        # Also handle construction/server-start failures and never unlock early.
        if worker is not None:
            worker.stop(90)
        if provisioning_store is not None:
            provisioning_store.close()
        if integration_store is not None:
            integration_store.close()
        store.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Use an unprivileged local port")
    try:
        config = json.loads(private_read(args.config))
        with managed_application(config) as app:
            uvicorn.run(
                app,
                host="127.0.0.1",
                port=args.port,
                workers=1,
                access_log=False,
                log_config=None,
                log_level="critical",
                ws_max_size=16384,
                ws_max_queue=8,
            )
        return 0
    except Exception:
        print('{"state":"managed_process_failed","action":"operator_check_required"}', flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
