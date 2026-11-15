"""Opt-in real HTTP + SSH test of operator-configured lab targets, no secrets printed."""

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx

parser = argparse.ArgumentParser()
parser.add_argument("--inventory", required=True, type=Path)
args = parser.parse_args()
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
process = subprocess.Popen(
    [
        str(Path(sys.executable).parent / "vg-api"),
        "--demo",
        "--port",
        str(port),
        "--lab-inventory",
        str(args.inventory.resolve()),
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
    start_new_session=True,
)
try:
    passwords = {}
    assert process.stdout
    while len(passwords) < 6:
        line = process.stdout.readline()
        if not line:
            raise RuntimeError("Lab demo failed to initialize; check operator inventory")
        if " demo password: " in line:
            name, password = line.strip().split(" demo password: ", 1)
            passwords[name] = password
    with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=15) as client:
        for _ in range(100):
            try:
                client.get("/health").raise_for_status()
                break
            except httpx.HTTPError:
                time.sleep(0.1)
        login = client.post("/auth/login", json={"username": "tech", "password": passwords["tech"]})
        login.raise_for_status()
        client.headers["X-CSRF-Token"] = login.json()["csrf_token"]
        inventory = json.loads(args.inventory.read_text())
        tested = 0
        for device in inventory["devices"]:
            if "ssh" not in device or "tech" not in device.get("entitled_users", []):
                continue
            response = client.post(
                "/v1/direct-access",
                json={
                    "device_id": device["id"],
                    "reason": "Approved isolated lab SSH verification",
                    "minutes": 1,
                },
            )
            response.raise_for_status()
            grant = response.json()
            assert grant["status"] == "active" and not grant["request_id"]
            probe = client.post(f"/v1/grants/{grant['id']}/ssh-test")
            probe.raise_for_status()
            assert probe.json()["status"] == "connected" and "FRRouting" in probe.json()["output"]
            client.post(f"/v1/grants/{grant['id']}/revoke").raise_for_status()
            denied = client.post(f"/v1/grants/{grant['id']}/ssh-test")
            assert denied.status_code in (403, 409)
            print(device["id"], "direct grant + actual pinned-key SSH + revoked denial: PASS")
            tested += 1
        assert tested >= 3, "Expected three configured FRR nodes"
        assert client.get("/v1/access-requests").json() == []
        print("PASS real lab SSH through authorized HTTP API, no approval requests created.")
finally:
    os.killpg(process.pid, signal.SIGTERM)
    process.wait(timeout=10)
