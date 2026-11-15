"""Isolated browser validation of direct entitlement; never claims a real SSH connection."""

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

with tempfile.TemporaryDirectory() as tmp:
    inventory = Path(tmp) / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "devices": [
                    {
                        "id": "frr-test",
                        "name": "Test FRR (unconfigured)",
                        "platform": "frr",
                        "protocol": "ssh",
                        "entitled_users": ["tech"],
                    }
                ]
            }
        )
    )
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
            str(inventory),
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
                raise RuntimeError("Demo initialization failed")
            if " demo password: " in line:
                name, password = line.strip().split(" demo password: ", 1)
                passwords[name] = password
        url = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                urllib.request.urlopen(url + "/health", timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)
        with sync_playwright() as pw:
            browser = pw.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH"))
            page = browser.new_page(viewport={"width": 390, "height": 844})
            page.goto(url)
            page.locator('#login-form [name="username"]').fill("tech")
            page.locator('#login-form [name="password"]').fill(passwords["tech"])
            page.locator("#login-submit").click()
            expect(page.locator("#device-count")).to_have_text("2")
            expect(page.locator("#devices")).to_be_visible()
            page.get_by_role("button", name="Connect", exact=True).click()
            expect(page.locator("#request-dialog")).not_to_be_visible()
            expect(page.locator("#feedback")).to_contain_text("transport is not configured")
            expect(page.locator("#request-count")).to_have_text("0")
            page.get_by_role("button", name="Connect", exact=True).click()
            page.locator('nav button[data-view="grants"]').click()
            expect(page.locator("#grant-list .badge")).to_have_count(1)
            expect(page.locator("#grant-list .badge")).to_have_text("active")
            expect(page.locator("#grant-list")).to_contain_text("no time limit")
            expect(page.locator("#grant-list")).to_contain_text("SSH endpoint not configured")
            expect(page.get_by_role("button", name="Test SSH", exact=True)).to_have_count(0)
            page.get_by_role("button", name="Revoke", exact=True).click()
            expect(page.locator("#grant-list .badge")).to_have_text("revoked")
            page.locator('nav button[data-view="devices"]').click()
            page.get_by_role("button", name="Request access", exact=True).click()
            expect(page.locator('[name="minutes"]')).to_be_visible()
            page.locator("#cancel").click()
            expect(page.locator("#request-dialog")).not_to_be_visible()
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            browser.close()
            print(
                "PASS direct entitlement without approval, honest unconfigured SSH, revoke/mobile."
            )
    finally:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=10)
