"""Browser integration with fictional in-memory AD; no DC or live demo touched."""

import os
import runpy
import socket
import threading
import time
from pathlib import Path

import uvicorn
from playwright.sync_api import expect, sync_playwright

root = Path(__file__).resolve().parents[2]
fixtures = runpy.run_path(str(root / "tests/unit/test_directory_auth.py"))
client, provider = fixtures["setup"]()
with socket.socket() as probe:
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
server = uvicorn.Server(uvicorn.Config(client.app, host="127.0.0.1", port=port, log_level="error"))
worker = threading.Thread(target=server.run, daemon=True)
worker.start()
try:
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    assert server.started
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH"))
        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(f"http://127.0.0.1:{port}")
        page.locator('[name="username"]').first.fill("boss")
        page.locator('[name="password"]').fill("test-only-password")
        page.locator('#login-submit').click()
        expect(page.locator('#directory-sync')).to_be_visible()
        expect(page.locator('#new-user-form')).to_be_hidden()
        page.locator('#directory-sync').click()
        expect(page.locator('#user-list')).to_contain_text('Alice Test')
        expect(page.locator('#user-list')).to_contain_text('alice@example.invalid')
        expect(page.locator('#user-list')).to_contain_text('Managed in Active Directory')
        page.locator('#logout').click()
        page.locator('[name="username"]').first.fill("alice")
        page.locator('[name="password"]').fill("test-only-password")
        page.locator('#login-submit').click()
        expect(page.locator('#role')).to_be_visible()
        page.locator('#role').select_option('auditor')
        page.locator('nav button[data-view="audit"]').click()
        page.locator('#verify').click()
        expect(page.locator('#verification')).to_contain_text('Chain verified')
        assert not errors, errors
        browser.close()
    print('AD browser smoke passed: login, directory sync, populated profile, read-only users')
finally:
    server.should_exit = True
    worker.join(timeout=10)
    assert not worker.is_alive()
