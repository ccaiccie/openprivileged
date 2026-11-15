"""AD integration editor browser smoke using synthetic records only."""

import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

import uvicorn
from playwright.sync_api import expect, sync_playwright

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / "tests/unit"))
from test_directory_management import application  # noqa: E402

with tempfile.TemporaryDirectory() as temporary:
    client, provider, store, cfg = application(Path(temporary))
    provider.list_groups = lambda: [
        {"name": "Owners", "dn": "CN=Owners,DC=test"},
        {"name": "Tech", "dn": "CN=Tech,DC=test"},
        {"name": "Reviewers", "dn": "CN=Reviewers,DC=test"},
    ]
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(client.app, host="127.0.0.1", port=port, log_level="error")
    )
    worker = threading.Thread(target=server.run, daemon=True)
    worker.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        assert server.started
        with (
            patch("vg_api.directory_management.LdapsDirectory", return_value=provider),
            sync_playwright() as pw,
        ):
            browser = pw.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH"))
            page = browser.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))

            def sign_in():
                page.locator('#login-form [name="username"]').fill("boss")
                page.locator('#login-form [name="password"]').fill("test-only-password")
                page.locator("#login-submit").click()
                expect(page.locator("#users")).to_be_visible()
                expect(page.locator("#directory-panel")).to_be_hidden()
                expect(page.locator('nav button[data-view="directory"]')).to_be_visible()
                page.locator('nav button[data-view="directory"]').click()
                expect(page.locator("#title")).to_have_text("Setup AD")
                expect(page.locator("#directory-panel")).to_be_visible()
                expect(page.locator("#users")).to_be_hidden()

            page.goto(f"http://127.0.0.1:{port}/admin")
            sign_in()
            page.locator('nav button[data-view="users"]').click()
            expect(page.locator("#directory-panel")).to_be_hidden()
            expect(page.locator("#users")).to_be_visible()
            page.locator('nav button[data-view="directory"]').click()
            form = page.locator("#directory-form")
            expect(form.locator('[name="host"]')).to_have_value(cfg.host)
            expect(form.locator('[name="bind_password"]')).to_have_value("")
            form.locator('[name="host"]').fill("discard.invalid")
            page.locator("#directory-cancel").click()
            expect(form.locator('[name="host"]')).to_have_value(cfg.host)
            page.locator("#directory-load-groups").click()
            expect(page.locator("#directory-message")).to_contain_text("3 groups loaded")
            page.locator("#directory-group-picker").select_option("CN=Reviewers,DC=test")
            page.locator("#directory-add-group").click()
            expect(page.locator("#directory-mappings fieldset")).to_have_count(3)
            page.locator("#directory-add-group").click()
            expect(page.locator("#directory-message")).to_contain_text("already mapped")
            mapping = page.locator("#directory-mappings fieldset").last
            mapping.get_by_label("approver", exact=True).check()
            mapping.get_by_label("One (one)", exact=True).check()
            page.locator("#directory-test").click()
            expect(page.locator("#directory-message")).to_contain_text("Verified LDAPS")
            page.locator("#directory-cancel").click()
            expect(page.locator("#directory-mappings fieldset")).to_have_count(2)
            page.locator("#provision-load").click()
            expect(page.locator("#provision-status")).to_contain_text("creation is disabled")
            expect(page.locator("#provision-form")).to_be_hidden()
            # Exercise staging consent UI with mocked endpoints; no AD writes.
            page.locator('nav button[data-view="users"]').click()
            page.locator("#directory-sync").click()
            expect(page.locator("#feedback")).to_contain_text("Imported")
            page.locator('nav button[data-view="directory"]').click()
            page.route("**/v1/directory/provisioning", lambda route: route.fulfill(json={
                "enabled": True, "target_ou_dn": "OU=Managed,DC=test", "permissions": "Scoped"
            }))
            page.route("**/v1/directory/provisioning/preview", lambda route: route.fulfill(json={
                "username": "a.alice", "exists": False, "target_ou_dn": "OU=Managed,DC=test"
            }))
            page.route("**/v1/directory/provisioning/create", lambda route: route.fulfill(json={
                "username": "a.alice", "state": "disabled_pending_enrollment"
            }))
            page.locator("#provision-load").click()
            expect(page.locator("#provision-form")).to_be_visible()
            page.locator("#provision-user").select_option(index=1)
            page.locator("#provision-preview").click()
            expect(page.locator("#provision-confirm")).to_be_visible()
            expect(page.locator("#provision-credentials")).to_be_hidden()
            page.locator("#provision-consent").check()
            expect(page.locator("#provision-credentials")).to_be_visible()
            page.locator("#provision-password").fill("synthetic-one-use")
            page.locator("#provision-cancel").click()
            expect(page.locator("#provision-password")).to_have_value("")
            expect(page.locator("#provision-confirm")).to_be_hidden()
            page.locator("#provision-preview").click()
            page.locator("#provision-consent").check()
            page.locator("#provision-writer").fill("CN=Creator,DC=test")
            page.locator("#provision-password").fill("synthetic-one-use")
            page.locator("#provision-create").click()
            expect(page.locator("#provision-status")).to_contain_text("disabled pending")
            expect(page.locator("#provision-password")).to_have_value("")
            for _ in range(2):
                page.locator("#directory-test").click()
                expect(page.locator("#directory-message")).to_contain_text("Verified LDAPS")
            form.locator('[name="bind_password"]').fill("new-synthetic-reader")
            page.locator("#directory-save").click()
            expect(page.locator("#login-screen")).to_be_visible()
            expect(page.locator("#login-error")).to_contain_text("integration saved")
            sign_in()
            expect(form.locator('[name="bind_password"]')).to_have_value("")
            page.locator("#logout").click()
            page.locator('#login-form [name="username"]').fill("alice")
            page.locator('#login-form [name="password"]').fill("test-only-password")
            page.locator("#login-submit").click()
            expect(page.locator("#devices")).to_be_visible()
            expect(page.locator('nav button[data-view="directory"]')).to_be_hidden()
            expect(page.locator("#directory-panel")).to_be_hidden()
            assert not errors, errors
            browser.close()
        print(
            "AD management browser smoke passed: view, group discovery, role/device pickers, "
            "duplicate guard, discard, "
            "repeat test, save/logout/relogin"
        )
    finally:
        server.should_exit = True
        worker.join(timeout=10)
