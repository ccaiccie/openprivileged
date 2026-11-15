"""Exercise the real localhost login UI with generated credentials, never printing secrets."""

import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

root = Path(__file__).resolve().parents[2]
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
p = subprocess.Popen(
    [str(Path(sys.executable).parent / "vg-api"), "--demo", "--port", str(port)],
    cwd=root,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
    start_new_session=True,
)
try:
    passwords = {}
    assert p.stdout
    while len(passwords) < 6:
        line = p.stdout.readline()
        if not line:
            raise RuntimeError("Demo failed to initialize")
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
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))

        def login(username, password=None):
            page.locator('#login-form [name="username"]').fill(username)
            page.locator('#login-form [name="password"]').fill(password or passwords[username])
            page.locator("#login-submit").click()
            expect(page.locator("#login-screen")).not_to_be_visible()
            expect(page.locator("#account-label")).to_contain_text(username)

        def logout():
            page.locator("#logout").click()
            expect(page.locator("#login-screen")).to_be_visible()

        def request(ticket):
            page.locator('nav button[data-view="devices"]').click()
            page.locator("#device-list button").click()
            page.locator('[name="reason"]').fill("Browser <script>literal text</script>")
            page.locator('[name="ticket_ref"]').fill(ticket)
            page.locator("#submit").click()
            expect(page.locator("#request-list .badge").first).to_have_text("pending")

        page.goto(url + "/admin")
        expect(page.locator("#login-screen")).to_be_visible()
        page.locator('#login-form [name="username"]').fill("tech")
        page.locator('#login-form [name="password"]').fill("wrong-password")
        page.locator("#login-submit").click()
        expect(page.locator("#login-error")).to_contain_text("Invalid")
        login("tech")
        expect(page.locator("#role")).not_to_be_visible()
        expect(page.locator("#device-count")).to_have_text("1")
        page.goto(url + "/admin")
        expect(page.locator("#account-label")).to_contain_text("tech")
        expect(page.locator("#portal-label")).to_have_text("technician")
        expect(page.locator('nav button[data-view="users"]')).not_to_be_visible()
        request("LAB-LOGIN")
        page.reload()
        expect(page.locator("#account-label")).to_contain_text("tech")
        logout()
        login("reviewer")
        page.locator('nav button[data-view="requests"]').click()
        page.get_by_role("button", name="Approve", exact=True).click()
        expect(page.locator("#request-list .badge").first).to_have_text("approved")
        logout()
        login("auditor")
        page.locator('nav button[data-view="grants"]').click()
        expect(page.get_by_role("button", name="Revoke", exact=True)).to_have_count(0)
        page.locator('nav button[data-view="audit"]').click()
        page.locator("#verify").click()
        expect(page.locator("#verification")).to_contain_text("Chain verified")
        logout()
        login("multi")
        expect(page.locator("#role")).to_be_visible()
        assert page.locator("#role option").all_text_contents() == ["technician", "approver"]
        request("LAB-MULTI")
        page.locator("#role").select_option("approver")
        expect(page.locator("#role")).to_have_value("approver")
        page.locator('nav button[data-view="requests"]').click()
        expect(page.get_by_role("button", name="Approve", exact=True)).to_have_count(0)
        logout()
        login("superadmin")
        expect(page.locator("#title")).to_have_text("Users & groups")
        expect(page.locator('nav button[data-view="devices"]')).not_to_be_visible()
        page.locator('#new-user-form [name="username"]').fill("browser-user")
        page.locator("#create-user").click()
        expect(page.locator("#user-error")).to_have_text(
            "Choose at least one group to assign a role."
        )
        assert page.locator('#new-user-form [name="username"]').input_value() == "browser-user"
        message = page.evaluate(
            """async()=>{
              try{await api('/v1/users','POST',{username:'bad name',groups:['technicians']});}
              catch(e){return e.message;}
            }"""
        )
        assert "Username must be 3–32" in message
        page.locator('#new-user-groups input[value="technicians"]').check()
        page.locator('#new-user-groups input[value="auditors"]').check()
        page.locator("#create-user").click()
        expect(page.locator("#new-password")).to_contain_text("Created browser-user")
        new_password = page.locator("#new-password").inner_text().split("once): ", 1)[1]
        page.screenshot(path="/tmp/vaultgate-login-desktop.png", full_page=True)
        logout()
        login("browser-user", new_password)
        expect(page.locator("#role")).to_be_visible()
        assert page.locator("#role option").all_text_contents() == ["technician", "auditor"]
        page.set_viewport_size({"width": 390, "height": 844})
        page.locator("#role").select_option("auditor")
        page.locator('nav button[data-view="audit"]').click()
        page.locator("#verify").click()
        expect(page.locator("#verification")).to_contain_text("Chain verified")
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.screenshot(path="/tmp/vaultgate-login-mobile.png", full_page=True)
        logout()
        page.reload()
        expect(page.locator("#login-screen")).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        assert not errors, errors
        browser.close()
        print(
            "PASS login, logout, roles, URL isolation, approval, audit, superadmin and mobile UI."
        )
finally:
    os.killpg(p.pid, signal.SIGTERM)
    p.wait(timeout=10)
