"""Opt-in real SSH/RDP browser sessions against the approved local lab."""

import argparse
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

parser = argparse.ArgumentParser()
parser.add_argument("--inventory", required=True)
parser.add_argument("--desktop-credentials", required=True)
parser.add_argument("--rdp-manifest", required=True)
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
        args.inventory,
        "--desktop-credentials",
        args.desktop_credentials,
        "--rdp-manifest",
        args.rdp_manifest,
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
            raise RuntimeError("Server initialization failed")
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
        closed = []
        page.on("websocket", lambda ws: ws.on("close", lambda: closed.append(True)))
        page.goto(url)
        page.locator('#login-form [name="username"]').fill("tech")
        page.locator('#login-form [name="password"]').fill(passwords["tech"])
        page.locator("#login-submit").click()
        expect(page.locator("#device-count")).to_have_text("6")
        grant = page.evaluate("""async()=>await api('/v1/direct-access','POST',
            {device_id:'vg-ubuntu-rdp',reason:'Browser interactive RDP test',minutes:1})""")
        page.evaluate("async()=>{await refresh();navigate('grants');}")
        page.get_by_role("button", name="Open RDP", exact=True).click()
        page.wait_for_function(
            """()=>{
            const c=activeSession.guac.getDisplay().flatten();
            if(!c||c.width<600)return false;
            const p=c.getContext('2d').getImageData(0,0,c.width,c.height).data;
            const colors=new Set();
            for(let i=0;i<p.length;i+=400)colors.add(p[i]+','+p[i+1]+','+p[i+2]);
            return colors.size>20;
        }""",
            timeout=15000,
        )
        page.locator("#desktop-container").click(position={"x": 100, "y": 100})
        page.keyboard.press("Control+Alt+t")
        page.wait_for_timeout(2000)
        page.keyboard.type("printf 'VAULTGATE_RDP_INTERACTIVE_OK\\n'")
        page.keyboard.press("Enter")
        page.wait_for_timeout(7000)
        assert not closed, "RDP closed before revocation"
        page.screenshot(path="/tmp/vaultgate-interactive-rdp.png", full_page=True)
        page.evaluate("async id=>await api('/v1/grants/'+id+'/revoke','POST')", grant["id"])
        expect(page.locator("#session-status")).to_contain_text("Disconnected", timeout=5000)
        assert closed, "RDP WebSocket did not close after revocation"
        assert not errors, errors
        print("PASS actual RDP framebuffer/input and revoke disconnect; no browser credentials")
        browser.close()
finally:
    os.killpg(process.pid, signal.SIGTERM)
    process.wait(timeout=10)
