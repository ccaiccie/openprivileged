"""Opt-in real SSH/VNC browser sessions against the approved local lab."""

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
        page.goto(url)
        page.locator('#login-form [name="username"]').fill("tech")
        page.locator('#login-form [name="password"]').fill(passwords["tech"])
        page.locator("#login-submit").click()
        expect(page.locator("#device-count")).to_have_text("6")
        grant = page.evaluate("""async()=>await api('/v1/direct-access','POST',
            {device_id:'vg-frr-1',reason:'Browser interactive SSH test',minutes:1})""")
        page.evaluate("async()=>{await refresh();navigate('grants');}")
        page.get_by_role("button", name="Open SSH", exact=True).click()
        expect(page.locator("#session-status")).to_contain_text("Connected", timeout=15000)
        page.locator(".xterm-helper-textarea").focus()
        page.keyboard.type("printf 'VAULTGATE_SSH_INTERACTIVE_OK\\n'")
        page.keyboard.press("Enter")
        page.wait_for_function(
            """()=>Array.from(
            {length:activeSession.term.buffer.active.length},(_,i)=>
            activeSession.term.buffer.active.getLine(i)?.translateToString().trim())
            .includes('VAULTGATE_SSH_INTERACTIVE_OK')""",
            timeout=15000,
        )
        page.screenshot(path="/tmp/vaultgate-interactive-ssh.png", full_page=True)
        page.evaluate("async id=>await api('/v1/grants/'+id+'/revoke','POST')", grant["id"])
        expect(page.locator("#session-status")).to_contain_text("Disconnected", timeout=5000)
        page.locator("#close-session").click()
        print("PASS actual SSH terminal input/output and revoke disconnect")
        grant = page.evaluate("""async()=>await api('/v1/direct-access','POST',
            {device_id:'vg-ubuntu-vnc',reason:'Browser interactive VNC test',minutes:1})""")
        page.evaluate("async()=>{await refresh();navigate('grants');}")
        page.get_by_role("button", name="Open desktop", exact=True).click()
        expect(page.locator("#session-status")).to_contain_text(
            "Connected · server-authorized VNC", timeout=20000
        )
        canvas = page.locator("#desktop-container canvas")
        expect(canvas).to_be_visible()
        page.wait_for_function(
            """()=>{
            const c=document.querySelector('#desktop-container canvas');
            if(!c||c.width<600)return false;
            const p=c.getContext('2d').getImageData(0,0,c.width,c.height).data;
            const colors=new Set();
            for(let i=0;i<p.length;i+=400)colors.add(p[i]+','+p[i+1]+','+p[i+2]);
            return colors.size>20;
        }""",
            timeout=15000,
        )
        canvas.click(position={"x": 100, "y": 100})
        page.keyboard.press("Control+Alt+t")
        page.wait_for_timeout(2000)
        page.screenshot(path="/tmp/vaultgate-interactive-vnc.png", full_page=True)
        page.evaluate("async id=>await api('/v1/grants/'+id+'/revoke','POST')", grant["id"])
        expect(page.locator("#session-status")).to_contain_text("Disconnected", timeout=5000)
        assert not errors, errors
        print("PASS actual VNC framebuffer/input and revoke disconnect; no browser credentials")
        browser.close()
finally:
    os.killpg(process.pid, signal.SIGTERM)
    process.wait(timeout=10)
