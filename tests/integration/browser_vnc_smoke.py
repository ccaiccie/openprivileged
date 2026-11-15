"""Authenticated noVNC rendering/input and revocation against approved isolated lab."""

import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
script = """
from pathlib import Path
import uvicorn
from vg_api.main import create_app,demo
from vg_api.desktop_bridge import load_desktop_target
plane,tokens=demo(Path('lab/gns3/inventory.json'))
target=load_desktop_target(Path('/path/to/private-lab/desktop-credentials.json'))
app=create_app(plane,tokens,demo_ui=True,demo_passwords={'tech':'browser-test-only'},
 desktop_targets={'vg-ubuntu-vnc':target})
uvicorn.run(app,host='127.0.0.1',port=PORT,access_log=False)
""".replace("PORT", str(port))
process = subprocess.Popen(
    [sys.executable, "-c", script],
    cwd=ROOT,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    start_new_session=True,
)
base = f"http://127.0.0.1:{port}"
try:
    for _ in range(150):
        try:
            urllib.request.urlopen(base + "/health", timeout=1).close()
            break
        except urllib.error.URLError:
            time.sleep(0.1)
    else:
        raise RuntimeError("Test server did not start")
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH"))
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.add_init_script(
            "window.testCsp=[];addEventListener('securitypolicyviolation',"
            "e=>window.testCsp.push(e.effectiveDirective))"
        )
        page.goto(base)
        result = page.evaluate(
            """async()=>{
const login=await fetch('/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({username:'tech',password:'browser-test-only'})});
window.vncIdentity=await login.json();
const response=await fetch('/v1/direct-access',{method:'POST',
 headers:{'Content-Type':'application/json',
 'X-CSRF-Token':window.vncIdentity.csrf_token},body:JSON.stringify({device_id:'vg-ubuntu-vnc',
 reason:'Isolated browser test',minutes:5})});
window.vncGrant=await response.json();
const {default:RFB}=await import('/static/vendor/novnc/core/rfb.js');
const display=document.createElement('div');display.id='test-display';
Object.assign(display.style,{width:'1280px',height:'800px'});
document.body.replaceChildren(display);document.body.style.display='block';
window.disconnected=false;window.connected=false;
window.testRfb=new RFB(display,`ws://${location.host}/v1/grants/${window.vncGrant.id}/vnc-session`,
 {wsProtocols:['binary','vaultgate-csrf.'+window.vncIdentity.csrf_token]});
window.testRfb.scaleViewport=true;window.testRfb.resizeSession=false;
window.testRfb.addEventListener('connect',()=>window.connected=true);
window.testRfb.addEventListener('disconnect',()=>window.disconnected=true);
return {login:login.status,grant:response.status};
}"""
        )
        assert result == {"login": 200, "grant": 201}, result
        page.wait_for_function("() => window.connected===true", timeout=20000)
        page.wait_for_function(
            "() => document.querySelector('#test-display canvas').width===1280", timeout=10000
        )
        page.mouse.move(600, 350)
        page.mouse.click(600, 350)
        page.evaluate(
            "window.testRfb.sendKey(0xff1b,'Escape',true);"
            "window.testRfb.sendKey(0xff1b,'Escape',false)"
        )
        page.wait_for_timeout(5000)
        page.screenshot(path="/tmp/vaultgate-browser-vnc.png")
        before = page.locator("#test-display canvas").screenshot()
        # Toggle GNOME overview with an actual remote Super key event.
        page.evaluate(
            "window.testRfb.sendKey(0xffeb,'MetaLeft',true);window.testRfb.sendKey(0xffeb,'MetaLeft',false)"
        )
        page.wait_for_timeout(1200)
        after = page.locator("#test-display canvas").screenshot()
        assert before != after, "Remote keyboard input did not change framebuffer"
        page.mouse.click(640, 400)
        status = page.evaluate(
            """async()=>{const r=await fetch(`/v1/grants/${window.vncGrant.id}/revoke`,
 {method:'POST',
 headers:{'X-CSRF-Token':window.vncIdentity.csrf_token}});return r.status;}"""
        )
        assert status == 200
        page.wait_for_function("() => window.disconnected===true", timeout=4000)
        assert not errors, errors
        assert page.evaluate("window.testCsp") == []
        browser.close()
        print("PASS browser VNC: login, grant, framebuffer, input, revoke disconnect")
finally:
    os.killpg(process.pid, signal.SIGTERM)
    process.wait(timeout=10)
