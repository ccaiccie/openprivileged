#!/usr/bin/env python3
"""Lab proof gate G5: rotate a local administrator on ws1 over WinRM-HTTPS (ADR-0007) and verify it.

    set -a; . lab/.env; set +a
    python lab/tests/local_admin_gate.py

Steps: connect as the domain admin over WinRM 5986, set a new password for the local account, then open a
fresh WinRM session as that local account with the new password (verify). The lab certificate is self-signed,
so certificate validation is off here; production must validate against the customer CA.
"""
from __future__ import annotations

import os
import secrets
import string
import sys

from pypsrp.client import Client

WS1 = os.environ["VG_WS1"]
ADMIN_USER = os.environ["VG_WS_ADMIN_USER"]
ADMIN_PW = os.environ["VG_WS_ADMIN_PASSWORD"]
LOCAL = os.environ.get("VG_LOCAL_ADMIN", "vgadmin")


def gen_password() -> str:
    alphabet = string.ascii_letters + string.digits + "!#%+-=_"
    return "A1a-" + "".join(secrets.choice(alphabet) for _ in range(24))


def client(user: str, pw: str) -> Client:
    return Client(WS1, username=user, password=pw, ssl=True, port=5986, cert_validation=False, auth="negotiate")


def main() -> int:
    new_pw = gen_password()
    admin = client(ADMIN_USER, ADMIN_PW)
    # The generated password only contains letters, digits and !#%+-=_, so embedding it in single quotes is safe.
    ps = f"Set-LocalUser -Name '{LOCAL}' -Password (ConvertTo-SecureString '{new_pw}' -AsPlainText -Force)"
    _, streams, had_errors = admin.execute_ps(ps)
    if had_errors:
        print("FAIL G5 set password:", [str(e) for e in streams.error])
        return 1
    print("PASS G5 set password")

    try:
        user = client(f".\\{LOCAL}", new_pw)
        who, _, errs = user.execute_ps("whoami")
        ok = not errs and LOCAL.lower() in who.lower()
    except Exception as e:  # noqa: BLE001 - lab script, report any failure
        print("FAIL G5 verify new password:", e)
        return 1
    print("PASS G5 verify with fresh session" if ok else "FAIL G5 verify with fresh session")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
