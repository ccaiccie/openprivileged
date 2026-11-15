#!/usr/bin/env python3
"""Lab proof gates G1-G4 for AD rotation (ADR-0007). Run against the KVM lab only.

    python -m venv .venv && . .venv/bin/activate && pip install -r lab/tests/requirements.txt
    set -a; . lab/.env; set +a
    python lab/tests/ad_rotation_gates.py

Gates:
  G1  delegated manager resets a test user's password over LDAPS, a fresh bind as the user succeeds (verify)
  G2  the same new password is visible on the second DC within a bounded time (replication)
  G3  delegation boundary: the manager CANNOT reset an account outside the VaultManaged OU
  G4  negative verify: the OLD password no longer works; a wrong password is rejected without locking the account
Passwords come from the environment and are generated at runtime; nothing is written to disk.
"""
from __future__ import annotations

import os
import secrets
import ssl
import string
import sys
import time

from ldap3 import ALL, NTLM, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException

DOMAIN = os.environ.get("VG_DOMAIN", "vg.lab")
NETBIOS = DOMAIN.split(".")[0].upper()
DC1, DC2 = os.environ["VG_DC1"], os.environ["VG_DC2"]
MGR = os.environ["VG_MANAGER_USER"]
MGR_PW = os.environ["VG_MANAGER_PASSWORD"]
USER = os.environ.get("VG_TEST_USER", "vgtest01")
BASE = ",".join(f"DC={p}" for p in DOMAIN.split("."))
USER_DN = f"CN={USER},OU=VaultManaged,{BASE}"
OUTSIDE_DN = f"CN=outside01,CN=Users,{BASE}"
# Lab CA is not in this machine's trust store by default. Export the CA cert and set VG_CA_FILE to verify properly.
CA_FILE = os.environ.get("VG_CA_FILE")
TLS = Tls(validate=ssl.CERT_REQUIRED if CA_FILE else ssl.CERT_NONE, ca_certs_file=CA_FILE)

results: list[tuple[str, bool, str]] = []


def gen_password() -> str:
    alphabet = string.ascii_letters + string.digits + "!#%+-=_"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(24))
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw):
            return pw


def bind(host: str, user: str, pw: str) -> Connection:
    server = Server(host, port=636, use_ssl=True, tls=TLS, get_info=ALL, connect_timeout=5)
    return Connection(server, user=f"{NETBIOS}\\{user}", password=pw, authentication=NTLM, auto_bind=True)


def record(gate: str, ok: bool, note: str = "") -> None:
    results.append((gate, ok, note))
    print(f"{'PASS' if ok else 'FAIL'}  {gate}  {note}")


def main() -> int:
    mgr = bind(DC1, MGR, MGR_PW)
    new_pw = gen_password()

    # G1: reset, then verify with a fresh bind as the user.
    t0 = time.monotonic()
    ok = mgr.extend.microsoft.modify_password(USER_DN, new_pw)
    record("G1 reset via LDAPS", bool(ok), mgr.result.get("description", ""))
    try:
        bind(DC1, USER, new_pw).unbind()
        record("G1 verify fresh bind on DC1", True, f"{time.monotonic() - t0:.2f}s")
    except LDAPException as e:
        record("G1 verify fresh bind on DC1", False, str(e))

    # G2: replication to dc2 (poll up to 60 s).
    deadline, seen = time.monotonic() + 60, None
    while time.monotonic() < deadline:
        try:
            bind(DC2, USER, new_pw).unbind()
            seen = time.monotonic() - t0
            break
        except LDAPException:
            time.sleep(1)
    record("G2 new password valid on DC2", seen is not None, f"after {seen:.1f}s" if seen else "not within 60s")

    # G3: delegation boundary.
    ok = mgr.extend.microsoft.modify_password(OUTSIDE_DN, gen_password())
    record("G3 reset outside OU is DENIED", not ok, mgr.result.get("description", ""))

    # G4: old password rejected, one wrong guess does not lock the account.
    try:
        bind(DC1, USER, "Initial-Lab-Pass-1!").unbind()
        record("G4 old password rejected", False, "old password still works")
    except LDAPException:
        record("G4 old password rejected", True)
    try:
        bind(DC1, USER, new_pw).unbind()
        record("G4 account not locked by one bad attempt", True)
    except LDAPException as e:
        record("G4 account not locked by one bad attempt", False, str(e))

    mgr.unbind()
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
