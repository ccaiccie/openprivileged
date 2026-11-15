"""Opt-in real guacd certificate-pin test against the approved isolated desktop."""

import argparse
import asyncio
from dataclasses import replace
from pathlib import Path

from vg_api.rdp_bridge import connect_rdp, instruction, load_rdp_target, read_instruction

parser = argparse.ArgumentParser()
parser.add_argument("--desktop-credentials", type=Path, required=True)
parser.add_argument("--rdp-manifest", type=Path, required=True)
args = parser.parse_args()
target = load_rdp_target(args.desktop_credentials.absolute(), args.rdp_manifest.absolute())


async def probe(target, valid):
    reader, writer = await connect_rdp(target)
    try:
        async with asyncio.timeout(30):
            while True:
                parts = await read_instruction(reader)
                if parts[0] == "sync":
                    writer.write(instruction(*parts))
                    await writer.drain()
                if parts[0] == "error":
                    assert not valid and parts[-1] == "519", "Unexpected RDP error"
                    return
                if parts[0] in ("img", "png", "jpeg", "blob"):
                    assert valid, "Mismatched certificate was not rejected"
                    return
    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    await probe(target, True)
    await probe(replace(target, fingerprint="00:" * 31 + "00"), False)
    print("PASS pinned RDP renders; mismatched SHA256 certificate rejected before display")


asyncio.run(main())
