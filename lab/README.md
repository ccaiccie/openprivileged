# OpenPrivileged KVM lab

A local, isolated lab to prove the Windows / AD / RDP design (ADR-0007, ADR-0008) before spending on GCP.
Everything here is written but **not yet run**: treat it as untested until you have executed each stage.
Nothing touches your LAN: the lab network `vglab` (10.77.0.0/24) has no uplink.

## Layout
| Path | Purpose |
|------|---------|
| `libvirt/vglab-net.xml` | Isolated host-only network |
| `scripts/create-vms.sh` | Defines the network and 3 Windows Server VMs. **Dry run unless `APPLY=1`** |
| `scripts/teardown.sh` | Deletes only `vglab-*` VMs, their disks and the `vglab` network, after a typed confirmation |
| `windows/01..05-*.ps1` | Forest, CA + delegated manager account, replica DC, member server (RDP, WinRM-HTTPS), dependent-service test |
| `docker/compose.yml` | `guacd` (RDP mode A), Postgres/Redis/MinIO (stand-ins for Cloud SQL/Memorystore/GCS), `rdp-proxy` spike |
| `spike-rdp-proxy/` | Mode B go/no-go spike with tests T1 to T7 |
| `tests/` | Automated proof gates for AD and local-admin rotation |

## Topology
```
host 10.77.0.1 ── virbr-vglab ──┬─ vglab-dc1  10.77.0.11  AD DS, DNS, CA (vg.lab)
                                ├─ vglab-dc2  10.77.0.12  replica DC
                                └─ vglab-ws1  10.77.0.21  member server: RDP+NLA, WinRM 5986, local admin, service
docker (on host): guacd, rdp-proxy (spike), postgres/redis/minio
```

## Prerequisites
- Windows Server 2022 **evaluation** ISO (Microsoft Evaluation Center; 180-day licence) and the virtio-win ISO.
- `cp lab/.env.example lab/.env` and fill in paths. `.env` is git-ignored. Use throwaway lab passwords only.

## Run order
1. `lab/scripts/create-vms.sh` (review the printed commands), then `APPLY=1 lab/scripts/create-vms.sh`.
2. Install Windows in each VM, then run `windows/01` on dc1, `02` on dc1, `03` on dc2, `04` on ws1, `05` on ws1. Snapshot after each stage (`virsh snapshot-create-as`).
3. `docker compose -f lab/docker/compose.yml up -d guacd` and optionally `--profile platform`.
4. Tests: `python -m venv lab/tests/.venv && . lab/tests/.venv/bin/activate && pip install -r lab/tests/requirements.txt && set -a && . lab/.env && set +a && python lab/tests/ad_rotation_gates.py && python lab/tests/local_admin_gate.py`.

## Proof gates (all must pass before a GCP dev deployment)
| Gate | What it proves | How |
|------|----------------|-----|
| G1 | Delegated manager can reset an AD password over LDAPS and verify it | `ad_rotation_gates.py` |
| G2 | New password valid on the second DC within 60 s (replication handling) | `ad_rotation_gates.py` |
| G3 | Delegation is least-privilege: reset outside `VaultManaged` is denied | `ad_rotation_gates.py` |
| G4 | Old password rejected; one bad attempt does not lock the account | `ad_rotation_gates.py` |
| G5 | Local admin rotates over WinRM-HTTPS and verifies | `local_admin_gate.py` |
| G6 | Dependent service on ws1 still starts after its account is rotated and the service credential updated | manual with `05-ws1-dependent-service.ps1` until the driver exists |
| G7 | Mode A: browser RDP via guacd with the password injected server-side, session recorded, clipboard blocked | manual, then automated once the broker exists |
| G8 | Mode B go/no-go | `spike-rdp-proxy/README.md` (T1 to T7) |
| G9 | Collector pattern: with the lab network egress-only from the "customer" side, rotation and RDP target legs work with no inbound path from the broker | firewall the VMs to deny inbound from the broker, run G1 and G7 via the collector |
| G10 | Core flow (request, approve, broker, record, expire, rotate) end to end | needs the product code; add as services land in `docker/compose.yml` |

G1 to G5 can run as soon as the VMs exist, because they use test clients rather than OpenPrivileged code. G6, G7, G9 and G10 become real tests as the product is built.

## Known limits
- Does not exercise GCP services (Cloud Run, KMS, Armor, NAT, WIF); MinIO and local keys are stand-ins. Follow with a `terraform plan` in a dev project.
- Scripts and the proxy config format are unverified against your exact Windows and FreeRDP versions.
- Lab certificates: for realistic LDAPS and RDP trust, export the `VG-Lab-CA` root and set `VG_CA_FILE` for the tests.
