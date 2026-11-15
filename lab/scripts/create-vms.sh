#!/usr/bin/env bash
# Create the VaultGate lab network and three Windows Server VMs (dc1, dc2, ws1) with libvirt.
# SAFE BY DEFAULT: prints the commands. Set APPLY=1 to execute. Only touches objects named vglab / vglab-*.
#   cp lab/.env.example lab/.env   # edit ISO paths
#   lab/scripts/create-vms.sh      # dry run
#   APPLY=1 lab/scripts/create-vms.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
[ -f "$HERE/.env" ] && set -a && . "$HERE/.env" && set +a
: "${WIN_ISO:?set WIN_ISO in lab/.env}" "${VIRTIO_ISO:?set VIRTIO_ISO in lab/.env}"
LAB_DIR="${LAB_DIR:-/var/lib/libvirt/images/vglab}"
URI="${LIBVIRT_URI:-qemu:///system}"

# Newest Windows Server variant this host's osinfo database knows (win2k22 may be missing on older distros).
if [ -z "${OS_VARIANT:-}" ]; then
  for v in win2k25 win2k22 win2k19 win2k16; do
    if osinfo-query os short-id="$v" >/dev/null 2>&1 && [ -n "$(osinfo-query os short-id="$v" -f short-id 2>/dev/null | tail -n +3)" ]; then OS_VARIANT="$v"; break; fi
  done
  OS_VARIANT="${OS_VARIANT:-win2k19}"
fi
echo "using os-variant: $OS_VARIANT"

run() { echo "+ $*"; [ "${APPLY:-0}" = "1" ] && "$@" || true; }

for f in "$WIN_ISO" "$VIRTIO_ISO"; do [ -f "$f" ] || { echo "missing file: $f" >&2; exit 1; }; done

run sudo mkdir -p "$LAB_DIR"
if ! virsh -c "$URI" net-info vglab >/dev/null 2>&1; then
  run virsh -c "$URI" net-define "$HERE/libvirt/vglab-net.xml"
fi
run virsh -c "$URI" net-autostart vglab
run virsh -c "$URI" net-start vglab || true

# name vcpus ram_mb disk_gb
VMS=("vglab-dc1 2 4096 60" "vglab-dc2 2 4096 60" "vglab-ws1 2 4096 60")
for spec in "${VMS[@]}"; do
  read -r name cpus ram disk <<<"$spec"
  if virsh -c "$URI" dominfo "$name" >/dev/null 2>&1; then echo "exists, skipping: $name"; continue; fi
  run sudo qemu-img create -f qcow2 "$LAB_DIR/$name.qcow2" "${disk}G"
  run virt-install --connect "$URI" --name "$name" \
    --vcpus "$cpus" --memory "$ram" --cpu host-passthrough \
    --disk path="$LAB_DIR/$name.qcow2",format=qcow2,bus=virtio \
    --cdrom "$WIN_ISO" \
    --disk path="$VIRTIO_ISO",device=cdrom \
    --network network=vglab,model=virtio \
    --os-variant "$OS_VARIANT" --boot uefi --graphics spice \
    --noautoconsole
done

cat <<'EOF'

Next (manual, inside each VM; load the virtio storage driver from the second CD during setup):
  1. Install "Windows Server 2022 Standard Evaluation (Desktop Experience)".
  2. Set the local Administrator password to your lab password.
  3. Run the scripts in lab/windows/ in order (copy via a shared ISO, or paste into PowerShell).
  4. Take a libvirt snapshot after each stage:  virsh snapshot-create-as vglab-dc1 post-ad
EOF
