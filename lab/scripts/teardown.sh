#!/usr/bin/env bash
# Remove the VaultGate lab (VMs named vglab-*, their disks, and the vglab network). Asks before doing anything.
set -euo pipefail
URI="${LIBVIRT_URI:-qemu:///system}"
LAB_DIR="${LAB_DIR:-/var/lib/libvirt/images/vglab}"
echo "This will delete libvirt domains vglab-dc1, vglab-dc2, vglab-ws1, their disks in $LAB_DIR, and network vglab."
read -r -p "Type 'delete vglab' to continue: " ans
[ "$ans" = "delete vglab" ] || { echo aborted; exit 1; }
for n in vglab-dc1 vglab-dc2 vglab-ws1; do
  virsh -c "$URI" destroy "$n" 2>/dev/null || true
  virsh -c "$URI" undefine "$n" --nvram --snapshots-metadata 2>/dev/null || true
  sudo rm -f "$LAB_DIR/$n.qcow2"
done
virsh -c "$URI" net-destroy vglab 2>/dev/null || true
virsh -c "$URI" net-undefine vglab 2>/dev/null || true
echo done
