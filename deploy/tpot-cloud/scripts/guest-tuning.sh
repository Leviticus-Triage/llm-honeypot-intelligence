#!/usr/bin/env bash
# VM 400 (tpot-honeypot) guest tuning — run as root inside the VM (or via qm guest exec).
set -euo pipefail

echo "[guest-tuning] zram + swapfile + sysctl (persistent)"

# --- zram: survives reboot via systemd oneshot ---
install -d -m 755 /usr/local/sbin
cat > /usr/local/sbin/zram-swap.sh <<'ZRAM'
#!/bin/bash
set -e
modprobe zram num_devices=1
echo lz4 > /sys/block/zram0/comp_algorithm
echo $((4 * 1024 * 1024 * 1024)) > /sys/block/zram0/disksize
if ! swapon --show | grep -q zram0; then
  mkswap /dev/zram0
  swapon -p 100 /dev/zram0
fi
ZRAM
chmod 755 /usr/local/sbin/zram-swap.sh

echo zram > /etc/modules-load.d/zram.conf

cat > /etc/systemd/system/zram-swap.service <<'UNIT'
[Unit]
Description=Enable zram compressed swap
After=local-fs.target
Before=swap.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/zram-swap.sh

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now zram-swap.service

# --- extra swapfile (8G) ---
if [[ ! -f /swapfile2 ]]; then
  # dd not fallocate — swapon rejects sparse/hole files on some filesystems
  dd if=/dev/zero of=/swapfile2 bs=1M count=8192 status=progress
  chmod 600 /swapfile2
  mkswap /swapfile2
fi
if ! swapon --show | grep -q swapfile2; then
  swapon /swapfile2
fi
grep -q swapfile2 /etc/fstab || echo '/swapfile2 none swap sw 0 0' >> /etc/fstab

# --- sysctl (idempotent) ---
cat > /etc/sysctl.d/99-tpot-tuning.conf <<'EOF'
vm.swappiness=20
vm.max_map_count=262144
EOF
sysctl -p /etc/sysctl.d/99-tpot-tuning.conf

# LLM runs on VM 200 — disable local Ollama if present
systemctl disable --now ollama 2>/dev/null || true
systemctl mask ollama 2>/dev/null || true

echo "[guest-tuning] done"
swapon --show
free -h
