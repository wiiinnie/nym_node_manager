#!/usr/bin/env bash
# install-nym-extra-blocks.sh
# Installs nym-extra-blocks: a runtime script + systemd unit that re-applies
# destination REJECTs AND a per-source rate-limit to NYM-EXIT on every nym-node start.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

SCRIPT=/usr/local/sbin/nym-extra-blocks.sh
UNIT=/etc/systemd/system/nym-extra-blocks.service

# --- the runtime script (written locally; never fetched-to-execute at boot) ---
cat > "$SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
LIST_URL="https://raw.githubusercontent.com/wiiinnie/nym_node_manager/refs/heads/main/blocklist.txt"
CACHE="/var/lib/nym-extra-blocks/blocklist.txt"
CHAIN="NYM-EXIT"
IP_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'
mkdir -p "$(dirname "$CACHE")"

# fetch IP blocklist (keep last-known-good on failure)
if curl -fsS --max-time 15 "$LIST_URL" -o "${CACHE}.new"; then
    mv "${CACHE}.new" "$CACHE"
else
    echo "fetch failed, using cached list" >&2; rm -f "${CACHE}.new"
fi

iptables -nL "$CHAIN" >/dev/null 2>&1 || { echo "$CHAIN not present yet"; exit 0; }

# per-source scan/enumeration rate-limit.
# Remove any prior copies first so re-runs don't stack duplicates, then insert.
# -I pushes to top, so insert in reverse of desired order:
#   final order -> 1) ESTABLISHED/RELATED accept  2) NEW up-to-rate accept  3) NEW over-rate drop
iptables -D "$CHAIN" -p tcp -m conntrack --ctstate NEW -j DROP 2>/dev/null || true
iptables -D "$CHAIN" -p tcp -m conntrack --ctstate NEW -m hashlimit \
    --hashlimit-mode srcip --hashlimit-upto 50/sec --hashlimit-burst 200 \
    --hashlimit-name nym_scan -j ACCEPT 2>/dev/null || true
iptables -D "$CHAIN" -p tcp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

iptables -I "$CHAIN" -p tcp -m conntrack --ctstate NEW -j DROP
iptables -I "$CHAIN" -p tcp -m conntrack --ctstate NEW -m hashlimit \
    --hashlimit-mode srcip --hashlimit-upto 50/sec --hashlimit-burst 200 \
    --hashlimit-name nym_scan -j ACCEPT
iptables -I "$CHAIN" -p tcp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# destination IP blocks (inserted last => end up above the rate-limit rules => evaluated first)
count=0
if [ -f "$CACHE" ]; then
  while IFS= read -r line; do
    ip="${line%%#*}"; ip="$(echo "$ip" | xargs)"
    [ -z "$ip" ] && continue
    [[ "$ip" =~ $IP_RE ]] || { echo "skipping invalid: $ip" >&2; continue; }
    iptables -C "$CHAIN" -d "$ip" -j REJECT --reject-with icmp-port-unreachable 2>/dev/null \
      || iptables -I "$CHAIN" -d "$ip" -j REJECT --reject-with icmp-port-unreachable
    count=$((count+1))
  done < "$CACHE"
fi

echo "applied rate-limit + $count block entries to $CHAIN"
EOF
chmod +x "$SCRIPT"

# --- the systemd unit (PartOf so a nym-node restart re-triggers it) ---
cat > "$UNIT" <<'EOF'
[Unit]
Description=Extra destination blocks + rate-limit for NYM-EXIT
After=nym-node.service
PartOf=nym-node.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 10
ExecStart=/usr/local/sbin/nym-extra-blocks.sh
RemainAfterExit=yes

[Install]
WantedBy=nym-node.service
EOF

systemctl daemon-reload
systemctl disable nym-extra-blocks.service 2>/dev/null || true
systemctl enable nym-extra-blocks.service
systemctl start nym-extra-blocks.service
echo "installed. status:"
systemctl --no-pager status nym-extra-blocks.service | head -n 8
