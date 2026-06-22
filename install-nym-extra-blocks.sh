#!/usr/bin/env bash
# install-nym-extra-blocks.sh
# Installs nym-extra-blocks: a script + systemd unit that re-applies
# destination REJECTs to NYM-EXIT on every nym-node start.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

SCRIPT=/usr/local/sbin/nym-extra-blocks.sh
UNIT=/etc/systemd/system/nym-extra-blocks.service

# --- the runtime script (written locally; never fetched-to-execute again) ---
cat > "$SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
LIST_URL="https://raw.githubusercontent.com/wiiinnie/nym_node_manager/refs/heads/main/blocklist.txt"
CACHE="/var/lib/nym-extra-blocks/blocklist.txt"
CHAIN="NYM-EXIT"
IP_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'
mkdir -p "$(dirname "$CACHE")"
if curl -fsS --max-time 15 "$LIST_URL" -o "${CACHE}.new"; then
    mv "${CACHE}.new" "$CACHE"
else
    echo "fetch failed, using cached list" >&2; rm -f "${CACHE}.new"
fi
[ -f "$CACHE" ] || { echo "no list available"; exit 0; }
iptables -nL "$CHAIN" >/dev/null 2>&1 || { echo "$CHAIN not present yet"; exit 0; }
count=0
while IFS= read -r line; do
    ip="${line%%#*}"; ip="$(echo "$ip" | xargs)"
    [ -z "$ip" ] && continue
    [[ "$ip" =~ $IP_RE ]] || { echo "skipping invalid: $ip" >&2; continue; }
    iptables -C "$CHAIN" -d "$ip" -j REJECT --reject-with icmp-port-unreachable 2>/dev/null \
      || iptables -I "$CHAIN" -d "$ip" -j REJECT --reject-with icmp-port-unreachable
    count=$((count+1))
done < "$CACHE"
echo "applied $count block entries to $CHAIN"
EOF
chmod +x "$SCRIPT"

# --- the systemd unit (PartOf so a nym-node restart re-triggers it) ---
cat > "$UNIT" <<'EOF'
[Unit]
Description=Extra destination blocks for NYM-EXIT (Skhron etc.)
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
systemctl enable nym-extra-blocks.service
systemctl start nym-extra-blocks.service
echo "installed. status:"
systemctl --no-pager status nym-extra-blocks.service | head -n 6
