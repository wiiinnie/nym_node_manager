#!/bin/bash

# ============================================================================
# Nym Node Manager v83 - Password Security Fix
# ============================================================================
# Description: Centralized management tool for Nym network nodes
# Requirements: dialog, expect, curl, rsync, openssl, nym-cli, jq
# Features: Multi-node operations, backup, updates, configuration, wallet mgmt
# 
# Changelog v83:
#   - Fixed: Password no longer appears in debug.log (Line 256)
#   - Security: Redacted password from root command logging
#   - All v82 functionality preserved
# 
# Changelog v82:
#   - Added "Disable root@ssh" security feature (from v78)
#   - Added "Fail2ban" management feature (from v78)
#   - All v77 wallet operations preserved (user-password encryption, .enc files)
#   - All v77 node operations preserved
#   - Clean build: v77 base + v78 security only
# 
# Changelog v77:
#   - Added hostname support for nodes
#   - Hostname prompt when adding new nodes (order: IP, Hostname, ID)
#   - Ability to add/edit hostname for existing nodes via "Edit node"
#   - All other functionality preserved from v76
# 
# Changelog v76 (Merged):
#   - Base functionality from v61_BACKUP
#   - Wallet Operations from v76 with all enhancements:
#     * Query wallets: Shows claimable rewards, wallet balance, USD values
#     * NYM price fetching from multiple APIs (CoinGecko, CoinPaprika, Binance)
#     * CSV export with dated versioned filenames (YYYYMMDD_nym_rewards_vXX.csv)
#     * Withdraw operator rewards with CSV export
#     * Create new transaction (multi-wallet support)
#     * "All Wallets" selection option
#     * Export wallet (show mnemonic)
#     * Delete wallet
#   - Node Management: List, Add, Edit, Delete nodes (from v61_BACKUP)
#   - Node Operations: Retrieve roles, Backup, Update, Toggle, Restart, SSH (from v61_BACKUP)
#   - Configuration: SSH port, Service name, Binary path (from v61_BACKUP)
#   - Diagnostics: SSH test, Debug log (from v61_BACKUP)
# ============================================================================

# ----------------------------------------------------------------------------
# GLOBAL CONFIGURATION
# ----------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
SCRIPT_NAME="Nym Node Manager"
VERSION="83"
SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")"
DEBUG_LOG="$SCRIPT_DIR/debug.log"
NODES_FILE="$SCRIPT_DIR/nodes.txt"
CONFIG_FILE="$SCRIPT_DIR/config.txt"

# Wallet management configuration
WALLET_DIR="$HOME/.nym_wallets"
WALLET_LIST="$WALLET_DIR/wallet_list.txt"

DEFAULT_SSH_PORT="22"
DEFAULT_SERVICE_NAME="nym-node.service"
DEFAULT_BINARY_PATH="/root/nym"

SSH_PORT=""
SERVICE_NAME=""
BINARY_PATH=""

SELECTED_NODES_NAMES=()
SELECTED_NODES_IPS=()
SELECTED_NODES_HOSTNAMES=()
SELECTED_NODES_IDS=()

# ----------------------------------------------------------------------------
# UTILITY FUNCTIONS
# ----------------------------------------------------------------------------

init_debug() { echo "=== Nym Node Manager v$VERSION - $(date) - User: $(whoami) ===" > "$DEBUG_LOG"; }
log() { local level="$1"; shift; echo "[$(date '+%H:%M:%S')] [$level] $*" >> "$DEBUG_LOG"; }

show_msg() { dialog --title "$1" --msgbox "$2" 10 60; }
show_error() { log "ERROR" "$1"; show_msg "Error" "$1"; }
show_success() { log "SUCCESS" "$1"; show_msg "Success" "$1"; }
confirm() { dialog --title "Confirm" --yesno "$1" 8 50; }
get_input() { dialog --title "$1" --inputbox "$2" 8 50 3>&1 1>&2 2>&3; }
get_password() { dialog --title "$1" --passwordbox "$2" 8 50 3>&1 1>&2 2>&3; }

load_config() {
    SSH_PORT="$DEFAULT_SSH_PORT"
    SERVICE_NAME="$DEFAULT_SERVICE_NAME"
    BINARY_PATH="$DEFAULT_BINARY_PATH"
    
    [[ ! -f "$CONFIG_FILE" ]] && return
    
    while IFS='=' read -r key value; do
        [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
        case "$key" in
            "SSH_PORT") SSH_PORT="$value" ;;
            "SERVICE_NAME") SERVICE_NAME="$value" ;;
            "BINARY_PATH") BINARY_PATH="$value" ;;
        esac
    done < "$CONFIG_FILE"
}

save_config() {
    cat > "$CONFIG_FILE" << EOF
# Nym Node Manager Configuration - Generated $(date)
SSH_PORT=$SSH_PORT
SERVICE_NAME=$SERVICE_NAME
BINARY_PATH=$BINARY_PATH
EOF
}

check_deps() {
    local missing=()
    for cmd in dialog expect curl rsync openssl jq; do
        command -v "$cmd" >/dev/null || missing+=("$cmd")
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}Missing packages: ${missing[*]}${NC}"
        if command -v apt-get >/dev/null; then
            sudo apt-get update && sudo apt-get install -y "${missing[@]}" || exit 1
        elif command -v brew >/dev/null; then
            brew install "${missing[@]}" || exit 1
        else
            echo -e "${RED}Install manually: ${missing[*]}${NC}"; exit 1
        fi
        echo -e "${GREEN}All packages installed!${NC}"
    fi
    
    # Note: nym-cli is optional for wallet operations
    if ! command -v nym-cli >/dev/null 2>&1; then
        echo -e "${YELLOW}Note: nym-cli not found - wallet operations require nym-cli${NC}"
        echo -e "${YELLOW}Download from: https://github.com/nymtech/nym/releases${NC}"
    fi
}

# ----------------------------------------------------------------------------
# NODE FILE OPERATIONS
# ----------------------------------------------------------------------------

node_name_exists() {
    [[ ! -f "$NODES_FILE" || ! -s "$NODES_FILE" ]] && return 1
    grep -q "^Node Name: $1$" "$NODES_FILE"
}

parse_nodes_file() {
    names=(); ips=(); hostnames=(); node_ids=()
    [[ ! -f "$NODES_FILE" || ! -s "$NODES_FILE" ]] && return 1
    
    local name="" ip="" hostname="" node_id=""
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name:\ (.+)$ ]]; then
            name="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^IP\ Address:\ (.+)$ ]]; then
            ip="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^Hostname:\ (.+)$ ]]; then
            hostname="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^Node\ ID:\ (.+)$ ]]; then
            node_id="${BASH_REMATCH[1]}"
            if [[ -n "$name" && -n "$ip" && -n "$node_id" ]]; then
                names+=("$name")
                ips+=("$ip")
                hostnames+=("${hostname:-N/A}")
                node_ids+=("$node_id")
                name=""; ip=""; hostname=""; node_id=""
            fi
        fi
    done < "$NODES_FILE"
    
    [[ ${#names[@]} -eq 0 ]] && return 1
    return 0
}

sort_nodes_file() {
    [[ ! -f "$NODES_FILE" || ! -s "$NODES_FILE" ]] && return
    
    local temp=$(mktemp) nodes=() current_node=""
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name: ]]; then
            [[ -n "$current_node" ]] && nodes+=("$current_node")
            current_node="$line\n"
        elif [[ -n "$current_node" ]]; then
            current_node+="$line\n"
        fi
    done < "$NODES_FILE"
    [[ -n "$current_node" ]] && nodes+=("$current_node")
    
    IFS=$'\n' sorted=($(printf '%s\n' "${nodes[@]}" | sort -t: -k2))
    for ((i=0; i<${#sorted[@]}; i++)); do
        [[ $i -gt 0 ]] && echo >> "$temp"
        echo -e "${sorted[i]}" | sed '/^$/d' >> "$temp"
    done
    mv "$temp" "$NODES_FILE"
}

insert_node_sorted() {
    local new_name="$1" new_ip="$2" new_hostname="$3" new_node_id="$4"
    local temp=$(mktemp) inserted=false
    
    if [[ ! -f "$NODES_FILE" ]]; then
        echo -e "Node Name: $new_name\nIP Address: $new_ip\nHostname: $new_hostname\nNode ID: $new_node_id" > "$NODES_FILE"
        return
    fi
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name:\ (.+)$ ]]; then
            local node_name="${BASH_REMATCH[1]}"
            if [[ "$inserted" == "false" && "$new_name" < "$node_name" ]]; then
                [[ -s "$temp" ]] && echo >> "$temp"
                echo -e "Node Name: $new_name\nIP Address: $new_ip\nHostname: $new_hostname\nNode ID: $new_node_id\n" >> "$temp"
                inserted=true
            fi
            [[ -s "$temp" ]] && echo >> "$temp"
        fi
        echo "$line" >> "$temp"
    done < "$NODES_FILE"
    
    if [[ "$inserted" == "false" ]]; then
        [[ -s "$temp" ]] && echo >> "$temp"
        echo -e "Node Name: $new_name\nIP Address: $new_ip\nHostname: $new_hostname\nNode ID: $new_node_id" >> "$temp"
    fi
    mv "$temp" "$NODES_FILE"
}

remove_nodes_from_file() {
    local nodes_to_remove=("$@")
    local temp=$(mktemp) in_target=false current_name=""
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name:\ (.+)$ ]]; then
            current_name="${BASH_REMATCH[1]}"
            in_target=false
            for target in "${nodes_to_remove[@]}"; do
                [[ "$current_name" == "$target" ]] && { in_target=true; break; }
            done
            [[ ! "$in_target" == "true" ]] && { [[ -s "$temp" ]] && echo "" >> "$temp"; echo "$line" >> "$temp"; }
        elif [[ ! "$in_target" == "true" ]]; then
            echo "$line" >> "$temp"
        fi
    done < "$NODES_FILE"
    mv "$temp" "$NODES_FILE"
}

# ----------------------------------------------------------------------------
# SSH OPERATIONS
# ----------------------------------------------------------------------------

ssh_exec() {
    local ip="$1" user="$2" pass="$3" cmd="$4" desc="${5:-SSH Command}" use_root="${6:-false}"
    
    log "SSH_EXEC" "Starting: $desc on $ip"
    log "SSH_EXEC" "Original command: $cmd"
    log "SSH_EXEC" "Use root: $use_root"
    
    # If root execution is needed, wrap the command appropriately
    if [[ "$use_root" == "true" ]]; then
        # Escape special characters for the nested command
        local escaped_cmd=$(echo "$cmd" | sed 's/"/\\"/g')
        cmd="echo '$pass' | sudo -S bash -c \"$escaped_cmd\""
        # Log without exposing password
        log "SSH_EXEC" "Root command: echo '[REDACTED]' | sudo -S bash -c \"$escaped_cmd\""
    fi
    
    local expect_script=$(mktemp)
    local output_file=$(mktemp)
    
    cat > "$expect_script" << EOF
#!/usr/bin/expect -f
set timeout 30
set ip [lindex \$argv 0]; set user [lindex \$argv 1]; set password [lindex \$argv 2]
set port [lindex \$argv 3]; set command [lindex \$argv 4]; set outfile [lindex \$argv 5]
log_user 0
set output ""
spawn ssh -p \$port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 \$user@\$ip \$command
expect {
    "password:" { 
        send "\$password\r"
        expect {
            "Permission denied" { exit 1 }
            eof {
                set output \$expect_out(buffer)
            }
        }
    }
    "Are you sure you want to continue connecting" { 
        send "yes\r"
        exp_continue
    }
    timeout { exit 2 }
    eof {
        set output \$expect_out(buffer)
    }
}
# Write only the command output to file
set fd [open \$outfile w]
puts -nonewline \$fd \$output
close \$fd
catch wait result
exit [lindex \$result 3]
EOF
    
    chmod 700 "$expect_script"
    "$expect_script" "$ip" "$user" "$pass" "$SSH_PORT" "$cmd" "$output_file" 2>/dev/null
    local exit_code=$?
    
    log "SSH_EXEC" "Exit code: $exit_code"
    
    local output=""
    if [[ -f "$output_file" ]]; then
        output=$(cat "$output_file")
        log "SSH_EXEC" "Raw output before filtering: '$output'"
        # Remove password prompt and sudo messages - but keep the actual command output
        output=$(echo "$output" | sed 's/\[sudo\] password for [^:]*: //g' | sed 's/^Password: //g' | sed 's/^spawn.*$//g' | grep -v "^Permanently added" | grep -v "^Warning:" | sed '/^$/d')
        log "SSH_EXEC" "Filtered output: '$output'"
    fi
    
    rm -f "$expect_script" "$output_file"
    
    echo "$output"
    return $exit_code
}

# New function to handle rsync with password using expect with detailed logging
rsync_with_password() {
    local user="$1" pass="$2" ip="$3" port="$4" remote_path="$5" local_path="$6"
    
    log "RSYNC" "Starting rsync transfer: $user@$ip:$remote_path -> $local_path (port: $port)"
    
    local expect_script=$(mktemp)
    local log_file=$(mktemp)
    
    cat > "$expect_script" << 'EXPECTEOF'
#!/usr/bin/expect -f
set timeout 300

if {[llength $argv] != 6} {
    puts "Error: Expected 6 arguments"
    exit 1
}

set user [lindex $argv 0]
set password [lindex $argv 1]
set ip [lindex $argv 2]
set port [lindex $argv 3]
set remote_path [lindex $argv 4]
set local_path [lindex $argv 5]

log_user 1
set timeout 300

puts "DEBUG: Starting rsync spawn..."
puts "DEBUG: Command: rsync -avz -e \"ssh -p $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR\" $user@$ip:$remote_path $local_path"

spawn rsync -avz -e "ssh -p $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR" $user@$ip:$remote_path $local_path

set password_sent 0

expect {
    -re "assword:" {
        puts "DEBUG: Password prompt detected, sending password..."
        send "$password\r"
        set password_sent 1
        exp_continue
    }
    "Are you sure you want to continue connecting" {
        puts "DEBUG: Host key verification prompt detected..."
        send "yes\r"
        exp_continue
    }
    -re "Permission denied" {
        puts "DEBUG: Permission denied error"
        exit 1
    }
    timeout {
        puts "DEBUG: Timeout waiting for response"
        exit 2
    }
    eof {
        puts "DEBUG: EOF received, password_sent=$password_sent"
        catch wait result
        set exit_code [lindex $result 3]
        puts "DEBUG: Exit code: $exit_code"
        exit $exit_code
    }
}
EXPECTEOF
    
    chmod 700 "$expect_script"
    
    # Run expect script and capture all output
    "$expect_script" "$user" "$pass" "$ip" "$port" "$remote_path" "$local_path" > "$log_file" 2>&1
    local exit_code=$?
    
    # Log the output
    if [[ -f "$log_file" ]]; then
        log "RSYNC" "Expect script output:"
        while IFS= read -r line; do
            log "RSYNC" "  $line"
        done < "$log_file"
    fi
    
    log "RSYNC" "Rsync exit code: $exit_code"
    
    rm -f "$expect_script" "$log_file"
    return $exit_code
}

# ----------------------------------------------------------------------------
# NODE SELECTION
# ----------------------------------------------------------------------------

select_nodes() {
    local mode="${1:-single}" title="${2:-Select Node}"
    SELECTED_NODES_NAMES=(); SELECTED_NODES_IPS=(); SELECTED_NODES_HOSTNAMES=(); SELECTED_NODES_IDS=()
    
    local names=() ips=() hostnames=() node_ids=()
    parse_nodes_file || { show_error "No nodes found. Add nodes first."; return 1; }
    
    local options=() counter=1
    for ((i=0; i<${#names[@]}; i++)); do
        if [[ "$mode" == "multi" ]]; then
            options+=("$counter" "${names[i]} (${ips[i]})" "OFF")
        else
            options+=("$counter" "${names[i]} (${ips[i]})")
        fi
        ((counter++))
    done
    
    local choices
    if [[ "$mode" == "multi" ]]; then
        local all_options=("ALL" "Select All Nodes" "OFF" "${options[@]}")
        choices=$(dialog --title "$title" --checklist "Choose nodes (Space to select, Enter to confirm):" $((${#names[@]} + 10)) 70 $((${#names[@]} + 1)) "${all_options[@]}" 3>&1 1>&2 2>&3)
    else
        choices=$(dialog --title "$title" --menu "Choose node:" 15 60 10 "${options[@]}" 3>&1 1>&2 2>&3)
    fi
    
    [[ $? -ne 0 ]] && return 1
    
    for choice in $choices; do
        choice=$(echo "$choice" | tr -d '"')
        if [[ "$choice" == "ALL" ]]; then
            SELECTED_NODES_NAMES=("${names[@]}")
            SELECTED_NODES_IPS=("${ips[@]}")
            SELECTED_NODES_HOSTNAMES=("${hostnames[@]}")
            SELECTED_NODES_IDS=("${node_ids[@]}")
            break
        else
            local idx=$((choice - 1))
            SELECTED_NODES_NAMES+=("${names[$idx]}")
            SELECTED_NODES_IPS+=("${ips[$idx]}")
            SELECTED_NODES_HOSTNAMES+=("${hostnames[$idx]}")
            SELECTED_NODES_IDS+=("${node_ids[$idx]}")
        fi
    done
    
    [[ ${#SELECTED_NODES_NAMES[@]} -eq 0 ]] && { show_error "No nodes selected."; return 1; }
    return 0
}

# ----------------------------------------------------------------------------
# RESULTS DISPLAY
# ----------------------------------------------------------------------------

show_operation_results() {
    local operation="$1"
    local -n success_arr="$2" fail_arr="$3"
    local additional="${4:-}"
    
    local results="$operation Results\n────────────────────────────────────────────────────────\n\n"
    [[ ${#success_arr[@]} -gt 0 ]] && {
        results+="✅ Success (${#success_arr[@]} nodes):\n"
        for item in "${success_arr[@]}"; do results+="   • $item\n"; done
        results+="\n"
    }
    [[ ${#fail_arr[@]} -gt 0 ]] && {
        results+="❌ Failed (${#fail_arr[@]} nodes):\n"
        for item in "${fail_arr[@]}"; do results+="   • $item\n"; done
        results+="\n"
    }
    [[ -n "$additional" ]] && results+="$additional\n"
    show_success "$results"
}

# ----------------------------------------------------------------------------
# NODE MANAGEMENT
# ----------------------------------------------------------------------------

list_nodes() {
    [[ ! -f "$NODES_FILE" || ! -s "$NODES_FILE" ]] && { show_msg "No Nodes" "No nodes found."; return; }
    sort_nodes_file
    
    local content="" current_node=""
    while IFS= read -r line; do
        case "$line" in
            "Node Name: "*) [[ -n "$current_node" ]] && content+="\n"
                content+="🖥️ NODE: ${line#Node Name: }\n────────────────────────────────────────\n"; current_node="yes" ;;
            "IP Address: "*) content+="🌐 IP: ${line#IP Address: }\n" ;;
            "Hostname: "*) content+="🏷️ Hostname: ${line#Hostname: }\n" ;;
            "Node ID: "*) content+="🆔 ID: ${line#Node ID: }\n" ;;
            "Build Version: "*) content+="📦 Version: ${line#Build Version: }\n" ;;
            *"mixnode"*"true"*) content+="🔀 Mixnode: \Z2✅ Enabled\Zn\n" ;;
            *"mixnode"*"false"*) content+="🔀 Mixnode: \Z1❌ Disabled\Zn\n" ;;
            *"gateway"*"true"*) content+="🚪 Gateway: \Z2✅ Enabled\Zn\n" ;;
            *"gateway"*"false"*) content+="🚪 Gateway: \Z1❌ Disabled\Zn\n" ;;
            *"network requester"*"true"*) content+="🌐 Network Requester: \Z2✅ Enabled\Zn\n" ;;
            *"network requester"*"false"*) content+="🌐 Network Requester: \Z1❌ Disabled\Zn\n" ;;
            *"ip packet router"*"true"*) content+="📦 IP Packet Router: \Z2✅ Enabled\Zn\n" ;;
            *"ip packet router"*"false"*) content+="📦 IP Packet Router: \Z1❌ Disabled\Zn\n" ;;
            *"Wireguard Status: enabled"*) content+="🔒 WireGuard: \Z2✅ ${line#*Wireguard Status: }\Zn\n" ;;
            *"Wireguard Status: disabled"*) content+="🔒 WireGuard: \Z1❌ Disabled\Zn\n" ;;
        esac
    done < "$NODES_FILE"
    
    [[ -n "$content" ]] && dialog --title "Nym Network Nodes" --colors --msgbox "$content" 25 85 || show_msg "No Data" "No readable node data found."
}

add_node() {
    local name="" attempt=0
    while true; do
        ((attempt++))
        name=$(get_input "Add Node" "$([[ $attempt -eq 1 ]] && echo "Enter Node Name:" || echo "Node '$name' already exists!\n\nEnter a different Node Name:")")
        [[ -z "$name" ]] && { show_msg "Cancelled" "Node creation cancelled."; return; }
        node_name_exists "$name" || break
    done
    
    local ip=$(get_input "Add Node" "Enter IP Address for '$name':")
    [[ -z "$ip" ]] && { show_msg "Cancelled" "Node creation cancelled."; return; }
    
    local hostname=$(get_input "Add Node" "Enter Hostname for '$name' (optional):")
    [[ -z "$hostname" ]] && hostname="N/A"
    
    local node_id=$(get_input "Add Node" "Enter Node ID for '$name':\n(The ID used during node initialization)")
    [[ -z "$node_id" ]] && { show_msg "Cancelled" "Node creation cancelled."; return; }
    
    insert_node_sorted "$name" "$ip" "$hostname" "$node_id"
    show_success "Node '$name' added successfully!\nIP: $ip\nHostname: $hostname\nID: $node_id"
}

edit_node() {
    select_nodes "single" "Edit Node" || return
    
    local old_name="${SELECTED_NODES_NAMES[0]}" old_ip="${SELECTED_NODES_IPS[0]}" old_hostname="${SELECTED_NODES_HOSTNAMES[0]}" old_id="${SELECTED_NODES_IDS[0]}"
    local new_name="" attempt=0
    
    while true; do
        ((attempt++))
        new_name=$(dialog --title "Edit Node Name" --inputbox "$([[ $attempt -eq 1 ]] && echo "Enter new Node Name:" || echo "Node '$new_name' already exists!\n\nEnter a different Node Name:")" 8 50 "$old_name" 3>&1 1>&2 2>&3)
        [[ $? -ne 0 || -z "$new_name" ]] && { show_msg "Cancelled" "Edit cancelled."; return; }
        [[ "$new_name" == "$old_name" ]] && break
        node_name_exists "$new_name" || break
    done
    
    local new_ip=$(dialog --title "Edit IP Address" --inputbox "Enter new IP Address:" 8 50 "$old_ip" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z "$new_ip" ]] && { show_msg "Cancelled" "Edit cancelled."; return; }
    
    local new_hostname=$(dialog --title "Edit Hostname" --inputbox "Enter new Hostname:" 8 50 "$old_hostname" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && { show_msg "Cancelled" "Edit cancelled."; return; }
    [[ -z "$new_hostname" ]] && new_hostname="N/A"
    
    local new_id=$(dialog --title "Edit Node ID" --inputbox "Enter new Node ID:" 8 50 "$old_id" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z "$new_id" ]] && { show_msg "Cancelled" "Edit cancelled."; return; }
    
    remove_nodes_from_file "$old_name"
    insert_node_sorted "$new_name" "$new_ip" "$new_hostname" "$new_id"
    show_success "Node updated!\n\nOld: $old_name ($old_ip) - $old_hostname - $old_id\nNew: $new_name ($new_ip) - $new_hostname - $new_id"
}

delete_node() {
    select_nodes "multi" "Delete Nodes" || return
    
    local node_list=""
    for ((i=0; i<${#SELECTED_NODES_NAMES[@]}; i++)); do
        node_list+="\n• ${SELECTED_NODES_NAMES[i]} (${SELECTED_NODES_IPS[i]})"
    done
    
    confirm "Delete ${#SELECTED_NODES_NAMES[@]} node(s)?$node_list\n\nThis cannot be undone." || return
    remove_nodes_from_file "${SELECTED_NODES_NAMES[@]}"
    show_success "${#SELECTED_NODES_NAMES[@]} node(s) deleted successfully!"
}

# ----------------------------------------------------------------------------
# NODE OPERATIONS
# ----------------------------------------------------------------------------

retrieve_node_roles() {
    [[ ! -f "$NODES_FILE" || ! -s "$NODES_FILE" ]] && { show_error "No nodes found."; return; }
    
    local clean_file=$(mktemp)
    while IFS= read -r line; do
        [[ "$line" =~ ^(Node\ Name:|IP\ Address:|Hostname:|Node\ ID:) || -z "$line" ]] && echo "$line" >> "$clean_file"
    done < "$NODES_FILE"
    
    local names=() ips=() hostnames=() node_ids=()
    parse_nodes_file
    local total=${#names[@]} processed=0
    
    local temp=$(mktemp)
    for ((i=0; i<total; i++)); do
        local name="${names[i]}" ip="${ips[i]}" hostname="${hostnames[i]}" node_id="${node_ids[i]}"
        ((processed++))
        dialog --title "Retrieving Roles" --infobox "Processing $name ($processed/$total)..." 6 50
        
        echo -e "Node Name: $name\nIP Address: $ip\nHostname: $hostname\nNode ID: $node_id" >> "$temp"
        
        local roles=$(curl -s --connect-timeout 5 --max-time 10 "http://$ip:8080/api/v1/roles" 2>/dev/null)
        local gateway=$(curl -s --connect-timeout 5 --max-time 10 "http://$ip:8080/api/v1/gateway" 2>/dev/null)
        local build_info=$(curl -s --connect-timeout 5 --max-time 10 "http://$ip:8080/api/v1/build-information" 2>/dev/null)
        
        if [[ -n "$roles" ]]; then
            for field in mixnode_enabled gateway_enabled network_requester_enabled ip_packet_router_enabled; do
                local label=$(echo "$field" | sed 's/_/ /g' | sed 's/\b\(.\)/\u\1/g')
                echo "$label: $(echo "$roles" | grep -o "\"$field\"[[:space:]]*:[[:space:]]*[^,}]*" | cut -d':' -f2 | tr -d ' ",' || echo "unknown")" >> "$temp"
            done
        else
            echo -e "Mixnode Enabled: error\nGateway Enabled: error\nNetwork Requester Enabled: error\nIP Packet Router Enabled: error" >> "$temp"
        fi
        
        if [[ -n "$gateway" ]]; then
            if echo "$gateway" | grep -q '"wireguard"[[:space:]]*:[[:space:]]*null'; then
                echo "Wireguard Status: disabled" >> "$temp"
            elif echo "$gateway" | grep -q '"wireguard"[[:space:]]*:[[:space:]]*{'; then
                local port=$(echo "$gateway" | grep -o '"port"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*')
                echo "Wireguard Status: enabled${port:+ (port: $port)}" >> "$temp"
            else
                echo "Wireguard Status: unknown" >> "$temp"
            fi
        else
            echo "Wireguard Status: error" >> "$temp"
        fi
        
        [[ -n "$build_info" ]] && echo "Build Version: $(echo "$build_info" | grep -o '"build_version"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d':' -f2 | tr -d ' "' || echo "unknown")" >> "$temp" || echo "Build Version: error" >> "$temp"
        [[ $i -lt $((total - 1)) ]] && echo >> "$temp"
    done
    
    rm -f "$clean_file"
    mv "$temp" "$NODES_FILE"
    sort_nodes_file
    show_success "Node roles retrieved for $processed nodes!"
}

backup_node() {
    log "BACKUP" "Starting backup_node function"
    command -v rsync >/dev/null 2>&1 || { show_error "rsync is not installed on this machine.\n\nPlease install it:\n- Debian/Ubuntu: sudo apt-get install rsync\n- macOS: brew install rsync"; return; }
    command -v expect >/dev/null 2>&1 || { show_error "expect is not installed on this machine.\n\nPlease install it:\n- Debian/Ubuntu: sudo apt-get install expect\n- macOS: brew install expect"; return; }
    
    # First select backup type
    local backup_type=$(dialog --clear --title "Backup Type" --menu "Select backup type:" 14 70 2 \
        1 "Light backup (excludes SQLite files, no downtime)" \
        2 "Full backup (complete .nym folder, requires downtime)" \
        3>&1 1>&2 2>&3)
    
    [[ $? -ne 0 || -z "$backup_type" ]] && return
    
    local backup_mode=""
    local exclude_opts=""
    local requires_stop=false
    
    case $backup_type in
        1)
            backup_mode="LIGHT"
            exclude_opts="--exclude='*.sqlite*' --exclude='*.corrupted' --exclude='*.bloom' --exclude='*.sqlite-wal' --exclude='*.sqlite-shm'"
            ;;
        2)
            backup_mode="FULL"
            exclude_opts="--exclude='*.corrupted'"
            requires_stop=true
            if ! confirm "⚠️  FULL BACKUP WARNING ⚠️\n\nThis will temporarily STOP nym-node.service\non the selected nodes to ensure data consistency.\n\nThe service will be restarted after backup.\n\nContinue?"; then
                return
            fi
            ;;
        *)
            return
            ;;
    esac
    
    log "BACKUP" "Backup mode selected: $backup_mode"
    
    select_nodes "multi" "Backup Nodes" || return
    log "BACKUP" "Nodes selected: ${#SELECTED_NODES_NAMES[@]}"
    
    local user=$(get_input "SSH Connection" "SSH username (same for all):")
    [[ -z "$user" ]] && { show_msg "Cancelled" "Backup cancelled."; return; }
    log "BACKUP" "Username entered: $user"
    
    local pass=$(get_password "SSH Connection" "SSH password for $user:")
    [[ -z "$pass" ]] && { show_msg "Cancelled" "Backup cancelled."; return; }
    log "BACKUP" "Password entered (length: ${#pass})"
    
    local backup_dir=$(get_input "Backup Destination" "Enter local backup directory:\n(Leave empty for: $SCRIPT_DIR)")
    [[ -z "$backup_dir" ]] && backup_dir="$SCRIPT_DIR"
    
    [[ ! -d "$backup_dir" ]] && { mkdir -p "$backup_dir" 2>/dev/null || { show_error "Cannot create: $backup_dir"; return; }; }
    backup_dir=$(cd "$backup_dir" && pwd)
    log "BACKUP" "Backup directory: $backup_dir"
    
    local node_list=""
    for ((i=0; i<${#SELECTED_NODES_NAMES[@]}; i++)); do
        node_list+="\n• ${SELECTED_NODES_NAMES[i]} (${SELECTED_NODES_IPS[i]})"
    done
    confirm "Backup ${#SELECTED_NODES_NAMES[@]} node(s) [$backup_mode]?$node_list\n\nLocal destination: $backup_dir" || return
    
    local successful=() failed=()
    local total=${#SELECTED_NODES_NAMES[@]} current=0 timestamp=$(date +%Y%m%d_%H%M%S)
    
    for ((i=0; i<total; i++)); do
        local name="${SELECTED_NODES_NAMES[i]}" ip="${SELECTED_NODES_IPS[i]}" node_id="${SELECTED_NODES_IDS[i]}"
        ((current++))
        log "BACKUP" "Processing node $current/$total: $name ($ip)"
        
        dialog --title "Backing Up ($backup_mode)" --infobox "Processing $name ($current/$total)...\nTesting connection..." 6 60
        log "BACKUP" "Step 1: Testing SSH connection to $ip"
        ssh_exec "$ip" "$user" "$pass" "echo 'OK'" "Connection Test" >/dev/null 2>&1
        if [[ $? -ne 0 ]]; then
            log "BACKUP" "SSH connection test FAILED for $name"
            failed+=("$name: SSH connection failed")
            continue
        fi
        log "BACKUP" "SSH connection test SUCCESS for $name"
        
        # Stop service if full backup
        local service_was_running=false
        if [[ "$requires_stop" == "true" ]]; then
            dialog --title "Backing Up ($backup_mode)" --infobox "Processing $name ($current/$total)...\nStopping service..." 6 60
            log "BACKUP" "Checking if service is running"
            local service_status=$(ssh_exec "$ip" "$user" "$pass" "systemctl is-active $SERVICE_NAME 2>/dev/null" "Check service" "true" 2>/dev/null | tr -d '[:space:]')
            
            if [[ "$service_status" == "active" ]]; then
                service_was_running=true
                log "BACKUP" "Service is running, stopping it"
                ssh_exec "$ip" "$user" "$pass" "systemctl stop $SERVICE_NAME" "Stop service" "true" >/dev/null 2>&1
                sleep 2
            fi
        fi
        
        dialog --title "Backing Up ($backup_mode)" --infobox "Processing $name ($current/$total)...\nChecking rsync..." 6 60
        log "BACKUP" "Step 2: Checking rsync on remote server"
        local remote_rsync_check=$(ssh_exec "$ip" "$user" "$pass" "command -v rsync >/dev/null && rsync --version 2>/dev/null | head -1" "Check rsync" 2>/dev/null)
        log "BACKUP" "Remote rsync check result: $remote_rsync_check"
        
        if [[ -z "$remote_rsync_check" ]]; then
            log "BACKUP" "Step 3: Installing rsync on remote server"
            dialog --title "Backing Up ($backup_mode)" --infobox "Processing $name ($current/$total)...\nInstalling rsync..." 6 60
            ssh_exec "$ip" "$user" "$pass" "apt-get update >/dev/null 2>&1 && apt-get install -y rsync 2>&1" "Install rsync" "true" >/dev/null 2>&1
            remote_rsync_check=$(ssh_exec "$ip" "$user" "$pass" "rsync --version 2>/dev/null | head -1" "Verify rsync" 2>/dev/null)
            if [[ -z "$remote_rsync_check" ]]; then
                log "BACKUP" "Failed to install rsync on $name"
                failed+=("$name: Could not install rsync on remote server")
                # Restart service if it was running
                if [[ "$service_was_running" == "true" ]]; then
                    ssh_exec "$ip" "$user" "$pass" "systemctl start $SERVICE_NAME" "Restart service" "true" >/dev/null 2>&1
                fi
                continue
            fi
            log "BACKUP" "Rsync installed successfully on $name"
        fi
        
        dialog --title "Backing Up ($backup_mode)" --infobox "Processing $name ($current/$total)...\nDetermining service user..." 6 60
        log "BACKUP" "Step 4: Determining service user"
        local check_user_cmd="if [ -f /etc/systemd/system/$SERVICE_NAME ]; then grep '^User=' /etc/systemd/system/$SERVICE_NAME | cut -d'=' -f2 | head -1; else echo 'NOFILE'; fi"
        local service_user=$(ssh_exec "$ip" "$user" "$pass" "$check_user_cmd" "Get service user" "true" 2>/dev/null | tr -d '[:space:]')
        
        [[ -z "$service_user" || "$service_user" == "NOFILE" ]] && service_user="root"
        local nym_path=$([[ "$service_user" == "root" ]] && echo "/root/.nym" || echo "/home/$service_user/.nym")
        log "BACKUP" "Service user: $service_user, nym_path: $nym_path"
        
        dialog --title "Backing Up ($backup_mode)" --infobox "Processing $name ($current/$total)...\nChecking folder access..." 6 60
        log "BACKUP" "Step 5: Checking folder access for: $nym_path"
        
        # First try with root
        local folder_check_raw=$(ssh_exec "$ip" "$user" "$pass" "[ -d $nym_path ] && echo EXISTS || echo NOTFOUND" "Check folder" "true" 2>&1)
        log "BACKUP" "Raw folder check output: '$folder_check_raw'"
        
        local folder_check=$(echo "$folder_check_raw" | grep -o "EXISTS\|NOTFOUND" | head -1)
        log "BACKUP" "Filtered folder check result: '$folder_check'"
        
        # If empty, try alternative method
        if [[ -z "$folder_check" ]]; then
            log "BACKUP" "First method failed, trying alternative with ls"
            folder_check_raw=$(ssh_exec "$ip" "$user" "$pass" "ls -ld $nym_path 2>/dev/null && echo EXISTS || echo NOTFOUND" "Check folder alt" "true" 2>&1)
            log "BACKUP" "Alternative raw output: '$folder_check_raw'"
            folder_check=$(echo "$folder_check_raw" | grep -o "EXISTS\|NOTFOUND" | tail -1)
            log "BACKUP" "Alternative filtered result: '$folder_check'"
        fi
        
        if [[ "$folder_check" != "EXISTS" ]]; then
            log "BACKUP" "Folder not found or inaccessible: $nym_path"
            failed+=("$name: .nym folder not found at $nym_path")
            # Restart service if it was running
            if [[ "$service_was_running" == "true" ]]; then
                ssh_exec "$ip" "$user" "$pass" "systemctl start $SERVICE_NAME" "Restart service" "true" >/dev/null 2>&1
            fi
            continue
        fi
        log "BACKUP" "Folder exists: $nym_path"
        
        dialog --title "Backing Up ($backup_mode)" --infobox "Processing $name ($current/$total)...\nCreating archive..." 6 60
        log "BACKUP" "Step 6: Creating tar archive with exclude options: $exclude_opts"
        
        local backup_file="nym_backup_${backup_mode}_${name}_${timestamp}.tar.gz"
        local backup_path="/tmp/$backup_file"
        local parent_dir=$(dirname "$nym_path")
        local dir_name=$(basename "$nym_path")
        local tar_cmd="cd $parent_dir && tar $exclude_opts -czf $backup_path $dir_name; echo \"EXIT_CODE:\$?\""
        
        log "BACKUP" "Tar command: $tar_cmd"
        local tar_output=$(ssh_exec "$ip" "$user" "$pass" "$tar_cmd" "Create archive" "true" 2>/dev/null)
        local tar_exit=$(echo "$tar_output" | grep "EXIT_CODE:" | sed 's/.*EXIT_CODE://g' | tr -d '[:space:]')
        [[ -z "$tar_exit" ]] && tar_exit=255
        
        log "BACKUP" "Tar exit code: $tar_exit"
        if [[ $tar_exit -gt 1 ]]; then
            log "BACKUP" "Tar creation failed"
            failed+=("$name: Failed to create archive - exit code $tar_exit")
            # Restart service if it was running
            if [[ "$service_was_running" == "true" ]]; then
                ssh_exec "$ip" "$user" "$pass" "systemctl start $SERVICE_NAME" "Restart service" "true" >/dev/null 2>&1
            fi
            continue
        fi
        
        # Restart service immediately after tar is complete
        if [[ "$service_was_running" == "true" ]]; then
            dialog --title "Backing Up ($backup_mode)" --infobox "Processing $name ($current/$total)...\nRestarting service..." 6 60
            log "BACKUP" "Restarting service after backup"
            ssh_exec "$ip" "$user" "$pass" "systemctl start $SERVICE_NAME" "Restart service" "true" >/dev/null 2>&1
        fi
        
        dialog --title "Backing Up ($backup_mode)" --infobox "Processing $name ($current/$total)...\nVerifying archive..." 6 60
        log "BACKUP" "Step 7: Verifying archive"
        local verify_output=$(ssh_exec "$ip" "$user" "$pass" "ls -lh $backup_path" "Verify archive" "true" 2>/dev/null)
        
        log "BACKUP" "Verify output: $verify_output"
        if [[ -z "$verify_output" ]]; then
            log "BACKUP" "Archive verification failed"
            failed+=("$name: Archive creation failed or file not found")
            continue
        fi
        
        local remote_size=$(echo "$verify_output" | awk '{print $5}')
        log "BACKUP" "Archive size: $remote_size"
        
        dialog --title "Backing Up ($backup_mode)" --infobox "Processing $name ($current/$total)...\nPreparing for download..." 6 60
        log "BACKUP" "Step 8: Changing ownership for download"
        ssh_exec "$ip" "$user" "$pass" "chown $user:$user $backup_path" "Change ownership" "true" >/dev/null 2>&1
        
        local local_backup_file="$backup_dir/$backup_file"
        
        dialog --title "Backing Up ($backup_mode)" --infobox "Processing $name ($current/$total)...\n\nStarting download...\nFile size: $remote_size\n\nThis may take several minutes depending on\nthe archive size and network speed.\n\nPlease wait..." 12 60
        
        log "BACKUP" "Step 9: Starting rsync download"
        log "BACKUP" "Remote path: $backup_path, Local path: $local_backup_file"
        
        # Use the new rsync_with_password function instead of direct rsync
        rsync_with_password "$user" "$pass" "$ip" "$SSH_PORT" "$backup_path" "$local_backup_file"
        local rsync_exit=$?
        
        log "BACKUP" "Rsync completed with exit code: $rsync_exit"
        
        if [[ -f "$local_backup_file" ]]; then
            local local_size=$(ls -lh "$local_backup_file" 2>/dev/null | awk '{print $5}')
            log "BACKUP" "Backup successful, local file size: $local_size"
            successful+=("$name: Downloaded successfully ($local_size) -> $backup_file")
            log "BACKUP" "Step 10: Cleaning up remote archive"
            ssh_exec "$ip" "$user" "$pass" "rm -f $backup_path" "Cleanup" "true" >/dev/null 2>&1
        else
            log "BACKUP" "Backup failed, local file not found"
            failed+=("$name: Download failed - file not found locally (rsync exit: $rsync_exit)")
            log "BACKUP" "Step 10: Cleaning up remote archive (failed backup)"
            ssh_exec "$ip" "$user" "$pass" "rm -f $backup_path" "Cleanup" "true" >/dev/null 2>&1
        fi
    done
    
    log "BACKUP" "Backup operation completed. Success: ${#successful[@]}, Failed: ${#failed[@]}"
    local info="📂 Local Backup Location: $backup_dir\n📦 Files excluded: *.corrupted, *.bloom, *.sqlite-wal, *.sqlite-shm\n🧹 Remote /tmp archives cleaned up"
    show_operation_results "💾 Node Backup" successful failed "$info"
}

update_nym_node() {
    local url=$(get_input "Nym-Node Update" "Enter download URL for latest binary:\n\nExample:\nhttps://github.com/nymtech/nym/releases/download/nym-binaries-v2025.13-emmental/nym-node")
    [[ -z "$url" ]] && { show_msg "Cancelled" "Update cancelled."; return; }
    
    select_nodes "multi" "Update Nodes" || return
    
    local user=$(get_input "SSH Connection" "SSH username (same for all):")
    [[ -z "$user" ]] && { show_msg "Cancelled" "Update cancelled."; return; }
    
    local pass=$(get_password "SSH Connection" "SSH password for $user:")
    [[ -z "$pass" ]] && { show_msg "Cancelled" "Update cancelled."; return; }
    
    local node_list=""
    for ((i=0; i<${#SELECTED_NODES_NAMES[@]}; i++)); do
        node_list+="\n• ${SELECTED_NODES_NAMES[i]} (${SELECTED_NODES_IPS[i]})"
    done
    confirm "Update nym-node on ${#SELECTED_NODES_NAMES[@]} node(s)?$node_list\n\nURL: $url" || return
    
    local successful=() failed=()
    local total=${#SELECTED_NODES_NAMES[@]} current=0
    
    for ((i=0; i<total; i++)); do
        local name="${SELECTED_NODES_NAMES[i]}" ip="${SELECTED_NODES_IPS[i]}"
        ((current++))
        
        dialog --title "Updating Nym-Node" --infobox "Processing $name ($current/$total)...\nTesting connection..." 6 60
        ssh_exec "$ip" "$user" "$pass" "echo 'OK'" "Connection Test" >/dev/null 2>&1 || { failed+=("$name: SSH connection failed"); continue; }
        
        dialog --title "Updating Nym-Node" --infobox "Processing $name ($current/$total)...\nPreparing..." 6 60
        local prep_cmd="mkdir -p $BINARY_PATH/old && cd $BINARY_PATH && if [ -f nym-node ]; then mv nym-node old/nym-node.backup.\$(date +%Y%m%d_%H%M%S) || true; fi"
        ssh_exec "$ip" "$user" "$pass" "$prep_cmd" "Prepare Directory" "true" >/dev/null 2>&1 || { failed+=("$name: Could not prepare directory"); continue; }
        
        dialog --title "Updating Nym-Node" --infobox "Processing $name ($current/$total)...\nDownloading..." 6 60
        local dl_cmd="cd $BINARY_PATH && curl -L -o nym-node '$url' && chmod +x nym-node"
        ssh_exec "$ip" "$user" "$pass" "$dl_cmd" "Download Binary" "true" >/dev/null 2>&1 || { failed+=("$name: Could not download binary"); continue; }
        
        dialog --title "Updating Nym-Node" --infobox "Processing $name ($current/$total)...\nVerifying..." 6 60
        local version_output=$(ssh_exec "$ip" "$user" "$pass" "cd $BINARY_PATH && ./nym-node --version" "Check Version" "true" 2>/dev/null)
        
        if [[ $? -eq 0 && -n "$version_output" ]]; then
            local version=$(echo "$version_output" | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1)
            [[ -z "$version" ]] && version="unknown (functional)"
            successful+=("$name: Updated to version $version")
        else
            failed+=("$name: Could not verify new binary")
        fi
    done
    
    local info="⚠️ IMPORTANT: Restart $SERVICE_NAME on updated nodes\n   Use 'Restart service' in Node Operations menu\n\n💾 Old binaries backed up to $BINARY_PATH/old/"
    show_operation_results "🔄 Nym-Node Update" successful failed "$info"
}

toggle_node_functionality() {
    select_nodes "multi" "Configure Nodes" || return
    
    local user=$(get_input "SSH Connection" "SSH username (same for all):")
    [[ -z "$user" ]] && { show_msg "Cancelled" "Configuration cancelled."; return; }
    
    local pass=$(get_password "SSH Connection" "SSH password for $user:")
    [[ -z "$pass" ]] && { show_msg "Cancelled" "Configuration cancelled."; return; }
    
    ssh_exec "${SELECTED_NODES_IPS[0]}" "$user" "$pass" "echo 'OK'" "Connection Test" >/dev/null 2>&1 || { show_error "SSH connection failed. Check credentials."; return; }
    
    local wg_choice=$(dialog --title "Wireguard Configuration" --radiolist "Select Wireguard setting:" 12 60 2 \
        "enabled" "Enable Wireguard" "OFF" "disabled" "Disable Wireguard" "ON" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && return
    
    local mode_choice=$(dialog --title "Mixnet Mode Configuration" --radiolist "Select mode:" 14 60 3 \
        "entry-gateway" "Entry Gateway" "OFF" "exit-gateway" "Exit Gateway" "OFF" "mixnode" "Mixnode" "ON" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && return
    
    local node_list=""
    for ((i=0; i<${#SELECTED_NODES_NAMES[@]}; i++)); do
        node_list+="\n• ${SELECTED_NODES_NAMES[i]} (${SELECTED_NODES_IPS[i]})"
    done
    confirm "Apply configuration to ${#SELECTED_NODES_NAMES[@]} node(s)?$node_list\n\n• Wireguard: $wg_choice\n• Mode: $mode_choice" || return
    
    local successful=() failed=()
    local total=${#SELECTED_NODES_NAMES[@]} current=0
    
    for ((i=0; i<total; i++)); do
        local name="${SELECTED_NODES_NAMES[i]}" ip="${SELECTED_NODES_IPS[i]}" node_id="${SELECTED_NODES_IDS[i]}"
        ((current++))
        
        dialog --title "Configuring Nodes" --infobox "Processing $name ($current/$total)..." 6 60
        ssh_exec "$ip" "$user" "$pass" "echo 'OK'" "Connection Test" >/dev/null 2>&1 || { failed+=("$name: SSH connection failed"); continue; }
        
        local service_user=$(ssh_exec "$ip" "$user" "$pass" "grep '^User=' /etc/systemd/system/$SERVICE_NAME | cut -d'=' -f2" "Get User" "true" 2>/dev/null)
        [[ -z "$service_user" ]] && service_user="root"
        local config_path=$([[ "$service_user" == "root" ]] && echo "/root/.nym/nym-nodes/$node_id/config/config.toml" || echo "/home/$service_user/.nym/nym-nodes/$node_id/config/config.toml")
        
        local service_updated=false config_updated=false
        local has_flags=$(ssh_exec "$ip" "$user" "$pass" "grep -E '(--wireguard-enabled|--mode)' /etc/systemd/system/$SERVICE_NAME" "Check Flags" "true" 2>/dev/null)
        
        if [[ -n "$has_flags" ]]; then
            local wg_flag=$([[ "$wg_choice" = "enabled" ]] && echo "true" || echo "false")
            local update_cmd="cp /etc/systemd/system/$SERVICE_NAME /etc/systemd/system/$SERVICE_NAME.backup.\$(date +%Y%m%d_%H%M%S) && "
            update_cmd+="sed -i 's/--wireguard-enabled [^ ]*/--wireguard-enabled $wg_flag/g; t wg; s/\\(ExecStart=[^ ]* run\\)/\\1 --wireguard-enabled $wg_flag/; :wg' /etc/systemd/system/$SERVICE_NAME && "
            update_cmd+="sed -i 's/--mode [^ ]*/--mode $mode_choice/g; t mode; s/\\(ExecStart=[^ ]* run\\)/\\1 --mode $mode_choice/; :mode' /etc/systemd/system/$SERVICE_NAME && "
            update_cmd+="systemctl daemon-reload"
            ssh_exec "$ip" "$user" "$pass" "$update_cmd" "Update Service" "true" >/dev/null 2>&1 && service_updated=true
        fi
        
        local config_exists=$(ssh_exec "$ip" "$user" "$pass" "test -f $config_path && echo 'exists'" "Check Config" "true" 2>/dev/null)
        if [[ "$config_exists" == "exists" ]]; then
            local mixnode_val="false" entry_val="false" exit_val="false"
            case "$mode_choice" in
                "mixnode") mixnode_val="true" ;;
                "entry-gateway") entry_val="true" ;;
                "exit-gateway") exit_val="true" ;;
            esac
            
            local wg_toml=$([[ "$wg_choice" = "enabled" ]] && echo "true" || echo "false")
            local config_cmd="cp $config_path ${config_path}.backup.\$(date +%Y%m%d_%H%M%S) && "
            config_cmd+="sed -i '/^\[modes\]/,/^\[/ { s/^mixnode = .*/mixnode = $mixnode_val/; s/^entry = .*/entry = $entry_val/; s/^exit = .*/exit = $exit_val/; }' $config_path && "
            config_cmd+="sed -i '/^\[wireguard\]/,/^\[/ { s/^enabled = .*/enabled = $wg_toml/; }' $config_path"
            ssh_exec "$ip" "$user" "$pass" "$config_cmd" "Update Config" "true" >/dev/null 2>&1 && config_updated=true
        fi
        
        if [[ "$service_updated" == "true" || "$config_updated" == "true" ]]; then
            local method=""
            [[ "$service_updated" == "true" && "$config_updated" == "true" ]] && method="service & config.toml"
            [[ "$service_updated" == "true" && "$config_updated" == "false" ]] && method="service file"
            [[ "$service_updated" == "false" && "$config_updated" == "true" ]] && method="config.toml"
            successful+=("$name: Updated ($method)")
        else
            failed+=("$name: Failed to update configuration")
        fi
    done
    
    local info="Applied Configuration:\n   • Wireguard: $wg_choice\n   • Mode: $mode_choice\n\n⚠️ IMPORTANT: Restart services on updated nodes"
    show_operation_results "🔧 Node Configuration" successful failed "$info"
}

restart_service() {
    select_nodes "multi" "Restart Service" || return
    
    local user=$(get_input "SSH Connection" "SSH username (same for all):")
    [[ -z "$user" ]] && { show_msg "Cancelled" "Restart cancelled."; return; }
    
    local pass=$(get_password "SSH Connection" "SSH password for $user:")
    [[ -z "$pass" ]] && { show_msg "Cancelled" "Restart cancelled."; return; }
    
    local node_list=""
    for ((i=0; i<${#SELECTED_NODES_NAMES[@]}; i++)); do
        node_list+="\n• ${SELECTED_NODES_NAMES[i]} (${SELECTED_NODES_IPS[i]})"
    done
    confirm "Restart $SERVICE_NAME on ${#SELECTED_NODES_NAMES[@]} node(s)?$node_list" || return
    
    local successful=() failed=()
    local total=${#SELECTED_NODES_NAMES[@]} current=0
    
    for ((i=0; i<total; i++)); do
        local name="${SELECTED_NODES_NAMES[i]}" ip="${SELECTED_NODES_IPS[i]}"
        ((current++))
        
        dialog --title "Restarting Services" --infobox "Processing $name ($current/$total)..." 6 60
        ssh_exec "$ip" "$user" "$pass" "echo 'OK'" "Connection Test" >/dev/null 2>&1 || { failed+=("$name: SSH connection failed"); continue; }
        
        # Use use_root parameter instead of embedding password in command
        if ssh_exec "$ip" "$user" "$pass" "systemctl restart $SERVICE_NAME" "Restart" "true" >/dev/null 2>&1; then
            sleep 2
            # Use use_root parameter for status check as well
            local status=$(ssh_exec "$ip" "$user" "$pass" "systemctl is-active $SERVICE_NAME" "Status Check" "true" 2>/dev/null)
            [[ -n "$status" ]] && successful+=("$name: Restarted (Status: $status)") || successful+=("$name: Restarted")
        else
            failed+=("$name: Failed to restart service")
        fi
    done
    
    show_operation_results "🔄 Service Restart" successful failed "🎯 Service Restart Complete!"
}

disable_root_ssh() {
    select_nodes "multi" "Disable root@ssh" || return
    
    local user=$(get_input "SSH Credentials" "SSH username:")
    [[ -z "$user" ]] && return
    
    local pass=$(get_password "SSH Credentials" "SSH password for $user:")
    [[ -z "$pass" ]] && return
    
    local results="🔒 Disable root@ssh Results\n════════════════════════════════════════════════════════════════\n\n"
    
    for i in "${!SELECTED_NODES_NAMES[@]}"; do
        local name="${SELECTED_NODES_NAMES[i]}" ip="${SELECTED_NODES_IPS[i]}"
        dialog --title "Disabling root SSH" --infobox "Processing: $name ($ip)..." 5 50
        
        log "SSH_ROOT" "Processing node: $name ($ip)"
        
        # First, check current configuration
        local check_cmd="grep -E '^#?PermitRootLogin' /etc/ssh/sshd_config | tail -1"
        local current_config=$(ssh_exec "$ip" "$user" "$pass" "$check_cmd" "Check SSH config" "true" 2>&1)
        
        log "SSH_ROOT" "$name - Current config: $current_config"
        
        # Check if already disabled
        if echo "$current_config" | grep -q "^PermitRootLogin no"; then
            results+="⏭️  $name ($ip) - Root SSH already disabled, skipping\n\n"
            log "SSH_ROOT" "$name - Already disabled, skipping"
            continue
        fi
        
        # Disable root login
        local disable_cmd="sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && echo 'CONFIG_UPDATED'"
        local disable_output=$(ssh_exec "$ip" "$user" "$pass" "$disable_cmd" "Disable root SSH" "true" 2>&1)
        
        if [[ "$disable_output" != *"CONFIG_UPDATED"* ]]; then
            results+="❌ $name ($ip) - Failed to update SSH configuration\n\n"
            log "SSH_ROOT" "$name - Failed to update config"
            continue
        fi
        
        log "SSH_ROOT" "$name - Configuration updated"
        
        # Restart SSH daemon
        local restart_cmd="systemctl restart sshd && echo 'SSHD_RESTARTED'"
        local restart_output=$(ssh_exec "$ip" "$user" "$pass" "$restart_cmd" "Restart SSHD" "true" 2>&1)
        
        if [[ "$restart_output" != *"SSHD_RESTARTED"* ]]; then
            results+="❌ $name ($ip) - Configuration updated but failed to restart SSHD\n\n"
            log "SSH_ROOT" "$name - Failed to restart SSHD"
            continue
        fi
        
        log "SSH_ROOT" "$name - SSHD restarted"
        
        results+="✅ $name ($ip) - Root SSH disabled successfully\n   ✓ Configuration updated\n   ✓ SSHD restarted\n\n"
        log "SSH_ROOT" "$name - Successfully disabled"
    done
    
    show_success "$results"
}

# ----------------------------------------------------------------------------
# FAIL2BAN ACTIVATION AND CONFIGURATION
# ----------------------------------------------------------------------------

activate_fail2ban() {
    local action=$(dialog --clear --title "Fail2ban Management" --menu "Select action:" 12 60 4 \
        1 "Install & Configure Fail2ban" \
        2 "Check jailed IPs" \
        3 "Adjust fail2ban settings" \
        0 "Back" 3>&1 1>&2 2>&3)
    
    [[ $? -ne 0 || "$action" == "0" ]] && return
    
    case $action in
        1) fail2ban_install_configure ;;
        2) fail2ban_check_jailed ;;
        3) fail2ban_adjust_settings ;;
    esac
}

fail2ban_install_configure() {
    select_nodes "multi" "Install & Configure Fail2ban" || return
    
    local user=$(get_input "SSH Credentials" "SSH username:")
    [[ -z "$user" ]] && return
    
    local pass=$(get_password "SSH Credentials" "SSH password for $user:")
    [[ -z "$pass" ]] && return
    
    local results="🔒 Fail2ban Installation Results\n════════════════════════════════════════════════════════════════\n\n"
    local already_running=""
    local newly_installed=""
    local failed=""
    
    for i in "${!SELECTED_NODES_NAMES[@]}"; do
        local name="${SELECTED_NODES_NAMES[i]}" ip="${SELECTED_NODES_IPS[i]}"
        dialog --title "Configuring Fail2ban" --infobox "Processing: $name ($ip)..." 5 50
        
        log "FAIL2BAN" "$name - Checking if fail2ban is running"
        
        # First, check if fail2ban is already running
        local output=$(expect -c "
            log_user 0
            set timeout 30
            
            spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $SSH_PORT $user@$ip
            
            expect {
                \"password:\" {
                    send \"$pass\r\"
                    exp_continue
                }
                -re \"\\\\$\" {
                    send \"sudo su\r\"
                    expect {
                        \"password\" {
                            send \"$pass\r\"
                            expect \"#\"
                        }
                        \"#\" {}
                        timeout {
                            puts \"SUDO_TIMEOUT\"
                            exit 0
                        }
                    }
                    
                    # Check systemctl status
                    send \"systemctl status fail2ban\r\"
                    expect \"#\"
                    set status_output \$expect_out(buffer)
                    
                    # Output the result - check for various patterns (case insensitive)
                    set lower_output [string tolower \$status_output]
                    if {[string match \"*could not be found*\" \$lower_output]} {
                        puts \"NOT_FOUND\"
                    } elseif {[string match \"*active (running)*\" \$lower_output]} {
                        puts \"RUNNING\"
                    } elseif {[string match \"*active: active*\" \$lower_output]} {
                        puts \"RUNNING\"
                    } else {
                        puts \"NOT_RUNNING\"
                    }
                    
                    send \"exit\r\"
                    expect {
                        \"\\\\$\" { send \"exit\r\" }
                        timeout {}
                    }
                }
                timeout {
                    puts \"CONNECTION_TIMEOUT\"
                    exit 0
                }
            }
            
            catch {expect eof}
        " 2>&1)
        
        log "FAIL2BAN" "$name - Status check output: $output"
        
        # If already running, skip installation
        if [[ "$output" == *"RUNNING"* ]]; then
            already_running+="$name ($ip), "
            log "FAIL2BAN" "$name - Already running, skipping"
            continue
        fi
        
        # Not running, proceed with installation
        dialog --title "Installing Fail2ban" --infobox "Installing on: $name ($ip)..." 5 50
        log "FAIL2BAN" "$name - Installing fail2ban"
        
        local install_output=$(expect -c "
            log_user 0
            set timeout 120
            
            spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $SSH_PORT $user@$ip
            
            expect {
                \"password:\" {
                    send \"$pass\r\"
                    exp_continue
                }
                -re \"\\\\$\" {
                    send \"sudo su\r\"
                    expect {
                        \"password\" {
                            send \"$pass\r\"
                            expect \"#\"
                        }
                        \"#\" {}
                        timeout {
                            puts \"SUDO_TIMEOUT\"
                            exit 0
                        }
                    }
                    
                    # Install fail2ban
                    send \"export DEBIAN_FRONTEND=noninteractive\r\"
                    expect \"#\"
                    send \"apt-get update -qq\r\"
                    expect \"#\" { }
                    send \"apt-get install -y fail2ban\r\"
                    expect \"#\" { }
                    
                    # Create configuration
                    send \"cat > /etc/fail2ban/jail.local << 'EOFMARKER'\r\"
                    expect \">\"
                    send \"\[DEFAULT\]\r\"
                    expect \">\"
                    send \"bantime = 1h\r\"
                    expect \">\"
                    send \"findtime = 10m\r\"
                    expect \">\"
                    send \"maxretry = 3\r\"
                    expect \">\"
                    send \"banaction = iptables-multiport\r\"
                    expect \">\"
                    send \"\r\"
                    expect \">\"
                    send \"\[sshd\]\r\"
                    expect \">\"
                    send \"enabled = true\r\"
                    expect \">\"
                    send \"port = ssh\r\"
                    expect \">\"
                    send \"logpath = %(sshd_log)s\r\"
                    expect \">\"
                    send \"backend = %(sshd_backend)s\r\"
                    expect \">\"
                    send \"EOFMARKER\r\"
                    expect \"#\"
                    
                    # Enable and start service
                    send \"systemctl enable fail2ban\r\"
                    expect \"#\"
                    send \"systemctl start fail2ban\r\"
                    expect \"#\"
                    
                    # Verify it's running  
                    send \"systemctl is-active fail2ban\r\"
                    expect {
                        \"active\" {
                            puts \"INSTALL_SUCCESS\"
                            expect \"#\"
                        }
                        -re \"inactive|failed\" {
                            puts \"INSTALL_FAILED\"
                            expect \"#\"
                        }
                        timeout {
                            puts \"VERIFY_TIMEOUT\"
                        }
                    }
                    
                    send \"exit\r\"
                    expect {
                        \"\\\\$\" { send \"exit\r\" }
                        timeout {}
                    }
                }
                timeout {
                    puts \"INSTALL_TIMEOUT\"
                    exit 0
                }
            }
            
            catch {expect eof}
        " 2>&1)
        
        log "FAIL2BAN" "$name - Installation output: $install_output"
        
        if [[ "$install_output" == *"INSTALL_SUCCESS"* ]]; then
            newly_installed+="$name ($ip), "
            log "FAIL2BAN" "$name - Successfully installed"
        else
            failed+="$name ($ip), "
            log "FAIL2BAN" "$name - Installation failed"
        fi
    done
    
    # Build summary report
    if [[ -n "$already_running" ]]; then
        already_running="${already_running%, }"  # Remove trailing comma
        results+="✅ Already configured (no changes made):\n   $already_running\n\n"
    fi
    
    if [[ -n "$newly_installed" ]]; then
        newly_installed="${newly_installed%, }"  # Remove trailing comma
        results+="🆕 Newly installed and configured:\n   $newly_installed\n   • Max retries: 3 failed attempts\n   • Ban time: 1 hour\n   • Service: enabled and running\n\n"
    fi
    
    if [[ -n "$failed" ]]; then
        failed="${failed%, }"  # Remove trailing comma
        results+="❌ Installation failed:\n   $failed\n\n"
    fi
    
    show_success "$results"
}

fail2ban_adjust_settings() {
    # Get current settings or use defaults
    local maxretry=$(dialog --inputbox "Max failed attempts before ban:" 10 50 "3" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z "$maxretry" ]] && return
    
    local bantime=$(dialog --inputbox "Ban duration (e.g., 1h, 30m, 2h):" 10 50 "1h" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z "$bantime" ]] && return
    
    local findtime=$(dialog --inputbox "Time window for counting attempts (e.g., 10m, 5m):" 10 50 "10m" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z "$findtime" ]] && return
    
    # Confirm settings
    local confirm=$(dialog --title "Confirm Settings" --yesno "Apply these settings to selected nodes?\n\nMax retries: $maxretry\nBan time: $bantime\nFind time: $findtime" 12 60 3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && return
    
    select_nodes "multi" "Adjust Fail2ban Settings" || return
    
    local user=$(get_input "SSH Credentials" "SSH username:")
    [[ -z "$user" ]] && return
    
    local pass=$(get_password "SSH Credentials" "SSH password for $user:")
    [[ -z "$pass" ]] && return
    
    local results="⚙️ Fail2ban Settings Update Results\n════════════════════════════════════════════════════════════════\n\n"
    
    for i in "${!SELECTED_NODES_NAMES[@]}"; do
        local name="${SELECTED_NODES_NAMES[i]}" ip="${SELECTED_NODES_IPS[i]}"
        dialog --title "Updating Settings" --infobox "Processing: $name ($ip)..." 5 50
        
        log "FAIL2BAN_ADJUST" "$name - Updating settings: maxretry=$maxretry, bantime=$bantime, findtime=$findtime"
        
        local output=$(expect -c "
            log_user 0
            set timeout 30
            
            spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $SSH_PORT $user@$ip
            
            expect {
                \"password:\" {
                    send \"$pass\r\"
                    exp_continue
                }
                -re \"\\\\$\" {
                    send \"sudo su\r\"
                    expect {
                        \"password\" {
                            send \"$pass\r\"
                            expect \"#\"
                        }
                        \"#\" {}
                        timeout {
                            puts \"SUDO_TIMEOUT\"
                            exit 0
                        }
                    }
                    
                    # Update configuration with new settings
                    send \"cat > /etc/fail2ban/jail.local << 'EOFMARKER'\r\"
                    expect \">\"
                    send \"\[DEFAULT\]\r\"
                    expect \">\"
                    send \"bantime = $bantime\r\"
                    expect \">\"
                    send \"findtime = $findtime\r\"
                    expect \">\"
                    send \"maxretry = $maxretry\r\"
                    expect \">\"
                    send \"banaction = iptables-multiport\r\"
                    expect \">\"
                    send \"\r\"
                    expect \">\"
                    send \"\[sshd\]\r\"
                    expect \">\"
                    send \"enabled = true\r\"
                    expect \">\"
                    send \"port = ssh\r\"
                    expect \">\"
                    send \"logpath = %(sshd_log)s\r\"
                    expect \">\"
                    send \"backend = %(sshd_backend)s\r\"
                    expect \">\"
                    send \"EOFMARKER\r\"
                    expect {
                        \"#\" {
                            puts \"CONFIG_UPDATED\"
                        }
                        timeout {
                            puts \"CONFIG_TIMEOUT\"
                        }
                    }
                    
                    # Restart fail2ban to apply changes
                    send \"systemctl restart fail2ban\r\"
                    expect \"#\"
                    
                    # Verify it's still running
                    send \"systemctl is-active fail2ban\r\"
                    expect {
                        \"active\" {
                            puts \"UPDATE_SUCCESS\"
                            expect \"#\"
                        }
                        -re \"inactive|failed\" {
                            puts \"UPDATE_FAILED\"
                            expect \"#\"
                        }
                        timeout {
                            puts \"VERIFY_TIMEOUT\"
                        }
                    }
                    
                    send \"exit\r\"
                    expect {
                        \"\\\\$\" { send \"exit\r\" }
                        timeout {}
                    }
                }
                timeout {
                    puts \"CONNECTION_TIMEOUT\"
                    exit 0
                }
            }
            
            catch {expect eof}
        " 2>&1)
        
        log "FAIL2BAN_ADJUST" "$name - Output: $output"
        
        if [[ "$output" == *"UPDATE_SUCCESS"* ]]; then
            results+="✅ $name ($ip) - Settings updated successfully\n"
            results+="   • Max retries: $maxretry\n"
            results+="   • Ban time: $bantime\n"
            results+="   • Find time: $findtime\n\n"
            log "FAIL2BAN_ADJUST" "$name - Successfully updated"
        elif [[ "$output" == *"UPDATE_FAILED"* ]]; then
            results+="❌ $name ($ip) - Settings updated but service failed to restart\n\n"
            log "FAIL2BAN_ADJUST" "$name - Service restart failed"
        elif [[ "$output" == *"TIMEOUT"* ]]; then
            results+="❌ $name ($ip) - Timeout during update\n\n"
            log "FAIL2BAN_ADJUST" "$name - Timeout"
        else
            results+="❌ $name ($ip) - Update failed\n\n"
            log "FAIL2BAN_ADJUST" "$name - Failed"
        fi
    done
    
    show_success "$results"
}

fail2ban_check_jailed() {
    select_nodes "multi" "Check Jailed IPs" || return
    
    local user=$(get_input "SSH Credentials" "SSH username:")
    [[ -z "$user" ]] && return
    
    local pass=$(get_password "SSH Credentials" "SSH password for $user:")
    [[ -z "$pass" ]] && return
    
    local results="🚫 Jailed IPs Report\n════════════════════════════════════════════════════════════════\n\n"
    local all_banned_ips=()
    
    for i in "${!SELECTED_NODES_NAMES[@]}"; do
        local name="${SELECTED_NODES_NAMES[i]}" ip="${SELECTED_NODES_IPS[i]}"
        dialog --title "Checking Jailed IPs" --infobox "Processing: $name ($ip)..." 5 50
        
        # Use expect directly to get jail status
        local output=$(expect -c "
            log_user 0
            set timeout 30
            
            spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $SSH_PORT $user@$ip
            
            expect {
                \"password:\" {
                    send \"$pass\r\"
                    exp_continue
                }
                -re \"\\\\$|#\" {
                    # Elevate to root
                    send \"sudo su\r\"
                    expect {
                        \"password\" {
                            send \"$pass\r\"
                            expect \"#\"
                        }
                        \"#\" {}
                    }
                    
                    # Get jail status - wait for the prompt after command
                    send \"fail2ban-client status sshd\r\"
                    
                    # Wait for the output and the next prompt
                    expect \"#\"
                    
                    # Capture what we got
                    set output \$expect_out(buffer)
                    
                    # Clean up and output
                    puts \"===DATA_START===\"
                    puts \$output
                    puts \"===DATA_END===\"
                    
                    send \"exit\r\"
                    expect \"\\\\$\"
                    send \"exit\r\"
                }
                timeout {
                    puts \"SSH_TIMEOUT\"
                    exit 1
                }
            }
            expect eof
        " 2>&1)
        
        log "FAIL2BAN_JAIL" "$name - Raw output: $output"
        
        if [[ "$output" == *"===DATA_START==="* && "$output" == *"===DATA_END==="* ]]; then
            # Extract the data between markers
            local jail_data=$(echo "$output" | sed -n '/===DATA_START===/,/===DATA_END===/p' | sed '1d;$d')
            
            log "FAIL2BAN_JAIL" "$name - Parsed data: $jail_data"
            
            # Check if we got actual jail status
            if [[ "$jail_data" == *"Status for the jail: sshd"* ]]; then
                # Parse statistics - use awk which handles special characters better
                local currently_banned=$(echo "$jail_data" | awk '/Currently banned:/ {print $NF}')
                local total_banned=$(echo "$jail_data" | awk '/Total banned:/ {print $NF}')
                local currently_failed=$(echo "$jail_data" | awk '/Currently failed:/ {print $NF}')
                local total_failed=$(echo "$jail_data" | awk '/Total failed:/ {print $NF}')
                
                # Set defaults if not found
                currently_banned=${currently_banned:-0}
                total_banned=${total_banned:-0}
                currently_failed=${currently_failed:-0}
                total_failed=${total_failed:-0}
                
                log "FAIL2BAN_JAIL" "$name - Parsed: Banned=$currently_banned/$total_banned, Failed=$currently_failed/$total_failed"
                
                results+="✅ $name ($ip) - Fail2ban active\n"
                results+="   📊 Currently banned: $currently_banned IPs\n"
                results+="   📊 Total bans: $total_banned\n"
                results+="   📊 Current failed attempts: $currently_failed\n"
                results+="   📊 Total failed attempts: $total_failed\n"
                
                # Extract banned IPs list - they come after "Banned IP list:"
                if [[ "$currently_banned" != "0" ]]; then
                    # Get everything after "Banned IP list:" until end of line or next section
                    local banned_ips=$(echo "$jail_data" | grep "Banned IP list:" | sed 's/.*Banned IP list://' | xargs)
                    if [[ -n "$banned_ips" ]]; then
                        # Add to global list for geolocation
                        for banned_ip in $banned_ips; do
                            all_banned_ips+=("$banned_ip")
                        done
                        
                        results+="   🚫 Banned IPs:\n"
                        # Format IPs nicely, max 4 per line
                        local ip_array=($banned_ips)
                        local line=""
                        local count=0
                        for banned_ip in "${ip_array[@]}"; do
                            line+="$banned_ip "
                            ((count++))
                            if [[ $count -eq 4 ]]; then
                                results+="      $line\n"
                                line=""
                                count=0
                            fi
                        done
                        [[ -n "$line" ]] && results+="      $line\n"
                    fi
                fi
                results+="\n"
                
                log "FAIL2BAN_JAIL" "$name - Active | Banned: $currently_banned | Failed: $currently_failed"
            elif [[ "$jail_data" == *"No jail by the name"* ]]; then
                results+="⚠️  $name ($ip) - Fail2ban running but SSH jail not found\n\n"
                log "FAIL2BAN_JAIL" "$name - No jail"
            else
                results+="❌ $name ($ip) - Unexpected output from fail2ban\n\n"
                log "FAIL2BAN_JAIL" "$name - Unexpected output"
            fi
        else
            results+="❌ $name ($ip) - Fail2ban not responding or not installed\n\n"
            log "FAIL2BAN_JAIL" "$name - Not active or timeout"
        fi
    done
    
    # If we have banned IPs, geolocate them and show top 10 countries
    if [[ ${#all_banned_ips[@]} -gt 0 ]]; then
        results+="════════════════════════════════════════════════════════════════\n"
        results+="🌍 Geolocation Analysis\n"
        results+="════════════════════════════════════════════════════════════════\n\n"
        results+="Analyzing ${#all_banned_ips[@]} banned IPs...\n\n"
        
        dialog --title "Geolocating IPs" --infobox "Analyzing ${#all_banned_ips[@]} banned IPs..." 5 50
        
        # Check if jq is available
        if ! command -v jq &> /dev/null; then
            results+="⚠️  jq not installed - cannot perform geolocation\n"
            results+="   Install with: apt-get install jq\n\n"
        else
            # Geolocate each IP
            local processed=0
            local temp_geo_file="/tmp/fail2ban_geo_$$.txt"
            > "$temp_geo_file"
            
            for banned_ip in "${all_banned_ips[@]}"; do
                ((processed++))
                dialog --title "Geolocating IPs" --infobox "Processing IP $processed/${#all_banned_ips[@]}: $banned_ip" 5 60
                
                # Use ip-api.com for geolocation (free, no API key needed)
                local geo_data=$(curl -s "http://ip-api.com/json/$banned_ip?fields=country,countryCode" 2>/dev/null)
                
                if [[ -n "$geo_data" ]]; then
                    local country=$(echo "$geo_data" | jq -r '.country // "Unknown"' 2>/dev/null)
                    if [[ "$country" != "Unknown" && "$country" != "null" && -n "$country" ]]; then
                        echo "$country" >> "$temp_geo_file"
                        log "GEOLOCATION" "$banned_ip -> $country"
                    fi
                fi
                
                # Rate limit to avoid API throttling (5 per second max)
                sleep 0.2
            done
            
            # Count countries and display top 10
            if [[ -s "$temp_geo_file" ]]; then
                results+="🏆 Top 10 Countries of Origin:\n\n"
                local rank=1
                
                # Sort and count countries
                while IFS= read -r line; do
                    local count=$(echo "$line" | awk '{print $1}')
                    local country=$(echo "$line" | cut -d' ' -f2-)
                    local percentage=$(awk "BEGIN {printf \"%.1f\", ($count / ${#all_banned_ips[@]}) * 100}")
                    results+="   $rank. $country: $count IPs ($percentage%)\n"
                    ((rank++))
                    [[ $rank -gt 10 ]] && break
                done < <(sort "$temp_geo_file" | uniq -c | sort -rn)
                
                results+="\n"
            else
                results+="⚠️  No geolocation data available\n\n"
            fi
            
            # Cleanup
            rm -f "$temp_geo_file"
        fi
    fi
    
    dialog --title "Jailed IPs Report" --msgbox "$results" 40 85
}

# ----------------------------------------------------------------------------
# SSH COMMAND EXECUTION
# ----------------------------------------------------------------------------

execute_ssh_command() {
    select_nodes "multi" "Execute SSH Command" || return
    
    local user=$(get_input "SSH Connection" "SSH username (same for all):")
    [[ -z "$user" ]] && { show_msg "Cancelled" "Operation cancelled."; return; }
    
    local pass=$(get_password "SSH Connection" "SSH password for $user:")
    [[ -z "$pass" ]] && { show_msg "Cancelled" "Operation cancelled."; return; }
    
    local command=$(dialog --title "SSH Command" --inputbox "Enter command to execute on selected nodes:\n(Multi-line commands supported)" 12 70 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z "$command" ]] && { show_msg "Cancelled" "Operation cancelled."; return; }
    
    local use_root="false"
    if dialog --title "Root Execution" --yesno "Execute command with sudo/root privileges?\n\nCommand: $command\n\nSelect 'Yes' for root execution\nSelect 'No' for normal user execution" 12 60; then
        use_root="true"
    fi
    
    local node_list=""
    for ((i=0; i<${#SELECTED_NODES_NAMES[@]}; i++)); do
        node_list+="\n• ${SELECTED_NODES_NAMES[i]} (${SELECTED_NODES_IPS[i]})"
    done
    
    local exec_mode=$([[ "$use_root" == "true" ]] && echo "as ROOT" || echo "as USER")
    confirm "Execute command on ${#SELECTED_NODES_NAMES[@]} node(s) $exec_mode?$node_list\n\nCommand:\n$command" || return
    
    local successful=() failed=()
    local total=${#SELECTED_NODES_NAMES[@]} current=0
    
    for ((i=0; i<total; i++)); do
        local name="${SELECTED_NODES_NAMES[i]}" ip="${SELECTED_NODES_IPS[i]}"
        ((current++))
        
        dialog --title "Executing Command" --infobox "Processing $name ($current/$total)...\nExecuting command..." 6 60
        
        ssh_exec "$ip" "$user" "$pass" "$command" "Custom Command" "$use_root" >/dev/null 2>&1
        local exec_result=$?
        
        if [[ $exec_result -eq 0 ]]; then
            successful+=("$name")
        else
            failed+=("$name")
        fi
    done
    
    local info="Command: $command\nExecution Mode: $exec_mode"
    show_operation_results "⚡ SSH Command Execution" successful failed "$info"
}

replace_index_html() {
    log "REPLACE_HTML" "Starting replace_index_html function"
    
    # Step 1: Prompt for local index.html file path
    local local_file=$(get_input "Replace index.html" "Enter path to local index.html file:")
    [[ -z "$local_file" ]] && { show_msg "Cancelled" "Operation cancelled."; return; }
    
    # Expand tilde to home directory if present
    local_file="${local_file/#\~/$HOME}"
    
    # Check if file exists
    if [[ ! -f "$local_file" ]]; then
        show_error "File not found: $local_file"
        log "REPLACE_HTML" "File not found: $local_file"
        return
    fi
    
    log "REPLACE_HTML" "Local file verified: $local_file"
    
    # Step 2: Select nodes
    select_nodes "multi" "Replace index.html" || return
    log "REPLACE_HTML" "Nodes selected: ${#SELECTED_NODES_NAMES[@]}"
    
    # Check if all selected nodes have valid hostnames
    local nodes_without_hostname=()
    for ((i=0; i<${#SELECTED_NODES_NAMES[@]}; i++)); do
        local hostname="${SELECTED_NODES_HOSTNAMES[i]}"
        if [[ "$hostname" == "N/A" || -z "$hostname" ]]; then
            nodes_without_hostname+=("${SELECTED_NODES_NAMES[i]}")
        fi
    done
    
    # If any nodes lack hostname, show error and stop
    if [[ ${#nodes_without_hostname[@]} -gt 0 ]]; then
        local error_msg="The following node(s) don't have a hostname configured:\n\n"
        for node in "${nodes_without_hostname[@]}"; do
            error_msg+="• $node\n"
        done
        error_msg+="\nPlease edit these nodes first and set their hostname.\n"
        error_msg+="(Node Management → Edit node → Hostname)\n\n"
        error_msg+="The hostname is used to locate the path:\n/var/www/<hostname>/index.html"
        show_error "$error_msg"
        log "REPLACE_HTML" "Operation aborted: ${#nodes_without_hostname[@]} node(s) without hostname"
        return
    fi
    
    # Step 3: Prompt for SSH credentials
    local user=$(get_input "SSH Connection" "SSH username (same for all):")
    [[ -z "$user" ]] && { show_msg "Cancelled" "Operation cancelled."; return; }
    log "REPLACE_HTML" "Username entered: $user"
    
    local pass=$(get_password "SSH Connection" "SSH password for $user:")
    [[ -z "$pass" ]] && { show_msg "Cancelled" "Operation cancelled."; return; }
    log "REPLACE_HTML" "Password entered (length: ${#pass})"
    
    # Confirm operation
    local node_list=""
    for ((i=0; i<${#SELECTED_NODES_NAMES[@]}; i++)); do
        node_list+="\n• ${SELECTED_NODES_NAMES[i]} (${SELECTED_NODES_IPS[i]}) → /var/www/${SELECTED_NODES_HOSTNAMES[i]}/index.html"
    done
    
    confirm "Replace index.html on ${#SELECTED_NODES_NAMES[@]} node(s)?$node_list\n\nLocal file: $local_file" || return
    
    local successful=() failed=()
    local total=${#SELECTED_NODES_NAMES[@]} current=0
    
    for ((i=0; i<total; i++)); do
        local name="${SELECTED_NODES_NAMES[i]}" 
        local ip="${SELECTED_NODES_IPS[i]}" 
        local hostname="${SELECTED_NODES_HOSTNAMES[i]}"
        ((current++))
        
        log "REPLACE_HTML" "Processing node $current/$total: $name ($ip), hostname: $hostname"
        
        local remote_path="/var/www/$hostname/index.html"
        
        # Step 4: Test SSH connection
        dialog --title "Replace index.html" --infobox "Processing $name ($current/$total)...\nTesting connection..." 6 60
        log "REPLACE_HTML" "Testing SSH connection to $ip"
        
        ssh_exec "$ip" "$user" "$pass" "echo 'OK'" "Connection Test" "false" >/dev/null 2>&1
        if [[ $? -ne 0 ]]; then
            log "REPLACE_HTML" "SSH connection test FAILED for $name"
            failed+=("$name: SSH connection failed")
            continue
        fi
        log "REPLACE_HTML" "SSH connection test SUCCESS for $name"
        
        # Step 5 & 6: Check if remote directory exists and create backup
        dialog --title "Replace index.html" --infobox "Processing $name ($current/$total)...\nChecking remote directory..." 6 60
        log "REPLACE_HTML" "Checking remote directory: /var/www/$hostname"
        
        local dir_check=$(ssh_exec "$ip" "$user" "$pass" "[ -d /var/www/$hostname ] && echo EXISTS || echo NOTFOUND" "Check directory" "true" 2>&1)
        log "REPLACE_HTML" "Directory check result: $dir_check"
        
        if ! echo "$dir_check" | grep -q "EXISTS"; then
            log "REPLACE_HTML" "Directory not found: /var/www/$hostname"
            failed+=("$name: Directory /var/www/$hostname not found")
            continue
        fi
        
        # Create backup of existing index.html if it exists
        dialog --title "Replace index.html" --infobox "Processing $name ($current/$total)...\nCreating backup..." 6 60
        log "REPLACE_HTML" "Creating backup of existing index.html"
        
        local backup_cmd="if [ -f $remote_path ]; then cp $remote_path ${remote_path}.backup_\$(date +%Y%m%d_%H%M%S); echo BACKED_UP; else echo NO_FILE; fi"
        local backup_result=$(ssh_exec "$ip" "$user" "$pass" "$backup_cmd" "Backup file" "true" 2>&1)
        log "REPLACE_HTML" "Backup result: $backup_result"
        
        # Step 7: Upload file using rsync with password (encrypted connection)
        dialog --title "Replace index.html" --infobox "Processing $name ($current/$total)...\nUploading index.html..." 6 60
        log "REPLACE_HTML" "Uploading file via rsync"
        
        # Upload to temp location as regular user using sshpass and rsync
        local temp_file="/tmp/index.html.tmp_$$"
        
        # Use expect to handle the upload with password
        local upload_script=$(mktemp)
        cat > "$upload_script" << 'UPLOADEOF'
#!/usr/bin/expect -f
set timeout 60

if {[llength $argv] != 5} {
    puts "Error: Expected 5 arguments"
    exit 1
}

set user [lindex $argv 0]
set password [lindex $argv 1]
set ip [lindex $argv 2]
set port [lindex $argv 3]
set local_file [lindex $argv 4]

set remote_file "/tmp/index.html.tmp_[pid]"

log_user 0

spawn rsync -avz -e "ssh -p $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" $local_file $user@$ip:$remote_file

expect {
    -re "assword:" {
        send "$password\r"
        exp_continue
    }
    eof
}

catch wait result
set exit_code [lindex $result 3]

puts $remote_file
exit $exit_code
UPLOADEOF
        
        chmod +x "$upload_script"
        
        log "REPLACE_HTML" "Executing upload to $ip:$temp_file"
        local upload_output=$("$upload_script" "$user" "$pass" "$ip" "$SSH_PORT" "$local_file" 2>&1)
        local rsync_exit=$?
        local actual_temp_file=$(echo "$upload_output" | tail -1)
        
        rm -f "$upload_script"
        
        log "REPLACE_HTML" "Rsync exit code: $rsync_exit, temp file: $actual_temp_file"
        
        if [[ $rsync_exit -ne 0 ]]; then
            log "REPLACE_HTML" "Rsync failed for $name"
            failed+=("$name: Upload failed (rsync exit: $rsync_exit)")
            continue
        fi
        
        # Now move the file to final location with sudo and set proper permissions
        dialog --title "Replace index.html" --infobox "Processing $name ($current/$total)...\nSetting permissions..." 6 60
        log "REPLACE_HTML" "Moving file to final location and setting permissions"
        
        local move_cmd="mv $actual_temp_file $remote_path && chown www-data:www-data $remote_path 2>/dev/null || chown root:root $remote_path && chmod 644 $remote_path && echo SUCCESS"
        local move_result=$(ssh_exec "$ip" "$user" "$pass" "$move_cmd" "Move and set permissions" "true" 2>&1)
        
        log "REPLACE_HTML" "Move result: $move_result"
        
        if echo "$move_result" | grep -q "SUCCESS"; then
            log "REPLACE_HTML" "Successfully replaced index.html on $name"
            successful+=("$name: index.html replaced at $remote_path")
        else
            log "REPLACE_HTML" "Failed to move file to final location on $name"
            failed+=("$name: Failed to move file to $remote_path")
        fi
    done
    
    log "REPLACE_HTML" "Operation completed. Success: ${#successful[@]}, Failed: ${#failed[@]}"
    local info="📁 Local file: $local_file\n📂 Remote path: /var/www/<hostname>/index.html\n💾 Backups created with timestamp suffix"
    show_operation_results "🔄 Replace index.html" successful failed "$info"
}


# ----------------------------------------------------------------------------
# WALLET MANAGEMENT FUNCTIONS (FROM V76)
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# CSV EXPORT FUNCTIONS (NEW IN V69, ENHANCED IN V70)
# ----------------------------------------------------------------------------

# Get next available CSV filename with date and version
# Format: YYYYMMDD_nym_rewards_vXX.csv
get_csv_filename() {
    local date_prefix=$(date '+%Y%m%d')
    local version=1
    local filename
    
    # Find next available version number
    while true; do
        filename=$(printf "%s_nym_rewards_v%02d.csv" "$date_prefix" "$version")
        local filepath="$SCRIPT_DIR/$filename"
        
        if [[ ! -f "$filepath" ]]; then
            echo "$filepath"
            return 0
        fi
        
        ((version++))
        
        # Safety check: prevent infinite loop
        if [[ $version -gt 99 ]]; then
            echo "$SCRIPT_DIR/${date_prefix}_nym_rewards_v99.csv"
            return 1
        fi
    done
}

# Initialize CSV file with headers if it doesn't exist
init_csv_file() {
    local csv_file="$1"
    
    if [[ ! -f "$csv_file" ]]; then
        echo '"Type","Buy","Cur.","Sell","Cur.","Fee","Cur.","Exchange","Group","Comment","Trade ID","Imported From","Add Date","Date"' > "$csv_file"
        log "CSV" "Created new CSV file: $(basename "$csv_file")"
    fi
}

# Add withdrawal entry to CSV
# Parameters: csv_file, amount, wallet_name, timestamp
add_csv_entry() {
    local csv_file="$1"
    local amount="$2"
    local wallet_name="$3"
    local timestamp="$4"
    
    # Format: DD.MM.YYYY HH:MM:SS
    local formatted_date=$(date -d "$timestamp" '+%d.%m.%Y %H:%M:%S' 2>/dev/null)
    if [[ -z "$formatted_date" ]]; then
        formatted_date=$(date '+%d.%m.%Y %H:%M:%S')
    fi
    
    # Create CSV line with proper escaping
    # Type, Buy Amount, Buy Currency, Sell, Sell Cur, Fee, Fee Cur, Exchange, Group, Comment, Trade ID, Imported From, Add Date, Date
    local csv_line="\"Masternode\",\"${amount}\",\"NYM2\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"${formatted_date}\",\"${formatted_date}\""
    
    echo "$csv_line" >> "$csv_file"
    log "CSV" "Added entry: $amount NYM from $wallet_name at $formatted_date to $(basename "$csv_file")"
}

# Query actual reward amount before withdrawal
query_reward_amount() {
    local mnemonic="$1"
    local wallet_name="$2"
    
    # Derive address
    local address=$(derive_address_from_mnemonic "$mnemonic")
    if [[ -z "$address" ]]; then
        echo "0"
        return 1
    fi
    
    # Query pending rewards
    local rewards_result=$(query_pending_rewards "$address" "$wallet_name")
    local rewards_status=$(echo "$rewards_result" | cut -d'|' -f1)
    
    if [[ "$rewards_status" == "SUCCESS" ]]; then
        local rewards_nym=$(echo "$rewards_result" | cut -d'|' -f3)
        echo "$rewards_nym"
        return 0
    else
        echo "0"
        return 1
    fi
}

init_wallet_dir() {
    mkdir -p "$WALLET_DIR"
    touch "$WALLET_LIST"
    chmod 700 "$WALLET_DIR"
}

# Encrypt mnemonic
encrypt_mnemonic() {
    local wallet_name="$1"
    local mnemonic="$2"
    local password="$3"
    
    local wallet_enc="$WALLET_DIR/${wallet_name}.enc"
    echo "$mnemonic" | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -out "$wallet_enc" -pass pass:"$password"
    chmod 600 "$wallet_enc"
    
    if [ ! -f "$WALLET_LIST" ]; then
        touch "$WALLET_LIST"
        chmod 600 "$WALLET_LIST"
    fi
    
    if ! grep -q "^${wallet_name}$" "$WALLET_LIST" 2>/dev/null; then
        echo "$wallet_name" >> "$WALLET_LIST"
    fi
    
    log "WALLET" "Wallet '$wallet_name' encrypted and saved"
}

# Decrypt mnemonic
decrypt_mnemonic() {
    local wallet_name="$1"
    local password="$2"
    local wallet_enc="$WALLET_DIR/${wallet_name}.enc"
    
    if [ ! -f "$wallet_enc" ]; then
        return 1
    fi
    
    mnemonic=$(openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 -in "$wallet_enc" -pass pass:"$password" 2>/dev/null)
    
    if [ $? -ne 0 ] || [ -z "$mnemonic" ]; then
        return 1
    fi
    
    echo "$mnemonic"
}

# Check if nym-cli is installed
check_nym_cli() {
    if ! command -v nym-cli &> /dev/null; then
        show_error "nym-cli not found in PATH\n\nPlease install nym-cli or add it to your PATH"
        return 1
    fi
    return 0
}

# Derive Nyx address from mnemonic
derive_address_from_mnemonic() {
    local mnemonic="$1"
    local address=""
    
    if ! check_nym_cli; then
        return 1
    fi
    
    # Try to get address using nym-cli
    local account_output=$(nym-cli account pub-key --mnemonic "$mnemonic" 2>&1)
    
    # Try multiple extraction patterns
    address=$(echo "$account_output" | sed -n 's/.*\(n1[0-9a-z]\{38,\}\).*/\1/p' | head -1)
    
    if [ -z "$address" ]; then
        address=$(echo "$account_output" | grep -Eo 'n1[0-9a-z]{38,}' | head -1)
    fi
    
    if [ -z "$address" ]; then
        address=$(echo "$account_output" | awk '/n1[0-9a-z]/ {for(i=1;i<=NF;i++) if($i ~ /^n1[0-9a-z]{38,}/) print $i}' | head -1)
    fi
    
    echo "$address"
}

# Query pending operator rewards from REST API
query_pending_rewards() {
    local address="$1"
    local wallet_name="$2"
    
    # Create base64 encoded query
    local query_json="{\"get_pending_operator_reward\":{\"address\":\"$address\"}}"
    local query_b64=$(echo -n "$query_json" | base64 -w 0 2>/dev/null || echo -n "$query_json" | base64)
    
    # Mixnet contract and REST API endpoint
    local contract="n17srjznxl9dvzdkpwpw24gg668wc73val88a6m5ajg6ankwvz9wtst0cznr"
    local url="https://rest.cosmos.directory/nyx/cosmwasm/wasm/v1/contract/${contract}/smart/${query_b64}"
    
    # Query the API
    local response=$(curl -s "$url" 2>&1)
    local curl_exit=$?
    
    if [ $curl_exit -ne 0 ]; then
        echo "ERROR|Network error: Failed to connect to API"
        return 1
    fi
    
    # Check for API errors
    if echo "$response" | jq -e '.code' &>/dev/null 2>&1; then
        local error_msg=$(echo "$response" | jq -r '.message // "Unknown error"' 2>/dev/null)
        echo "ERROR|API error: $error_msg"
        return 1
    fi
    
    # Extract the amount_earned.amount from the response
    local amount_unym=$(echo "$response" | jq -r '.data.amount_earned.amount' 2>/dev/null)
    
    if [ -z "$amount_unym" ] || [ "$amount_unym" == "null" ]; then
        # Check if it's an empty response or error
        if echo "$response" | grep -qi "error\|not found"; then
            echo "NONE|No operator rewards found (no node bonded or no rewards available)"
        else
            echo "NONE|No pending rewards"
        fi
        return 0
    fi
    
    if [ "$amount_unym" == "0" ]; then
        echo "NONE|No pending rewards (0 uNYM)"
        return 0
    fi
    
    # Convert uNYM to NYM (divide by 1,000,000)
    local amount_nym=$(echo "scale=6; $amount_unym / 1000000" | bc 2>/dev/null)
    
    if [ -z "$amount_nym" ]; then
        amount_nym="N/A"
    fi
    
    echo "SUCCESS|$amount_unym|$amount_nym"
    return 0
}

# Get current NYM price in USD from CoinGecko API
get_nym_price_usd() {
    # Try CoinGecko API first
    local price=$(curl -s --connect-timeout 5 --max-time 10 "https://api.coingecko.com/api/v3/simple/price?ids=nym&vs_currencies=usd" 2>/dev/null | grep -o '"usd":[0-9.]*' | cut -d':' -f2)
    
    # If CoinGecko fails, try CoinPaprika
    if [[ -z "$price" || "$price" == "0" ]]; then
        price=$(curl -s --connect-timeout 5 --max-time 10 "https://api.coinpaprika.com/v1/tickers/nym-nym" 2>/dev/null | grep -o '"price":[0-9.]*' | head -1 | cut -d':' -f2)
    fi
    
    # If both fail, try Binance (if they list NYM)
    if [[ -z "$price" || "$price" == "0" ]]; then
        price=$(curl -s --connect-timeout 5 --max-time 10 "https://api.binance.com/api/v3/ticker/price?symbol=NYMUSDT" 2>/dev/null | grep -o '"price":"[0-9.]*"' | cut -d'"' -f4)
    fi
    
    # Return price or empty if all failed
    if [[ -n "$price" && "$price" != "0" ]]; then
        echo "$price"
        return 0
    else
        echo ""
        return 1
    fi
}

# Calculate USD value from NYM amount and price
calculate_usd_value() {
    local nym_amount="$1"
    local nym_price="$2"
    
    # Validate inputs
    if [[ ! "$nym_amount" =~ ^[0-9]+\.?[0-9]*$ ]] || [[ ! "$nym_price" =~ ^[0-9]+\.?[0-9]*$ ]]; then
        echo "0.00"
        return 1
    fi
    
    # Calculate USD value
    local usd_value=$(echo "scale=2; $nym_amount * $nym_price" | bc 2>/dev/null)
    
    if [[ -z "$usd_value" ]]; then
        echo "0.00"
        return 1
    fi
    
    # Format with thousand separators
    printf "%'.2f" "$usd_value" 2>/dev/null || echo "$usd_value"
    return 0
}

# Get wallet balance using nym-cli
get_wallet_balance() {
    local address="$1"
    
    if ! check_nym_cli; then
        echo "ERROR"
        return 1
    fi
    
    # Query balance using nym-cli
    local balance_output=$(nym-cli account balance "$address" 2>&1)
    
    # Extract the balance from the last line (format: "144.974769 nym")
    local balance=$(echo "$balance_output" | tail -1 | grep -Eo '[0-9]+\.[0-9]+ nym' | awk '{print $1}')
    
    if [ -z "$balance" ]; then
        # Try alternate format without decimal
        balance=$(echo "$balance_output" | tail -1 | grep -Eo '[0-9]+ nym' | awk '{print $1}')
    fi
    
    if [ -z "$balance" ]; then
        echo "0"
    else
        echo "$balance"
    fi
    return 0
}

# Validate Nym address format
validate_nym_address() {
    local address="$1"
    
    # Nym addresses start with 'n1' or 'n' followed by 38-50 alphanumeric characters
    if [[ "$address" =~ ^n1[a-z0-9]{38,50}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Get list of wallets sorted alphabetically
get_wallet_list() {
    if [[ ! -f "$WALLET_LIST" ]] || [[ ! -s "$WALLET_LIST" ]]; then
        return 1
    fi
    # Sort wallet names alphabetically
    sort "$WALLET_LIST"
    return 0
}

# Add a new wallet
wallet_add() {
    local wallet_name=$(get_input "Add Wallet" "Enter wallet name:")
    [[ -z "$wallet_name" ]] && return
    
    # Check if wallet already exists
    if get_wallet_list | grep -q "^${wallet_name}$"; then
        show_error "Wallet '$wallet_name' already exists!"
        return
    fi
    
    local mnemonic=$(get_input "Add Wallet" "Enter 24-word mnemonic phrase:")
    [[ -z "$mnemonic" ]] && return
    
    # Validate mnemonic word count
    local word_count=$(echo "$mnemonic" | wc -w)
    if [[ $word_count -ne 24 ]]; then
        show_error "Invalid mnemonic! Must be exactly 24 words. You provided $word_count words."
        return
    fi
    
    local password=$(get_password "Add Wallet" "Enter encryption password:")
    [[ -z "$password" ]] && return
    
    local password_confirm=$(get_password "Add Wallet" "Confirm encryption password:")
    [[ -z "$password_confirm" ]] && return
    
    if [[ "$password" != "$password_confirm" ]]; then
        show_error "Passwords do not match!"
        return
    fi
    
    # Encrypt and save mnemonic using the v61 function
    encrypt_mnemonic "$wallet_name" "$mnemonic" "$password"
    
    log "WALLET" "Added wallet: $wallet_name"
    show_success "Wallet '$wallet_name' added successfully!"
}

# List all wallets
wallet_list() {
    init_wallet_dir
    
    local wallets
    if ! wallets=$(get_wallet_list); then
        show_msg "No Wallets" "No wallets found.\n\nUse 'Add new wallet' to create one."
        return
    fi
    
    # Ask for password once to decrypt and show addresses
    local password=$(get_password "Query Wallets" "Enter password to display wallet information:")
    [[ -z "$password" ]] && return
    
    # Show loading message
    dialog --title "Loading Wallets" --infobox "Querying wallet information...\nThis may take a moment." 5 50
    
    # Get current NYM price in USD (non-blocking, continue if fails)
    local nym_price=$(get_nym_price_usd)
    local price_available=false
    if [[ -n "$nym_price" && "$nym_price" != "0" ]]; then
        price_available=true
    fi
    
    local wallet_details=""
    local count=0
    local success_count=0
    local fail_count=0
    local total_rewards=0
    
    while IFS= read -r wallet_name; do
        ((count++))
        
        # Try to decrypt and derive address
        local mnemonic=$(decrypt_mnemonic "$wallet_name" "$password" 2>/dev/null)
        
        if [ $? -ne 0 ] || [ -z "$mnemonic" ]; then
            wallet_details+="$wallet_name\n"
            wallet_details+="  Status: Failed to decrypt (wrong password)\n\n"
            ((fail_count++))
            continue
        fi
        
        # Derive address using the same function as other menus
        local address=$(derive_address_from_mnemonic "$mnemonic")
        
        if [ -z "$address" ]; then
            wallet_details+="$wallet_name\n"
            wallet_details+="  Status: Failed to derive address\n\n"
            ((fail_count++))
            continue
        fi
        
        # Query balance using the same function as "Create new transaction"
        local balance=$(get_wallet_balance "$address")
        if [ -z "$balance" ] || [ "$balance" == "ERROR" ]; then
            balance="0"
        fi
        
        # Query operator rewards
        local rewards_result=$(query_pending_rewards "$address" "$wallet_name")
        local rewards_status=$(echo "$rewards_result" | cut -d'|' -f1)
        local rewards_nym="0"
        local rewards_unym="0"
        
        if [ "$rewards_status" == "SUCCESS" ]; then
            rewards_unym=$(echo "$rewards_result" | cut -d'|' -f2)
            rewards_nym=$(echo "$rewards_result" | cut -d'|' -f3)
            # Add to total rewards
            total_rewards=$(echo "$total_rewards + $rewards_nym" | bc 2>/dev/null)
        elif [ "$rewards_status" == "NONE" ]; then
            rewards_nym="0"
            rewards_unym="0"
        else
            # ERROR case
            rewards_nym="Error"
            rewards_unym="Error"
        fi
        
        # Format individual wallet output with 2 decimal places
        local rewards_display=$rewards_nym
        if [[ "$rewards_nym" =~ ^[0-9]+\.?[0-9]*$ ]]; then
            rewards_display=$(printf "%.2f" "$rewards_nym")
        fi
        
        local balance_display=$balance
        if [[ "$balance" =~ ^[0-9]+\.?[0-9]*$ ]]; then
            balance_display=$(printf "%.2f" "$balance")
        fi
        
        wallet_details+="$wallet_name\n"
        wallet_details+="  Address: $address\n"
        wallet_details+="  Claimable operator rewards: $rewards_display NYM\n"
        wallet_details+="  Wallet balance: $balance_display NYM\n\n"
        
        ((success_count++))
    done <<< "$wallets"
    
    # Format total rewards to 2 decimal places
    local total_rewards_display=$(printf "%.2f" "$total_rewards")
    
    # Build final output with total at the top
    local wallet_list=""
    if [[ "$price_available" == "true" ]]; then
        # Format price to 3 decimal places
        local nym_price_display=$(printf "%.3f" "$nym_price")
        # Calculate USD value
        local total_usd=$(calculate_usd_value "$total_rewards" "$nym_price")
        wallet_list="TOTAL claimable rewards for $count wallets: $total_rewards_display NYM (equals \$$total_usd USD)\n"
        wallet_list+="Current NYM price: \$$nym_price_display USD\n\n"
    else
        wallet_list="TOTAL claimable rewards for $count wallets: $total_rewards_display NYM\n"
        wallet_list+="(Price data unavailable)\n\n"
    fi
    
    wallet_list+="════════════════════════════════════════════════════════════════════════════════════════════════\n\n"
    wallet_list+="$wallet_details"
    wallet_list+="════════════════════════════════════════════════════════════════════════════════════════════════\n"
    wallet_list+="Total: $count | Successfully displayed: $success_count | Failed: $fail_count"
    
    dialog --title "Query Wallets" --msgbox "$wallet_list" 35 100
}

# Export wallet (show mnemonic)
wallet_export() {
    local wallets
    if ! wallets=$(get_wallet_list); then
        show_msg "No Wallets" "No wallets configured. Add a wallet first!"
        return
    fi
    
    # Create menu options from sorted wallet list
    local options=()
    local count=0
    while IFS= read -r wallet; do
        ((count++))
        options+=("$count" "$wallet")
    done <<< "$wallets"
    
    local choice=$(dialog --clear --title "Export Wallet" --menu "Select wallet to export:" 15 60 "${#options[@]}" "${options[@]}" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && return
    
    # Get wallet name from sorted list
    local wallet_name=$(echo "$wallets" | sed -n "${choice}p")
    [[ -z "$wallet_name" ]] && return
    
    local password=$(get_password "Export Wallet" "Enter encryption password for '$wallet_name':")
    [[ -z "$password" ]] && return
    
    local mnemonic=$(decrypt_mnemonic "$wallet_name" "$password")
    
    if [[ $? -ne 0 ]] || [[ -z "$mnemonic" ]]; then
        show_error "Decryption failed! Incorrect password."
        return
    fi
    
    dialog --title "Wallet Mnemonic" --msgbox "Wallet: $wallet_name\n\nMnemonic Phrase:\n────────────────────────────────────────────────────────\n$mnemonic\n────────────────────────────────────────────────────────\n\nWARNING: Keep this safe! Anyone with this phrase can access your funds." 20 80
    
    log "WALLET" "Exported wallet: $wallet_name"
}

# Delete wallet
wallet_delete() {
    local wallets
    if ! wallets=$(get_wallet_list); then
        show_msg "No Wallets" "No wallets configured. Add a wallet first!"
        return
    fi
    
    # Add "All Wallets" option at the beginning
    local checklist=("0" "🌟 All Wallets" "off")
    local count=0
    while IFS= read -r wallet; do
        ((count++))
        checklist+=("$count" "$wallet" "off")
    done <<< "$wallets"
    
    local choices=$(dialog --clear --title "Delete Wallet" --separate-output --checklist "Select wallets to delete (Space=toggle, Enter=confirm):" 18 60 "${#checklist[@]}" "${checklist[@]}" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z "$choices" ]] && return
    
    # Check if "All Wallets" was selected
    local delete_all=false
    if echo "$choices" | grep -q "^0$"; then
        delete_all=true
    fi
    
    # Collect selected wallets
    local selected_wallets=()
    if [[ "$delete_all" == "true" ]]; then
        # Add all wallets
        while IFS= read -r wallet; do
            selected_wallets+=("$wallet")
        done <<< "$wallets"
    else
        # Add only selected wallets
        while IFS= read -r choice; do
            [[ "$choice" == "0" ]] && continue  # Skip "All Wallets" option
            local wallet_name=$(echo "$wallets" | sed -n "${choice}p")
            selected_wallets+=("$wallet_name")
        done <<< "$choices"
    fi
    
    [[ ${#selected_wallets[@]} -eq 0 ]] && return
    
    # Build confirmation message
    local confirm_msg="Delete ${#selected_wallets[@]} wallet(s)?\n\n"
    for wallet in "${selected_wallets[@]}"; do
        confirm_msg+="• $wallet\n"
    done
    confirm_msg+="\nWARNING: This action cannot be undone!\nMake sure you have backed up all mnemonics."
    
    confirm "$confirm_msg" || return
    
    # Delete selected wallets
    local deleted=0
    for wallet_name in "${selected_wallets[@]}"; do
        local wallet_file="$WALLET_DIR/${wallet_name}.enc"
        rm -f "$wallet_file"
        
        # Remove from wallet list
        local temp=$(mktemp)
        grep -v "^${wallet_name}$" "$WALLET_LIST" > "$temp"
        mv "$temp" "$WALLET_LIST"
        
        log "WALLET" "Deleted wallet: $wallet_name"
        ((deleted++))
    done
    
    show_success "$deleted wallet(s) deleted successfully!"
}

# Withdraw operator rewards from selected wallets
wallet_withdraw_rewards() {
    if ! check_nym_cli; then
        return
    fi
    
    init_wallet_dir
    
    local wallets
    if ! wallets=$(get_wallet_list); then
        show_msg "No Wallets" "No wallets configured. Add a wallet first!"
        return
    fi
    
    # Ask if user wants to export only or withdraw and export
    local mode_choice=$(dialog --clear --title "Withdraw Rewards" --menu "Choose operation mode:" 12 60 2 \
        1 "Withdraw rewards and export to CSV" \
        2 "Export to CSV only (no withdrawal - for testing)" \
        3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && return
    
    local export_only=false
    case $mode_choice in
        2) export_only=true ;;
        1) export_only=false ;;
        *) return ;;
    esac
    
    # Create checklist options from sorted wallet list with "All Wallets" option at the top
    local checklist=("0" "🌟 All Wallets" "off")
    local count=0
    while IFS= read -r wallet; do
        ((count++))
        checklist+=("$count" "$wallet" "off")
    done <<< "$wallets"
    
    local choices=$(dialog --clear --title "Withdraw Rewards" --separate-output --checklist "Select wallets (Space=toggle, Enter=confirm):" 18 60 "${#checklist[@]}" "${checklist[@]}" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z "$choices" ]] && return
    
    # Check if "All Wallets" was selected
    local select_all=false
    if echo "$choices" | grep -q "^0$"; then
        select_all=true
    fi
    
    # Collect selected wallets in order
    local selected_wallets=()
    if [[ "$select_all" == "true" ]]; then
        # Add all wallets
        while IFS= read -r wallet; do
            selected_wallets+=("$wallet")
        done <<< "$wallets"
    else
        # Add only selected wallets
        while IFS= read -r choice; do
            [[ "$choice" == "0" ]] && continue  # Skip "All Wallets" option if mixed selection
            local wallet_name=$(echo "$wallets" | sed -n "${choice}p")
            selected_wallets+=("$wallet_name")
        done <<< "$choices"
    fi
    
    [[ ${#selected_wallets[@]} -eq 0 ]] && return
    
    # Warning confirmation
    if [ "$export_only" == "false" ]; then
        if ! confirm "WARNING: This will WITHDRAW rewards!\n\nThe rewards will be withdrawn to your account.\n\nProceed with withdrawal for ${#selected_wallets[@]} wallet(s)?"; then
            show_msg "Cancelled" "Rewards withdrawal cancelled."
            return
        fi
    else
        if ! confirm "Export CSV for ${#selected_wallets[@]} wallet(s)?\n\nThis will query reward amounts and add entries to CSV\nwithout actually withdrawing."; then
            show_msg "Cancelled" "CSV export cancelled."
            return
        fi
    fi
    
    # Get versioned CSV filename for this export
    local csv_file=$(get_csv_filename)
    if [[ $? -ne 0 ]]; then
        show_error "Failed to determine CSV filename. Too many exports today (>99)?"
        return
    fi
    
    # Initialize CSV file with headers
    init_csv_file "$csv_file"
    
    local csv_basename=$(basename "$csv_file")
    log "CSV" "Using CSV file: $csv_basename"
    
    # Ask for password strategy
    local use_same_password=true
    if [ ${#selected_wallets[@]} -gt 1 ]; then
        if ! confirm "Use the same password for all selected wallets?\n\n(Select 'No' to enter password for each wallet individually)"; then
            use_same_password=false
        fi
    fi
    
    local password=""
    if [ "$use_same_password" == "true" ]; then
        password=$(get_password "Withdraw Rewards" "Enter decryption password:")
        [[ -z "$password" ]] && return
    fi
    
    # Process withdrawals
    local results=""
    if [ "$export_only" == "false" ]; then
        results="Withdrawal Results\n────────────────────────────────────────────────────────\n\n"
    else
        results="CSV Export Results (No Withdrawals)\n────────────────────────────────────────────────────────\n\n"
    fi
    
    local success=0 failed=0 exported=0
    local total=${#selected_wallets[@]}
    local current=0
    
    for wallet_name in "${selected_wallets[@]}"; do
        ((current++))
        
        if [ "$export_only" == "false" ]; then
            dialog --title "Processing" --infobox "Withdrawing rewards ($current/$total)\n$wallet_name..." 6 50
        else
            dialog --title "Processing" --infobox "Exporting to CSV ($current/$total)\n$wallet_name..." 6 50
        fi
        
        # Get password for this wallet if needed
        local wallet_password="$password"
        if [ "$use_same_password" == "false" ]; then
            wallet_password=$(get_password "Withdraw Rewards" "Enter password for '$wallet_name':")
            [[ -z "$wallet_password" ]] && { results+="$wallet_name: Skipped (no password)\n\n"; ((failed++)); continue; }
        fi
        
        local mnemonic=$(decrypt_mnemonic "$wallet_name" "$wallet_password")
        
        if [[ $? -ne 0 ]] || [[ -z "$mnemonic" ]]; then
            results+="$wallet_name - Decryption failed (wrong password?)\n\n"
            ((failed++))
            continue
        fi
        
        # Get address for display
        local address=$(derive_address_from_mnemonic "$mnemonic")
        
        # Query reward amount BEFORE withdrawal
        local reward_amount=$(query_reward_amount "$mnemonic" "$wallet_name")
        
        if [ "$export_only" == "true" ]; then
            # Export only mode - just add to CSV
            if [[ "$reward_amount" =~ ^[0-9]+\.?[0-9]*$ ]] && (( $(echo "$reward_amount > 0" | bc -l) )); then
                local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
                add_csv_entry "$csv_file" "$reward_amount" "$wallet_name" "$timestamp"
                results+="EXPORTED: $wallet_name"
                [[ -n "$address" ]] && results+=" (${address:0:15}...)"
                results+="\n   Amount: $reward_amount NYM\n   Added to CSV\n\n"
                ((exported++))
                ((success++))
            else
                results+="SKIPPED: $wallet_name"
                [[ -n "$address" ]] && results+=" (${address:0:15}...)"
                results+="\n   No rewards available to export\n\n"
                ((failed++))
            fi
        else
            # Normal withdrawal mode
            # Execute withdrawal using nym-cli
            local withdraw_output=$(nym-cli mixnet operators nymnode rewards claim --mnemonic "$mnemonic" 2>&1)
            local withdraw_status=$?
            
            if [[ $withdraw_status -eq 0 ]]; then
                # Add to CSV only if withdrawal succeeded and amount > 0
                if [[ "$reward_amount" =~ ^[0-9]+\.?[0-9]*$ ]] && (( $(echo "$reward_amount > 0" | bc -l) )); then
                    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
                    add_csv_entry "$csv_file" "$reward_amount" "$wallet_name" "$timestamp"
                    exported_status=" [CSV: ✓]"
                    ((exported++))
                else
                    exported_status=" [CSV: N/A]"
                fi
                
                results+="SUCCESS: $wallet_name"
                [[ -n "$address" ]] && results+=" (${address:0:15}...)"
                results+="\n   Withdrawal initiated successfully"
                results+="\n   Amount: $reward_amount NYM$exported_status\n\n"
                ((success++))
            else
                results+="FAILED: $wallet_name"
                [[ -n "$address" ]] && results+=" (${address:0:15}...)"
                results+="\n   Error: $withdraw_output\n\n"
                ((failed++))
            fi
        fi
    done
    
    if [ "$export_only" == "false" ]; then
        results+="Summary: $success succeeded, $failed failed, $exported exported to CSV\n"
        results+="CSV file: $csv_basename"
    else
        results+="Summary: $exported exported to CSV, $failed skipped\n"
        results+="CSV file: $csv_basename"
    fi
    
    dialog --title "Results" --msgbox "$results" 25 80
    
    if [ "$export_only" == "false" ]; then
        log "WALLET" "Withdrawal operation: $success succeeded, $failed failed, $exported exported to $csv_basename"
    else
        log "WALLET" "CSV export operation: $exported exported, $failed skipped to $csv_basename"
    fi
}

# Create new transaction
wallet_create_transaction() {
    if ! check_nym_cli; then
        return
    fi
    
    init_wallet_dir
    
    local wallets
    if ! wallets=$(get_wallet_list); then
        show_msg "No Wallets" "No wallets configured. Add a wallet first!"
        return
    fi
    
    # Ask for password to decrypt wallets
    local password=$(get_password "Create Transaction" "Enter password to decrypt wallets and query balances:")
    [[ -z "$password" ]] && return
    
    # Query balances for all wallets
    dialog --title "Loading" --infobox "Querying wallet balances...\nThis may take a moment..." 5 50
    
    local wallet_data=()
    local wallet_addresses=()
    local wallet_balances=()
    local wallet_names_array=()
    
    while IFS= read -r wallet_name; do
        # Decrypt wallet
        local mnemonic=$(decrypt_mnemonic "$wallet_name" "$password" 2>/dev/null)
        
        if [ $? -ne 0 ] || [ -z "$mnemonic" ]; then
            wallet_data+=("$wallet_name|ERROR|Wrong password")
            continue
        fi
        
        # Derive address
        local address=$(derive_address_from_mnemonic "$mnemonic")
        
        if [ -z "$address" ]; then
            wallet_data+=("$wallet_name|ERROR|Failed to derive address")
            continue
        fi
        
        # Get balance
        local balance=$(get_wallet_balance "$address")
        
        wallet_data+=("$wallet_name|$address|$balance")
        wallet_addresses+=("$address")
        wallet_balances+=("$balance")
        wallet_names_array+=("$wallet_name")
    done <<< "$wallets"
    
    # Display wallet list with balances
    local wallet_list="Wallet Balances:\n════════════════════════════════════════════════════════\n\n"
    local count=0
    local total_balance=0
    
    # First pass: calculate total balance
    for data in "${wallet_data[@]}"; do
        local addr=$(echo "$data" | cut -d'|' -f2)
        local bal=$(echo "$data" | cut -d'|' -f3)
        
        if [[ "$addr" != "ERROR" ]] && [[ "$bal" =~ ^[0-9]+\.?[0-9]*$ ]]; then
            total_balance=$(echo "$total_balance + $bal" | bc 2>/dev/null)
        fi
    done
    
    # Format total balance to 2 decimal places
    local total_balance_display=$(printf "%.2f" "$total_balance")
    
    # Create checklist with total in "Select All Wallets" option
    local checklist=("0" "Select ALL wallets ($total_balance_display NYM)" "off")
    
    for data in "${wallet_data[@]}"; do
        ((count++))
        local name=$(echo "$data" | cut -d'|' -f1)
        local addr=$(echo "$data" | cut -d'|' -f2)
        local bal=$(echo "$data" | cut -d'|' -f3)
        
        if [[ "$addr" == "ERROR" ]]; then
            wallet_list+="$count. $name\n    WARNING: $bal\n\n"
        else
            # Format balance to 2 decimal places for display
            local bal_display=$bal
            if [[ "$bal" =~ ^[0-9]+\.?[0-9]*$ ]]; then
                bal_display=$(printf "%.2f" "$bal")
            fi
            wallet_list+="$count. $name\n    ${addr:0:20}...${addr: -10}\n    Balance: $bal_display NYM\n\n"
            checklist+=("$count" "$name ($bal_display NYM)" "off")
        fi
    done
    
    # Show wallet list first
    dialog --title "Wallet Balances" --msgbox "$wallet_list" 25 70
    
    # Select wallets for transaction
    local choices=$(dialog --clear --title "Select Wallets" --separate-output --checklist "Select wallets to send from (Space=toggle, Enter=confirm):" 20 70 "${#checklist[@]}" "${checklist[@]}" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z "$choices" ]] && return
    
    # Collect selected wallets
    local selected_wallets=()
    local select_all=false
    
    while IFS= read -r choice; do
        if [[ "$choice" == "0" ]]; then
            select_all=true
        else
            local idx=$((choice - 1))
            selected_wallets+=("$idx")
        fi
    done <<< "$choices"
    
    # If "Select All" was chosen, add all valid wallets
    if [ "$select_all" == "true" ]; then
        selected_wallets=()
        for i in "${!wallet_names_array[@]}"; do
            selected_wallets+=("$i")
        done
    fi
    
    if [ ${#selected_wallets[@]} -eq 0 ]; then
        show_msg "No Selection" "No wallets selected."
        return
    fi
    
    # Get receiver address with validation
    local receiver_address=""
    while true; do
        receiver_address=$(get_input "Receiver Address" "Enter the receiver Nym address (n1...):")
        [[ -z "$receiver_address" ]] && return
        
        if validate_nym_address "$receiver_address"; then
            break
        else
            show_error "Invalid Nym address format!\n\nAddress must start with 'n1' followed by 38-50 characters.\n\nExample: n1abc123...xyz789"
        fi
    done
    
    # Calculate total amount and prepare transaction summary
    local total_nym=0
    local tx_summary="Transaction Summary:\n════════════════════════════════════════════════════════\n\n"
    tx_summary+="Receiver: $receiver_address\n\n"
    tx_summary+="Sending from:\n"
    
    local tx_wallets=()
    local tx_amounts_nym=()
    
    for idx in "${selected_wallets[@]}"; do
        local wallet_name="${wallet_names_array[$idx]}"
        local balance="${wallet_balances[$idx]}"
        
        # Convert balance to integer (remove decimal part)
        local amount_nym=$(echo "$balance" | cut -d'.' -f1)
        
        # Skip if balance is 0 or empty
        if [ -z "$amount_nym" ] || [ "$amount_nym" == "0" ]; then
            tx_summary+="  WARNING: $wallet_name - Skipped (balance: $balance NYM)\n"
            continue
        fi
        
        tx_wallets+=("$wallet_name")
        tx_amounts_nym+=("$amount_nym")
        
        total_nym=$((total_nym + amount_nym))
        tx_summary+="  • $wallet_name: $amount_nym NYM\n"
    done
    
    tx_summary+="\n────────────────────────────────────────────────────────\n"
    tx_summary+="Total to send: $total_nym NYM\n"
    tx_summary+="════════════════════════════════════════════════════════\n\n"
    tx_summary+="WARNING: This will send the MAXIMUM available balance\n"
    tx_summary+="(excluding decimal amounts) from each selected wallet!"
    
    # Show confirmation
    if ! dialog --title "Confirm Transaction" --yesno "$tx_summary" 25 70; then
        show_msg "Cancelled" "Transaction cancelled."
        return
    fi
    
    # Execute transactions
    local results="Transaction Results:\n════════════════════════════════════════════════════════\n\n"
    local success=0
    local failed=0
    local total_sent=0
    local total_txs=${#tx_wallets[@]}
    
    for i in "${!tx_wallets[@]}"; do
        local wallet_name="${tx_wallets[$i]}"
        local amount_nym="${tx_amounts_nym[$i]}"
        local amount_unym=$((amount_nym * 1000000))
        
        dialog --title "Processing" --infobox "Sending transaction $((i+1))/$total_txs\n$wallet_name: $amount_nym NYM..." 6 50
        
        # Decrypt wallet
        local mnemonic=$(decrypt_mnemonic "$wallet_name" "$password" 2>/dev/null)
        
        if [ $? -ne 0 ] || [ -z "$mnemonic" ]; then
            results+="FAILED: $wallet_name\n"
            results+="   Error: Failed to decrypt wallet\n\n"
            ((failed++))
            continue
        fi
        
        # Execute transaction
        local tx_output=$(nym-cli account send "$receiver_address" "$amount_unym" --mnemonic "$mnemonic" 2>&1)
        local tx_status=$?
        
        if [[ $tx_status -eq 0 ]]; then
            results+="SUCCESS: $wallet_name\n"
            results+="   Sent: $amount_nym NYM ($amount_unym uNYM)\n"
            results+="   Status: Success\n\n"
            ((success++))
            total_sent=$((total_sent + amount_nym))
        else
            results+="FAILED: $wallet_name\n"
            results+="   Amount: $amount_nym NYM ($amount_unym uNYM)\n"
            results+="   Error: $tx_output\n\n"
            ((failed++))
        fi
    done
    
    results+="════════════════════════════════════════════════════════\n"
    results+="Summary: $success succeeded | $failed failed\n"
    results+="Total sent: $total_sent NYM"
    
    dialog --title "Transaction Complete" --msgbox "$results" 30 80
    
    log "WALLET" "Transaction operation: $success succeeded, $failed failed, total sent: $total_sent NYM"
}

# Wallet operations menu
wallet_operations_menu() {
    init_wallet_dir
    
    while true; do
        local choice=$(dialog --clear --title "Wallet Operations" --menu "Manage your Nym wallets:" 18 65 7 \
            1 "Add new wallet" \
            2 "Query wallets" \
            3 "Withdraw operator rewards" \
            4 "Create new transaction" \
            5 "Export wallet (show mnemonic)" \
            6 "Delete wallet" \
            0 "Back to Main Menu" 3>&1 1>&2 2>&3)
        
        [[ $? -ne 0 ]] && break
        
        case $choice in
            1) wallet_add ;;
            2) wallet_list ;;
            3) wallet_withdraw_rewards ;;
            4) wallet_create_transaction ;;
            5) wallet_export ;;
            6) wallet_delete ;;
            0) break ;;
        esac
    done
}
# ----------------------------------------------------------------------------
# CONFIGURATION FUNCTIONS
# ----------------------------------------------------------------------------

config_menu() {
    while true; do
        local info="Current Configuration:\n• SSH Port: $SSH_PORT\n• Service Name: $SERVICE_NAME\n• Binary Path: $BINARY_PATH"
        local choice=$(dialog --clear --title "Configuration Menu" --menu "$info\n\nSelect option:" 18 70 5 \
            1 "Custom SSH Port (Current: $SSH_PORT)" \
            2 "Systemd Service Name (Current: $SERVICE_NAME)" \
            3 "Custom Binary Folder (Current: $BINARY_PATH)" \
            4 "Reset to Defaults" \
            0 "Back to Main Menu" 3>&1 1>&2 2>&3)
        
        [[ $? -ne 0 ]] && break
        
        case $choice in
            1) config_ssh_port ;;
            2) config_service_name ;;
            3) config_binary_path ;;
            4) config_reset_defaults ;;
            0) break ;;
        esac
    done
}

config_ssh_port() {
    local new_port=$(get_input "SSH Port Configuration" "Enter SSH port (current: $SSH_PORT):")
    [[ -z "$new_port" ]] && return
    
    if [[ "$new_port" =~ ^[0-9]+$ ]] && [[ "$new_port" -ge 1 ]] && [[ "$new_port" -le 65535 ]]; then
        SSH_PORT="$new_port"
        save_config
        show_success "SSH port updated to $SSH_PORT"
    else
        show_error "Invalid port. Enter a number between 1 and 65535."
    fi
}

config_service_name() {
    local new_service=$(get_input "Service Name Configuration" "Enter systemd service name (current: $SERVICE_NAME):")
    [[ -z "$new_service" ]] && return
    [[ "$new_service" != *.service ]] && new_service="$new_service.service"
    SERVICE_NAME="$new_service"
    save_config
    show_success "Service name updated to $SERVICE_NAME"
}

config_binary_path() {
    local new_path=$(get_input "Binary Path Configuration" "Enter binary folder path (current: $BINARY_PATH):")
    [[ -z "$new_path" ]] && return
    new_path=$(echo "$new_path" | sed 's|/$||')
    BINARY_PATH="$new_path"
    save_config
    show_success "Binary path updated to $BINARY_PATH"
}

config_reset_defaults() {
    confirm "Reset all configuration to defaults?\n\nSSH Port: $DEFAULT_SSH_PORT\nService: $DEFAULT_SERVICE_NAME\nBinary: $DEFAULT_BINARY_PATH" || return
    SSH_PORT="$DEFAULT_SSH_PORT"
    SERVICE_NAME="$DEFAULT_SERVICE_NAME"
    BINARY_PATH="$DEFAULT_BINARY_PATH"
    save_config
    show_success "Configuration reset to defaults"
}

# ----------------------------------------------------------------------------
# DIAGNOSTICS
# ----------------------------------------------------------------------------

test_ssh() {
    select_nodes "single" "Test SSH" || return
    local name="${SELECTED_NODES_NAMES[0]}" ip="${SELECTED_NODES_IPS[0]}"
    
    local user=$(get_input "SSH Test" "SSH username for $name:")
    [[ -z "$user" ]] && return
    
    local pass=$(get_password "SSH Test" "SSH password for $user@$ip:")
    [[ -z "$pass" ]] && return
    
    local results="🔧 SSH Test Results: $name ($ip:$SSH_PORT)\n────────────────────────────────────────────────────────\n\n"
    local tests=("Basic Connection:echo 'OK'" "Working Directory:pwd" "User Identity:whoami" 
                 "Sudo Access:whoami" "Root Switch:whoami" 
                 "Service File:test -f /etc/systemd/system/$SERVICE_NAME && echo 'EXISTS'" 
                 "Service Status:systemctl is-active $SERVICE_NAME")
    
    local step=1
    for test in "${tests[@]}"; do
        local desc="${test%%:*}" cmd="${test#*:}"
        dialog --title "SSH Test" --infobox "Step $step/7: Testing $desc..." 5 50
        
        # Determine if root access is needed for this test
        local needs_root="false"
        [[ "$desc" =~ (Sudo|Root|Service) ]] && needs_root="true"
        
        output=$(ssh_exec "$ip" "$user" "$pass" "$cmd" "$desc" "$needs_root" 2>/dev/null) && results+="✅ Step $step: $desc - SUCCESS\n   Result: $output\n" || results+="❌ Step $step: $desc - FAILED\n"
        ((step++))
    done
    
    results+="\n🎯 SSH Test Complete!"
    show_success "$results"
}

show_debug() {
    [[ -f "$DEBUG_LOG" ]] && dialog --title "Debug Log (Last 50 lines)" --msgbox "$(tail -50 "$DEBUG_LOG")" 25 100 || show_msg "No Log" "Debug log not found."
}

# ----------------------------------------------------------------------------
# MENU SYSTEM
# ----------------------------------------------------------------------------

node_management_menu() {
    while true; do
        local choice=$(dialog --clear --title "Node Management" --menu "Manage your Nym nodes:" 15 60 5 \
            1 "List all nodes" 2 "Add node" 3 "Edit node" 4 "Delete node" 0 "Back to Main Menu" 3>&1 1>&2 2>&3)
        [[ $? -ne 0 ]] && break
        case $choice in
            1) list_nodes ;; 2) add_node ;; 3) edit_node ;; 4) delete_node ;; 0) break ;;
        esac
    done
}

node_operations_menu() {
    while true; do
        local choice=$(dialog --clear --title "Node Operations" --menu "Perform operations on nodes:" 21 70 10 \
            1 "Retrieve node roles" 2 "Backup node" 3 "Update nym-node binary" \
            4 "Toggle functionality (Mixnet & Wireguard)" 5 "Restart service" \
            6 "Replace index.html" 7 "Disable root@ssh" 8 "Fail2ban" \
            9 "Execute SSH command" \
            0 "Back to Main Menu" 3>&1 1>&2 2>&3)
        [[ $? -ne 0 ]] && break
        case $choice in
            1) retrieve_node_roles ;; 2) backup_node ;; 3) update_nym_node ;; 
            4) toggle_node_functionality ;; 5) restart_service ;; 6) replace_index_html ;; 
            7) disable_root_ssh ;; 8) activate_fail2ban ;; 9) execute_ssh_command ;;
            0) break ;;
        esac
    done
}

diagnostics_menu() {
    while true; do
        local choice=$(dialog --clear --title "Diagnostics" --menu "Diagnostic tools:" 13 60 3 \
            1 "Test SSH connection" 2 "Show debug log" 0 "Back to Main Menu" 3>&1 1>&2 2>&3)
        [[ $? -ne 0 ]] && break
        case $choice in
            1) test_ssh ;; 2) show_debug ;; 0) break ;;
        esac
    done
}

main_menu() {
    while true; do
        local choice=$(dialog --clear --title "$SCRIPT_NAME v$VERSION" --menu "Select category:" 18 60 6 \
            1 "Node Management" \
            2 "Node Operations" \
            3 "Wallet Operations" \
            4 "Configuration" \
            5 "Diagnostics" \
            0 "Exit" 3>&1 1>&2 2>&3)
        [[ $? -ne 0 ]] && break
        case $choice in
            1) node_management_menu ;; 
            2) node_operations_menu ;; 
            3) wallet_operations_menu ;;
            4) config_menu ;; 
            5) diagnostics_menu ;; 
            0) confirm "Exit?" && break ;;
        esac
    done
}

# ----------------------------------------------------------------------------
# MAIN EXECUTION
# ----------------------------------------------------------------------------

main() {
    init_debug
    log "MAIN" "Application starting - Version $VERSION"
    load_config
    trap 'clear; echo -e "${GREEN}Thank you for using $SCRIPT_NAME!${NC}"; exit 0' EXIT INT TERM
    check_deps
    main_menu
}

main "$@"
