#!/bin/bash

# ============================================================================
# Nym Node Manager v66 - Refined Wallet Display
# ============================================================================
# Description: Centralized management tool for Nym network nodes
# Requirements: dialog, expect, curl, rsync, sshpass, openssl, nym-cli, jq
# Features: Multi-node operations, backup, updates, configuration, wallet mgmt
# Changelog v66:
#   - Renamed "Available Operator Rewards" to "Claimable operator rewards"
#   - Renamed "Available Balance" to "Wallet balance"
#   - Removed uNYM values from wallet list (only NYM shown)
#   - Removed "Query available rewards" menu item (integrated into List wallets)
#   - Swapped menu positions: "Withdraw operator rewards" now before "Create new transaction"
# Changelog v65:
#   - "List wallets" now queries and displays both balance and operator rewards
#   - Enhanced wallet display format with address, rewards, and balance
#   - Removed emojis from Wallet Operations menu and submenus
#   - Extended window size for wallet list (35 rows x 100 columns)
# Changelog v63:
#   - Added "Create new transaction" feature to Wallet Operations
#   - Query wallet balances and display with addresses
#   - Multi-wallet transaction support (send max available from each)
#   - Receiver address validation
#   - Transaction confirmation before execution
#   - Automatic uNYM conversion (1 NYM = 1,000,000 uNYM)
# Changelog v62:
#   - Wallets now displayed in alphabetical order in all operations
#   - Improved wallet selection menu consistency
# Changelog v61:
#   - Fixed "Query available rewards" to correctly extract amount_earned.amount
#   - Now properly parses the Nym API response structure
#   - Verified secure encryption: mnemonics and passwords only in memory/encrypted
# Changelog v60:
#   - Added "Query available rewards" to Wallet Operations menu
#   - Multi-wallet selection for batch rewards queries
#   - Derives Nyx address from mnemonic using nym-cli
#   - Queries pending operator rewards via REST API
#   - Displays rewards in both uNYM and NYM formats
#   - Select individual wallets or query all at once
# Changelog v59:
#   - Added Wallet Operations submenu at position 3
#   - Integrated encrypted wallet management functions
#   - Support for multiple wallets with AES-256 encryption
#   - Operator rewards withdrawal functionality
#   - Account balance checking
#   - Moved previous menus (Configuration, Diagnostics) to positions 4-5
# ============================================================================

# ----------------------------------------------------------------------------
# GLOBAL CONFIGURATION
# ----------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
SCRIPT_NAME="Nym Node Manager"
VERSION="66"
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
    names=(); ips=(); node_ids=()
    [[ ! -f "$NODES_FILE" || ! -s "$NODES_FILE" ]] && return 1
    
    local name="" ip="" node_id=""
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name:\ (.+)$ ]]; then
            name="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^IP\ Address:\ (.+)$ ]]; then
            ip="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^Node\ ID:\ (.+)$ ]]; then
            node_id="${BASH_REMATCH[1]}"
            if [[ -n "$name" && -n "$ip" && -n "$node_id" ]]; then
                names+=("$name")
                ips+=("$ip")
                node_ids+=("$node_id")
                name=""; ip=""; node_id=""
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
    local new_name="$1" new_ip="$2" new_node_id="$3"
    local temp=$(mktemp) inserted=false
    
    if [[ ! -f "$NODES_FILE" ]]; then
        echo -e "Node Name: $new_name\nIP Address: $new_ip\nNode ID: $new_node_id" > "$NODES_FILE"
        return
    fi
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name:\ (.+)$ ]]; then
            local node_name="${BASH_REMATCH[1]}"
            if [[ "$inserted" == "false" && "$new_name" < "$node_name" ]]; then
                [[ -s "$temp" ]] && echo >> "$temp"
                echo -e "Node Name: $new_name\nIP Address: $new_ip\nNode ID: $new_node_id\n" >> "$temp"
                inserted=true
            fi
            [[ -s "$temp" ]] && echo >> "$temp"
        fi
        echo "$line" >> "$temp"
    done < "$NODES_FILE"
    
    if [[ "$inserted" == "false" ]]; then
        [[ -s "$temp" ]] && echo >> "$temp"
        echo -e "Node Name: $new_name\nIP Address: $new_ip\nNode ID: $new_node_id" >> "$temp"
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
        fi
        [[ "$in_target" == "false" ]] && echo "$line" >> "$temp"
    done < "$NODES_FILE"
    mv "$temp" "$NODES_FILE"
}

# ----------------------------------------------------------------------------
# NODE MANAGEMENT
# ----------------------------------------------------------------------------

add_node() {
    local name=$(get_input "Add Node" "Enter node name:")
    [[ -z "$name" ]] && return
    
    if node_name_exists "$name"; then
        show_error "Node name '$name' already exists!"
        return
    fi
    
    local ip=$(get_input "Add Node" "Enter IP address for '$name':")
    [[ -z "$ip" ]] && return
    
    local node_id=$(get_input "Add Node" "Enter Node ID for '$name':")
    [[ -z "$node_id" ]] && return
    
    insert_node_sorted "$name" "$ip" "$node_id"
    show_success "Node '$name' added successfully!"
}

list_nodes() {
    local names=() ips=() node_ids=()
    if ! parse_nodes_file; then
        show_msg "No Nodes" "No nodes configured. Add nodes first!"
        return
    fi
    
    local output="📋 Configured Nodes:\n────────────────────────────────────────────────────────\n\n"
    for ((i=0; i<${#names[@]}; i++)); do
        output+="$((i+1)). ${names[i]}\n   IP: ${ips[i]}\n   Node ID: ${node_ids[i]}\n\n"
    done
    dialog --title "Node List" --msgbox "$output" 20 70
}

edit_node() {
    select_nodes "single" "Edit Node" || return
    local old_name="${SELECTED_NODES_NAMES[0]}" old_ip="${SELECTED_NODES_IPS[0]}" old_id="${SELECTED_NODES_IDS[0]}"
    
    local choice=$(dialog --clear --title "Edit Node: $old_name" --menu "What to edit?" 12 60 3 \
        1 "Name (Current: $old_name)" \
        2 "IP Address (Current: $old_ip)" \
        3 "Node ID (Current: $old_id)" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && return
    
    case $choice in
        1)
            local new_name=$(get_input "Edit Node Name" "New name for '$old_name':")
            [[ -z "$new_name" || "$new_name" == "$old_name" ]] && return
            if node_name_exists "$new_name"; then
                show_error "Node name '$new_name' already exists!"
                return
            fi
            remove_nodes_from_file "$old_name"
            insert_node_sorted "$new_name" "$old_ip" "$old_id"
            show_success "Node renamed to '$new_name'"
            ;;
        2)
            local new_ip=$(get_input "Edit IP Address" "New IP for '$old_name':")
            [[ -z "$new_ip" || "$new_ip" == "$old_ip" ]] && return
            remove_nodes_from_file "$old_name"
            insert_node_sorted "$old_name" "$new_ip" "$old_id"
            show_success "IP updated for '$old_name'"
            ;;
        3)
            local new_id=$(get_input "Edit Node ID" "New Node ID for '$old_name':")
            [[ -z "$new_id" || "$new_id" == "$old_id" ]] && return
            remove_nodes_from_file "$old_name"
            insert_node_sorted "$old_name" "$old_ip" "$new_id"
            show_success "Node ID updated for '$old_name'"
            ;;
    esac
}

delete_node() {
    select_nodes "multi" "Delete Nodes" || return
    confirm "Delete ${#SELECTED_NODES_NAMES[@]} node(s)?" || return
    remove_nodes_from_file "${SELECTED_NODES_NAMES[@]}"
    show_success "${#SELECTED_NODES_NAMES[@]} node(s) deleted successfully!"
}

# ----------------------------------------------------------------------------
# NODE SELECTION
# ----------------------------------------------------------------------------

select_nodes() {
    local mode="$1" title="$2"
    SELECTED_NODES_NAMES=(); SELECTED_NODES_IPS=(); SELECTED_NODES_IDS=()
    
    local names=() ips=() node_ids=()
    if ! parse_nodes_file; then
        show_msg "No Nodes" "No nodes configured. Add nodes first!"
        return 1
    fi
    
    if [[ "$mode" == "single" ]]; then
        local options=()
        for ((i=0; i<${#names[@]}; i++)); do
            options+=("$((i+1))" "${names[i]} (${ips[i]})")
        done
        
        local choice=$(dialog --clear --title "$title" --menu "Select a node:" 15 70 "${#names[@]}" "${options[@]}" 3>&1 1>&2 2>&3)
        [[ $? -ne 0 ]] && return 1
        
        local idx=$((choice-1))
        SELECTED_NODES_NAMES=("${names[idx]}")
        SELECTED_NODES_IPS=("${ips[idx]}")
        SELECTED_NODES_IDS=("${node_ids[idx]}")
    else
        local checklist=()
        for ((i=0; i<${#names[@]}; i++)); do
            checklist+=("$((i+1))" "${names[i]} (${ips[i]})" "off")
        done
        
        local choices=$(dialog --clear --title "$title" --separate-output --checklist "Select nodes (Space=toggle, Enter=confirm):" 18 70 "${#names[@]}" "${checklist[@]}" 3>&1 1>&2 2>&3)
        [[ $? -ne 0 || -z "$choices" ]] && return 1
        
        while IFS= read -r choice; do
            local idx=$((choice-1))
            SELECTED_NODES_NAMES+=("${names[idx]}")
            SELECTED_NODES_IPS+=("${ips[idx]}")
            SELECTED_NODES_IDS+=("${node_ids[idx]}")
        done <<< "$choices"
    fi
    
    return 0
}

# ----------------------------------------------------------------------------
# SSH OPERATIONS
# ----------------------------------------------------------------------------

ssh_exec() {
    local ip="$1" user="$2" pass="$3" cmd="$4" desc="$5" needs_root="${6:-false}"
    local timeout=30
    
    log "SSH" "Executing on $ip: $desc"
    
    # Build command based on root access needs
    local ssh_cmd="$cmd"
    if [[ "$needs_root" == "true" ]]; then
        # Check if user is root, otherwise use sudo
        if [[ "$user" == "root" ]]; then
            ssh_cmd="$cmd"
        else
            ssh_cmd="sudo -S bash -c '$cmd'"
        fi
    fi
    
    expect -c "
        set timeout $timeout
        log_user 0
        spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=$timeout -p $SSH_PORT $user@$ip \"$ssh_cmd\"
        expect {
            \"assword:\" {
                send \"$pass\r\"
                expect {
                    \"assword:\" {
                        send \"$pass\r\"
                        exp_continue
                    }
                    eof
                }
            }
            eof
        }
        catch wait result
        exit [lindex \$result 3]
    " 2>/dev/null
}

batch_ssh_exec() {
    local cmd="$1" desc="$2" needs_root="${3:-false}" show_progress="${4:-true}"
    
    local user=$(get_input "SSH Credentials" "Enter SSH username (same for all nodes):")
    [[ -z "$user" ]] && return
    
    local pass=$(get_password "SSH Password" "Enter password for $user:")
    [[ -z "$pass" ]] && return
    
    local results="🔧 Operation: $desc\n────────────────────────────────────────────────────────\n\n"
    local success=0 failed=0
    
    for ((i=0; i<${#SELECTED_NODES_NAMES[@]}; i++)); do
        local name="${SELECTED_NODES_NAMES[i]}" ip="${SELECTED_NODES_IPS[i]}"
        
        [[ "$show_progress" == "true" ]] && dialog --title "Processing" --infobox "[$((i+1))/${#SELECTED_NODES_NAMES[@]}] $name..." 5 50
        
        if output=$(ssh_exec "$ip" "$user" "$pass" "$cmd" "$desc" "$needs_root" 2>&1); then
            results+="✅ $name ($ip)\n"
            [[ -n "$output" ]] && results+="   Output: $output\n"
            ((success++))
        else
            results+="❌ $name ($ip) - FAILED\n"
            ((failed++))
        fi
        results+="\n"
    done
    
    results+="📊 Summary: $success succeeded, $failed failed"
    dialog --title "Results" --msgbox "$results" 20 80
}

execute_ssh_command() {
    select_nodes "multi" "Execute SSH Command" || return
    
    local cmd=$(dialog --title "SSH Command" --inputbox "Enter command to execute:" 8 70 3>&1 1>&2 2>&3)
    [[ -z "$cmd" ]] && return
    
    local needs_root="false"
    if confirm "Does this command require root/sudo access?"; then
        needs_root="true"
    fi
    
    batch_ssh_exec "$cmd" "Custom Command" "$needs_root" "true"
}

# ----------------------------------------------------------------------------
# NODE OPERATIONS
# ----------------------------------------------------------------------------

retrieve_node_roles() {
    select_nodes "multi" "Retrieve Node Roles" || return
    
    local user=$(get_input "SSH Credentials" "Enter SSH username:")
    [[ -z "$user" ]] && return
    
    local pass=$(get_password "SSH Password" "Enter password for $user:")
    [[ -z "$pass" ]] && return
    
    local results="🎭 Node Roles Report\n────────────────────────────────────────────────────────\n\n"
    
    for ((i=0; i<${#SELECTED_NODES_NAMES[@]}; i++)); do
        local name="${SELECTED_NODES_NAMES[i]}" ip="${SELECTED_NODES_IPS[i]}" node_id="${SELECTED_NODES_IDS[i]}"
        
        dialog --title "Retrieving Roles" --infobox "[$((i+1))/${#SELECTED_NODES_NAMES[@]}] Checking $name..." 5 50
        
        local cmd="cd $BINARY_PATH && ./nym-node node-details --id $node_id 2>/dev/null | grep -E '(mixnode_mode|entry_gateway_mode|exit_gateway_mode)' | awk '{print \$1, \$2}'"
        
        if output=$(ssh_exec "$ip" "$user" "$pass" "$cmd" "Get node roles" "false" 2>&1); then
            results+="✅ $name ($ip)\n"
            if [[ -n "$output" ]]; then
                results+="$output\n"
            else
                results+="   No roles found or command failed\n"
            fi
        else
            results+="❌ $name - Connection failed\n"
        fi
        results+="\n"
    done
    
    dialog --title "Node Roles" --msgbox "$results" 20 80
}

backup_node() {
    select_nodes "single" "Backup Node" || return
    local name="${SELECTED_NODES_NAMES[0]}" ip="${SELECTED_NODES_IPS[0]}" node_id="${SELECTED_NODES_IDS[0]}"
    
    local user=$(get_input "SSH Credentials" "SSH username for $name:")
    [[ -z "$user" ]] && return
    
    local pass=$(get_password "SSH Password" "Password for $user@$ip:")
    [[ -z "$pass" ]] && return
    
    local backup_dir="$HOME/nym_backups/${name}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    dialog --title "Backup Progress" --infobox "Creating backup for $name...\nThis may take several minutes..." 6 50
    
    # Use rsync with sshpass for backup
    if command -v sshpass >/dev/null 2>&1; then
        if sshpass -p "$pass" rsync -avz -e "ssh -o StrictHostKeyChecking=no -p $SSH_PORT" \
            "$user@$ip:/root/.nym/nym-nodes/$node_id/" "$backup_dir/" 2>&1 | tee -a "$DEBUG_LOG"; then
            show_success "Backup completed!\n\nLocation: $backup_dir"
        else
            show_error "Backup failed! Check $DEBUG_LOG for details."
        fi
    else
        show_error "sshpass not installed. Install it to use this feature:\nsudo apt-get install sshpass"
    fi
}

update_nym_node() {
    select_nodes "multi" "Update Nym-Node Binary" || return
    
    local url=$(get_input "Update Binary" "Enter download URL for nym-node binary:")
    [[ -z "$url" ]] && return
    
    confirm "Update ${#SELECTED_NODES_NAMES[@]} node(s) with binary from:\n$url\n\nThis will:\n1. Stop the service\n2. Backup old binary\n3. Download new binary\n4. Make executable\n5. Restart service" || return
    
    local cmd="
        systemctl stop $SERVICE_NAME &&
        cd $BINARY_PATH &&
        mv nym-node nym-node.backup.\$(date +%Y%m%d_%H%M%S) &&
        curl -L '$url' -o nym-node &&
        chmod +x nym-node &&
        systemctl start $SERVICE_NAME &&
        sleep 2 &&
        systemctl status $SERVICE_NAME | head -10
    "
    
    batch_ssh_exec "$cmd" "Update nym-node binary" "true" "true"
}

toggle_node_functionality() {
    select_nodes "single" "Toggle Functionality" || return
    local name="${SELECTED_NODES_NAMES[0]}" ip="${SELECTED_NODES_IPS[0]}" node_id="${SELECTED_NODES_IDS[0]}"
    
    local user=$(get_input "SSH Credentials" "SSH username for $name:")
    [[ -z "$user" ]] && return
    
    local pass=$(get_password "SSH Password" "Password for $user@$ip:")
    [[ -z "$pass" ]] && return
    
    local choice=$(dialog --clear --title "Toggle Functionality: $name" --menu "Select mode to toggle:" 12 60 3 \
        1 "Toggle Mixnode" \
        2 "Toggle Entry Gateway" \
        3 "Toggle Exit Gateway" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && return
    
    local mode_flag=""
    case $choice in
        1) mode_flag="mixnode" ;;
        2) mode_flag="entry-gateway" ;;
        3) mode_flag="exit-gateway" ;;
    esac
    
    dialog --title "Processing" --infobox "Toggling $mode_flag for $name..." 5 50
    
    local cmd="cd $BINARY_PATH && systemctl stop $SERVICE_NAME && ./nym-node mode --id $node_id --mode $mode_flag && systemctl start $SERVICE_NAME && sleep 2 && systemctl status $SERVICE_NAME | head -5"
    
    if output=$(ssh_exec "$ip" "$user" "$pass" "$cmd" "Toggle $mode_flag" "true" 2>&1); then
        show_success "Mode toggled successfully for $name!\n\nService Status:\n$output"
    else
        show_error "Failed to toggle mode for $name"
    fi
}

restart_service() {
    select_nodes "multi" "Restart Service" || return
    confirm "Restart service on ${#SELECTED_NODES_NAMES[@]} node(s)?" || return
    batch_ssh_exec "systemctl restart $SERVICE_NAME && sleep 2 && systemctl status $SERVICE_NAME | head -5" "Restart $SERVICE_NAME" "true" "true"
}

# ----------------------------------------------------------------------------
# WALLET MANAGEMENT FUNCTIONS
# ----------------------------------------------------------------------------

# Initialize wallet directory structure
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
    local password=$(get_password "List Wallets" "Enter password to display wallet information:")
    [[ -z "$password" ]] && return
    
    # Show loading message
    dialog --title "Loading Wallets" --infobox "Querying wallet information...\nThis may take a moment." 5 50
    
    local wallet_list="Saved Wallets:\n════════════════════════════════════════════════════════════════════════════════════════════════\n\n"
    local count=0
    local success_count=0
    local fail_count=0
    
    while IFS= read -r wallet_name; do
        ((count++))
        
        # Try to decrypt and derive address
        local mnemonic=$(decrypt_mnemonic "$wallet_name" "$password" 2>/dev/null)
        
        if [ $? -ne 0 ] || [ -z "$mnemonic" ]; then
            wallet_list+="$wallet_name\n"
            wallet_list+="  Status: Failed to decrypt (wrong password)\n\n"
            ((fail_count++))
            continue
        fi
        
        # Derive address using the same function as other menus
        local address=$(derive_address_from_mnemonic "$mnemonic")
        
        if [ -z "$address" ]; then
            wallet_list+="$wallet_name\n"
            wallet_list+="  Status: Failed to derive address\n\n"
            ((fail_count++))
            continue
        fi
        
        # Query balance using the same function as "Create new transaction"
        local balance=$(get_wallet_balance "$address")
        if [ -z "$balance" ] || [ "$balance" == "ERROR" ]; then
            balance="0"
        fi
        
        # Query operator rewards using the same function as "Query available rewards"
        local rewards_result=$(query_pending_rewards "$address" "$wallet_name")
        local rewards_status=$(echo "$rewards_result" | cut -d'|' -f1)
        local rewards_nym="0"
        local rewards_unym="0"
        
        if [ "$rewards_status" == "SUCCESS" ]; then
            rewards_unym=$(echo "$rewards_result" | cut -d'|' -f2)
            rewards_nym=$(echo "$rewards_result" | cut -d'|' -f3)
        elif [ "$rewards_status" == "NONE" ]; then
            rewards_nym="0"
            rewards_unym="0"
        else
            # ERROR case
            rewards_nym="Error"
            rewards_unym="Error"
        fi
        
        # Format output
        wallet_list+="$wallet_name\n"
        wallet_list+="  Address: $address\n"
        wallet_list+="  Claimable operator rewards: $rewards_nym NYM\n"
        wallet_list+="  Wallet balance: $balance NYM\n\n"
        
        ((success_count++))
    done <<< "$wallets"
    
    wallet_list+="════════════════════════════════════════════════════════════════════════════════════════════════\n"
    wallet_list+="Total: $count | Successfully displayed: $success_count | Failed: $fail_count"
    
    dialog --title "Wallet List" --msgbox "$wallet_list" 35 100
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

# Derive Nyx address from mnemonic using nym-cli
derive_nyx_address() {
    local mnemonic="$1"
    
    # Check if nym-cli is available
    if ! command -v nym-cli >/dev/null 2>&1; then
        echo "ERROR: nym-cli not found"
        return 1
    fi
    
    # Create temporary file for mnemonic (security: only in memory/temp, immediately deleted)
    local temp_mnemonic=$(mktemp)
    echo "$mnemonic" > "$temp_mnemonic"
    
    # Use nym-cli to derive address (using account 0, typically operator account)
    local address=$(nym-cli --mnemonic-file "$temp_mnemonic" account show 2>/dev/null | grep "Address:" | awk '{print $2}')
    
    # Clean up temp file immediately
    shred -u "$temp_mnemonic" 2>/dev/null || rm -f "$temp_mnemonic"
    
    if [[ -z "$address" ]]; then
        echo "ERROR: Failed to derive address"
        return 1
    fi
    
    echo "$address"
    return 0
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
    
    # Create checklist options from sorted wallet list
    local checklist=()
    local count=0
    while IFS= read -r wallet; do
        ((count++))
        checklist+=("$count" "$wallet" "off")
    done <<< "$wallets"
    
    local choices=$(dialog --clear --title "Withdraw Rewards" --separate-output --checklist "Select wallets (Space=toggle, Enter=confirm):" 18 60 "${#checklist[@]}" "${checklist[@]}" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z "$choices" ]] && return
    
    # Collect selected wallets in order
    local selected_wallets=()
    while IFS= read -r choice; do
        local wallet_name=$(echo "$wallets" | sed -n "${choice}p")
        selected_wallets+=("$wallet_name")
    done <<< "$choices"
    
    [[ ${#selected_wallets[@]} -eq 0 ]] && return
    
    # Warning confirmation
    if ! confirm "WARNING: This will WITHDRAW rewards!\n\nThe rewards will be withdrawn to your account.\n\nProceed with withdrawal for ${#selected_wallets[@]} wallet(s)?"; then
        show_msg "Cancelled" "Rewards withdrawal cancelled."
        return
    fi
    
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
    local results="Withdrawal Results\n────────────────────────────────────────────────────────\n\n"
    local success=0 failed=0
    local total=${#selected_wallets[@]}
    local current=0
    
    for wallet_name in "${selected_wallets[@]}"; do
        ((current++))
        
        dialog --title "Processing" --infobox "Withdrawing rewards ($current/$total)\n$wallet_name..." 6 50
        
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
        
        # Execute withdrawal using nym-cli
        local withdraw_output=$(nym-cli mixnet operators nymnode rewards claim --mnemonic "$mnemonic" 2>&1)
        local withdraw_status=$?
        
        if [[ $withdraw_status -eq 0 ]]; then
            results+="SUCCESS: $wallet_name"
            [[ -n "$address" ]] && results+=" (${address:0:15}...)"
            results+="\n   Withdrawal initiated successfully\n\n"
            ((success++))
        else
            results+="FAILED: $wallet_name"
            [[ -n "$address" ]] && results+=" (${address:0:15}...)"
            results+="\n   Error: $withdraw_output\n\n"
            ((failed++))
        fi
    done
    
    results+="Summary: $success succeeded, $failed failed"
    dialog --title "Withdrawal Results" --msgbox "$results" 25 80
    
    log "WALLET" "Withdrawal operation: $success succeeded, $failed failed"
}

# Query available rewards for selected wallets
wallet_query_rewards() {
    if ! check_nym_cli; then
        return
    fi
    
    init_wallet_dir
    
    local wallets
    if ! wallets=$(get_wallet_list); then
        show_msg "No Wallets" "No wallets configured. Add a wallet first!"
        return
    fi
    
    # Create checklist with "Select All" option
    local checklist=("0" "🌟 Select All Wallets" "off")
    local count=0
    while IFS= read -r wallet; do
        ((count++))
        checklist+=("$count" "$wallet" "off")
    done <<< "$wallets"
    
    local choices=$(dialog --clear --title "Query Rewards" --separate-output --checklist "Select wallets to query (Space=toggle, Enter=confirm):" 18 60 "${#checklist[@]}" "${checklist[@]}" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z "$choices" ]] && return
    
    # Collect selected wallets
    local selected_wallets=()
    local select_all=false
    
    while IFS= read -r choice; do
        if [[ "$choice" == "0" ]]; then
            select_all=true
        else
            local wallet_name=$(echo "$wallets" | sed -n "${choice}p")
            selected_wallets+=("$wallet_name")
        fi
    done <<< "$choices"
    
    # If "Select All" was chosen, add all wallets
    if [ "$select_all" == "true" ]; then
        selected_wallets=()
        while IFS= read -r wallet_name; do
            selected_wallets+=("$wallet_name")
        done <<< "$wallets"
    fi
    
    if [ ${#selected_wallets[@]} -eq 0 ]; then
        show_msg "No Selection" "No wallets selected."
        return
    fi
    
    # Ask for password once (assuming same password for all, or ask per wallet)
    local use_same_password=true
    if [ ${#selected_wallets[@]} -gt 1 ]; then
        if ! confirm "Use the same password for all selected wallets?\n\n(Select 'No' to enter password for each wallet individually)"; then
            use_same_password=false
        fi
    fi
    
    local password=""
    if [ "$use_same_password" == "true" ]; then
        password=$(get_password "Query Rewards" "Enter decryption password:")
        [[ -z "$password" ]] && return
    fi
    
    # Process each wallet
    local results=""
    local total=${#selected_wallets[@]}
    local current=0
    local success_count=0
    local fail_count=0
    local total_rewards_nym=0
    
    for wallet_name in "${selected_wallets[@]}"; do
        ((current++))
        
        dialog --title "Query Rewards" --infobox "Processing wallet $current/$total\n$wallet_name\n\nDecrypting..." 7 50
        
        # Get password for this wallet if needed
        local wallet_password="$password"
        if [ "$use_same_password" == "false" ]; then
            wallet_password=$(get_password "Query Rewards" "Enter password for '$wallet_name':")
            [[ -z "$wallet_password" ]] && { results+="$wallet_name: Skipped (no password)\n"; ((fail_count++)); continue; }
        fi
        
        # Decrypt mnemonic
        local mnemonic=$(decrypt_mnemonic "$wallet_name" "$wallet_password" 2>/dev/null)
        
        if [ $? -ne 0 ] || [ -z "$mnemonic" ]; then
            results+="❌ $wallet_name: Failed to decrypt (wrong password?)\n"
            ((fail_count++))
            continue
        fi
        
        dialog --title "Query Rewards" --infobox "Processing wallet $current/$total\n$wallet_name\n\nDeriving address..." 7 50
        
        # Derive address
        local address=$(derive_address_from_mnemonic "$mnemonic")
        
        if [ -z "$address" ]; then
            results+="❌ $wallet_name: Failed to derive address\n"
            ((fail_count++))
            continue
        fi
        
        dialog --title "Query Rewards" --infobox "Processing wallet $current/$total\n$wallet_name\n\nQuerying rewards..." 7 50
        
        # Query rewards
        local query_result=$(query_pending_rewards "$address" "$wallet_name")
        local query_status=$(echo "$query_result" | cut -d'|' -f1)
        local query_message=$(echo "$query_result" | cut -d'|' -f2-)
        
        case "$query_status" in
            "SUCCESS")
                local unym=$(echo "$query_message" | cut -d'|' -f1)
                local nym=$(echo "$query_message" | cut -d'|' -f2)
                results+="$wallet_name\n"
                results+="   Address: ${address:0:20}...${address: -10}\n"
                results+="   Rewards: $nym NYM ($unym uNYM)\n\n"
                # Add to total rewards
                total_rewards_nym=$(echo "$total_rewards_nym + $nym" | bc 2>/dev/null)
                ((success_count++))
                ;;
            "NONE")
                results+="$wallet_name\n"
                results+="   Address: ${address:0:20}...${address: -10}\n"
                results+="   Status: $query_message\n\n"
                ((success_count++))
                ;;
            "ERROR")
                results+="$wallet_name: $query_message\n\n"
                ((fail_count++))
                ;;
            *)
                results+="$wallet_name: Unknown error\n\n"
                ((fail_count++))
                ;;
        esac
    done
    
    # Display results
    local header="Pending Operator Rewards Query Results\n"
    header+="════════════════════════════════════════════════════\n"
    header+="Processed: $total wallet(s)\n"
    header+="Successful: $success_count | Failed: $fail_count\n"
    header+="Combined rewards: $total_rewards_nym NYM\n"
    header+="════════════════════════════════════════════════════\n\n"
    
    dialog --title "Query Results" --msgbox "${header}${results}\n\n💡 Tip: Use 'Withdraw operator rewards' to claim" 30 80
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
    local checklist=("0" "Select All Wallets" "off")
    local count=0
    
    for data in "${wallet_data[@]}"; do
        ((count++))
        local name=$(echo "$data" | cut -d'|' -f1)
        local addr=$(echo "$data" | cut -d'|' -f2)
        local bal=$(echo "$data" | cut -d'|' -f3)
        
        if [[ "$addr" == "ERROR" ]]; then
            wallet_list+="$count. $name\n    WARNING: $bal\n\n"
        else
            wallet_list+="$count. $name\n    ${addr:0:20}...${addr: -10}\n    Balance: $bal NYM\n\n"
            checklist+=("$count" "$name ($bal NYM)" "off")
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
            2 "List wallets" \
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
        local choice=$(dialog --clear --title "Node Operations" --menu "Perform operations on nodes:" 18 65 7 \
            1 "Retrieve node roles" 2 "Backup node" 3 "Update nym-node binary" \
            4 "Toggle functionality (Mixnet & Wireguard)" 5 "Restart service" \
            6 "Execute SSH command" 0 "Back to Main Menu" 3>&1 1>&2 2>&3)
        [[ $? -ne 0 ]] && break
        case $choice in
            1) retrieve_node_roles ;; 2) backup_node ;; 3) update_nym_node ;; 
            4) toggle_node_functionality ;; 5) restart_service ;; 6) execute_ssh_command ;;
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
