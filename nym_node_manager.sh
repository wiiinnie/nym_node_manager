#!/bin/bash

# ============================================================================
# Nym Node Manager v58 - Fixed Restart Service Password Logging
# ============================================================================
# Description: Centralized management tool for Nym network nodes
# Requirements: dialog, expect, curl, rsync, sshpass
# Features: Multi-node operations, backup, updates, configuration management
# Changelog v58:
#   - Fixed password logging in restart_service function
#   - Fixed sudo password prompt in service status check
#   - Both functions now use use_root parameter properly
# ============================================================================

# ----------------------------------------------------------------------------
# GLOBAL CONFIGURATION
# ----------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
SCRIPT_NAME="Nym Node Manager"
VERSION="58"
SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")"
DEBUG_LOG="$SCRIPT_DIR/debug.log"
NODES_FILE="$SCRIPT_DIR/nodes.txt"
CONFIG_FILE="$SCRIPT_DIR/config.txt"

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
    for cmd in dialog expect curl rsync; do
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
        log "SSH_EXEC" "Root command: $cmd"
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
    SELECTED_NODES_NAMES=(); SELECTED_NODES_IPS=(); SELECTED_NODES_IDS=()
    
    local names=() ips=() node_ids=()
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
            SELECTED_NODES_IDS=("${node_ids[@]}")
            break
        else
            local idx=$((choice - 1))
            SELECTED_NODES_NAMES+=("${names[$idx]}")
            SELECTED_NODES_IPS+=("${ips[$idx]}")
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
    
    local node_id=$(get_input "Add Node" "Enter Node ID for '$name':\n(The ID used during node initialization)")
    [[ -z "$node_id" ]] && { show_msg "Cancelled" "Node creation cancelled."; return; }
    
    insert_node_sorted "$name" "$ip" "$node_id"
    show_success "Node '$name' added successfully!\nIP: $ip\nID: $node_id"
}

edit_node() {
    select_nodes "single" "Edit Node" || return
    
    local old_name="${SELECTED_NODES_NAMES[0]}" old_ip="${SELECTED_NODES_IPS[0]}" old_id="${SELECTED_NODES_IDS[0]}"
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
    
    local new_id=$(dialog --title "Edit Node ID" --inputbox "Enter new Node ID:" 8 50 "$old_id" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z "$new_id" ]] && { show_msg "Cancelled" "Edit cancelled."; return; }
    
    remove_nodes_from_file "$old_name"
    insert_node_sorted "$new_name" "$new_ip" "$new_id"
    show_success "Node updated!\n\nOld: $old_name ($old_ip) - $old_id\nNew: $new_name ($new_ip) - $new_id"
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
        [[ "$line" =~ ^(Node\ Name:|IP\ Address:|Node\ ID:) || -z "$line" ]] && echo "$line" >> "$clean_file"
    done < "$NODES_FILE"
    
    local names=() ips=() node_ids=()
    parse_nodes_file
    local total=${#names[@]} processed=0
    
    local temp=$(mktemp)
    for ((i=0; i<total; i++)); do
        local name="${names[i]}" ip="${ips[i]}" node_id="${node_ids[i]}"
        ((processed++))
        dialog --title "Retrieving Roles" --infobox "Processing $name ($processed/$total)..." 6 50
        
        echo -e "Node Name: $name\nIP Address: $ip\nNode ID: $node_id" >> "$temp"
        
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
    confirm "Backup ${#SELECTED_NODES_NAMES[@]} node(s)?$node_list\n\nLocal destination: $backup_dir" || return
    
    local successful=() failed=()
    local total=${#SELECTED_NODES_NAMES[@]} current=0 timestamp=$(date +%Y%m%d_%H%M%S)
    
    for ((i=0; i<total; i++)); do
        local name="${SELECTED_NODES_NAMES[i]}" ip="${SELECTED_NODES_IPS[i]}" node_id="${SELECTED_NODES_IDS[i]}"
        ((current++))
        log "BACKUP" "Processing node $current/$total: $name ($ip)"
        
        dialog --title "Backing Up" --infobox "Processing $name ($current/$total)...\nTesting connection..." 6 60
        log "BACKUP" "Step 1: Testing SSH connection to $ip"
        ssh_exec "$ip" "$user" "$pass" "echo 'OK'" "Connection Test" >/dev/null 2>&1
        if [[ $? -ne 0 ]]; then
            log "BACKUP" "SSH connection test FAILED for $name"
            failed+=("$name: SSH connection failed")
            continue
        fi
        log "BACKUP" "SSH connection test SUCCESS for $name"
        
        dialog --title "Backing Up" --infobox "Processing $name ($current/$total)...\nChecking rsync..." 6 60
        log "BACKUP" "Step 2: Checking rsync on remote server"
        local remote_rsync_check=$(ssh_exec "$ip" "$user" "$pass" "command -v rsync >/dev/null && rsync --version 2>/dev/null | head -1" "Check rsync" 2>/dev/null)
        log "BACKUP" "Remote rsync check result: $remote_rsync_check"
        
        if [[ -z "$remote_rsync_check" ]]; then
            log "BACKUP" "Step 3: Installing rsync on remote server"
            dialog --title "Backing Up" --infobox "Processing $name ($current/$total)...\nInstalling rsync..." 6 60
            ssh_exec "$ip" "$user" "$pass" "apt-get update >/dev/null 2>&1 && apt-get install -y rsync 2>&1" "Install rsync" "true" >/dev/null 2>&1
            remote_rsync_check=$(ssh_exec "$ip" "$user" "$pass" "rsync --version 2>/dev/null | head -1" "Verify rsync" 2>/dev/null)
            if [[ -z "$remote_rsync_check" ]]; then
                log "BACKUP" "Failed to install rsync on $name"
                failed+=("$name: Could not install rsync on remote server")
                continue
            fi
            log "BACKUP" "Rsync installed successfully on $name"
        fi
        
        dialog --title "Backing Up" --infobox "Processing $name ($current/$total)...\nDetermining service user..." 6 60
        log "BACKUP" "Step 4: Determining service user"
        local check_user_cmd="if [ -f /etc/systemd/system/$SERVICE_NAME ]; then grep '^User=' /etc/systemd/system/$SERVICE_NAME | cut -d'=' -f2 | head -1; else echo 'NOFILE'; fi"
        local service_user=$(ssh_exec "$ip" "$user" "$pass" "$check_user_cmd" "Get service user" "true" 2>/dev/null | tr -d '[:space:]')
        
        [[ -z "$service_user" || "$service_user" == "NOFILE" ]] && service_user="root"
        local nym_path=$([[ "$service_user" == "root" ]] && echo "/root/.nym" || echo "/home/$service_user/.nym")
        log "BACKUP" "Service user: $service_user, nym_path: $nym_path"
        
        dialog --title "Backing Up" --infobox "Processing $name ($current/$total)...\nChecking folder access..." 6 60
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
            continue
        fi
        log "BACKUP" "Folder exists: $nym_path"
        
        dialog --title "Backing Up" --infobox "Processing $name ($current/$total)...\nCreating archive..." 6 60
        log "BACKUP" "Step 6: Creating tar archive"
        
        local backup_file="nym_backup_${name}_${timestamp}.tar.gz"
        local backup_path="/tmp/$backup_file"
        local parent_dir=$(dirname "$nym_path")
        local dir_name=$(basename "$nym_path")
        local tar_cmd="cd $parent_dir && tar --exclude='*.corrupted' --exclude='*.bloom' --exclude='*.sqlite-wal' --exclude='*.sqlite-shm' -czf $backup_path $dir_name; echo \"EXIT_CODE:\$?\""
        
        log "BACKUP" "Tar command: $tar_cmd"
        local tar_output=$(ssh_exec "$ip" "$user" "$pass" "$tar_cmd" "Create archive" "true" 2>/dev/null)
        local tar_exit=$(echo "$tar_output" | grep "EXIT_CODE:" | sed 's/.*EXIT_CODE://g' | tr -d '[:space:]')
        [[ -z "$tar_exit" ]] && tar_exit=255
        
        log "BACKUP" "Tar exit code: $tar_exit"
        if [[ $tar_exit -gt 1 ]]; then
            log "BACKUP" "Tar creation failed"
            failed+=("$name: Failed to create archive - exit code $tar_exit")
            continue
        fi
        
        dialog --title "Backing Up" --infobox "Processing $name ($current/$total)...\nVerifying archive..." 6 60
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
        
        dialog --title "Backing Up" --infobox "Processing $name ($current/$total)...\nPreparing for download..." 6 60
        log "BACKUP" "Step 8: Changing ownership for download"
        ssh_exec "$ip" "$user" "$pass" "chown $user:$user $backup_path" "Change ownership" "true" >/dev/null 2>&1
        
        local local_backup_file="$backup_dir/$backup_file"
        
        dialog --title "Backing Up" --infobox "Processing $name ($current/$total)...\n\nStarting download...\nFile size: $remote_size\n\nThis may take several minutes depending on\nthe archive size and network speed.\n\nPlease wait..." 12 60
        
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
        local choice=$(dialog --clear --title "$SCRIPT_NAME v$VERSION" --menu "Select category:" 16 60 5 \
            1 "Node Management" 2 "Node Operations" 3 "Configuration" 4 "Diagnostics" 0 "Exit" 3>&1 1>&2 2>&3)
        [[ $? -ne 0 ]] && break
        case $choice in
            1) node_management_menu ;; 2) node_operations_menu ;; 
            3) config_menu ;; 4) diagnostics_menu ;; 
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
