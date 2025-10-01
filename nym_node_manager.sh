#!/bin/bash

# ============================================================================
# Nym Node Manager v51 - Optimized & Refactored
# ============================================================================
# Description: Centralized management tool for Nym network nodes
# Requirements: dialog, sshpass, curl
# Features: Multi-node operations, backup, updates, configuration management
# ============================================================================

# ----------------------------------------------------------------------------
# GLOBAL CONFIGURATION
# ----------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
SCRIPT_NAME="Nym Node Manager"
VERSION="51"
SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")"
DEBUG_LOG="$SCRIPT_DIR/debug.log"
NODES_FILE="$SCRIPT_DIR/nodes.txt"
CONFIG_FILE="$SCRIPT_DIR/config.txt"

# Default configuration
DEFAULT_SSH_PORT="22"
DEFAULT_SERVICE_NAME="nym-node.service"
DEFAULT_BINARY_PATH="/root/nym"

# Runtime configuration (loaded from config file)
SSH_PORT=""
SERVICE_NAME=""
BINARY_PATH=""

# Node selection arrays (global for multi-node operations)
SELECTED_NODES_NAMES=()
SELECTED_NODES_IPS=()
SELECTED_NODES_IDS=()

# ----------------------------------------------------------------------------
# UTILITY FUNCTIONS - Logging & Initialization
# ----------------------------------------------------------------------------

# Initialize debug logging
# Creates new log file with session header
init_debug() {
    echo "=== Nym Node Manager v$VERSION Started - $(date) - User: $(whoami) ===" > "$DEBUG_LOG"
}

# Unified logging function
# Args: $1=level, $@=message
log() {
    local level="$1"; shift
    echo "[$(date '+%H:%M:%S')] [$level] $*" >> "$DEBUG_LOG"
}

# ----------------------------------------------------------------------------
# UTILITY FUNCTIONS - Dialog Wrappers
# ----------------------------------------------------------------------------

show_msg() { dialog --title "$1" --msgbox "$2" 10 60; }
show_error() { log "ERROR" "$1"; show_msg "Error" "$1"; }
show_success() { log "SUCCESS" "$1"; show_msg "Success" "$1"; }
confirm() { dialog --title "Confirm" --yesno "$1" 8 50; }
get_input() { dialog --title "$1" --inputbox "$2" 8 50 3>&1 1>&2 2>&3; }
get_password() { dialog --title "$1" --passwordbox "$2" 8 50 3>&1 1>&2 2>&3; }

# ----------------------------------------------------------------------------
# UTILITY FUNCTIONS - Configuration Management
# ----------------------------------------------------------------------------

# Load configuration from file or use defaults
# Sets global variables: SSH_PORT, SERVICE_NAME, BINARY_PATH
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
    
    log "CONFIG" "Loaded - SSH_PORT:$SSH_PORT SERVICE_NAME:$SERVICE_NAME BINARY_PATH:$BINARY_PATH"
}

# Save current configuration to file
save_config() {
    cat > "$CONFIG_FILE" << EOF
# Nym Node Manager Configuration - Generated $(date)
SSH_PORT=$SSH_PORT
SERVICE_NAME=$SERVICE_NAME
BINARY_PATH=$BINARY_PATH
EOF
    log "CONFIG" "Configuration saved"
}

# ----------------------------------------------------------------------------
# UTILITY FUNCTIONS - Dependencies
# ----------------------------------------------------------------------------

# Check and install missing dependencies
check_deps() {
    local missing=()
    for cmd in dialog sshpass curl; do
        command -v "$cmd" >/dev/null || missing+=("$cmd")
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}Missing packages: ${missing[*]}${NC}"
        if command -v apt-get >/dev/null; then
            echo "Installing with apt-get..."
            sudo apt-get update && sudo apt-get install -y "${missing[@]}" || exit 1
        else
            echo -e "${RED}Install manually: ${missing[*]}${NC}"; exit 1
        fi
        echo -e "${GREEN}All packages installed!${NC}"
    fi
}

# ----------------------------------------------------------------------------
# NODE FILE OPERATIONS - Parsing & Sorting
# ----------------------------------------------------------------------------

# Check if node name already exists
# Args: $1=name to check
# Returns: 0 if exists, 1 if not exists
node_name_exists() {
    local check_name="$1"
    
    [[ ! -f "$NODES_FILE" || ! -s "$NODES_FILE" ]] && return 1
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name:\ (.+)$ ]]; then
            local existing_name="${BASH_REMATCH[1]}"
            [[ "$existing_name" == "$check_name" ]] && return 0
        fi
    done < "$NODES_FILE"
    
    return 1
}

# Parse nodes file into structured arrays
# Returns via global arrays: names, ips, node_ids
# Usage: parse_nodes_file
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

# Sort nodes file alphabetically by name
sort_nodes_file() {
    [[ ! -f "$NODES_FILE" || ! -s "$NODES_FILE" ]] && return
    
    local temp=$(mktemp)
    local nodes=() current_node=""
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name:\ (.+)$ ]]; then
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

# Insert node in alphabetically correct position
# Args: $1=name, $2=ip, $3=node_id
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
                echo -e "Node Name: $new_name\nIP Address: $new_ip\nNode ID: $new_node_id" >> "$temp"
                echo >> "$temp"
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

# Remove nodes by name from file
# Args: $@ = array of node names to remove
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
            
            if [[ ! "$in_target" == "true" ]]; then
                [[ -s "$temp" ]] && echo "" >> "$temp"
                echo "$line" >> "$temp"
            fi
        elif [[ ! "$in_target" == "true" ]]; then
            echo "$line" >> "$temp"
        fi
    done < "$NODES_FILE"
    
    mv "$temp" "$NODES_FILE"
}

# ----------------------------------------------------------------------------
# SSH OPERATIONS - Unified SSH execution
# ----------------------------------------------------------------------------

# Unified SSH execution with optional sudo/root elevation
# Args: $1=ip, $2=user, $3=pass, $4=command, $5=description, $6=use_root(true/false)
ssh_exec() {
    local ip="$1" user="$2" pass="$3" cmd="$4" desc="${5:-SSH Command}" use_root="${6:-false}"
    
    # Build command with root elevation if requested
    if [[ "$use_root" == "true" ]]; then
        cmd="echo '$pass' | sudo -S su -c \"$cmd\""
    fi
    
    # Sanitize for logging
    local safe_cmd=$(echo "$cmd" | sed "s/${pass//\//\\/}/***REDACTED***/g")
    log "SSH" "$desc: $user@$ip:$SSH_PORT - $safe_cmd"
    
    local output=$(sshpass -p "$pass" ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 -o BatchMode=no "$user@$ip" "$cmd" 2>&1)
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        echo "$output"
        return 0
    else
        show_error "$desc Failed\nNode: $ip:$SSH_PORT\nExit Code: $exit_code\nError: $output"
        return $exit_code
    fi
}

# ----------------------------------------------------------------------------
# NODE SELECTION - Unified selection dialog
# ----------------------------------------------------------------------------

# Select single or multiple nodes with optional "Select All"
# Args: $1=mode ("single" or "multi"), $2=title
# Returns: 0 on success, 1 on cancel/error
# Sets global: SELECTED_NODES_NAMES, SELECTED_NODES_IPS, SELECTED_NODES_IDS
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
        choices=$(dialog --title "$title" --checklist \
            "Choose nodes (Space to select, Enter to confirm):" \
            $((${#names[@]} + 10)) 70 $((${#names[@]} + 1)) "${all_options[@]}" 3>&1 1>&2 2>&3)
    else
        choices=$(dialog --title "$title" --menu "Choose node:" 15 60 10 "${options[@]}" 3>&1 1>&2 2>&3)
    fi
    
    [[ $? -ne 0 ]] && return 1
    
    # Parse selections
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
# RESULTS DISPLAY - Unified results formatting
# ----------------------------------------------------------------------------

# Display operation results in consistent format
# Args: $1=operation_name, $2=success_array_name, $3=fail_array_name, $4=additional_info
show_operation_results() {
    local operation="$1"
    local -n success_arr="$2"
    local -n fail_arr="$3"
    local additional="${4:-}"
    
    local results="$operation Results\n"
    results+="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
    
    if [[ ${#success_arr[@]} -gt 0 ]]; then
        results+="✅ Success (${#success_arr[@]} nodes):\n"
        for item in "${success_arr[@]}"; do
            results+="   • $item\n"
        done
        results+="\n"
    fi
    
    if [[ ${#fail_arr[@]} -gt 0 ]]; then
        results+="❌ Failed (${#fail_arr[@]} nodes):\n"
        for item in "${fail_arr[@]}"; do
            results+="   • $item\n"
        done
        results+="\n"
    fi
    
    [[ -n "$additional" ]] && results+="$additional\n"
    
    show_success "$results"
}

# ----------------------------------------------------------------------------
# NODE MANAGEMENT FUNCTIONS
# ----------------------------------------------------------------------------

# List all nodes with their configuration
list_nodes() {
    log "FUNCTION" "list_nodes"
    [[ ! -f "$NODES_FILE" || ! -s "$NODES_FILE" ]] && { show_msg "No Nodes" "No nodes found."; return; }
    
    sort_nodes_file
    
    local content="" current_node=""
    while IFS= read -r line; do
        case "$line" in
            "Node Name: "*)
                [[ -n "$current_node" ]] && content+="\n"
                content+="🖥️ NODE: ${line#Node Name: }\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                current_node="yes" ;;
            "IP Address: "*) content+="🌐 IP: ${line#IP Address: }\n" ;;
            "Node ID: "*) content+="🆔 ID: ${line#Node ID: }\n" ;;
            "Build Version: "*) content+="📦 Version: ${line#Build Version: }\n" ;;
            "Mixnode Enabled: true") content+="🔀 Mixnode: \Z2✅ Enabled\Zn\n" ;;
            "Mixnode Enabled: false") content+="🔀 Mixnode: \Z1❌ Disabled\Zn\n" ;;
            "Gateway Enabled: true") content+="🚪 Gateway: \Z2✅ Enabled\Zn\n" ;;
            "Gateway Enabled: false") content+="🚪 Gateway: \Z1❌ Disabled\Zn\n" ;;
            "Network Requester Enabled: true") content+="🌐 Network Requester: \Z2✅ Enabled\Zn\n" ;;
            "Network Requester Enabled: false") content+="🌐 Network Requester: \Z1❌ Disabled\Zn\n" ;;
            "IP Packet Router Enabled: true") content+="📦 IP Packet Router: \Z2✅ Enabled\Zn\n" ;;
            "IP Packet Router Enabled: false") content+="📦 IP Packet Router: \Z1❌ Disabled\Zn\n" ;;
            "Wireguard Status: enabled"*) content+="🔒 WireGuard: \Z2✅ ${line#Wireguard Status: }\Zn\n" ;;
            "Wireguard Status: disabled") content+="🔒 WireGuard: \Z1❌ Disabled\Zn\n" ;;
        esac
    done < "$NODES_FILE"
    
    [[ -n "$content" ]] && dialog --title "Nym Network Nodes" --colors --msgbox "$content" 25 85 ||
        show_msg "No Data" "No readable node data found."
}

# Add new node
add_node() {
    log "FUNCTION" "add_node"
    
    local name=""
    local attempt=0
    
    # Loop until valid unique name is provided or user cancels
    while true; do
        ((attempt++))
        
        if [[ $attempt -eq 1 ]]; then
            name=$(get_input "Add Node" "Enter Node Name:")
        else
            name=$(get_input "Add Node" "Node '$name' already exists!\n\nEnter a different Node Name:")
        fi
        
        # Check if user cancelled
        [[ -z "$name" ]] && { show_msg "Cancelled" "Node creation cancelled."; return; }
        
        # Check if name already exists
        if node_name_exists "$name"; then
            log "ADD_NODE" "Duplicate name attempt: $name"
            continue  # Loop back to ask for new name
        else
            break  # Name is unique, proceed
        fi
    done
    
    local ip=$(get_input "Add Node" "Enter IP Address for '$name':")
    [[ -z "$ip" ]] && { show_msg "Cancelled" "Node creation cancelled."; return; }
    
    local node_id=$(get_input "Add Node" "Enter Node ID for '$name':\n(The ID used during node initialization)")
    [[ -z "$node_id" ]] && { show_msg "Cancelled" "Node creation cancelled."; return; }
    
    insert_node_sorted "$name" "$ip" "$node_id"
    show_success "Node '$name' added successfully!\nIP: $ip\nID: $node_id"
    log "ADD_NODE" "Successfully added node: $name"
}

# Edit existing node
edit_node() {
    log "FUNCTION" "edit_node"
    
    select_nodes "single" "Edit Node" || return
    
    local old_name="${SELECTED_NODES_NAMES[0]}"
    local old_ip="${SELECTED_NODES_IPS[0]}"
    local old_id="${SELECTED_NODES_IDS[0]}"
    
    local new_name=""
    local attempt=0
    
    # Loop until valid unique name is provided or user cancels
    while true; do
        ((attempt++))
        
        if [[ $attempt -eq 1 ]]; then
            new_name=$(dialog --title "Edit Node Name" --inputbox "Enter new Node Name:" 8 50 "$old_name" 3>&1 1>&2 2>&3)
        else
            new_name=$(dialog --title "Edit Node Name" --inputbox "Node '$new_name' already exists!\n\nEnter a different Node Name:" 8 50 "$old_name" 3>&1 1>&2 2>&3)
        fi
        
        # Check if user cancelled
        [[ $? -ne 0 || -z "$new_name" ]] && { show_msg "Cancelled" "Edit cancelled."; return; }
        
        # Allow keeping the same name (editing same node)
        if [[ "$new_name" == "$old_name" ]]; then
            break
        fi
        
        # Check if new name already exists
        if node_name_exists "$new_name"; then
            log "EDIT_NODE" "Duplicate name attempt: $new_name"
            continue  # Loop back to ask for new name
        else
            break  # Name is unique, proceed
        fi
    done
    
    local new_ip=$(dialog --title "Edit IP Address" --inputbox "Enter new IP Address:" 8 50 "$old_ip" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z "$new_ip" ]] && { show_msg "Cancelled" "Edit cancelled."; return; }
    
    local new_id=$(dialog --title "Edit Node ID" --inputbox "Enter new Node ID:" 8 50 "$old_id" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z "$new_id" ]] && { show_msg "Cancelled" "Edit cancelled."; return; }
    
    remove_nodes_from_file "$old_name"
    insert_node_sorted "$new_name" "$new_ip" "$new_id"
    
    show_success "Node updated!\n\nOld: $old_name ($old_ip) - $old_id\nNew: $new_name ($new_ip) - $new_id"
    log "EDIT_NODE" "Successfully edited: $old_name -> $new_name"
}

# Delete nodes with multi-selection
delete_node() {
    log "FUNCTION" "delete_node"
    
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
# NODE OPERATIONS FUNCTIONS
# ----------------------------------------------------------------------------

# Retrieve node roles from API
retrieve_node_roles() {
    log "FUNCTION" "retrieve_node_roles"
    [[ ! -f "$NODES_FILE" || ! -s "$NODES_FILE" ]] && { show_error "No nodes found."; return; }
    
    # Clean file - keep only Node Name, IP, and Node ID
    local clean_file=$(mktemp)
    while IFS= read -r line; do
        [[ "$line" =~ ^(Node\ Name:|IP\ Address:|Node\ ID:) || -z "$line" ]] && echo "$line" >> "$clean_file"
    done < "$NODES_FILE"
    
    local names=() ips=() node_ids=()
    parse_nodes_file
    local total=${#names[@]} processed=0
    
    dialog --title "Retrieving Roles" --infobox "Processing 0/$total nodes..." 6 40 &
    local dialog_pid=$!
    
    local temp=$(mktemp)
    for ((i=0; i<total; i++)); do
        local name="${names[i]}" ip="${ips[i]}" node_id="${node_ids[i]}"
        ((processed++))
        
        kill $dialog_pid 2>/dev/null
        dialog --title "Retrieving Roles" --infobox "Processing $name ($processed/$total)..." 6 50 &
        dialog_pid=$!
        
        echo -e "Node Name: $name\nIP Address: $ip\nNode ID: $node_id" >> "$temp"
        
        # Fetch API data
        local roles=$(curl -s --connect-timeout 5 --max-time 10 "http://$ip:8080/api/v1/roles" 2>/dev/null)
        local gateway=$(curl -s --connect-timeout 5 --max-time 10 "http://$ip:8080/api/v1/gateway" 2>/dev/null)
        local build_info=$(curl -s --connect-timeout 5 --max-time 10 "http://$ip:8080/api/v1/build-information" 2>/dev/null)
        
        # Parse and add role information
        if [[ -n "$roles" ]]; then
            echo "Mixnode Enabled: $(echo "$roles" | grep -o '"mixnode_enabled"[[:space:]]*:[[:space:]]*[^,}]*' | cut -d':' -f2 | tr -d ' ",' || echo "unknown")" >> "$temp"
            echo "Gateway Enabled: $(echo "$roles" | grep -o '"gateway_enabled"[[:space:]]*:[[:space:]]*[^,}]*' | cut -d':' -f2 | tr -d ' ",' || echo "unknown")" >> "$temp"
            echo "Network Requester Enabled: $(echo "$roles" | grep -o '"network_requester_enabled"[[:space:]]*:[[:space:]]*[^,}]*' | cut -d':' -f2 | tr -d ' ",' || echo "unknown")" >> "$temp"
            echo "IP Packet Router Enabled: $(echo "$roles" | grep -o '"ip_packet_router_enabled"[[:space:]]*:[[:space:]]*[^,}]*' | cut -d':' -f2 | tr -d ' ",' || echo "unknown")" >> "$temp"
        else
            echo -e "Mixnode Enabled: error\nGateway Enabled: error\nNetwork Requester Enabled: error\nIP Packet Router Enabled: error" >> "$temp"
        fi
        
        # Parse Wireguard
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
        
        # Parse version
        if [[ -n "$build_info" ]]; then
            local version=$(echo "$build_info" | grep -o '"build_version"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d':' -f2 | tr -d ' "' || echo "unknown")
            echo "Build Version: $version" >> "$temp"
        else
            echo "Build Version: error" >> "$temp"
        fi
        
        [[ $i -lt $((total - 1)) ]] && echo >> "$temp"
    done
    
    kill $dialog_pid 2>/dev/null
    rm -f "$clean_file"
    mv "$temp" "$NODES_FILE"
    sort_nodes_file
    show_success "Node roles retrieved for $processed nodes!"
}

# Backup nodes to local directory
backup_node() {
    log "FUNCTION" "backup_node"
    
    local backup_dir=$(get_input "Backup Destination" "Enter local backup directory:\n(Leave empty for: $SCRIPT_DIR)")
    [[ -z "$backup_dir" ]] && backup_dir="$SCRIPT_DIR"
    
    if [[ ! -d "$backup_dir" ]]; then
        dialog --title "Create Directory" --infobox "Creating: $backup_dir..." 5 60
        mkdir -p "$backup_dir" 2>/dev/null || { show_error "Cannot create: $backup_dir"; return; }
    fi
    backup_dir=$(cd "$backup_dir" && pwd)
    
    select_nodes "multi" "Backup Nodes" || return
    
    local user=$(get_input "SSH Connection" "SSH username (same for all):")
    [[ -z "$user" ]] && { show_msg "Cancelled" "Backup cancelled."; return; }
    
    local pass=$(get_password "SSH Connection" "SSH password for $user:")
    [[ -z "$pass" ]] && { show_msg "Cancelled" "Backup cancelled."; return; }
    
    local node_list=""
    for ((i=0; i<${#SELECTED_NODES_NAMES[@]}; i++)); do
        node_list+="\n• ${SELECTED_NODES_NAMES[i]} (${SELECTED_NODES_IPS[i]})"
    done
    confirm "Backup ${#SELECTED_NODES_NAMES[@]} node(s)?$node_list\n\nDestination: $backup_dir" || return
    
    local successful=() failed=()
    local total=${#SELECTED_NODES_NAMES[@]} current=0
    local timestamp=$(date +%Y%m%d)
    
    for ((i=0; i<total; i++)); do
        local name="${SELECTED_NODES_NAMES[i]}" ip="${SELECTED_NODES_IPS[i]}"
        ((current++))
        
        dialog --title "Backing Up" --infobox "Processing $name ($current/$total)...\nTesting connection..." 6 60
        
        ssh_exec "$ip" "$user" "$pass" "echo 'OK'" "Connection Test" >/dev/null 2>&1 || \
            { failed+=("$name: SSH connection failed"); continue; }
        
        local backup_file="${timestamp}_${name}_backup.tar.gz"
        local remote_path="/tmp/$backup_file"
        
        dialog --title "Backing Up" --infobox "Processing $name ($current/$total)...\nCreating archive..." 6 60
        
        local tar_cmd="cd /root && tar --exclude='*.bloom' -czf $remote_path .nym 2>/dev/null"
        ssh_exec "$ip" "$user" "$pass" "$tar_cmd" "Create Archive" "true" >/dev/null 2>&1 || \
            { failed+=("$name: Failed to create archive"); continue; }
        
        dialog --title "Backing Up" --infobox "Processing $name ($current/$total)...\nTransferring..." 6 60
        
        if sshpass -p "$pass" scp -P "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            "$user@$ip:$remote_path" "$backup_dir/$backup_file" 2>/dev/null; then
            local size=$(ls -lh "$backup_dir/$backup_file" 2>/dev/null | awk '{print $5}')
            ssh_exec "$ip" "$user" "$pass" "rm -f $remote_path" "Cleanup" "true" >/dev/null 2>&1
            successful+=("$name: Backup completed ($size) -> $backup_file")
            log "BACKUP" "Successfully backed up $name"
        else
            failed+=("$name: Failed to transfer backup")
            ssh_exec "$ip" "$user" "$pass" "rm -f $remote_path" "Cleanup" "true" >/dev/null 2>&1
        fi
    done
    
    local info="📂 Backup Location: $backup_dir\n📝 Note: .bloom files excluded"
    show_operation_results "💾 Node Backup" successful failed "$info"
}

# Update nym-node binary
update_nym_node() {
    log "FUNCTION" "update_nym_node"
    
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
        
        ssh_exec "$ip" "$user" "$pass" "echo 'OK'" "Connection Test" >/dev/null 2>&1 || \
            { failed+=("$name: SSH connection failed"); continue; }
        
        dialog --title "Updating Nym-Node" --infobox "Processing $name ($current/$total)...\nPreparing..." 6 60
        
        # Create directory and backup current binary
        local prep_cmd="mkdir -p $BINARY_PATH/old && cd $BINARY_PATH && if [ -f nym-node ]; then mv nym-node old/nym-node.backup.\$(date +%Y%m%d_%H%M%S) || true; fi"
        ssh_exec "$ip" "$user" "$pass" "$prep_cmd" "Prepare Directory" "true" >/dev/null 2>&1 || \
            { failed+=("$name: Could not prepare directory"); continue; }
        
        dialog --title "Updating Nym-Node" --infobox "Processing $name ($current/$total)...\nDownloading..." 6 60
        
        # Download and make executable
        local dl_cmd="cd $BINARY_PATH && curl -L -o nym-node '$url' && chmod +x nym-node"
        ssh_exec "$ip" "$user" "$pass" "$dl_cmd" "Download Binary" "true" >/dev/null 2>&1 || \
            { failed+=("$name: Could not download binary"); continue; }
        
        dialog --title "Updating Nym-Node" --infobox "Processing $name ($current/$total)...\nVerifying..." 6 60
        
        # Check version
        local version_output=$(ssh_exec "$ip" "$user" "$pass" "cd $BINARY_PATH && ./nym-node --version" "Check Version" "true" 2>/dev/null)
        
        if [[ $? -eq 0 && -n "$version_output" ]]; then
            local version=$(echo "$version_output" | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1)
            [[ -z "$version" ]] && version="unknown (functional)"
            successful+=("$name: Updated to version $version")
            log "UPDATE" "Successfully updated $name to $version"
        else
            failed+=("$name: Could not verify new binary")
        fi
    done
    
    local info="⚠️  IMPORTANT: Restart $SERVICE_NAME on updated nodes\n   Use 'Restart service' in Node Operations menu\n\n💾 Old binaries backed up to $BINARY_PATH/old/"
    show_operation_results "🔄 Nym-Node Update" successful failed "$info"
}

# Toggle node functionality (Wireguard & Mode)
toggle_node_functionality() {
    log "FUNCTION" "toggle_node_functionality"
    
    select_nodes "multi" "Configure Nodes" || return
    
    local user=$(get_input "SSH Connection" "SSH username (same for all):")
    [[ -z "$user" ]] && { show_msg "Cancelled" "Configuration cancelled."; return; }
    
    local pass=$(get_password "SSH Connection" "SSH password for $user:")
    [[ -z "$pass" ]] && { show_msg "Cancelled" "Configuration cancelled."; return; }
    
    dialog --title "Configuration" --infobox "Testing SSH connection..." 5 50
    ssh_exec "${SELECTED_NODES_IPS[0]}" "$user" "$pass" "echo 'OK'" "Connection Test" >/dev/null 2>&1 || \
        { show_error "SSH connection failed. Check credentials."; return; }
    
    # Get Wireguard setting
    local wg_choice=$(dialog --title "Wireguard Configuration" --radiolist \
        "Select Wireguard setting:" 12 60 2 \
        "enabled" "Enable Wireguard" "OFF" \
        "disabled" "Disable Wireguard" "ON" \
        3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && return
    
    # Get Mode setting
    local mode_choice=$(dialog --title "Mixnet Mode Configuration" --radiolist \
        "Select mode:" 14 60 3 \
        "entry-gateway" "Entry Gateway" "OFF" \
        "exit-gateway" "Exit Gateway" "OFF" \
        "mixnode" "Mixnode" "ON" \
        3>&1 1>&2 2>&3)
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
        
        ssh_exec "$ip" "$user" "$pass" "echo 'OK'" "Connection Test" >/dev/null 2>&1 || \
            { failed+=("$name: SSH connection failed"); continue; }
        
        # Get service user
        local service_user=$(ssh_exec "$ip" "$user" "$pass" "grep '^User=' /etc/systemd/system/$SERVICE_NAME | cut -d'=' -f2" "Get User" "true" 2>/dev/null)
        [[ -z "$service_user" ]] && service_user="root"
        
        # Build config path
        local config_path="/root/.nym/nym-nodes/$node_id/config/config.toml"
        [[ "$service_user" != "root" ]] && config_path="/home/$service_user/.nym/nym-nodes/$node_id/config/config.toml"
        
        local service_updated=false config_updated=false
        
        # Check for service file flags
        local has_flags=$(ssh_exec "$ip" "$user" "$pass" "grep -E '(--wireguard-enabled|--mode)' /etc/systemd/system/$SERVICE_NAME" "Check Flags" "true" 2>/dev/null)
        
        if [[ -n "$has_flags" ]]; then
            local wg_flag=$([ "$wg_choice" = "enabled" ] && echo "true" || echo "false")
            local update_cmd="cp /etc/systemd/system/$SERVICE_NAME /etc/systemd/system/$SERVICE_NAME.backup.\$(date +%Y%m%d_%H%M%S) && "
            update_cmd+="sed -i 's/--wireguard-enabled [^ ]*/--wireguard-enabled $wg_flag/g; t wg; s/\\(ExecStart=[^ ]* run\\)/\\1 --wireguard-enabled $wg_flag/; :wg' /etc/systemd/system/$SERVICE_NAME && "
            update_cmd+="sed -i 's/--mode [^ ]*/--mode $mode_choice/g; t mode; s/\\(ExecStart=[^ ]* run\\)/\\1 --mode $mode_choice/; :mode' /etc/systemd/system/$SERVICE_NAME && "
            update_cmd+="systemctl daemon-reload"
            
            ssh_exec "$ip" "$user" "$pass" "$update_cmd" "Update Service" "true" >/dev/null 2>&1 && service_updated=true
        fi
        
        # Update config.toml if exists
        local config_exists=$(ssh_exec "$ip" "$user" "$pass" "test -f $config_path && echo 'exists'" "Check Config" "true" 2>/dev/null)
        
        if [[ "$config_exists" == "exists" ]]; then
            local mixnode_val="false" entry_val="false" exit_val="false"
            case "$mode_choice" in
                "mixnode") mixnode_val="true" ;;
                "entry-gateway") entry_val="true" ;;
                "exit-gateway") exit_val="true" ;;
            esac
            
            local wg_toml=$([ "$wg_choice" = "enabled" ] && echo "true" || echo "false")
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
            log "CONFIG" "Updated $name via $method"
        else
            failed+=("$name: Failed to update configuration")
        fi
    done
    
    local info="Applied Configuration:\n   • Wireguard: $wg_choice\n   • Mode: $mode_choice\n\n⚠️  IMPORTANT: Restart services on updated nodes"
    show_operation_results "🔧 Node Configuration" successful failed "$info"
}

# Restart service on nodes
restart_service() {
    log "FUNCTION" "restart_service"
    
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
        
        ssh_exec "$ip" "$user" "$pass" "echo 'OK'" "Connection Test" >/dev/null 2>&1 || \
            { failed+=("$name: SSH connection failed"); continue; }
        
        if ssh_exec "$ip" "$user" "$pass" "echo '$pass' | sudo -S systemctl restart $SERVICE_NAME" "Restart" >/dev/null 2>&1; then
            sleep 2
            local status=$(ssh_exec "$ip" "$user" "$pass" "sudo systemctl is-active $SERVICE_NAME" "Status Check" 2>/dev/null)
            [[ -n "$status" ]] && successful+=("$name: Restarted (Status: $status)") || successful+=("$name: Restarted")
            log "RESTART" "Successfully restarted $name"
        else
            failed+=("$name: Failed to restart service")
        fi
    done
    
    show_operation_results "🔄 Service Restart" successful failed "🎯 Service Restart Complete!"
}

# ----------------------------------------------------------------------------
# CONFIGURATION MENU FUNCTIONS
# ----------------------------------------------------------------------------

# Configuration submenu
config_menu() {
    log "FUNCTION" "config_menu"
    
    while true; do
        local info="Current Configuration:\n• SSH Port: $SSH_PORT\n• Service Name: $SERVICE_NAME\n• Binary Path: $BINARY_PATH"
        
        local choice=$(dialog --clear --title "Configuration Menu" \
            --menu "$info\n\nSelect option:" 18 70 5 \
            1 "Custom SSH Port (Current: $SSH_PORT)" \
            2 "Systemd Service Name (Current: $SERVICE_NAME)" \
            3 "Custom Binary Folder (Current: $BINARY_PATH)" \
            4 "Reset to Defaults" \
            0 "Back to Main Menu" \
            3>&1 1>&2 2>&3)
        
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

# Configure SSH Port
config_ssh_port() {
    local new_port=$(get_input "SSH Port Configuration" "Enter SSH port (current: $SSH_PORT):")
    [[ -z "$new_port" ]] && return
    
    if [[ "$new_port" =~ ^[0-9]+$ ]] && [[ "$new_port" -ge 1 ]] && [[ "$new_port" -le 65535 ]]; then
        SSH_PORT="$new_port"
        save_config
        show_success "SSH port updated to $SSH_PORT"
        log "CONFIG" "SSH port changed to $SSH_PORT"
    else
        show_error "Invalid port. Enter a number between 1 and 65535."
    fi
}

# Configure Service Name
config_service_name() {
    local new_service=$(get_input "Service Name Configuration" "Enter systemd service name (current: $SERVICE_NAME):")
    [[ -z "$new_service" ]] && return
    
    [[ "$new_service" != *.service ]] && new_service="$new_service.service"
    
    SERVICE_NAME="$new_service"
    save_config
    show_success "Service name updated to $SERVICE_NAME"
    log "CONFIG" "Service name changed to $SERVICE_NAME"
}

# Configure Binary Path
config_binary_path() {
    local new_path=$(get_input "Binary Path Configuration" "Enter binary folder path (current: $BINARY_PATH):")
    [[ -z "$new_path" ]] && return
    
    new_path=$(echo "$new_path" | sed 's|/$||')
    
    BINARY_PATH="$new_path"
    save_config
    show_success "Binary path updated to $BINARY_PATH"
    log "CONFIG" "Binary path changed to $BINARY_PATH"
}

# Reset configuration to defaults
config_reset_defaults() {
    confirm "Reset all configuration to defaults?\n\nSSH Port: $DEFAULT_SSH_PORT\nService: $DEFAULT_SERVICE_NAME\nBinary: $DEFAULT_BINARY_PATH" || return
    
    SSH_PORT="$DEFAULT_SSH_PORT"
    SERVICE_NAME="$DEFAULT_SERVICE_NAME"
    BINARY_PATH="$DEFAULT_BINARY_PATH"
    save_config
    show_success "Configuration reset to defaults"
    log "CONFIG" "Configuration reset to defaults"
}

# ----------------------------------------------------------------------------
# DIAGNOSTICS MENU FUNCTIONS
# ----------------------------------------------------------------------------

# Test SSH connection and capabilities
test_ssh() {
    log "FUNCTION" "test_ssh"
    
    select_nodes "single" "Test SSH" || return
    
    local name="${SELECTED_NODES_NAMES[0]}" ip="${SELECTED_NODES_IPS[0]}"
    
    local user=$(get_input "SSH Test" "SSH username for $name:")
    [[ -z "$user" ]] && return
    
    local pass=$(get_password "SSH Test" "SSH password for $user@$ip:")
    [[ -z "$pass" ]] && return
    
    local results="🔧 SSH Test Results: $name ($ip:$SSH_PORT)\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
    
    local tests=(
        "Basic Connection:echo 'OK'"
        "Working Directory:pwd"
        "User Identity:whoami"
        "Sudo Access:echo '$pass' | sudo -S whoami"
        "Root Switch:echo '$pass' | sudo -S su -c 'whoami'"
        "Service File:echo '$pass' | sudo -S test -f /etc/systemd/system/$SERVICE_NAME && echo 'EXISTS'"
        "Service Status:echo '$pass' | sudo -S systemctl is-active $SERVICE_NAME"
    )
    
    local step=1
    for test in "${tests[@]}"; do
        local desc="${test%%:*}" cmd="${test#*:}"
        dialog --title "SSH Test" --infobox "Step $step/7: Testing $desc..." 5 50
        
        if output=$(ssh_exec "$ip" "$user" "$pass" "$cmd" "$desc" 2>/dev/null); then
            results+="✅ Step $step: $desc - SUCCESS\n   Result: $output\n"
        else
            results+="❌ Step $step: $desc - FAILED\n"
        fi
        ((step++))
    done
    
    results+="\n🎯 SSH Test Complete!"
    show_success "$results"
}

# Show debug log
show_debug() {
    log "FUNCTION" "show_debug"
    
    [[ -f "$DEBUG_LOG" ]] && dialog --title "Debug Log (Last 50 lines)" --msgbox "$(tail -50 "$DEBUG_LOG")" 25 100 ||
        show_msg "No Log" "Debug log not found."
}

# ----------------------------------------------------------------------------
# MENU SYSTEM - Organized submenus
# ----------------------------------------------------------------------------

# Node Management submenu
node_management_menu() {
    while true; do
        local choice=$(dialog --clear --title "Node Management" \
            --menu "Manage your Nym nodes:" 15 60 5 \
            1 "List all nodes" \
            2 "Add node" \
            3 "Edit node" \
            4 "Delete node" \
            0 "Back to Main Menu" \
            3>&1 1>&2 2>&3)
        
        [[ $? -ne 0 ]] && break
        
        case $choice in
            1) list_nodes ;;
            2) add_node ;;
            3) edit_node ;;
            4) delete_node ;;
            0) break ;;
        esac
    done
}

# Node Operations submenu
node_operations_menu() {
    while true; do
        local choice=$(dialog --clear --title "Node Operations" \
            --menu "Perform operations on nodes:" 17 60 6 \
            1 "Retrieve node roles" \
            2 "Backup node" \
            3 "Update nym-node binary" \
            4 "Toggle functionality (Mixnet & Wireguard)" \
            5 "Restart service" \
            0 "Back to Main Menu" \
            3>&1 1>&2 2>&3)
        
        [[ $? -ne 0 ]] && break
        
        case $choice in
            1) retrieve_node_roles ;;
            2) backup_node ;;
            3) update_nym_node ;;
            4) toggle_node_functionality ;;
            5) restart_service ;;
            0) break ;;
        esac
    done
}

# Diagnostics submenu
diagnostics_menu() {
    while true; do
        local choice=$(dialog --clear --title "Diagnostics" \
            --menu "Diagnostic tools:" 13 60 3 \
            1 "Test SSH connection" \
            2 "Show debug log" \
            0 "Back to Main Menu" \
            3>&1 1>&2 2>&3)
        
        [[ $? -ne 0 ]] && break
        
        case $choice in
            1) test_ssh ;;
            2) show_debug ;;
            0) break ;;
        esac
    done
}

# Main menu
main_menu() {
    while true; do
        local choice=$(dialog --clear --title "$SCRIPT_NAME v$VERSION" \
            --menu "Select category:" 16 60 5 \
            1 "Node Management" \
            2 "Node Operations" \
            3 "Configuration" \
            4 "Diagnostics" \
            0 "Exit" \
            3>&1 1>&2 2>&3)
        
        [[ $? -ne 0 ]] && break
        
        case $choice in
            1) node_management_menu ;;
            2) node_operations_menu ;;
            3) config_menu ;;
            4) diagnostics_menu ;;
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
