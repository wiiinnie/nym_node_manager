#!/bin/bash

# Nym Node Manager v40 - Optimized Version
# Requires: dialog, sshpass, curl
# This is only a test for GIT workflow

# Colors and config
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
SCRIPT_NAME="Nym Node Manager"
VERSION="40"
DEBUG_LOG="debug.log"
NODES_FILE="$(dirname "${BASH_SOURCE[0]}")/nodes.txt"

# Initialize debug logging
init_debug() {
    echo "=== Nym Node Manager Started - $(date) - User: $(whoami) ===" > "$DEBUG_LOG"
}

# Unified logging function
log() {
    local level="$1"; shift
    echo "[$(date '+%H:%M:%S')] [$level] $*" >> "$DEBUG_LOG"
}

# Check and install dependencies
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

# Unified dialog functions
show_msg() { dialog --title "$1" --msgbox "$2" 10 60; }
show_error() { log "ERROR" "$1"; show_msg "Error" "$1"; }
show_success() { log "SUCCESS" "$1"; show_msg "Success" "$1"; }
confirm() { dialog --title "Confirm" --yesno "$1" 8 50; }
get_input() { dialog --title "$1" --inputbox "$2" 8 50 3>&1 1>&2 2>&3; }
get_password() { dialog --title "$1" --passwordbox "$2" 8 50 3>&1 1>&2 2>&3; }

# Sort nodes in file alphabetically
sort_nodes_file() {
    [[ ! -f "$NODES_FILE" || ! -s "$NODES_FILE" ]] && return
    
    local temp=$(mktemp)
    local nodes=()
    local current_node=""
    
    # Read all nodes into array
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name:\ (.+)$ ]]; then
            [[ -n "$current_node" ]] && nodes+=("$current_node")
            current_node="$line\n"
        elif [[ -n "$current_node" ]]; then
            current_node+="$line\n"
        fi
    done < "$NODES_FILE"
    [[ -n "$current_node" ]] && nodes+=("$current_node")
    
    # Sort nodes by name
    IFS=$'\n' sorted=($(printf '%s\n' "${nodes[@]}" | sort -t: -k2))
    
    # Write sorted nodes back
    for ((i=0; i<${#sorted[@]}; i++)); do
        [[ $i -gt 0 ]] && echo >> "$temp"
        echo -e "${sorted[i]}" | sed '/^$/d' >> "$temp"
    done
    
    mv "$temp" "$NODES_FILE"
}

# Node selection helper
select_node() {
    [[ ! -f "$NODES_FILE" || ! -s "$NODES_FILE" ]] && { show_error "No nodes found. Add nodes first."; return 1; }
    
    local options=() names=() ips=() counter=1 name="" ip=""
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name:\ (.+)$ ]]; then
            name="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^IP\ Address:\ (.+)$ ]]; then
            ip="${BASH_REMATCH[1]}"
            if [[ -n "$name" && -n "$ip" ]]; then
                names+=("$name"); ips+=("$ip")
                options+=("$counter" "$name ($ip)")
                ((counter++)); name=""; ip=""
            fi
        fi
    done < "$NODES_FILE"
    
    [[ ${#names[@]} -eq 0 ]] && { show_error "No valid nodes found."; return 1; }
    
    local choice=$(dialog --title "Select Node" --menu "Choose node:" 15 60 10 "${options[@]}" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && return 1
    
    local idx=$((choice - 1))
    SELECTED_NODE_NAME="${names[$idx]}"
    SELECTED_NODE_IP="${ips[$idx]}"
    return 0
}

# Insert node in correct alphabetical position
insert_node_sorted() {
    local new_name="$1" new_ip="$2"
    local temp=$(mktemp)
    local inserted=false
    local current_node="" in_node=false
    
    if [[ ! -f "$NODES_FILE" ]]; then
        echo -e "Node Name: $new_name\nIP Address: $new_ip" > "$NODES_FILE"
        return
    fi
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name:\ (.+)$ ]]; then
            local node_name="${BASH_REMATCH[1]}"
            if [[ "$inserted" == "false" && "$new_name" < "$node_name" ]]; then
                [[ -s "$temp" ]] && echo >> "$temp"
                echo -e "Node Name: $new_name\nIP Address: $new_ip" >> "$temp"
                echo >> "$temp"
                inserted=true
            fi
            [[ -s "$temp" ]] && echo >> "$temp"
            echo "$line" >> "$temp"
            in_node=true
        else
            echo "$line" >> "$temp"
        fi
    done < "$NODES_FILE"
    
    # If not inserted yet, add at end
    if [[ "$inserted" == "false" ]]; then
        [[ -s "$temp" ]] && echo >> "$temp"
        echo -e "Node Name: $new_name\nIP Address: $new_ip" >> "$temp"
    fi
    
    mv "$temp" "$NODES_FILE"
}

# SSH execution with error handling
ssh_exec() {
    local ip="$1" user="$2" pass="$3" cmd="$4" desc="${5:-SSH Command}"
    log "SSH" "$desc: $user@$ip - $cmd"
    
    local output=$(sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 -o BatchMode=no "$user@$ip" "$cmd" 2>&1)
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        echo "$output"
        return 0
    else
        show_error "$desc Failed\nNode: $ip\nExit Code: $exit_code\nError: $output"
        return $exit_code
    fi
}

# Root SSH execution
ssh_root() {
    local ip="$1" user="$2" pass="$3" cmd="$4" desc="${5:-Root Command}"
    ssh_exec "$ip" "$user" "$pass" "echo '$pass' | sudo -S su -c \"$cmd\"" "$desc"
}

# 1) List all nodes (sorted alphabetically)
list_nodes() {
    log "FUNCTION" "list_nodes"
    [[ ! -f "$NODES_FILE" ]] && { show_msg "No Nodes" "No nodes.txt file found."; return; }
    [[ ! -s "$NODES_FILE" ]] && { show_msg "No Nodes" "The nodes.txt file is empty."; return; }
    
    # Ensure file is sorted before display
    sort_nodes_file
    
    local content="" current_node=""
    while IFS= read -r line; do
        case "$line" in
            "Node Name: "*)
                [[ -n "$current_node" ]] && content+="\n"
                content+="🖥️ NODE: ${line#Node Name: }\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                current_node="yes" ;;
            "IP Address: "*) content+="🌐 IP: ${line#IP Address: }\n" ;;
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
    
    [[ -n "$content" ]] && dialog --title "Nym Network Nodes (Alphabetically Sorted)" --colors --msgbox "$content" 25 85 ||
        show_msg "No Data" "No readable node data found."
}

# 2) Add node (insert in sorted order)
add_node() {
    log "FUNCTION" "add_node"
    local name=$(get_input "Add New Node" "Enter Node Name:")
    [[ -z "$name" ]] && { show_msg "Cancelled" "Node creation cancelled."; return; }
    
    local ip=$(get_input "Add New Node" "Enter IP Address for '$name':")
    [[ -z "$ip" ]] && { show_msg "Cancelled" "Node creation cancelled."; return; }
    
    insert_node_sorted "$name" "$ip"
    show_success "Node '$name' with IP '$ip' added successfully in alphabetical order!"
}

# 3) Delete node
delete_node() {
    log "FUNCTION" "delete_node"
    select_node || return
    
    confirm "Delete node: $SELECTED_NODE_NAME ($SELECTED_NODE_IP)?\nThis cannot be undone." || return
    
    local temp=$(mktemp) in_target=false
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name:\ (.+)$ ]]; then
            if [[ "${BASH_REMATCH[1]}" == "$SELECTED_NODE_NAME" ]]; then
                in_target=true; continue
            else
                in_target=false
                [[ -s "$temp" ]] && echo "" >> "$temp"
                echo "$line" >> "$temp"
            fi
        elif [[ ! "$in_target" == "true" ]]; then
            echo "$line" >> "$temp"
        fi
    done < "$NODES_FILE"
    
    mv "$temp" "$NODES_FILE"
    show_success "Node '$SELECTED_NODE_NAME' deleted successfully!"
}

# 4) Retrieve node roles
retrieve_node_roles() {
    log "FUNCTION" "retrieve_node_roles"
    [[ ! -f "$NODES_FILE" || ! -s "$NODES_FILE" ]] && { show_error "No nodes found."; return; }
    
    # First, create a clean file with only Node Name and IP Address lines
    local clean_file=$(mktemp)
    while IFS= read -r line; do
        if [[ "$line" =~ ^(Node\ Name:|IP\ Address:) ]] || [[ -z "$line" ]]; then
            echo "$line" >> "$clean_file"
        fi
    done < "$NODES_FILE"
    
    # Count nodes for progress
    local count=$(grep -c "^Node Name:" "$clean_file")
    local processed=0
    
    dialog --title "Retrieving Roles" --infobox "Processing 0/$count nodes..." 6 40 &
    local dialog_pid=$!
    
    # Now process the clean file and add fresh role data
    local temp=$(mktemp)
    local name="" ip=""
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name:\ (.+)$ ]]; then
            name="${BASH_REMATCH[1]}"
            echo "$line" >> "$temp"
        elif [[ "$line" =~ ^IP\ Address:\ (.+)$ ]]; then
            ip="${BASH_REMATCH[1]}"
            echo "$line" >> "$temp"
            
            # Process this node if we have both name and IP
            if [[ -n "$name" && -n "$ip" ]]; then
                ((processed++))
                kill $dialog_pid 2>/dev/null
                dialog --title "Retrieving Roles" --infobox "Processing $name ($processed/$count)..." 6 50 &
                dialog_pid=$!
                
                # Get data from APIs
                local roles=$(curl -s --connect-timeout 5 --max-time 10 "http://$ip:8080/api/v1/roles" 2>/dev/null)
                local gateway=$(curl -s --connect-timeout 5 --max-time 10 "http://$ip:8080/api/v1/gateway" 2>/dev/null)
                local build_info=$(curl -s --connect-timeout 5 --max-time 10 "http://$ip:8080/api/v1/build-information" 2>/dev/null)
                
                # Add fresh role information
                if [[ -n "$roles" ]]; then
                    echo "Mixnode Enabled: $(echo "$roles" | grep -o '"mixnode_enabled"[[:space:]]*:[[:space:]]*[^,}]*' | cut -d':' -f2 | tr -d ' ",' || echo "unknown")" >> "$temp"
                    echo "Gateway Enabled: $(echo "$roles" | grep -o '"gateway_enabled"[[:space:]]*:[[:space:]]*[^,}]*' | cut -d':' -f2 | tr -d ' ",' || echo "unknown")" >> "$temp"
                    echo "Network Requester Enabled: $(echo "$roles" | grep -o '"network_requester_enabled"[[:space:]]*:[[:space:]]*[^,}]*' | cut -d':' -f2 | tr -d ' ",' || echo "unknown")" >> "$temp"
                    echo "IP Packet Router Enabled: $(echo "$roles" | grep -o '"ip_packet_router_enabled"[[:space:]]*:[[:space:]]*[^,}]*' | cut -d':' -f2 | tr -d ' ",' || echo "unknown")" >> "$temp"
                else
                    echo -e "Mixnode Enabled: error\nGateway Enabled: error\nNetwork Requester Enabled: error\nIP Packet Router Enabled: error" >> "$temp"
                fi
                
                # Parse Wireguard status
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
                
                # Parse build version
                if [[ -n "$build_info" ]]; then
                    local version=$(echo "$build_info" | grep -o '"build_version"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d':' -f2 | tr -d ' "' || echo "unknown")
                    echo "Build Version: $version" >> "$temp"
                else
                    echo "Build Version: error" >> "$temp"
                fi
                
                # Reset for next node
                name=""; ip=""
            fi
        else
            # Copy blank lines
            echo "$line" >> "$temp"
        fi
    done < "$clean_file"
    
    # Cleanup
    kill $dialog_pid 2>/dev/null
    rm -f "$clean_file"
    mv "$temp" "$NODES_FILE"
    sort_nodes_file
    show_success "Node roles retrieved for $processed nodes!"
}

# Multi-node selection helper
select_multiple_nodes() {
    [[ ! -f "$NODES_FILE" || ! -s "$NODES_FILE" ]] && { show_error "No nodes found. Add nodes first."; return 1; }
    
    local options=() names=() ips=() counter=1 name="" ip=""
    
    # Parse nodes from file
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name:\ (.+)$ ]]; then
            name="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^IP\ Address:\ (.+)$ ]]; then
            ip="${BASH_REMATCH[1]}"
            if [[ -n "$name" && -n "$ip" ]]; then
                names+=("$name"); ips+=("$ip")
                options+=("$counter" "$name ($ip)" "OFF")
                ((counter++)); name=""; ip=""
            fi
        fi
    done < "$NODES_FILE"
    
    [[ ${#names[@]} -eq 0 ]] && { show_error "No valid nodes found."; return 1; }
    
    # Add "Select All" option at the beginning
    local all_options=("ALL" "Select All Nodes" "OFF" "${options[@]}")
    
    # Show checklist for multiple selection
    local choices=$(dialog --title "Select Nodes to Update" --checklist \
        "Choose nodes to update (Space to select, Enter to confirm):" \
        $((${#names[@]} + 10)) 70 $((${#names[@]} + 1)) "${all_options[@]}" 3>&1 1>&2 2>&3)
    
    [[ $? -ne 0 ]] && return 1
    
    # Parse selections
    SELECTED_NODES_NAMES=()
    SELECTED_NODES_IPS=()
    
    # Process choices
    for choice in $choices; do
        choice=$(echo "$choice" | tr -d '"')  # Remove quotes
        if [[ "$choice" == "ALL" ]]; then
            # Select all nodes
            SELECTED_NODES_NAMES=("${names[@]}")
            SELECTED_NODES_IPS=("${ips[@]}")
            break
        else
            # Individual selection
            local idx=$((choice - 1))
            SELECTED_NODES_NAMES+=("${names[$idx]}")
            SELECTED_NODES_IPS+=("${ips[$idx]}")
        fi
    done
    
    [[ ${#SELECTED_NODES_NAMES[@]} -eq 0 ]] && { show_error "No nodes selected."; return 1; }
    return 0
}

# 5) Update nym-node
update_nym_node() {
    log "FUNCTION" "update_nym_node"
    
    # Step 1: Get download URL from user
    local download_url
    download_url=$(get_input "Nym-Node Update" "Enter download URL for latest nym-node binary:\n\nExample:\nhttps://github.com/nymtech/nym/releases/download/nym-binaries-v2025.13-emmental/nym-node")
    [[ -z "$download_url" ]] && { show_msg "Cancelled" "Update cancelled."; return; }
    
    # Step 2: Select nodes to update
    if ! select_multiple_nodes; then
        show_msg "Cancelled" "Node selection cancelled."
        return
    fi
    
    # Step 3: Get SSH credentials
    local ssh_user
    ssh_user=$(get_input "SSH Connection" "Enter SSH username (same for all selected nodes):")
    [[ -z "$ssh_user" ]] && { show_msg "Cancelled" "Update cancelled."; return; }
    
    local ssh_pass
    ssh_pass=$(get_password "SSH Connection" "Enter SSH password for $ssh_user:")
    [[ -z "$ssh_pass" ]] && { show_msg "Cancelled" "Update cancelled."; return; }
    
    # Step 4: Confirm update
    local node_list=""
    for ((i=0; i<${#SELECTED_NODES_NAMES[@]}; i++)); do
        node_list+="\n• ${SELECTED_NODES_NAMES[i]} (${SELECTED_NODES_IPS[i]})"
    done
    
    confirm "Update nym-node on the following ${#SELECTED_NODES_NAMES[@]} node(s)?$node_list\n\nDownload URL:\n$download_url" || return
    
    # Step 5: Process each node
    local results=""
    local successful_updates=()
    local failed_updates=()
    local total=${#SELECTED_NODES_NAMES[@]}
    local current=0
    
    for ((i=0; i<${#SELECTED_NODES_NAMES[@]}; i++)); do
        local node_name="${SELECTED_NODES_NAMES[i]}"
        local node_ip="${SELECTED_NODES_IPS[i]}"
        ((current++))
        
        dialog --title "Updating Nym-Node" --infobox "Processing $node_name ($current/$total)...\nTesting SSH connection..." 6 60
        
        # Test SSH connection
        if ! ssh_exec "$node_ip" "$ssh_user" "$ssh_pass" "echo 'OK'" "Connection Test" >/dev/null 2>&1; then
            failed_updates+=("$node_name: SSH connection failed")
            continue
        fi
        
        dialog --title "Updating Nym-Node" --infobox "Processing $node_name ($current/$total)...\nNavigating to /root/nym..." 6 60
        
        # Create /root/nym directory if it doesn't exist and navigate there
        if ! ssh_root "$node_ip" "$ssh_user" "$ssh_pass" "mkdir -p /root/nym && cd /root/nym && pwd" "Create Directory" >/dev/null 2>&1; then
            failed_updates+=("$node_name: Could not access /root/nym directory")
            continue
        fi
        
        dialog --title "Updating Nym-Node" --infobox "Processing $node_name ($current/$total)...\nBacking up current binary..." 6 60
        
        # Create old directory and backup current binary
        if ! ssh_root "$node_ip" "$ssh_user" "$ssh_pass" "cd /root/nym && mkdir -p old && if [ -f nym-node ]; then mv nym-node old/nym-node.backup.\$(date +%Y%m%d_%H%M%S) || true; fi" "Backup Binary" >/dev/null 2>&1; then
            failed_updates+=("$node_name: Could not backup current binary")
            continue
        fi
        
        dialog --title "Updating Nym-Node" --infobox "Processing $node_name ($current/$total)...\nDownloading new binary..." 6 60
        
        # Download new binary
        if ! ssh_root "$node_ip" "$ssh_user" "$ssh_pass" "cd /root/nym && curl -L -o nym-node '$download_url' && ls -la nym-node" "Download Binary" >/dev/null 2>&1; then
            failed_updates+=("$node_name: Could not download new binary")
            continue
        fi
        
        dialog --title "Updating Nym-Node" --infobox "Processing $node_name ($current/$total)...\nMaking binary executable..." 6 60
        
        # Make binary executable
        if ! ssh_root "$node_ip" "$ssh_user" "$ssh_pass" "cd /root/nym && chmod +x nym-node" "Make Executable" >/dev/null 2>&1; then
            failed_updates+=("$node_name: Could not make binary executable")
            continue
        fi
        
        dialog --title "Updating Nym-Node" --infobox "Processing $node_name ($current/$total)...\nChecking version..." 6 60
        
        # Get version information
        local version_output
        version_output=$(ssh_root "$node_ip" "$ssh_user" "$ssh_pass" "cd /root/nym && ./nym-node --version" "Check Version" 2>/dev/null)
        
        if [[ $? -ne 0 || -z "$version_output" ]]; then
            failed_updates+=("$node_name: Could not check version of new binary")
            continue
        fi
        
        # Extract version from output
        local version=""
        if [[ "$version_output" =~ Build\ Version:[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+) ]]; then
            version="${BASH_REMATCH[1]}"
        else
            # Fallback: try to extract any version pattern
            version=$(echo "$version_output" | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1)
        fi
        
        if [[ -z "$version" ]]; then
            version="unknown (binary appears functional)"
        fi
        
        successful_updates+=("$node_name: Updated to version $version")
        log "UPDATE" "Successfully updated $node_name to version $version"
    done
    
    # Step 6: Display results
    results="🔄 Nym-Node Update Results\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
    
    if [[ ${#successful_updates[@]} -gt 0 ]]; then
        results+="✅ Successfully Updated (${#successful_updates[@]} nodes):\n"
        for update in "${successful_updates[@]}"; do
            results+="   • $update\n"
        done
        results+="\n"
    fi
    
    if [[ ${#failed_updates[@]} -gt 0 ]]; then
        results+="❌ Failed Updates (${#failed_updates[@]} nodes):\n"
        for failure in "${failed_updates[@]}"; do
            results+="   • $failure\n"
        done
        results+="\n"
    fi
    
    results+="⚠️  IMPORTANT: Restart nym-node service on successfully updated nodes\n"
    results+="   Use menu option 7 to restart services\n\n"
    results+="📁 Old binaries backed up to /root/nym/old/ for rollback"
    
    show_success "$results"
}

# Get current node settings from service file
get_current_settings() {
    local ip="$1" user="$2" pass="$3"
    local service=$(ssh_root "$ip" "$user" "$pass" "cat /etc/systemd/system/nym-node.service" "Read Service" 2>/dev/null)
    
    # Default values
    CURRENT_WIREGUARD="disabled"
    CURRENT_MODE="mixnode"
    
    if [[ -n "$service" ]]; then
        # Check Wireguard status
        if echo "$service" | grep -q -- "--wireguard-enabled true"; then
            CURRENT_WIREGUARD="enabled"
        fi
        
        # Check mode
        if echo "$service" | grep -q -- "--mode entry-gateway"; then
            CURRENT_MODE="entry-gateway"
        elif echo "$service" | grep -q -- "--mode exit-gateway"; then
            CURRENT_MODE="exit-gateway"
        elif echo "$service" | grep -q -- "--mode mixnode"; then
            CURRENT_MODE="mixnode"
        fi
    fi
}

# 6) Toggle node functionality (Combined Mixnet & Wireguard)
toggle_node_functionality() {
    log "FUNCTION" "toggle_node_functionality"
    select_node || return
    
    local user=$(get_input "SSH Connection" "SSH username for $SELECTED_NODE_NAME:")
    [[ -z "$user" ]] && return
    local pass=$(get_password "SSH Connection" "SSH password for $user@$SELECTED_NODE_IP:")
    [[ -z "$pass" ]] && return
    
    # Test connection first
    ssh_exec "$SELECTED_NODE_IP" "$user" "$pass" "echo 'OK'" "Connection Test" >/dev/null || return
    
    # Get current settings
    dialog --title "Node Configuration" --infobox "Reading current configuration..." 5 50
    get_current_settings "$SELECTED_NODE_IP" "$user" "$pass"
    
    # Create radiolist options for Wireguard
    local wg_options=()
    if [[ "$CURRENT_WIREGUARD" == "enabled" ]]; then
        wg_options+=("enabled" "Enable Wireguard" "ON" "disabled" "Disable Wireguard" "OFF")
    else
        wg_options+=("enabled" "Enable Wireguard" "OFF" "disabled" "Disable Wireguard" "ON")
    fi
    
    # Get Wireguard choice
    local wg_choice=$(dialog --title "Wireguard Configuration" --radiolist \
        "Current Wireguard status: $CURRENT_WIREGUARD\nSelect desired setting:" 12 60 2 \
        "${wg_options[@]}" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && return
    
    # Create radiolist options for Mixnet mode
    local mode_options=()
    local modes=("entry-gateway" "Entry Gateway" "exit-gateway" "Exit Gateway" "mixnode" "Mixnode")
    for ((i=0; i<${#modes[@]}; i+=2)); do
        local mode="${modes[i]}" desc="${modes[i+1]}"
        if [[ "$CURRENT_MODE" == "$mode" ]]; then
            mode_options+=("$mode" "$desc" "ON")
        else
            mode_options+=("$mode" "$desc" "OFF")
        fi
    done
    
    # Get Mode choice
    local mode_choice=$(dialog --title "Mixnet Mode Configuration" --radiolist \
        "Current mode: $CURRENT_MODE\nSelect desired mode:" 14 60 3 \
        "${mode_options[@]}" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && return
    
    # Show confirmation
    local changes=""
    [[ "$wg_choice" != "$CURRENT_WIREGUARD" ]] && changes+="• Wireguard: $CURRENT_WIREGUARD → $wg_choice\n"
    [[ "$mode_choice" != "$CURRENT_MODE" ]] && changes+="• Mixnet Mode: $CURRENT_MODE → $mode_choice\n"
    
    if [[ -z "$changes" ]]; then
        show_msg "No Changes" "No configuration changes were made."
        return
    fi
    
    confirm "Apply the following changes to $SELECTED_NODE_NAME?\n\n$changes" || return
    
    # Apply changes
    dialog --title "Applying Changes" --infobox "Updating node configuration..." 5 50
    
    # Build sed commands for updates
    local sed_commands=""
    
    # Update Wireguard setting
    if [[ "$wg_choice" != "$CURRENT_WIREGUARD" ]]; then
        local wg_flag=$([ "$wg_choice" = "enabled" ] && echo "true" || echo "false")
        sed_commands+="sed -i 's/--wireguard-enabled [^ ]*/--wireguard-enabled $wg_flag/g; t wireguard_updated; s/\\(ExecStart=[^ ]* run\\)/\\1 --wireguard-enabled $wg_flag/; :wireguard_updated' /etc/systemd/system/nym-node.service && "
    fi
    
    # Update Mode setting
    if [[ "$mode_choice" != "$CURRENT_MODE" ]]; then
        sed_commands+="sed -i 's/--mode [^ ]*/--mode $mode_choice/g; t mode_updated; s/\\(ExecStart=[^ ]* run\\)/\\1 --mode $mode_choice/; :mode_updated' /etc/systemd/system/nym-node.service && "
    fi
    
    # Create backup and apply changes
    local update_cmd="cp /etc/systemd/system/nym-node.service /etc/systemd/system/nym-node.service.backup.\$(date +%Y%m%d_%H%M%S) && ${sed_commands}systemctl daemon-reload"
    
    if ssh_root "$SELECTED_NODE_IP" "$user" "$pass" "$update_cmd" "Update Configuration"; then
        show_success "Configuration updated successfully on $SELECTED_NODE_NAME!\n\n$changes\nRestart the service to apply changes."
    fi
}

# 7) Restart service
restart_service() {
    log "FUNCTION" "restart_service"
    select_node || return
    
    local user=$(get_input "SSH Connection" "SSH username for $SELECTED_NODE_NAME:")
    [[ -z "$user" ]] && return
    local pass=$(get_password "SSH Connection" "SSH password for $user@$SELECTED_NODE_IP:")
    [[ -z "$pass" ]] && return
    
    confirm "Restart nym-node service on $SELECTED_NODE_NAME?" || return
    
    dialog --title "Restarting" --infobox "Restarting service..." 5 50
    
    if ssh_exec "$SELECTED_NODE_IP" "$user" "$pass" "echo '$pass' | sudo -S systemctl restart nym-node.service" "Restart Service"; then
        sleep 2
        local status=$(ssh_exec "$SELECTED_NODE_IP" "$user" "$pass" "sudo systemctl is-active nym-node.service" "Check Status")
        show_success "Service restarted! Status: $status"
    fi
}

# 8) Test SSH
test_ssh() {
    log "FUNCTION" "test_ssh"
    select_node || return
    
    local user=$(get_input "SSH Test" "SSH username for $SELECTED_NODE_NAME:")
    [[ -z "$user" ]] && return
    local pass=$(get_password "SSH Test" "SSH password for $user@$SELECTED_NODE_IP:")
    [[ -z "$pass" ]] && return
    
    local results="🔧 SSH Test Results for $SELECTED_NODE_NAME ($SELECTED_NODE_IP)\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
    local tests=(
        "Basic Connection:echo 'OK'"
        "Working Directory:pwd"
        "User Identity:whoami"
        "Sudo Access:echo '$pass' | sudo -S whoami"
        "Root Switch:echo '$pass' | sudo -S su -c 'whoami'"
        "Service File:echo '$pass' | sudo -S test -f /etc/systemd/system/nym-node.service && echo 'EXISTS'"
        "Systemctl:echo '$pass' | sudo -S systemctl is-active nym-node.service"
    )
    
    local step=1
    for test in "${tests[@]}"; do
        local desc="${test%%:*}" cmd="${test#*:}"
        dialog --title "SSH Test" --infobox "Step $step/7: Testing $desc..." 5 50
        
        if output=$(ssh_exec "$SELECTED_NODE_IP" "$user" "$pass" "$cmd" "$desc" 2>/dev/null); then
            results+="✅ Step $step: $desc - SUCCESS\n   Result: $output\n"
        else
            results+="❌ Step $step: $desc - FAILED\n"
        fi
        ((step++))
    done
    
    results+="\n🎯 SSH Test Complete!"
    show_success "$results"
}

# 9) Show debug log
show_debug() {
    [[ -f "$DEBUG_LOG" ]] && dialog --title "Debug Log" --msgbox "$(tail -50 "$DEBUG_LOG")" 25 100 ||
        show_msg "No Log" "Debug log not found."
}

# Main menu
main_menu() {
    while true; do
        local choice=$(dialog --clear --title "$SCRIPT_NAME v$VERSION" \
            --menu "Select an option:" 18 70 10 \
            1 "List all nodes" 2 "Add node" 3 "Delete node" 4 "Retrieve node roles" \
            5 "Update nym-node" 6 "Toggle node functionality (Mixnet & Wireguard)" \
            7 "Restart service" 8 "Test SSH" 9 "Show debug log" 0 "Exit" \
            3>&1 1>&2 2>&3)
        
        [[ $? -ne 0 ]] && break
        
        case $choice in
            1) list_nodes ;; 2) add_node ;; 3) delete_node ;; 4) retrieve_node_roles ;;
            5) update_nym_node ;; 6) toggle_node_functionality ;; 7) restart_service ;;
            8) test_ssh ;; 9) show_debug ;;
            0) confirm "Exit?" && break ;;
            *) show_error "Invalid option." ;;
        esac
    done
}

# Main execution
main() {
    init_debug; log "MAIN" "Application starting"
    trap 'clear; echo -e "${GREEN}Thank you for using $SCRIPT_NAME!${NC}"; exit 0' EXIT INT TERM
    check_deps; main_menu
}

main "$@"
