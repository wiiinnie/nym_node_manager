#!/bin/bash

# Nym Node Manager v46 - Optimized Version with Configuration Management
# Requires: dialog, sshpass, curl

# Colors and config
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
SCRIPT_NAME="Nym Node Manager"
VERSION="46"
DEBUG_LOG="debug.log"
NODES_FILE="$(dirname "${BASH_SOURCE[0]}")/nodes.txt"
CONFIG_FILE="$(dirname "${BASH_SOURCE[0]}")/config.txt"

# Default configuration values
DEFAULT_SSH_PORT="22"
DEFAULT_SERVICE_NAME="nym-node.service"
DEFAULT_BINARY_PATH="/root/nym"

# Global configuration variables
SSH_PORT=""
SERVICE_NAME=""
BINARY_PATH=""

# Initialize debug logging
init_debug() {
    echo "=== Nym Node Manager Started - $(date) - User: $(whoami) ===" > "$DEBUG_LOG"
}

# Unified logging function
log() {
    local level="$1"; shift
    echo "[$(date '+%H:%M:%S')] [$level] $*" >> "$DEBUG_LOG"
}

# Load configuration from file
load_config() {
    # Set defaults
    SSH_PORT="$DEFAULT_SSH_PORT"
    SERVICE_NAME="$DEFAULT_SERVICE_NAME"
    BINARY_PATH="$DEFAULT_BINARY_PATH"
    
    # Load from config file if it exists
    if [[ -f "$CONFIG_FILE" ]]; then
        while IFS='=' read -r key value; do
            # Skip empty lines and comments
            [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
            
            case "$key" in
                "SSH_PORT") SSH_PORT="$value" ;;
                "SERVICE_NAME") SERVICE_NAME="$value" ;;
                "BINARY_PATH") BINARY_PATH="$value" ;;
            esac
        done < "$CONFIG_FILE"
    fi
    
    log "CONFIG" "Loaded config - SSH_PORT: $SSH_PORT, SERVICE_NAME: $SERVICE_NAME, BINARY_PATH: $BINARY_PATH"
}

# Save configuration to file
save_config() {
    cat > "$CONFIG_FILE" << EOF
# Nym Node Manager Configuration File
# Generated on $(date)

# SSH Port (default: 22)
SSH_PORT=$SSH_PORT

# Systemd Service Name (default: nym-node.service)
SERVICE_NAME=$SERVICE_NAME

# Binary Path (default: /root/nym)
BINARY_PATH=$BINARY_PATH
EOF
    log "CONFIG" "Configuration saved to $CONFIG_FILE"
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
    local new_name="$1" new_ip="$2" new_node_id="$3"
    local temp=$(mktemp)
    local inserted=false
    local current_node="" in_node=false
    
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
            echo "$line" >> "$temp"
            in_node=true
        else
            echo "$line" >> "$temp"
        fi
    done < "$NODES_FILE"
    
    # If not inserted yet, add at end
    if [[ "$inserted" == "false" ]]; then
        [[ -s "$temp" ]] && echo >> "$temp"
        echo -e "Node Name: $new_name\nIP Address: $new_ip\nNode ID: $new_node_id" >> "$temp"
    fi
    
    mv "$temp" "$NODES_FILE"
}

# SSH execution with error handling (using configured port)
ssh_exec() {
    local ip="$1" user="$2" pass="$3" cmd="$4" desc="${5:-SSH Command}"
    log "SSH" "$desc: $user@$ip:$SSH_PORT - $cmd"
    
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

# Root SSH execution (using configured service name and binary path)
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
                content+="🖥️ NODE: ${line#Node Name: }\n────────────────────────────────────────\n"
                current_node="yes" ;;
            "IP Address: "*) content+="🌐 IP: ${line#IP Address: }\n" ;;
            "Node ID: "*) content+="🆔 ID: ${line#Node ID: }\n" ;;
            "Build Version: "*) content+="📦 Version: ${line#Build Version: }\n" ;;
            "Mixnode Enabled: true") content+="🔀 Mixnode: \Z2✅ Enabled\Zn\n" ;;
            "Mixnode Enabled: false") content+="🔀 Mixnode: \Z1❌ Disabled\Zn\n" ;;
            "Gateway Enabled: true") content+="🚪 Gateway: \Z2✅ Enabled\Zn\n" ;;
            "Gateway Enabled: false") content+="🚪 Gateway: \Z1❌ Disabled\Zn\n" ;;
            "Network Requester Enabled: true") content+="🌍 Network Requester: \Z2✅ Enabled\Zn\n" ;;
            "Network Requester Enabled: false") content+="🌍 Network Requester: \Z1❌ Disabled\Zn\n" ;;
            "IP Packet Router Enabled: true") content+="📦 IP Packet Router: \Z2✅ Enabled\Zn\n" ;;
            "IP Packet Router Enabled: false") content+="📦 IP Packet Router: \Z1❌ Disabled\Zn\n" ;;
            "Wireguard Status: enabled"*) content+="🔒 WireGuard: \Z2✅ ${line#Wireguard Status: }\Zn\n" ;;
            "Wireguard Status: disabled") content+="🔒 WireGuard: \Z1❌ Disabled\Zn\n" ;;
        esac
    done < "$NODES_FILE"
    
    [[ -n "$content" ]] && dialog --title "Nym Network Nodes (Alphabetically Sorted)" --colors --msgbox "$content" 25 85 ||
        show_msg "No Data" "No readable node data found."
}

# 2) Add node (insert in sorted order) - Now includes Node ID
add_node() {
    log "FUNCTION" "add_node"
    local name=$(get_input "Add New Node" "Enter Node Name:")
    [[ -z "$name" ]] && { show_msg "Cancelled" "Node creation cancelled."; return; }
    
    local ip=$(get_input "Add New Node" "Enter IP Address for '$name':")
    [[ -z "$ip" ]] && { show_msg "Cancelled" "Node creation cancelled."; return; }
    
    local node_id=$(get_input "Add New Node" "Enter Node ID for '$name':\n(The ID you used during node initialization)")
    [[ -z "$node_id" ]] && { show_msg "Cancelled" "Node creation cancelled."; return; }
    
    insert_node_sorted "$name" "$ip" "$node_id"
    show_success "Node '$name' with IP '$ip' and ID '$node_id' added successfully!"
}

# 3) Edit node
edit_node() {
    log "FUNCTION" "edit_node"
    [[ ! -f "$NODES_FILE" || ! -s "$NODES_FILE" ]] && { show_error "No nodes found. Add nodes first."; return 1; }
    
    local options=() names=() ips=() node_ids=() counter=1 name="" ip="" node_id=""
    
    # Parse nodes from file
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name:\ (.+)$ ]]; then
            name="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^IP\ Address:\ (.+)$ ]]; then
            ip="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^Node\ ID:\ (.+)$ ]]; then
            node_id="${BASH_REMATCH[1]}"
            if [[ -n "$name" && -n "$ip" && -n "$node_id" ]]; then
                names+=("$name"); ips+=("$ip"); node_ids+=("$node_id")
                options+=("$counter" "$name ($ip)")
                ((counter++)); name=""; ip=""; node_id=""
            fi
        fi
    done < "$NODES_FILE"
    
    [[ ${#names[@]} -eq 0 ]] && { show_error "No valid nodes found."; return 1; }
    
    local choice=$(dialog --title "Edit Node" --menu "Choose node to edit:" 15 60 10 "${options[@]}" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && return 1
    
    local idx=$((choice - 1))
    local old_name="${names[$idx]}"
    local old_ip="${ips[$idx]}"
    local old_node_id="${node_ids[$idx]}"
    
    # Get new values
    local new_name=$(dialog --title "Edit Node Name" --inputbox "Enter new Node Name:" 8 50 "$old_name" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z "$new_name" ]] && { show_msg "Cancelled" "Edit cancelled."; return; }
    
    local new_ip=$(dialog --title "Edit IP Address" --inputbox "Enter new IP Address:" 8 50 "$old_ip" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z "$new_ip" ]] && { show_msg "Cancelled" "Edit cancelled."; return; }
    
    local new_node_id=$(dialog --title "Edit Node ID" --inputbox "Enter new Node ID:" 8 50 "$old_node_id" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z "$new_node_id" ]] && { show_msg "Cancelled" "Edit cancelled."; return; }
    
    # Remove old node entry and add updated one
    local temp=$(mktemp)
    local in_target=false
    local current_node_name=""
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name:\ (.+)$ ]]; then
            current_node_name="${BASH_REMATCH[1]}"
            if [[ "$current_node_name" == "$old_name" ]]; then
                in_target=true
                continue
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
    
    # Insert updated node in correct position
    insert_node_sorted "$new_name" "$new_ip" "$new_node_id"
    
    show_success "Node updated successfully!\n\nOld: $old_name ($old_ip) - $old_node_id\nNew: $new_name ($new_ip) - $new_node_id"
}

# 4) Delete nodes (Multi-selection with "Select All")
delete_node() {
    log "FUNCTION" "delete_node"
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
    local choices=$(dialog --title "Select Nodes to Delete" --checklist \
        "Choose nodes to DELETE (Space to select, Enter to confirm):" \
        $((${#names[@]} + 10)) 70 $((${#names[@]} + 1)) "${all_options[@]}" 3>&1 1>&2 2>&3)
    
    [[ $? -ne 0 ]] && return 1
    
    # Parse selections
    local selected_names=()
    local selected_ips=()
    
    # Process choices
    for choice in $choices; do
        choice=$(echo "$choice" | tr -d '"')  # Remove quotes
        if [[ "$choice" == "ALL" ]]; then
            # Select all nodes
            selected_names=("${names[@]}")
            selected_ips=("${ips[@]}")
            break
        else
            # Individual selection
            local idx=$((choice - 1))
            selected_names+=("${names[$idx]}")
            selected_ips+=("${ips[$idx]}")
        fi
    done
    
    [[ ${#selected_names[@]} -eq 0 ]] && { show_error "No nodes selected."; return 1; }
    
    # Build confirmation message
    local node_list=""
    for ((i=0; i<${#selected_names[@]}; i++)); do
        node_list+="\n• ${selected_names[i]} (${selected_ips[i]})"
    done
    
    confirm "Delete the following ${#selected_names[@]} node(s)?$node_list\n\nThis cannot be undone." || return
    
    # Create temporary file to rebuild nodes file
    local temp=$(mktemp)
    local in_target=false
    local current_node_name=""
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name:\ (.+)$ ]]; then
            current_node_name="${BASH_REMATCH[1]}"
            # Check if this node should be deleted
            local should_delete=false
            for selected_name in "${selected_names[@]}"; do
                if [[ "$current_node_name" == "$selected_name" ]]; then
                    should_delete=true
                    break
                fi
            done
            
            if [[ "$should_delete" == "true" ]]; then
                in_target=true
                continue
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
    show_success "${#selected_names[@]} node(s) deleted successfully!"
}

# 5) Retrieve node roles
retrieve_node_roles() {
    log "FUNCTION" "retrieve_node_roles"
    [[ ! -f "$NODES_FILE" || ! -s "$NODES_FILE" ]] && { show_error "No nodes found."; return; }
    
    # First, create a clean file with only Node Name, IP Address and Node ID lines
    local clean_file=$(mktemp)
    while IFS= read -r line; do
        if [[ "$line" =~ ^(Node\ Name:|IP\ Address:|Node\ ID:) ]] || [[ -z "$line" ]]; then
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
    local name="" ip="" node_id=""
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name:\ (.+)$ ]]; then
            name="${BASH_REMATCH[1]}"
            echo "$line" >> "$temp"
        elif [[ "$line" =~ ^IP\ Address:\ (.+)$ ]]; then
            ip="${BASH_REMATCH[1]}"
            echo "$line" >> "$temp"
        elif [[ "$line" =~ ^Node\ ID:\ (.+)$ ]]; then
            node_id="${BASH_REMATCH[1]}"
            echo "$line" >> "$temp"
            
            # Process this node if we have all info
            if [[ -n "$name" && -n "$ip" && -n "$node_id" ]]; then
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
                name=""; ip=""; node_id=""
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
    
    local options=() names=() ips=() node_ids=() counter=1 name="" ip="" node_id=""
    
    # Parse nodes from file
    while IFS= read -r line; do
        if [[ "$line" =~ ^Node\ Name:\ (.+)$ ]]; then
            name="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^IP\ Address:\ (.+)$ ]]; then
            ip="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^Node\ ID:\ (.+)$ ]]; then
            node_id="${BASH_REMATCH[1]}"
            if [[ -n "$name" && -n "$ip" && -n "$node_id" ]]; then
                names+=("$name"); ips+=("$ip"); node_ids+=("$node_id")
                options+=("$counter" "$name ($ip)" "OFF")
                ((counter++)); name=""; ip=""; node_id=""
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
    SELECTED_NODES_IDS=()
    
    # Process choices
    for choice in $choices; do
        choice=$(echo "$choice" | tr -d '"')  # Remove quotes
        if [[ "$choice" == "ALL" ]]; then
            # Select all nodes
            SELECTED_NODES_NAMES=("${names[@]}")
            SELECTED_NODES_IPS=("${ips[@]}")
            SELECTED_NODES_IDS=("${node_ids[@]}")
            break
        else
            # Individual selection
            local idx=$((choice - 1))
            SELECTED_NODES_NAMES+=("${names[$idx]}")
            SELECTED_NODES_IPS+=("${ips[$idx]}")
            SELECTED_NODES_IDS+=("${node_ids[$idx]}")
        fi
    done
    
    [[ ${#SELECTED_NODES_NAMES[@]} -eq 0 ]] && { show_error "No nodes selected."; return 1; }
    return 0
}

# 6) Update nym-node
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
        
        dialog --title "Updating Nym-Node" --infobox "Processing $node_name ($current/$total)...\nNavigating to $BINARY_PATH..." 6 60
        
        # Create binary directory if it doesn't exist and navigate there
        if ! ssh_root "$node_ip" "$ssh_user" "$ssh_pass" "mkdir -p $BINARY_PATH && cd $BINARY_PATH && pwd" "Create Directory" >/dev/null 2>&1; then
            failed_updates+=("$node_name: Could not access $BINARY_PATH directory")
            continue
        fi
        
        dialog --title "Updating Nym-Node" --infobox "Processing $node_name ($current/$total)...\nBacking up current binary..." 6 60
        
        # Create old directory and backup current binary
        if ! ssh_root "$node_ip" "$ssh_user" "$ssh_pass" "cd $BINARY_PATH && mkdir -p old && if [ -f nym-node ]; then mv nym-node old/nym-node.backup.\$(date +%Y%m%d_%H%M%S) || true; fi" "Backup Binary" >/dev/null 2>&1; then
            failed_updates+=("$node_name: Could not backup current binary")
            continue
        fi
        
        dialog --title "Updating Nym-Node" --infobox "Processing $node_name ($current/$total)...\nDownloading new binary..." 6 60
        
        # Download new binary
        if ! ssh_root "$node_ip" "$ssh_user" "$ssh_pass" "cd $BINARY_PATH && curl -L -o nym-node '$download_url' && ls -la nym-node" "Download Binary" >/dev/null 2>&1; then
            failed_updates+=("$node_name: Could not download new binary")
            continue
        fi
        
        dialog --title "Updating Nym-Node" --infobox "Processing $node_name ($current/$total)...\nMaking binary executable..." 6 60
        
        # Make binary executable
        if ! ssh_root "$node_ip" "$ssh_user" "$ssh_pass" "cd $BINARY_PATH && chmod +x nym-node" "Make Executable" >/dev/null 2>&1; then
            failed_updates+=("$node_name: Could not make binary executable")
            continue
        fi
        
        dialog --title "Updating Nym-Node" --infobox "Processing $node_name ($current/$total)...\nChecking version..." 6 60
        
        # Get version information
        local version_output
        version_output=$(ssh_root "$node_ip" "$ssh_user" "$ssh_pass" "cd $BINARY_PATH && ./nym-node --version" "Check Version" 2>/dev/null)
        
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
    results="📄 Nym-Node Update Results\n────────────────────────────────────────────────────\n\n"
    
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
    
    results+="⚠️  IMPORTANT: Restart $SERVICE_NAME on successfully updated nodes\n"
    results+="   Use menu option 7 to restart services\n\n"
    results+="📁 Old binaries backed up to $BINARY_PATH/old/ for rollback"
    
    show_success "$results"
}

# Get current node settings from service file
get_current_settings() {
    local ip="$1" user="$2" pass="$3"
    local service=$(ssh_root "$ip" "$user" "$pass" "cat /etc/systemd/system/$SERVICE_NAME" "Read Service" 2>/dev/null)
    
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

# 7) Toggle node functionality (Multi-selection with "Select All") - Enhanced with config.toml support
toggle_node_functionality() {
    log "FUNCTION" "toggle_node_functionality"
    
    # Step 1: Select nodes
    if ! select_multiple_nodes; then
        show_msg "Cancelled" "Node selection cancelled."
        return
    fi
    
    # Step 2: Get SSH credentials (same for all nodes)
    local user=$(get_input "SSH Connection" "SSH username (same for all selected nodes):")
    [[ -z "$user" ]] && return
    local pass=$(get_password "SSH Connection" "SSH password for $user:")
    [[ -z "$pass" ]] && return
    
    # Step 3: Test connection to first node
    dialog --title "Configuration" --infobox "Testing SSH connection..." 5 50
    if ! ssh_exec "${SELECTED_NODES_IPS[0]}" "$user" "$pass" "echo 'OK'" "Connection Test" >/dev/null 2>&1; then
        show_error "SSH connection failed to ${SELECTED_NODES_NAMES[0]}. Please check credentials."
        return
    fi
    
    # Step 4: Get configuration preferences
    # Wireguard setting
    local wg_choice=$(dialog --title "Wireguard Configuration" --radiolist \
        "Select Wireguard setting for all selected nodes:" 12 60 2 \
        "enabled" "Enable Wireguard" "OFF" \
        "disabled" "Disable Wireguard" "ON" \
        3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && return
    
    # Mixnet mode setting
    local mode_choice=$(dialog --title "Mixnet Mode Configuration" --radiolist \
        "Select mode for all selected nodes:" 14 60 3 \
        "entry-gateway" "Entry Gateway" "OFF" \
        "exit-gateway" "Exit Gateway" "OFF" \
        "mixnode" "Mixnode" "ON" \
        3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && return
    
    # Step 5: Show confirmation
    local node_list=""
    for ((i=0; i<${#SELECTED_NODES_NAMES[@]}; i++)); do
        node_list+="\n• ${SELECTED_NODES_NAMES[i]} (${SELECTED_NODES_IPS[i]})"
    done
    
    confirm "Apply the following configuration to ${#SELECTED_NODES_NAMES[@]} node(s)?$node_list\n\n• Wireguard: $wg_choice\n• Mixnet Mode: $mode_choice" || return
    
    # Step 6: Process each node
    local results=""
    local successful_updates=()
    local failed_updates=()
    local total=${#SELECTED_NODES_NAMES[@]}
    local current=0
    
    for ((i=0; i<${#SELECTED_NODES_NAMES[@]}; i++)); do
        local node_name="${SELECTED_NODES_NAMES[i]}"
        local node_ip="${SELECTED_NODES_IPS[i]}"
        local node_id="${SELECTED_NODES_IDS[i]}"
        ((current++))
        
        dialog --title "Configuring Nodes" --infobox "Processing $node_name ($current/$total)...\nUpdating configuration..." 6 60
        
        # Test SSH connection for each node
        if ! ssh_exec "$node_ip" "$user" "$pass" "echo 'OK'" "Connection Test" >/dev/null 2>&1; then
            failed_updates+=("$node_name: SSH connection failed")
            continue
        fi
        
        # Get the User from service file
        local service_user=$(ssh_root "$node_ip" "$user" "$pass" "grep '^User=' /etc/systemd/system/$SERVICE_NAME | cut -d'=' -f2" "Get Service User" 2>/dev/null)
        
        if [[ -z "$service_user" ]]; then
            service_user="root"  # Default to root if not found
        fi
        
        # Build path to config.toml
        local config_path
        if [[ "$service_user" == "root" ]]; then
            config_path="/root/.nym/nym-nodes/$node_id/config/config.toml"
        else
            config_path="/home/$service_user/.nym/nym-nodes/$node_id/config/config.toml"
        fi
        
        # Check if config.toml exists
        local config_exists=$(ssh_root "$node_ip" "$user" "$pass" "test -f $config_path && echo 'exists'" "Check Config" 2>/dev/null)
        
        local service_updated=false
        local config_updated=false
        
        # Try to update service file first (for backward compatibility)
        local wg_flag=$([ "$wg_choice" = "enabled" ] && echo "true" || echo "false")
        local sed_commands=""
        
        # Check if service file has flags
        local has_flags=$(ssh_root "$node_ip" "$user" "$pass" "grep -E '(--wireguard-enabled|--mode)' /etc/systemd/system/$SERVICE_NAME" "Check Flags" 2>/dev/null)
        
        if [[ -n "$has_flags" ]]; then
            # Update service file if it has flags
            sed_commands+="sed -i 's/--wireguard-enabled [^ ]*/--wireguard-enabled $wg_flag/g; t wireguard_updated; s/\\(ExecStart=[^ ]* run\\)/\\1 --wireguard-enabled $wg_flag/; :wireguard_updated' /etc/systemd/system/$SERVICE_NAME && "
            sed_commands+="sed -i 's/--mode [^ ]*/--mode $mode_choice/g; t mode_updated; s/\\(ExecStart=[^ ]* run\\)/\\1 --mode $mode_choice/; :mode_updated' /etc/systemd/system/$SERVICE_NAME && "
            
            local update_cmd="cp /etc/systemd/system/$SERVICE_NAME /etc/systemd/system/$SERVICE_NAME.backup.\$(date +%Y%m%d_%H%M%S) && ${sed_commands}systemctl daemon-reload"
            
            if ssh_root "$node_ip" "$user" "$pass" "$update_cmd" "Update Service File" >/dev/null 2>&1; then
                service_updated=true
            fi
        fi
        
        # Update config.toml if it exists
        if [[ "$config_exists" == "exists" ]]; then
            # Determine mode booleans based on choice
            local mixnode_val="false"
            local entry_val="false"
            local exit_val="false"
            
            case "$mode_choice" in
                "mixnode") mixnode_val="true" ;;
                "entry-gateway") entry_val="true" ;;
                "exit-gateway") exit_val="true" ;;
            esac
            
            local wg_toml_val=$([ "$wg_choice" = "enabled" ] && echo "true" || echo "false")
            
            # Update config.toml
            local config_update_cmd="cp $config_path ${config_path}.backup.\$(date +%Y%m%d_%H%M%S) && "
            config_update_cmd+="sed -i '/^\[modes\]/,/^\[/ { s/^mixnode = .*/mixnode = $mixnode_val/; s/^entry = .*/entry = $entry_val/; s/^exit = .*/exit = $exit_val/; }' $config_path && "
            config_update_cmd+="sed -i '/^\[wireguard\]/,/^\[/ { s/^enabled = .*/enabled = $wg_toml_val/; }' $config_path"
            
            if ssh_root "$node_ip" "$user" "$pass" "$config_update_cmd" "Update Config TOML" >/dev/null 2>&1; then
                config_updated=true
            fi
        fi
        
        # Determine success
        if [[ "$service_updated" == "true" || "$config_updated" == "true" ]]; then
            local update_method=""
            if [[ "$service_updated" == "true" && "$config_updated" == "true" ]]; then
                update_method="service file and config.toml"
            elif [[ "$service_updated" == "true" ]]; then
                update_method="service file"
            else
                update_method="config.toml"
            fi
            successful_updates+=("$node_name: Updated ($update_method)")
            log "CONFIG" "Successfully updated $node_name configuration via $update_method"
        else
            failed_updates+=("$node_name: Failed to update configuration")
        fi
    done
    
    # Step 7: Display results
    results="🔧 Node Configuration Results\n────────────────────────────────────────────────────\n\n"
    
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
    
    results+="Applied Configuration:\n"
    results+="   • Wireguard: $wg_choice\n"
    results+="   • Mixnet Mode: $mode_choice\n\n"
    results+="⚠️  IMPORTANT: Restart services on successfully updated nodes\n"
    results+="   Use menu option 8 to restart services"
    
    show_success "$results"
}

# 8) Restart service (Multi-selection with "Select All")
restart_service() {
    log "FUNCTION" "restart_service"
    
    # Step 1: Select nodes
    if ! select_multiple_nodes; then
        show_msg "Cancelled" "Node selection cancelled."
        return
    fi
    
    # Step 2: Get SSH credentials (same for all nodes)
    local user=$(get_input "SSH Connection" "SSH username (same for all selected nodes):")
    [[ -z "$user" ]] && return
    local pass=$(get_password "SSH Connection" "SSH password for $user:")
    [[ -z "$pass" ]] && return
    
    # Step 3: Show confirmation
    local node_list=""
    for ((i=0; i<${#SELECTED_NODES_NAMES[@]}; i++)); do
        node_list+="\n• ${SELECTED_NODES_NAMES[i]} (${SELECTED_NODES_IPS[i]})"
    done
    
    confirm "Restart $SERVICE_NAME on the following ${#SELECTED_NODES_NAMES[@]} node(s)?$node_list" || return
    
    # Step 4: Process each node
    local results=""
    local successful_restarts=()
    local failed_restarts=()
    local total=${#SELECTED_NODES_NAMES[@]}
    local current=0
    
    for ((i=0; i<${#SELECTED_NODES_NAMES[@]}; i++)); do
        local node_name="${SELECTED_NODES_NAMES[i]}"
        local node_ip="${SELECTED_NODES_IPS[i]}"
        ((current++))
        
        dialog --title "Restarting Services" --infobox "Processing $node_name ($current/$total)...\nRestarting $SERVICE_NAME..." 6 60
        
        # Test SSH connection
        if ! ssh_exec "$node_ip" "$user" "$pass" "echo 'OK'" "Connection Test" >/dev/null 2>&1; then
            failed_restarts+=("$node_name: SSH connection failed")
            continue
        fi
        
        # Restart service
        if ssh_exec "$node_ip" "$user" "$pass" "echo '$pass' | sudo -S systemctl restart $SERVICE_NAME" "Restart Service" >/dev/null 2>&1; then
            # Wait a moment and check status
            sleep 2
            local status=$(ssh_exec "$node_ip" "$user" "$pass" "sudo systemctl is-active $SERVICE_NAME" "Check Status" 2>/dev/null)
            if [[ -n "$status" ]]; then
                successful_restarts+=("$node_name: Service restarted (Status: $status)")
                log "RESTART" "Successfully restarted $node_name service"
            else
                successful_restarts+=("$node_name: Service restarted (Status check failed)")
            fi
        else
            failed_restarts+=("$node_name: Failed to restart service")
        fi
    done
    
    # Step 5: Display results
    results="🔄 Service Restart Results\n────────────────────────────────────────────────────\n\n"
    
    if [[ ${#successful_restarts[@]} -gt 0 ]]; then
        results+="✅ Successfully Restarted (${#successful_restarts[@]} nodes):\n"
        for restart in "${successful_restarts[@]}"; do
            results+="   • $restart\n"
        done
        results+="\n"
    fi
    
    if [[ ${#failed_restarts[@]} -gt 0 ]]; then
        results+="❌ Failed Restarts (${#failed_restarts[@]} nodes):\n"
        for failure in "${failed_restarts[@]}"; do
            results+="   • $failure\n"
        done
        results+="\n"
    fi
    
    results+="🎯 Service Restart Complete!"
    
    show_success "$results"
}

# 9) Configuration menu
config_menu() {
    log "FUNCTION" "config_menu"
    
    while true; do
        local current_config="Current Configuration:\n"
        current_config+="• SSH Port: $SSH_PORT\n"
        current_config+="• Service Name: $SERVICE_NAME\n"
        current_config+="• Binary Path: $BINARY_PATH"
        
        local choice=$(dialog --clear --title "Configuration Menu" \
            --menu "$current_config\n\nSelect configuration option:" 18 70 5 \
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
            *) show_error "Invalid option." ;;
        esac
    done
}

# Configure SSH Port
config_ssh_port() {
    local new_port=$(get_input "SSH Port Configuration" "Enter SSH port (current: $SSH_PORT):")
    [[ -z "$new_port" ]] && return
    
    # Validate port number
    if [[ "$new_port" =~ ^[0-9]+$ ]] && [[ "$new_port" -ge 1 ]] && [[ "$new_port" -le 65535 ]]; then
        SSH_PORT="$new_port"
        save_config
        show_success "SSH port updated to $SSH_PORT"
        log "CONFIG" "SSH port changed to $SSH_PORT"
    else
        show_error "Invalid port number. Please enter a number between 1 and 65535."
    fi
}

# Configure Service Name
config_service_name() {
    local new_service=$(get_input "Service Name Configuration" "Enter systemd service name (current: $SERVICE_NAME):")
    [[ -z "$new_service" ]] && return
    
    # Add .service extension if not present
    if [[ "$new_service" != *.service ]]; then
        new_service="$new_service.service"
    fi
    
    SERVICE_NAME="$new_service"
    save_config
    show_success "Service name updated to $SERVICE_NAME"
    log "CONFIG" "Service name changed to $SERVICE_NAME"
}

# Configure Binary Path
config_binary_path() {
    local new_path=$(get_input "Binary Path Configuration" "Enter binary folder path (current: $BINARY_PATH):")
    [[ -z "$new_path" ]] && return
    
    # Remove trailing slash if present
    new_path=$(echo "$new_path" | sed 's|/$||')
    
    BINARY_PATH="$new_path"
    save_config
    show_success "Binary path updated to $BINARY_PATH"
    log "CONFIG" "Binary path changed to $BINARY_PATH"
}

# Reset to defaults
config_reset_defaults() {
    confirm "Reset all configuration to defaults?\n\nSSH Port: $DEFAULT_SSH_PORT\nService Name: $DEFAULT_SERVICE_NAME\nBinary Path: $DEFAULT_BINARY_PATH" || return
    
    SSH_PORT="$DEFAULT_SSH_PORT"
    SERVICE_NAME="$DEFAULT_SERVICE_NAME"
    BINARY_PATH="$DEFAULT_BINARY_PATH"
    save_config
    show_success "Configuration reset to defaults"
    log "CONFIG" "Configuration reset to defaults"
}

# 10) Test SSH
test_ssh() {
    log "FUNCTION" "test_ssh"
    select_node || return
    
    local user=$(get_input "SSH Test" "SSH username for $SELECTED_NODE_NAME:")
    [[ -z "$user" ]] && return
    local pass=$(get_password "SSH Test" "SSH password for $user@$SELECTED_NODE_IP:")
    [[ -z "$pass" ]] && return
    
    local results="🔧 SSH Test Results for $SELECTED_NODE_NAME ($SELECTED_NODE_IP:$SSH_PORT)\n────────────────────────────────────────────────────\n\n"
    local tests=(
        "Basic Connection:echo 'OK'"
        "Working Directory:pwd"
        "User Identity:whoami"
        "Sudo Access:echo '$pass' | sudo -S whoami"
        "Root Switch:echo '$pass' | sudo -S su -c 'whoami'"
        "Service File:echo '$pass' | sudo -S test -f /etc/systemd/system/$SERVICE_NAME && echo 'EXISTS'"
        "Systemctl:echo '$pass' | sudo -S systemctl is-active $SERVICE_NAME"
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

# 11) Show debug log
show_debug() {
    [[ -f "$DEBUG_LOG" ]] && dialog --title "Debug Log" --msgbox "$(tail -50 "$DEBUG_LOG")" 25 100 ||
        show_msg "No Log" "Debug log not found."
}

# Main menu
main_menu() {
    while true; do
        local choice=$(dialog --clear --title "$SCRIPT_NAME v$VERSION" \
            --menu "Select an option:" 20 70 12 \
            1 "List all nodes" 2 "Add node" 3 "Edit node" 4 "Delete node" \
            5 "Retrieve node roles" 6 "Update nym-node" \
            7 "Toggle node functionality (Mixnet & Wireguard)" \
            8 "Restart service" 9 "Config" 10 "Test SSH" 11 "Show debug log" 0 "Exit" \
            3>&1 1>&2 2>&3)
        
        [[ $? -ne 0 ]] && break
        
        case $choice in
            1) list_nodes ;; 2) add_node ;; 3) edit_node ;; 4) delete_node ;;
            5) retrieve_node_roles ;; 6) update_nym_node ;; 
            7) toggle_node_functionality ;; 8) restart_service ;;
            9) config_menu ;; 10) test_ssh ;; 11) show_debug ;;
            0) confirm "Exit?" && break ;;
            *) show_error "Invalid option." ;;
        esac
    done
}

# Main execution
main() {
    init_debug; log "MAIN" "Application starting"
    load_config  # Load configuration on startup
    trap 'clear; echo -e "${GREEN}Thank you for using $SCRIPT_NAME!${NC}"; exit 0' EXIT INT TERM
    check_deps; main_menu
}

main "$@"
