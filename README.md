# Nym Node Manager

A comprehensive bash script for managing multiple Nym network nodes with an intuitive dialog-based interface. Streamline your Nym node operations with batch processing, persistent configuration, and detailed monitoring capabilities.

## 🚀 Features

### Core Node Management
- **📋 Node Registry**: Add, list, and delete nodes with automatic alphabetical sorting
- **🔍 Role Monitoring**: Retrieve and display node roles, configurations, and status
- **📊 Real-time Status**: Monitor Mixnode, Gateway, Network Requester, and IP Packet Router states
- **🔒 WireGuard Integration**: Track WireGuard status and port configurations

### Batch Operations
- **🔄 Multi-Node Updates**: Update nym-node binaries across multiple nodes simultaneously
- **⚙️ Bulk Configuration**: Apply Wireguard and Mixnet settings to multiple nodes at once
- **🔄 Mass Service Restart**: Restart services across your entire node fleet
- **✅ Select All Option**: Quickly select all nodes for any batch operation

### Configuration Management
- **🔧 Persistent Settings**: Custom SSH ports, service names, and binary paths
- **💾 Config File**: All settings automatically saved to `config.txt`
- **🔄 Easy Reset**: One-click restore to default settings
- **🌐 Custom SSH Ports**: Support for non-standard SSH ports (1-65535)

### Advanced Features
- **🧪 SSH Testing**: Comprehensive 7-step SSH connectivity and configuration validation
- **📝 Debug Logging**: Detailed logging for troubleshooting and audit trails
- **🔒 Secure Operations**: Password-protected SSH with sudo privilege escalation
- **📁 Automatic Backups**: Binary backups before updates with timestamp preservation

## 📋 Prerequisites

### Required Packages
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install dialog sshpass curl

# CentOS/RHEL
sudo yum install dialog sshpass curl
```

### System Requirements
- **OS**: Linux-based system (Ubuntu, Debian, CentOS, RHEL)
- **Network**: SSH access to target Nym nodes
- **Permissions**: Sudo access on target nodes
- **Dependencies**: `dialog`, `sshpass`, `curl`

## 🛠️ Installation

### Quick Setup
```bash
# Download the script
wget https://github.com/yourusername/nym-node-manager/releases/latest/download/nym_node_manager.sh

# Make executable
chmod +x nym_node_manager.sh

# Run the script
./nym_node_manager.sh
```

### Manual Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/nym-node-manager.git
cd nym-node-manager

# Make executable
chmod +x nym_node_manager.sh

# Run
./nym_node_manager.sh
```

## 📖 Usage Guide

### Initial Setup

1. **Launch the script**: `./nym_node_manager.sh`
2. **Configure settings** (optional): Use menu option 8 to customize SSH ports, service names, or binary paths
3. **Add your nodes**: Use menu option 2 to add your Nym nodes
4. **Retrieve node roles**: Use menu option 4 to fetch current configurations

### Menu Overview

```
┌─────────────────────────────────────┐
│         Nym Node Manager v46        │
├─────────────────────────────────────┤
│ 1  List all nodes                   │
│ 2  Add node                         │
│ 3  Delete node                      │
│ 4  Retrieve node roles              │
│ 5  Update nym-node                  │
│ 6  Toggle node functionality        │
│ 7  Restart service                  │
│ 8  Config                           │
│ 9  Test SSH                         │
│ 10 Show debug log                   │
│ 0  Exit                             │
└─────────────────────────────────────┘
```

## 🔧 Detailed Functions

### 1. List All Nodes
**Purpose**: Display comprehensive overview of all registered nodes

**Features**:
- Alphabetically sorted node listing
- Real-time status indicators with color coding
- Role configurations (Mixnode, Gateway, Network Requester, IP Packet Router)
- WireGuard status and port information
- Build version information

**Output Example**:
```
🖥️ NODE: MyNode-01
────────────────────────────────────────
🌐 IP: 192.168.1.100
📦 Version: 2025.13.0
🔀 Mixnode: ✅ Enabled
🚪 Gateway: ❌ Disabled
🌍 Network Requester: ✅ Enabled
📦 IP Packet Router: ❌ Disabled
🔒 WireGuard: ✅ enabled (port: 51820)
```

### 2. Add Node
**Purpose**: Register new Nym nodes in the management system

**Process**:
1. Enter node name (used for identification)
2. Enter IP address
3. Automatic alphabetical insertion in node registry

**Features**:
- Duplicate prevention
- Input validation
- Automatic sorting

### 3. Delete Node
**Purpose**: Remove nodes from management (supports multi-selection)

**Features**:
- **Multi-selection**: Choose multiple nodes for deletion
- **Select All**: Quickly select all nodes
- **Confirmation dialog**: Prevents accidental deletions
- **Permanent removal**: Cannot be undone

**Use Cases**:
- Decommissioning nodes
- Cleaning up test environments
- Bulk node removal

### 4. Retrieve Node Roles
**Purpose**: Fetch current configuration and status from all registered nodes

**Process**:
1. Connects to each node's API (port 8080)
2. Retrieves role information (`/api/v1/roles`)
3. Fetches gateway configuration (`/api/v1/gateway`)
4. Gets build information (`/api/v1/build-information`)
5. Updates local node registry with fresh data

**Retrieved Information**:
- Mixnode status
- Gateway status  
- Network Requester status
- IP Packet Router status
- WireGuard configuration
- Build version

### 5. Update Nym-Node
**Purpose**: Update nym-node binaries across multiple nodes simultaneously

**Features**:
- **Multi-node selection**: Update multiple nodes at once
- **Custom download URLs**: Support for any GitHub release or custom URL
- **Automatic backup**: Creates timestamped backups before update
- **Version verification**: Confirms successful update with version check
- **Progress tracking**: Real-time progress for batch operations
- **Rollback capability**: Backup files allow easy rollback if needed

**Process**:
1. Select target nodes (individual or all)
2. Provide download URL for new binary
3. Enter SSH credentials
4. Automated process per node:
   - Test SSH connectivity
   - Navigate to binary directory
   - Backup current binary
   - Download new binary
   - Set execute permissions
   - Verify installation

**Safety Features**:
- Connection testing before modification
- Automatic backup with timestamps
- Error handling and reporting
- Detailed success/failure reporting

### 6. Toggle Node Functionality
**Purpose**: Configure Wireguard and Mixnet settings across multiple nodes

**Configuration Options**:
- **Wireguard**: Enable/Disable
- **Mixnet Mode**: Mixnode, Entry Gateway, Exit Gateway

**Features**:
- **Batch configuration**: Apply same settings to multiple nodes
- **Service file modification**: Direct systemd service configuration
- **Automatic backup**: Service files backed up before changes
- **Daemon reload**: Automatic systemctl daemon-reload after changes

**Use Cases**:
- Switching node roles across fleet
- Enabling/disabling WireGuard for security
- Standardizing configurations

### 7. Restart Service
**Purpose**: Restart nym-node services across multiple nodes

**Features**:
- **Multi-node restart**: Restart services on multiple nodes simultaneously
- **Status verification**: Confirms service status after restart
- **Progress tracking**: Real-time progress for batch operations
- **Error handling**: Continues processing even if individual nodes fail

**Process**:
1. Select target nodes
2. Enter SSH credentials
3. Restart systemd service on each node
4. Verify service status
5. Report results

### 8. Config (Configuration Menu)
**Purpose**: Manage persistent script configuration

**Configuration Options**:

#### 8.1 Custom SSH Port
- **Default**: 22
- **Range**: 1-65535
- **Purpose**: Support for non-standard SSH ports
- **Validation**: Ensures valid port numbers

#### 8.2 Systemd Service Name
- **Default**: `nym-node.service`
- **Purpose**: Support for custom service names
- **Auto-extension**: Automatically adds `.service` if omitted

#### 8.3 Custom Binary Folder
- **Default**: `/root/nym`
- **Purpose**: Support for custom binary locations
- **Path handling**: Removes trailing slashes automatically

#### 8.4 Reset to Defaults
- **Purpose**: Restore all settings to defaults
- **Confirmation**: Requires user confirmation
- **Immediate effect**: Changes apply instantly

**Persistence**:
- All settings saved to `config.txt`
- Automatically loaded on script startup
- Survives script restarts

### 9. Test SSH
**Purpose**: Comprehensive SSH connectivity and configuration testing

**Test Suite** (7 Tests):
1. **Basic Connection**: Verifies SSH connectivity
2. **Working Directory**: Confirms access and path
3. **User Identity**: Validates user account
4. **Sudo Access**: Tests privilege escalation
5. **Root Switch**: Verifies sudo su capability
6. **Service File**: Confirms systemd service file exists
7. **Systemctl**: Tests service status checking

**Features**:
- **Step-by-step progress**: Visual progress indicator
- **Detailed results**: Success/failure with output details
- **Configuration display**: Shows current SSH port and service settings
- **Troubleshooting aid**: Identifies specific connectivity issues

### 10. Show Debug Log
**Purpose**: Display recent debug and error information

**Features**:
- **Last 50 entries**: Most recent log entries
- **Timestamped entries**: Precise timing information
- **Function tracking**: Shows which functions were called
- **Error details**: SSH errors, connection issues, and failures

**Log Categories**:
- `MAIN`: Application lifecycle
- `FUNCTION`: Function calls
- `SSH`: SSH operations and errors
- `CONFIG`: Configuration changes
- `UPDATE`: Binary updates
- `RESTART`: Service operations

## 📁 File Structure

```
nym-node-manager/
├── nym_node_manager.sh    # Main script
├── nodes.txt              # Node registry (auto-created)
├── config.txt             # Configuration file (auto-created)
├── debug.log              # Debug logging (auto-created)
└── README.md              # This file
```

### File Descriptions

**`nodes.txt`**: Stores node information including names, IPs, roles, and status
**`config.txt`**: Persistent configuration (SSH port, service name, binary path)
**`debug.log`**: Detailed logging for troubleshooting and audit trails

## 🔒 Security Considerations

### SSH Security
- **Password Authentication**: Uses sshpass for automated authentication
- **Host Key Checking**: Disabled for automation (consider security implications)
- **Timeout Controls**: 10-second connection timeout prevents hanging
- **Privilege Escalation**: Secure sudo access for required operations

### Best Practices
- **Use SSH Keys**: Consider implementing SSH key authentication
- **Network Security**: Ensure proper firewall rules
- **Access Control**: Limit script access to authorized users
- **Regular Updates**: Keep dependencies updated
- **Audit Logging**: Review debug logs regularly

### Recommendations
```bash
# Set restrictive permissions
chmod 700 nym_node_manager.sh
chmod 600 config.txt nodes.txt

# Consider using SSH keys instead of passwords
ssh-keygen -t rsa -b 4096
ssh-copy-id user@node-ip
```

## 🐛 Troubleshooting

### Common Issues

#### SSH Connection Failures
```bash
# Check connectivity
ping node-ip

# Verify SSH service
ssh user@node-ip -p custom-port

# Check SSH configuration
ssh -v user@node-ip
```

#### Permission Denied
```bash
# Verify sudo access
sudo whoami

# Check service file permissions
ls -la /etc/systemd/system/nym-node.service
```

#### Service Start Failures
```bash
# Check service status
systemctl status nym-node.service

# View service logs
journalctl -u nym-node.service -n 50
```

### Debug Information
- **Debug Log**: Menu option 10 shows recent operations and errors
- **Verbose SSH**: SSH operations logged with full command details
- **Function Tracking**: All function calls logged with timestamps

## 📊 Configuration Examples

### Standard Setup
```bash
SSH_PORT=22
SERVICE_NAME=nym-node.service
BINARY_PATH=/root/nym
```

### Custom Setup
```bash
SSH_PORT=2222
SERVICE_NAME=nym-custom.service
BINARY_PATH=/opt/nym-node
```

### Enterprise Setup
```bash
SSH_PORT=9922
SERVICE_NAME=nym-production.service
BINARY_PATH=/usr/local/bin/nym
```

## 🤝 Contributing

### Bug Reports
1. Check existing issues
2. Provide detailed reproduction steps
3. Include debug log output
4. Specify system information

### Feature Requests
1. Describe the use case
2. Explain the expected behavior
3. Consider backward compatibility

### Pull Requests
1. Fork the repository
2. Create a feature branch
3. Test thoroughly
4. Update documentation
5. Submit pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- [Nym Network](https://github.com/nymtech/nym) - The main Nym project
- [Nym Docs](https://nymtech.net/docs/) - Official documentation

## ⚡ Quick Reference

### Essential Commands
```bash
# Start the manager
./nym_node_manager.sh

# Make executable (if needed)
chmod +x nym_node_manager.sh

# View debug information
tail -f debug.log

# Check configuration
cat config.txt
```

### Directory Structure
```
Working Directory/
├── nym_node_manager.sh    # The script
├── nodes.txt              # Your nodes
├── config.txt             # Your settings  
└── debug.log              # Troubleshooting
```

---

**Happy Node Managing! 🚀**

For support, please create an issue on GitHub or check the debug logs for detailed error information.
