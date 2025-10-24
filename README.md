# Nym Node Manager

A comprehensive terminal-based management tool for Nym network nodes with built-in wallet operations.

<img width="449" height="280" alt="Screenshot 2025-10-24 at 12 03 26" src="https://github.com/user-attachments/assets/8a94b93a-b4a2-47a4-a91b-c1c81a662463" />

## 📖 Overview

Nym Node Manager is a powerful bash-based tool that simplifies the management of Nym network nodes and cryptocurrency wallets. With an intuitive dialog-based interface, it provides centralized control over multiple nodes, secure wallet management, and automated operations.

### Key Highlights

- 🖥️ **Multi-Node Management** - Control multiple Nym nodes from a single interface
- 💰 **Integrated Wallet Operations** - Manage wallets with AES-256 encryption
- 🔐 **Security First** - Encrypted storage, secure SSH, no plaintext credentials
- 🚀 **Batch Operations** - Execute commands across multiple nodes/wallets simultaneously
- 📊 **Real-Time Data** - Live balance and rewards tracking from Nym network
- 🎨 **User-Friendly** - Clean terminal UI with dialog menus

---

## ✨ Features

### 🔧 Node Management

- **Add/Edit/Delete Nodes** - Full CRUD operations for your node fleet
- **Alphabetical Organization** - Nodes automatically sorted for easy navigation
- **Node Configuration Tracking** - Store IPs, Node IDs, and custom identifiers
- **Bulk Selection** - Multi-select for batch operations

### ⚙️ Node Operations

- **Retrieve Node Roles** - View mixnet, entry gateway, and exit gateway configurations
- **Automated Backups** - Rsync-based backup of node data
- **Binary Updates** - One-click updates to latest nym-node version
- **Toggle Functionality** - Enable/disable node features on the fly
- **Service Management** - Restart services across multiple nodes
- **Custom SSH Commands** - Execute arbitrary commands with sudo support

### 💳 Wallet Operations

- **Secure Wallet Storage** - AES-256-CBC encryption with PBKDF2
- **Multi-Wallet Support** - Manage unlimited wallets
- **Real-Time Balances** - Live balance queries via nym-cli
- **Operator Rewards** - View and claim pending operator rewards
- **Transaction Creation** - Send NYM tokens with validation
- **Batch Operations** - Query/withdraw from multiple wallets at once
- **Export/Import** - Securely backup and restore wallet mnemonics

### 🛠️ Configuration

- **Custom SSH Ports** - Non-standard port support
- **Service Name Configuration** - Custom systemd service names
- **Binary Path Management** - Specify custom binary locations
- **Persistent Settings** - Configuration saved between sessions

### 🔍 Diagnostics

- **SSH Connection Testing** - 7-step verification process
- **Debug Logging** - Comprehensive activity logs
- **Service Status Checks** - Verify systemd service states
- **Sudo Access Verification** - Test privilege escalation

---

## 📦 Installation

### Quick Start

```bash
# Download the script
wget https://github.com/yourusername/nym-node-manager/releases/download/v66/nym_node_manager_v66.sh

# Make executable
chmod +x nym_node_manager_v66.sh

# Run
./nym_node_manager_v66.sh
```

### Requirements

The script automatically installs missing dependencies on supported systems:

**Required:**
- `dialog` - Terminal UI framework
- `expect` - SSH automation
- `curl` - HTTP requests
- `rsync` - File synchronization
- `sshpass` - SSH authentication (optional, for password auth)
- `openssl` - Encryption
- `jq` - JSON parsing

**Optional (for wallet operations):**
- `nym-cli` - Nym command-line tool
  - Download: https://github.com/nymtech/nym/releases
  - Required for wallet operations

### Supported Systems

- ✅ Ubuntu/Debian (apt-get)
- ✅ macOS (Homebrew)
- ✅ Any Linux with bash 4.0+

---

## 🚀 Usage

### First-Time Setup

1. **Launch the script:**
   ```bash
   ./nym_node_manager_v66.sh
   ```

2. **Add your first node:**
   - Select: `1. Node Management` → `2. Add node`
   - Enter: Node name, IP address, Node ID

3. **Import a wallet (optional):**
   - Select: `3. Wallet Operations` → `1. Add new wallet`
   - Enter: Wallet name, 24-word mnemonic, encryption password

### Menu Structure

```
Nym Node Manager v66
├── 1. Node Management
│   ├── List all nodes
│   ├── Add node
│   ├── Edit node
│   └── Delete node
│
├── 2. Node Operations
│   ├── Retrieve node roles
│   ├── Backup node
│   ├── Update nym-node binary
│   ├── Toggle functionality
│   ├── Restart service
│   └── Execute SSH command
│
├── 3. Wallet Operations
│   ├── Add new wallet
│   ├── List wallets (with balances & rewards)
│   ├── Withdraw operator rewards
│   ├── Create new transaction
│   ├── Export wallet
│   └── Delete wallet
│
├── 4. Configuration
│   ├── Custom SSH Port
│   ├── Systemd Service Name
│   ├── Custom Binary Folder
│   └── Reset to Defaults
│
└── 5. Diagnostics
    ├── Test SSH connection
    └── Show debug log
```

---

## 💡 Common Use Cases

### Managing Multiple Nodes

```
1. Add all your nodes via "Node Management"
2. Use "Retrieve node roles" to audit configurations
3. Select multiple nodes for batch "Restart service"
4. Use "Update nym-node binary" for fleet-wide updates
```

### Wallet Operations

```
1. Import wallets: "Add new wallet" with your mnemonics
2. Check status: "List wallets" shows balances + rewards
3. Claim rewards: "Withdraw operator rewards"
4. Send tokens: "Create new transaction"
```

### Daily Monitoring

```
1. Launch script
2. "List wallets" - Quick overview of all wallet states
3. Check claimable operator rewards
4. "Retrieve node roles" - Verify node configurations
```

### Backing Up Node Data

```
1. Select "Node Operations" → "Backup node"
2. Choose node(s) to backup
3. Enter SSH credentials
4. Backup saved to ~/nym_backups/<nodename>_<timestamp>/
```

---

## 🔐 Security

### Wallet Security

- **Encryption**: AES-256-CBC with PBKDF2 key derivation
- **Storage**: Encrypted mnemonics in `~/.nym_wallets/wallet_list.txt`
- **Memory**: Sensitive data cleared after use with `shred`
- **Passwords**: Never logged or stored

### SSH Security

- **No Credential Storage**: SSH passwords entered per-session
- **Sudo Support**: Secure privilege escalation
- **Host Key Checking**: Can be configured per environment

### Best Practices

1. **Use strong passwords** for wallet encryption
2. **Keep mnemonic backups** offline and secure
3. **Regular exports** of wallet mnemonics to secure storage
4. **Verify checksums** when downloading the script
5. **Run from secure systems** - not on shared/public machines

---

## 📊 File Structure

```
.
├── nym_node_manager_v66.sh    # Main script
├── nodes.txt                  # Node configurations (auto-generated)
├── config.txt                 # Settings (auto-generated)
├── debug.log                  # Activity log (auto-generated)
└── ~/.nym_wallets/            # Wallet storage (auto-generated)
    └── wallet_list.txt        # Encrypted wallet data
```

---

## 🔄 Upgrading

### From v58 or earlier:

1. Download v66
2. Run the new script
3. Existing `nodes.txt` and `config.txt` are preserved
4. Import your wallets using "Add new wallet"

### Preserving Data:

Your node configurations are stored in:
- `nodes.txt` - Node list
- `config.txt` - Settings
- `~/.nym_wallets/` - Encrypted wallets

These files persist across versions.

---

## 🛠️ Advanced Configuration

### Custom SSH Port

```
Main Menu → Configuration → Custom SSH Port
```
Set once, applies to all nodes.

### Custom Service Name

```
Main Menu → Configuration → Systemd Service Name
```
Useful if your nodes use custom service names.

### Custom Binary Path

```
Main Menu → Configuration → Custom Binary Folder
```
Specify where nym-node binary is located on remote servers.

---

## 📝 Troubleshooting

### "nym-cli not found"

**Solution:** Install nym-cli for wallet operations:
```bash
# Download from GitHub
wget https://github.com/nymtech/nym/releases/latest/download/nym-cli
chmod +x nym-cli
sudo mv nym-cli /usr/local/bin/
```

### SSH Connection Fails

**Solution:** Use the diagnostic tool:
```
Main Menu → Diagnostics → Test SSH connection
```
This runs 7 tests to identify the issue.

### "Wrong password" on Wallet Operations

**Solution:** 
- Ensure you're using the correct encryption password
- Password is case-sensitive
- Try "Export wallet" to verify password separately

### Script Hangs on Remote Commands

**Solution:**
- Check SSH connectivity manually
- Verify sudo password is correct
- Check `debug.log` for detailed error messages

### Wallet Balance Shows 0

**Solution:**
- Verify nym-cli is installed and in PATH
- Check network connectivity to Nym validators
- Ensure wallet address is correct (use "List wallets")

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Test thoroughly
4. Submit a pull request

### Areas for Contribution

- Additional node operations
- Support for more cryptocurrencies
- GUI version
- Docker containerization
- Automated testing suite

---

## 📜 Changelog

See [RELEASE_NOTES.md](RELEASE_NOTES_v66.md) for detailed version history.

**Latest (v66):**
- Refined wallet display labels
- Removed uNYM values (NYM only)
- Integrated rewards query into wallet list
- Reordered menu items for better UX

---

## 📄 License

MIT License - See LICENSE file for details.

---

## 🔗 Links

- **Nym Project**: https://nymtech.net
- **Nym GitHub**: https://github.com/nymtech/nym
- **Nym Documentation**: https://nymtech.net/docs
- **Download nym-cli**: https://github.com/nymtech/nym/releases

---

## ⚠️ Disclaimer

This tool is provided as-is for managing Nym network nodes and wallets. The authors are not responsible for:

- Loss of funds due to misuse
- Node downtime or misconfigurations
- Security breaches on your systems

**Always:**
- Keep backups of your mnemonics
- Test on non-production systems first
- Verify the script source code before use
- Use strong passwords and secure systems

---

## 🙏 Acknowledgments

- Nym Technologies for the Nym network
- The open-source community for dependencies
- Contributors and testers

---

## 📧 Support

For issues, questions, or feature requests:
- Open an issue on GitHub
- Check existing issues for solutions
- Review the troubleshooting section above

---

**Made with ❤️ for the Nym community**

*Manage your Nym nodes and wallets with confidence.*
