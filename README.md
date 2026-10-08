# SSH Alert - Secure SSH Connection Monitoring

[![Bash](https://img.shields.io/badge/bash-4.0+-blue.svg?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Python](https://img.shields.io/badge/python-3.6+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Discord](https://img.shields.io/discord/1411852800241176616?style=for-the-badge&logo=discord&logoColor=white&label=Discord)](https://discord.gg/3hCYtH5Q83)

A secure and reliable utility for monitoring SSH connections to a server with Telegram notifications.

## 🚀 Features

- **Maximum user identification**: IP address, key fingerprint, key comment, connection type
- **Flexible notifications**: Separate sound and silent messages for different connection types
- **Reliability**: Independent alerts for concurrent logins, with duplicate suppression per account/IP/key
- **Retry logic**: Automatic retries on network or Telegram API failures
- **Flexible configuration**: Configuration through config file
- **Security**: Minimal dependencies, works without SSH client modifications

## 📋 Requirements

- Linux server with OpenSSH
- Python 3.6+
- curl
- bash 4.0+
- sudo with `/etc/sudoers.d/` enabled, and visudo
- flock, ss, logrotate
- Root privileges for installation

## 🛠 Installation

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/B4DCATs/ssh-login-alert
cd ssh-login-alert

# Run the installation
sudo ./install.sh
```

**After installation, the repository can be removed:**
```bash
# After successful installation
cd ..
rm -rf ssh-login-alert
```

### What happens during installation

1. **Files are copied** to `/opt/ssh-alert/` and `/etc/ssh-alert/`
2. **SSH integration** is added to `/etc/ssh/sshrc`, preserving existing commands
3. **A restricted sudo helper** sends alerts for ordinary users while keeping Telegram credentials readable only by root
4. **Log rotation configuration** is created
5. **Interactive Telegram setup** is launched
6. **Configuration is tested**

### Installation details

The installer copies all runtime and management scripts to `/opt/ssh-alert/`. The SSH hook runs `ssh-alert-login.sh`, which passes session metadata to `ssh-alert-session.py` through a passwordless sudo rule. That rule allows only the installed helper with no command-line arguments and no caller environment overrides. The helper derives the login account from sudo's caller UID and starts the notifier with a minimal environment.

Keep `/opt/ssh-alert/` and its scripts owned by root and unwritable by ordinary users. Telegram credentials remain in `/etc/ssh-alert/config.conf` with permissions `600`.

Notifications run as a short-lived background process triggered by the SSH login hook.

Re-running `sudo ./install.sh` preserves an existing configuration and replaces only SSH Alert's hook. Use the installer for upgrades so that the helper and its sudo rule are installed together.

## ⚙️ Configuration

### Basic Settings

Edit the file `/etc/ssh-alert/config.conf`:

```bash
# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN="your_bot_token_here"
TELEGRAM_CHAT_ID="your_chat_id_here"

# Server Information
SERVER_NAME="server01"
SERVER_DOMAIN="example.com"

# Notification Settings
NOTIFY_INTERACTIVE_SESSIONS=true
NOTIFY_TUNNELS=false
NOTIFY_COMMANDS=false
DISABLE_NOTIFICATION_SOUND_FOR_TUNNELS=true

# Rate Limiting (seconds)
RATE_LIMIT_PER_IP=300
RATE_LIMIT_PER_KEY=60
```

### authorized_keys Configuration

The parser reads the login account's `~/.ssh/authorized_keys` by default. Set `SSH_AUTHORIZED_KEYS_PATH` to a specific file only when needed. For installations upgraded from the earlier root-only default, set it to an empty string to enable automatic per-account selection:

```bash
SSH_AUTHORIZED_KEYS_PATH=""
```

Key comments identify the person in notifications. An optional label can also be stored in a key's options:

```
environment="SSH_USER=alice@example.com" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... alice@laptop
```

The parser reads this option directly; OpenSSH does not need to export it into the session. It matches successful authentication logs by account, source IP and source port. Unidentified keys remain `unknown`; password logins use the login account for identification.

### Exclusions from Notifications

For automated connections (pipelines, monitoring, CI/CD runners), you can exclude connections from notifications using three methods:

#### 1. Key Comment Exclusions

Exclude SSH keys by their comment in `authorized_keys`:

```bash
# Add key comment exclusion
sudo /opt/ssh-alert/manage-exclusions.sh add key "pipeline@ci"
sudo /opt/ssh-alert/manage-exclusions.sh add key "deploy@automation"

# Remove key comment exclusion
sudo /opt/ssh-alert/manage-exclusions.sh remove key "pipeline@ci"
```

#### 2. IP Address Exclusions

Exclude connections from specific IP addresses (useful for password-based runners):

```bash
# Add IP exclusion
sudo /opt/ssh-alert/manage-exclusions.sh add ip "192.168.1.100"
sudo /opt/ssh-alert/manage-exclusions.sh add ip "10.0.0.50"

# Remove IP exclusion
sudo /opt/ssh-alert/manage-exclusions.sh remove ip "192.168.1.100"
```

#### 3. Username Exclusions

Exclude connections by username:

```bash
# Add username exclusion
sudo /opt/ssh-alert/manage-exclusions.sh add user "gitlab-runner"
sudo /opt/ssh-alert/manage-exclusions.sh add user "jenkins"

# Remove username exclusion
sudo /opt/ssh-alert/manage-exclusions.sh remove user "gitlab-runner"
```

#### Managing Exclusions

```bash
# View all exclusions
sudo /opt/ssh-alert/manage-exclusions.sh list

# View specific type
sudo /opt/ssh-alert/manage-exclusions.sh list key
sudo /opt/ssh-alert/manage-exclusions.sh list ip
sudo /opt/ssh-alert/manage-exclusions.sh list user

# Clear all exclusions of a type
sudo /opt/ssh-alert/manage-exclusions.sh clear key
sudo /opt/ssh-alert/manage-exclusions.sh clear ip
sudo /opt/ssh-alert/manage-exclusions.sh clear user
```

**Usage examples:**
- **Key comments**: `pipeline@ci`, `deploy@automation`, `monitoring@system`
- **IP addresses**: `192.168.1.100`, `10.0.0.50`, GitLab Runner IP
- **Usernames**: `gitlab-runner`, `jenkins`, `deploy-bot`

**Note:** Changes take effect immediately for new connections. IP and username exclusions are perfect for CI/CD runners that connect via password authentication.

## 📱 Creating a Telegram Bot

1. **Create a bot**:
   - Send `/newbot` to [@BotFather](https://t.me/BotFather)
   - Follow the instructions to create a bot
   - Save the received token

2. **Get Chat ID**:
   - Add the bot to a chat or send it a message
   - Go to the link: `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
   - Find `chat.id` in the response

## 🔧 Usage

### Basic Commands

```bash
# View logs
sudo tail -f /var/log/ssh-alert.log

# Check script and configuration syntax
sudo bash -n /opt/ssh-alert/ssh-alert-enhanced.sh
sudo bash -n /etc/ssh-alert/config.conf
# Test notification delivery by opening a new SSH session

# Log management
sudo /opt/ssh-alert/check-log-rotation.sh status    # Check rotation status
sudo /opt/ssh-alert/check-log-rotation.sh test      # Test configuration
sudo /opt/ssh-alert/check-log-rotation.sh rotate    # Force rotation

# Exclusion management
sudo /opt/ssh-alert/manage-exclusions.sh list                    # Show all exclusions
sudo /opt/ssh-alert/manage-exclusions.sh add key "pipeline@ci"   # Add key exclusion
sudo /opt/ssh-alert/manage-exclusions.sh add ip "192.168.1.100"  # Add IP exclusion
sudo /opt/ssh-alert/manage-exclusions.sh add user "gitlab-runner" # Add user exclusion
sudo /opt/ssh-alert/manage-exclusions.sh remove key "pipeline@ci" # Remove key exclusion
sudo /opt/ssh-alert/manage-exclusions.sh clear key               # Clear key exclusions

# Uninstall
sudo /opt/ssh-alert/uninstall.sh
```

### Notification Types

The login hook distinguishes the following session types:

- **Interactive shell** - Interactive session (default with sound)
- **Tunnel** - Session explicitly marked with `SSH_TUNNEL` (default without sound)
- **Command execution** - Session without a TTY, or a forced command (configurable)

OpenSSH does not run `sshrc` for a pure forwarding connection such as `ssh -N`. Such connections do not trigger this login hook. If `~/.ssh/rc` is enabled for an account, OpenSSH uses that file instead of `/etc/ssh/sshrc`; add `/opt/ssh-alert/ssh-alert-login.sh >/dev/null 2>&1 &` to its rc file to receive alerts for that account.

### Notification Example

```
🔐 SSH Login Alert:
Host IP: 203.0.113.1 / 192.168.1.100
Host: server01.example.com
Person: alice@example.com
IP: 198.51.100.50
Type: Interactive shell
Key: SHA256:abcd1234...
Time: 2024-01-15 14:30:25 UTC
```

## 🛡 Security

### Recommendations

1. **Restrict access to configuration**:
   ```bash
   sudo chmod 600 /etc/ssh-alert/config.conf
   sudo chown root:root /etc/ssh-alert/config.conf
   ```

2. **Configure firewall**:
   ```bash
   # Allow SSH only from trusted IPs
   sudo ufw allow from 192.168.1.0/24 to any port 22
   ```

3. **Use keys instead of passwords**:
   ```bash
   sudo nano /etc/ssh/sshd_config
   # Set: PasswordAuthentication no
   sudo systemctl restart sshd
   ```

### Logging

SSH Alert maintains detailed logs:

```bash
# View logs
sudo tail -f /var/log/ssh-alert.log

# JSON logging (optional)
# Set JSON_LOGGING=true in config.conf
```

### Log Rotation

SSH Alert automatically configures log rotation through `logrotate`:

```bash
# Check rotation status
sudo /opt/ssh-alert/check-log-rotation.sh status

# Test rotation configuration
sudo /opt/ssh-alert/check-log-rotation.sh test

# Force rotation
sudo /opt/ssh-alert/check-log-rotation.sh rotate
```

**Rotation settings:**
- 📅 **Daily rotation** of logs
- 📦 **30 days** of compressed log storage
- 🗜️ **Compression** of old logs
- 📏 **Minimum size** 100KB for rotation
- 📏 **Maximum size** 10MB for forced rotation
- 🧹 Rate limiting state stays in the private `/run/ssh-alert/` directory and resets on reboot

## 🔍 Troubleshooting

### Common Issues

1. **Post-installation errors**:
   ```bash
   # Re-run from the repository to reinstall scripts and integration
   sudo ./install.sh
   ```

2. **Notifications not arriving**:
   ```bash
   # Check token and chat_id
   sudo grep -E "TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID" /etc/ssh-alert/config.conf
   
   # Check logs
   sudo tail -f /var/log/ssh-alert.log
   ```

3. **Script not starting**:
   ```bash
   # Check permissions
   ls -la /opt/ssh-alert/ssh-alert-enhanced.sh
   
   # Check syntax
   bash -n /opt/ssh-alert/ssh-alert-enhanced.sh
   ```

4. **Python errors**:
   ```bash
   # Check Python version
   python3 --version
   
   # Test parser
   python3 /opt/ssh-alert/key-parser.py get-info
   ```

### Debugging

Enable debug logs:

```bash
sudo nano /etc/ssh-alert/config.conf
# Set: LOG_LEVEL="DEBUG"
```

## 📊 Monitoring

### System Check

```bash
# Check the SSH login hook
sudo grep -F '/opt/ssh-alert/ssh-alert-login.sh' /etc/ssh/sshrc

# Active connections
sudo ss -tnp | grep sshd

# Recent notifications
sudo grep "SSH alert sent" /var/log/ssh-alert.log | tail -5
```

### Metrics

SSH Alert can integrate with monitoring systems through JSON logs:

```bash
# Enable JSON logging
echo 'JSON_LOGGING=true' | sudo tee -a /etc/ssh-alert/config.conf

# Parse logs
sudo tail -f /var/log/ssh-alert.log | jq -R 'fromjson?'
```

## 🔄 Updates

### Automatic Update

```bash
# Update from repository
git pull origin main
sudo ./install.sh
```

### Upgrade behavior

The installer keeps `/etc/ssh-alert/config.conf`, including credentials and exclusions. It backs up `/etc/ssh/sshrc` before updating the managed hook. Update through `sudo ./install.sh` so runtime scripts, sudo permissions and log rotation stay consistent.

## 🗑️ Uninstallation

### Complete Removal

```bash
# Run the uninstall script
sudo /opt/ssh-alert/uninstall.sh
```

### What gets removed

- ✅ All SSH Alert files
- ✅ SSH Alert hook from `/etc/ssh/sshrc` and its restricted sudo rule
- ✅ Legacy systemd service, if present from an older installation
- ✅ Log rotation configuration
- ✅ Temporary files and cache
- ✅ Backup copies are created

### Manual Removal

Run the installed uninstaller to preserve unrelated SSH initialization commands. It removes the managed hook and `/etc/sudoers.d/ssh-alert` before deleting the installed files. It also cleans `/run/ssh-alert/` and legacy temporary state; log files are retained.

## Development checks

```bash
python3 -m unittest discover -s tests -v
```

Tests use temporary files and mocked Telegram requests. They cover key options, account exclusions, concurrent notifications, version checks, helper input validation and upgrade preservation.

## 📝 License

This project is distributed under the MIT license. See the `LICENSE` file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a branch for a new feature (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

If you encounter problems or have questions:

1. Check the [troubleshooting section](#troubleshooting)
2. Create an [Issue](https://github.com/B4DCATs/ssh-login-alert/issues)
3. Refer to the documentation

## 🔮 Development Roadmap

- [ ] Support for other messengers (Slack, Discord)
- [ ] Web interface for management
- [ ] Integration with SIEM systems
- [ ] Machine learning for anomaly detection
- [ ] IPv6 support
- [ ] Advanced connection analytics
