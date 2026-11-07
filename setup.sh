#!/usr/bin/env bash
# https://github.com/aiovin/lazy-vps

set -uo pipefail

# ==========================

usage() {
    echo "Usage: ${0##*/} [--help] [--no-hit] [--password-auth] [--allow-weak-passwords] [--skip-update-upgrade]"
}

# ==========================

# System check
if ! [ -d "/run/systemd/system" ] || ! [ "$(ps -p 1 -o comm=)" = "systemd" ]; then
    echo "This script requires a systemd-based system (Ubuntu/Debian)."
    exit 1
fi

# ==========================

AUTH_METHOD="key"

MIN_PASS_LEN=8
ALLOW_WEAK_PASSWORDS="no"

SKIP_UPDATE_UPGRADE="no"

# A variable to run the script without script run counter
NOHIT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help|-help)        usage; exit 0 ;;
        -nohit|--no-hit|-n)     NOHIT="yes" ;;
        --password-auth|-p)     AUTH_METHOD="password" ;;
        --allow-weak-passwords) ALLOW_WEAK_PASSWORDS="yes";;
        --skip-update-upgrade)  SKIP_UPDATE_UPGRADE="yes" ;;
        -*)   echo "Invalid option: $1"; exit 1 ;;
    esac
    shift
done

# ==========================

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root or with root privileges."
    exit 1
fi

# ==========================

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
L_YELLOW='\033[1;33m'
RED='\033[0;31m'
PURPLE='\033[95m'
BLUE='\033[1;34m'
NC='\033[0m'

# ==========================

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=l

apt_opts=(-o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold")

if [[ "$SKIP_UPDATE_UPGRADE" == "yes" ]]; then
    echo "System update skipped."

elif [[ "$SKIP_UPDATE_UPGRADE" == "no" ]]; then
    echo "Updating the system..."
    if ! apt-get update; then
        echo "Error: failed to update package lists." >&2
        exit 1
    fi

    if ! apt-get upgrade -y "${apt_opts[@]}"; then
        echo "Error: failed to upgrade packages." >&2
        exit 1
    fi
fi

# ==========================

printf '\033[H\033[2J'

echo -e "Starting server setup..\n"

# Changing the root password
echo "Changing the root password."
[[ "$ALLOW_WEAK_PASSWORDS" == "yes" ]] && echo "Password strength checks: disabled"
while true; do
    while true; do
        read -r -sp "Enter a new password for root: " root_password
        echo
        if [ -z "$root_password" ]; then
            echo -e "\nError: Password cannot be empty. Try again."
        elif [ "${#root_password}" -lt "$MIN_PASS_LEN" ] && [ "$ALLOW_WEAK_PASSWORDS" == "no" ]; then
            echo -e "\nError: Password must be at least $MIN_PASS_LEN characters."
        else
            break
        fi
    done

    while true; do
        read -r -sp "Repeat the new password for root: " root_password_confirm
        echo
        if [ -z "$root_password_confirm" ]; then
            echo -e "\nError: Password cannot be empty. Try again."
        else
            break
        fi

    done
    if [ "$root_password" != "$root_password_confirm" ]; then
        echo -e "\nPasswords do not match. Try again."
    else
        echo "New password for root successfully set."
        break
    fi
done

# Create a new user
echo -e "\nConfiguring user."
while true; do
    read -r -p "Enter username: " new_user_name

    if [ -z "$new_user_name" ]; then
        echo -e "\nError: Username cannot be empty. Try again."
        continue
    fi

    if [[ ! "$new_user_name" =~ ^[a-zA-Z_][a-zA-Z0-9_-]*$ ]]; then
        echo -e "\nError: Username contains invalid characters. Username can only contain letters, numbers, hyphens, and underscores. It must also start with a letter or underscore. Try again."
        continue
    fi

    if [[ "$new_user_name" == "root" ]]; then
        echo -e "\nError: Username cannot be 'root'. Please choose another username."
        continue
    fi

    if id "$new_user_name" &>/dev/null; then
        echo -e "${YELLOW}[WARN]${NC} User '$new_user_name' already exists!"
        echo "Existing user configuration will be overwritten (password, SSH keys, .bashrc)."
        read -r -p "Do you want to proceed with this username? (y/n): " overwrite_confirm
        if [[ ! "$overwrite_confirm" =~ ^[Yy](es)?$ ]]; then
            echo "Please choose a different username."
            continue
        fi
    fi
    break
done

# Set the user's password
echo
while true; do
    while true; do
        read -r -sp "Set a password for user $new_user_name: " new_user_password
        echo
        if [ -z "$new_user_password" ]; then
            echo -e "\nError: Password cannot be empty. Try again."
        elif [ "${#new_user_password}" -lt "$MIN_PASS_LEN" ] && [ "$ALLOW_WEAK_PASSWORDS" == "no" ]; then
            echo -e "\nError: Password must be at least $MIN_PASS_LEN characters."
        else
            break
        fi
    done

    while true; do
        read -r -sp "Repeat the password for user $new_user_name: " new_user_password_confirm
        echo
        if [ -z "$new_user_password_confirm" ]; then
            echo -e "\nError: Password cannot be empty. Try again."
        else
            break
        fi
    done

    if [ "$new_user_password" != "$new_user_password_confirm" ]; then
        echo -e "\nPasswords do not match. Try again."
    else
        echo "Password for user $new_user_name successfully set."
        break
    fi
done

# Set a new SSH port
echo
while true; do
    read -r -p "Enter a new SSH port (between 1024 and 65535). Press Enter to generate a random port: " new_ssh_port

    if [ -z "$new_ssh_port" ]; then
        new_ssh_port=$(shuf -i 1024-65535 -n 1)
        echo "Your SSH connection port: $new_ssh_port"
        break
    fi

    if [[ "$new_ssh_port" =~ ^[0-9]+$ ]] && [ "$new_ssh_port" -ge 1024 ] && [ "$new_ssh_port" -le 65535 ]; then
        echo "Your SSH connection port: $new_ssh_port"
        break
    else
        echo -e "\nError: The entered port must be a number between 1024 and 65535. Try again."
    fi
done

# Set timezone
echo
read -r -p "Specify the timezone (e.g., Europe/Moscow). For reference, visit: https://wikipedia.org/wiki/List_of_tz_database_time_zones). Press Enter to set UTC by default: " timezone
timezone=${timezone:-"Etc/UTC"}
echo "Timezone set to: $timezone"

# Set a new server name
current_hostname=$(hostname)
echo
while true; do
    read -r -p "Enter a new hostname (press Enter to keep '$current_hostname'): " new_hostname

    if [ -z "$new_hostname" ]; then
        new_hostname=$current_hostname
        echo "Hostname left unchanged ($new_hostname)."
        break
    fi

    if [[ "$new_hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$ ]]; then
        echo "New hostname set to: $new_hostname"
        break
    else
        echo -e "\nError: Invalid hostname. Hostname must contain only letters, numbers, and hyphens, cannot start or end with a hyphen, and must be between 1 and 63 characters long."
    fi
done

if [[ "$AUTH_METHOD" == "key" ]]; then
    # Adding an ssh key
    echo -e "\nAdding public SSH key."
    echo "Generate it manually."
    echo -e "You can use these commands for ${BLUE}PowerShell${NC}:"
    echo
    echo "# Create a folder."
    echo -e "${BLUE}if (-not (Test-Path -Path \$env:USERPROFILE\.ssh\\\\$new_hostname)) {"
    echo -e "    New-Item -Path \$env:USERPROFILE\.ssh\\\\$new_hostname -ItemType Directory"
    echo -e "}${NC}"
    echo
    echo "# Generate an SSH key pair."
    echo -e "${BLUE}ssh-keygen -t ed25519 -f \$env:USERPROFILE\\.ssh\\\\$new_hostname\\id_ed25519_$new_hostname${NC}"
    echo
    echo "# Copy the public key to clipboard."
    echo -e "${BLUE}Get-Content ~/.ssh/$new_hostname/id_ed25519_$new_hostname.pub | clip${NC}"
    echo
    while true; do
        read -r -p "Enter your public SSH key (Right-click to paste from clipboard): " public_ssh_key

        if [[ -z "$public_ssh_key" ]]; then
            echo -e "\nError: Key cannot be empty. Try again."
            continue
        fi

        if [[ ! "$public_ssh_key" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519) ]]; then
            echo -e "\nError: The entered text does not look like a public SSH key. Try again."
            continue
        fi
        break
    done
    echo "Public SSH key successfully added."
fi

# Configuration of server startup notifications
echo
read -r -p "Do you want to configure ntfy notifications about server startup? (y/n, Enter for 'n') " setup_ntfy
setup_ntfy=${setup_ntfy:-n}

if [[ "$setup_ntfy" =~ ^[Yy](es)?$ ]]; then
    echo -e "${YELLOW}Warning:${NC} Only letters, numbers, - and _ are allowed. All other characters will be removed!"

    read -r -p "Enter a tag for ntfy (press Enter to use 'computer'): " ntfy_startup_tag
    ntfy_startup_tag=$(LC_ALL=C tr -dc 'a-zA-Z0-9_-' <<< "$ntfy_startup_tag")
    ntfy_startup_tag=${ntfy_startup_tag:-'computer'}

    read -r -p "Enter your ntfy topic (press Enter to generate 'server-startup-<6-random-digits>'): " ntfy_startup_topic
    ntfy_startup_topic=$(LC_ALL=C tr -dc 'a-zA-Z0-9_-' <<< "$ntfy_startup_topic")
    ntfy_startup_topic=${ntfy_startup_topic:-"server-startup-$(shuf -i 100000-999999 -n 1)"}

    echo "ntfy startup notifications configured with tag '$ntfy_startup_tag' and topic '$ntfy_startup_topic'."
    setup_ntfy="yes"
else
    echo "The server startup notifications will not be set up."
    setup_ntfy="no"
fi

# Free Disk space monitoring script
echo
read -r -p "Do you want to configure ntfy notifications about low disk space? (y/n, Enter for 'n'): " setup_disk_monitor
setup_disk_monitor=${setup_disk_monitor:-n}

if [[ "$setup_disk_monitor" =~ ^[Yy](es)?$ ]]; then
    echo -e "${YELLOW}Warning:${NC} Only letters, numbers, - and _ are allowed. All other characters will be removed!"

    read -r -p "Enter your ntfy topic (press Enter to generate 'server-misc-<6-random-digits>'): " ntfy_disk_topic
    ntfy_disk_topic=$(LC_ALL=C tr -dc 'a-zA-Z0-9_-' <<< "$ntfy_disk_topic")
    ntfy_disk_topic=${ntfy_disk_topic:-"server-misc-$(shuf -i 100000-999999 -n 1)"}

    read -r -p "Enter threshold from 1 to 100 (percent) at which the notification will be sent. Press Enter for '90': " disk_threshold
    disk_threshold=${disk_threshold:-90}

    while [[ ! "$disk_threshold" =~ ^[0-9]{1,3}$ ]] || [ "$disk_threshold" -lt 1 ] || [ "$disk_threshold" -gt 100 ]; do
        echo -e "\nError: Threshold must be between 1 and 100."
        read -r -p "Enter threshold for low disk space notifications: " disk_threshold
    done

    echo -e "\nntfy notifications to '$ntfy_disk_topic' when disk space reaches $disk_threshold% have been configured."
    echo -e "${YELLOW}[INFO]${NC} By default '/' is monitored. Add other mount points if needed later:"
    echo "/home/$new_user_name/scripts/low-disk-space-notify.sh"
    setup_disk_monitor="yes"
else
    echo "The script will not be installed."
    setup_disk_monitor="no"
fi

# Display entered data for confirmation
echo -e "\nPlease confirm your setup:"
echo
echo "New user name: $new_user_name"
echo "SSH port: $new_ssh_port"
echo "Authentication method: $AUTH_METHOD"
echo "Timezone: $timezone"
echo "New hostname: $new_hostname"
echo "Startup notifications: $setup_ntfy"
echo "Low disk space notifications: $setup_disk_monitor"

if [[ "$setup_ntfy" == "yes" ]]; then
    echo "   - Tag for server startup: $ntfy_startup_tag"
    echo "   - Topic for server startup: $ntfy_startup_topic"
fi

if [[ "$setup_disk_monitor" == "yes" ]]; then
    echo "   - Topic for disk space notifications: $ntfy_disk_topic"
fi
echo

# Get confirmation about the correctness of the data
while true; do
    read -r -p "Begin server configuration? (y/n): " confirm
    case $confirm in
        [Yy]|[Yy][Ee][Ss]) echo "Great, lets start.."; break;;
        [Nn]|[Nn][Oo]) echo -e "Exit.\n"; exit 0;;
        * ) echo -e "\nPlease enter 'y' to begin server configuration or 'n' to exit.";;
    esac
done
echo

progress_tag=">"

# Function to install utilities
install_packages() {
    echo -e "${GREEN}[$progress_tag]${NC} Installing utilities: $*"
    apt-get install -y "${apt_opts[@]}" "$@" >/dev/null 2>&1
}

# Install utilities
packages=("sudo"
    "nano"
    "ufw"
    "curl"
    "htop"
    "gzip"
    "logrotate"
    "bash-completion"
    "jq"
    "bind9-dnsutils"
)

# Also install fail2ban if the authentication method is a password
if [[ "$AUTH_METHOD" == "password" ]]; then packages+=("fail2ban" "nftables"); fi

install_packages "${packages[@]}"

for p in "${packages[@]}"; do
    if ! dpkg -s "$p" &>/dev/null; then
        echo -e "${RED}Error:${NC} Failed to install package '$p'"
        echo "The script cannot guarantee correct operation without all required packages. Exiting."
        exit 1
    fi
done

# Function to modify configuration files
# It removes all duplicate lines with the parameter (including commented ones)
# and inserts a single valid line at the position of the first match,
# or appends it to the end if the parameter was not found.
replace_config() {
    local key="$1"
    local new_line="$2"
    local file="$3"
    mapfile -t lines < <(
        grep -nE "^[[:space:]]*#?[[:space:]]*${key}\b" "$file" |
        cut -d: -f1
    )
    if [ "${#lines[@]}" -gt 0 ]; then
        local first_line="${lines[0]}"
        local total_lines
        total_lines=$(wc -l < "$file")
        sed -i -E "/^[[:space:]]*#?[[:space:]]*${key}\b/Id" "$file"
        if [ "$first_line" -ge "$total_lines" ]; then
            echo "$new_line" >> "$file"
        else
            sed -i "${first_line}i${new_line}" "$file"
        fi
    else
        echo "$new_line" >> "$file"
    fi
}

# Changing the root password
echo -e "${GREEN}[$progress_tag]${NC} Changing the root password.."
if ! echo "root:$root_password" | chpasswd; then
    echo -e "${RED}[ERROR] Failed to change root password.${NC}"
fi

# Creating a new user
echo -e "${GREEN}[$progress_tag]${NC} Configuring a new user '$new_user_name'.."
if ! id "$new_user_name" &>/dev/null; then
    useradd -m -s /bin/bash "$new_user_name"
fi

# Always change the password and add the user to the sudo group
echo "$new_user_name:$new_user_password" | chpasswd
usermod -aG sudo "$new_user_name"

# Configuring SSH
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

echo -e "${GREEN}[$progress_tag]${NC} Configuring SSH.."

# The first parameter is the one we are searching for, the second is the replacement, and the third is the file to modify
replace_config "Port" "Port $new_ssh_port" "/etc/ssh/sshd_config"
replace_config "PermitRootLogin" "PermitRootLogin no" "/etc/ssh/sshd_config"
replace_config "PubkeyAuthentication" "PubkeyAuthentication yes" "/etc/ssh/sshd_config"

if [[ "$AUTH_METHOD" == "key" ]]; then
    replace_config "PasswordAuthentication" "PasswordAuthentication no" "/etc/ssh/sshd_config"

    # Adding SSH key
    user_ssh_dir="/home/$new_user_name/.ssh"
    echo -e "${GREEN}[$progress_tag]${NC} Adding SSH key.."
    mkdir -p "$user_ssh_dir"
    echo "$public_ssh_key" > "$user_ssh_dir/authorized_keys"
    chmod 700 "$user_ssh_dir"
    chmod 600 "$user_ssh_dir/authorized_keys"
    chown -R "$new_user_name:$new_user_name" "$user_ssh_dir"
fi

if [[ "$AUTH_METHOD" == "password" ]]; then
    replace_config "PasswordAuthentication" "PasswordAuthentication yes" "/etc/ssh/sshd_config"
fi

# Commenting duplicates in 50-cloud-init.conf (if the file exists)
for conf_file in /etc/ssh/sshd_config.d/*.conf; do
    [ -f "$conf_file" ] && \
    sed -i -E 's/^(Port|PermitRootLogin|PubkeyAuthentication|PasswordAuthentication)/# \1/' "$conf_file"
done

# Configure fail2ban
if [[ "$AUTH_METHOD" == "password" ]]; then
    fail2ban_config_file="/etc/fail2ban/jail.d/sshd.conf"
    tee "$fail2ban_config_file" >/dev/null <<EOF
[sshd]
enabled = true
maxretry = 3
findtime = 10m
bantime = 1h
port = $new_ssh_port
EOF
    systemctl enable --now fail2ban.service >/dev/null 2>&1
fi

# Configure firewall
echo -e "${GREEN}[$progress_tag]${NC} Configuring UFW.."
ufw limit "$new_ssh_port/tcp" >/dev/null

# Checking if there is .bashrc. If not, making a new one
bashrc_file="/home/$new_user_name/.bashrc"

if [ ! -f "$bashrc_file" ]; then
    touch "$bashrc_file"
    chown "$new_user_name:$new_user_name" "$bashrc_file"
fi

# Array of aliases
declare -A aliases=(
    ["export EDITOR="]="export EDITOR=nano"
    ["alias cls="]="alias cls='clear'"
    ["alias сды="]="alias сды='clear'"
    ["alias act="]="alias act='source venv/bin/activate'"
    ["alias x="]="alias x='exit'"
    ["alias cp="]="alias cp='cp -i'"
    ["alias mv="]="alias mv='mv -i'"
    ["alias rm="]="alias rm='rm -i'"
    ["alias hr="]="alias hr='numfmt --to=iec --suffix=b'"
    ["listen()"]='listen() { sudo ss -tulnp | grep ":$1"; }'
    ["alias portgen="]="alias portgen='echo \$(shuf -i 1024-9999 -n 10)'"
    ["passgen()"]='passgen() {
    tr -dc '"'"'A-Za-z0-9!@#$%^&*()_+'"'"' < /dev/urandom | head -c "${1:-16}"
    echo
}'
    ["ipinfo()"]='ipinfo() {
  [[ -z "$1" ]] && { echo "usage: ipinfo [ip|domain]"; return 1; }
  local target="$1"
  local ip
  if [[ "$target" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    ip="$target"
  elif [[ "$target" =~ : ]]; then
    ip="$target"
  else
    local ips
    mapfile -t ips < <(host "$target" 2>/dev/null | awk '"'"'/has address/{print $NF} /has IPv6 address/{print $NF}'"'"')
    [[ ${#ips[@]} -eq 0 ]] && { echo "error: could not resolve '"'"'$target'"'"'"; return 1; }
    if [[ ${#ips[@]} -gt 1 ]]; then
      echo "found ${#ips[@]} addresses for '"'"'$target'"'"':"
      for i in "${!ips[@]}"; do
        echo "  ${ips[$i]}"
      done
      echo
    fi
    ip="${ips[0]}"
  fi
  curl -s "https://ipinfo.io/$ip" | jq .
}'
)

grep -Fxq "# === Custom Aliases ===" "$bashrc_file" || {
    [ -s "$bashrc_file" ] && echo -e "\n# === Custom Aliases ===" || echo "# === Custom Aliases ==="
} >> "$bashrc_file"

# Adding aliases
for pattern in "${!aliases[@]}"; do
    grep -qF "$pattern" "$bashrc_file" || echo "${aliases[$pattern]}" >> "$bashrc_file"
done

# Checking if the specified time zone exists
if timedatectl set-timezone "$timezone" >/dev/null 2>&1; then
  echo -e "${GREEN}[$progress_tag]${NC} Configuring the time zone.."
else
  echo -e "${RED}[ERROR]${NC} Time zone '$timezone' not found!" >&2
  echo -e "${YELLOW}[INFO]${NC} Available time zones: timedatectl list-timezones | grep -i 'your_region'" >&2
fi

# Configure hostname
hostnamectl set-hostname "$new_hostname"
if grep -q "^127.0.1.1" /etc/hosts; then
    sed -i "s/^127.0.1.1.*/127.0.1.1 $new_hostname/" /etc/hosts
else
    echo "127.0.1.1 $new_hostname" >> /etc/hosts
fi

# Changing TCP Congestion Control
echo -e "${GREEN}[$progress_tag]${NC} Configuring TCP BBR and FQ.."
{
    echo "net.core.default_qdisc=fq"
    echo "net.ipv4.tcp_congestion_control=bbr"
} | tee /etc/sysctl.d/90-bbr.conf >/dev/null

sysctl -p /etc/sysctl.d/90-bbr.conf >/dev/null

# Systemd Journal
journal_system_max_use='50M'
sed -i '/^#*SystemMaxUse=/d' /etc/systemd/journald.conf
echo "SystemMaxUse=$journal_system_max_use" | tee -a /etc/systemd/journald.conf >/dev/null
systemctl restart systemd-journald

# Creating systemd service startup-notify.service
if [[ "${setup_ntfy}" == "yes" ]]; then
    echo -e "${GREEN}[$progress_tag]${NC} Configuring NTFY notifications on server startup.."

    tee /etc/systemd/system/startup-notify.service >/dev/null <<EOF
[Unit]
Description=Send NTFY notification on startup
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c '/usr/bin/curl -m 10 -H "prio:default" -H "tags:${ntfy_startup_tag:-system}" -d "\$(hostname) has successfully started" "https://ntfy.sh/${ntfy_startup_topic}"'
User=root

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable startup-notify.service >/dev/null 2>&1
fi

# Creating low-disk-space-notify.sh script
if [[ "${setup_disk_monitor:-no}" == "yes" && -n "${ntfy_disk_topic:-}" ]]; then
    echo -e "${GREEN}[$progress_tag]${NC} Configuring disk space monitoring.."

    scripts_dir="/home/${new_user_name}/scripts"
    mkdir -p "$scripts_dir"
    touch "${scripts_dir}/low-disk-space-notify.sh"
    chown "${new_user_name}:${new_user_name}" "$scripts_dir"
    chmod 755 "$scripts_dir"

    cat > "${scripts_dir}/low-disk-space-notify.sh" <<EOF
#!/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Disk usage threshold (in percent)
THRESHOLD=$disk_threshold
# List of monitored mount points (space-separated)
MONITORED_MOUNTS="/"

# Checking usage of specified disks
for mount in \$MONITORED_MOUNTS; do
output=\$(df -H | grep -E "[[:space:]]\${mount}$")
if [ -n "\$output" ]; then
  usep=\$(echo "\$output" | awk '{ print \$5}' | cut -d'%' -f1)
  if [ "\$usep" -ge \$THRESHOLD ]; then
    echo "\$(date): Disk usage on \$(hostname) for \$mount is \$usep%"
    curl -m 10 -H "Title: \$(hostname) running out of space" \\
    -H "Priority: high" \\
    -H "Tags: warning" \\
    -d "\$(hostname) is almost out of disk space on '\$mount' (\$usep%)" \\
    https://ntfy.sh/$ntfy_disk_topic >/dev/null 2>&1
  fi
else
  echo "\$(date): Mount point \$mount not found on \$(hostname)"
fi
done
EOF
    chmod +x "${scripts_dir}/low-disk-space-notify.sh"
    chown "${new_user_name}:${new_user_name}" "${scripts_dir}/low-disk-space-notify.sh"

### Systemd service
    tee /etc/systemd/system/low-disk-space-notify.service >/dev/null <<EOF
[Unit]
Description=Disk Space Monitor Service
After=network.target

[Service]
Type=oneshot
User=${new_user_name}
ExecStart=${scripts_dir}/low-disk-space-notify.sh
EOF

### Systemd timer
    tee /etc/systemd/system/low-disk-space-notify.timer >/dev/null <<EOF
[Unit]
Description=Run Disk Space Monitor every 15 minutes

[Timer]
OnCalendar=*:0/15
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now low-disk-space-notify.timer >/dev/null 2>&1
fi

# Restarting services
systemctl daemon-reload

# Validate SSH configuration before restarting
if ! sshd -t; then
    echo -e "${RED}[CRITICAL] SSH configuration test failed!${NC}"
    ufw disable >/dev/null 2>&1
    echo "SSH was not restarted. UFW disabled."

    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.broken
    cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    echo "Unfortunately, this error requires edits to the script after identifying the problem by 'sshd -t -f /etc/ssh/sshd_config.broken'"

    echo "The main config '/etc/ssh/sshd_config' has been restored."
    exit 1
fi

if ! systemctl restart ssh >/dev/null; then
    echo -e "${RED}[CRITICAL]${NC} Failed to restart SSH service!"
    ufw disable >/dev/null 2>&1

    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.broken
    cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config

    # Restart sshd with the restored config
    if systemctl restart ssh >/dev/null 2>&1; then
        echo "Config restored, SSH restarted with the original config (old port)."
    else
        echo -e "${RED}SSH is still not running!${NC} Use the provider console: systemctl status ssh"
    fi
    exit 1
fi

systemctl enable ssh >/dev/null 2>&1

ufw default deny incoming >/dev/null
ufw --force enable >/dev/null

if [[ "$AUTH_METHOD" == "password" ]]; then
    systemctl restart fail2ban.service >/dev/null 2>&1
    sleep 1
fi

# Clear sensitive variable from memory
unset root_password new_user_password public_ssh_key root_password_confirm new_user_password_confirm

print_check() {
    if [ "$1" -eq 0 ]; then
        echo -e "${GREEN}[OK]${NC} $2"
    elif [ "$1" -eq 2 ]; then
        echo -e "${L_YELLOW}[WARN]${NC} $2"
    else
        echo -e "${RED}[FAIL]${NC} $2"
    fi
}

# Small check of main server settings
printf '\033[H\033[2J'
echo -e "\nCompletion check..\n"

systemctl is-enabled ssh | grep -qi "enabled"
print_check $? "SSH server is set to enabled"

ufw status | grep -qi "Status: active"
print_check $? "UFW is running"

systemctl is-enabled ufw | grep -qi "enabled"
print_check $? "UFW is enabled on boot"

LC_ALL=C ufw status verbose | grep -qi "deny (incoming)"
print_check $? "UFW default policy is deny (incoming)"

grep -qE "^Port $new_ssh_port( |$)" /etc/ssh/sshd_config
print_check $? "SSH port: $new_ssh_port"

ss -tlnp | grep sshd | grep -qE ":$new_ssh_port( |$)"
print_check $? "sshd is listening on port $new_ssh_port"

iptables -S | grep -qE -- "--dport $new_ssh_port( |$)"
print_check $? "Port $new_ssh_port is open in the kernel firewall"

sshd -T 2>/dev/null | grep -i permitrootlogin | grep -qiw "no"
print_check $? "Root login over SSH disabled"

if [[ "$AUTH_METHOD" == "key" ]]; then
    sshd -T 2>/dev/null | grep -i passwordAuthentication | grep -qw "no"
    print_check $? "Password authentication disabled"

    sshd -T 2>/dev/null | grep -i pubkeyAuthentication | grep -qiw "yes"
    print_check $? "SSH key authentication enabled"

    [ -f "/home/$new_user_name/.ssh/authorized_keys" ] && [ -s "/home/$new_user_name/.ssh/authorized_keys" ]
    print_check $? "Public SSH key successfully added to user $new_user_name"
fi

if [[ "$AUTH_METHOD" == "password" ]]; then
    sshd -T 2>/dev/null | grep -i passwordAuthentication | grep -qw "yes"
    print_check $? "${L_YELLOW}Password authentication enabled${NC}"

    systemctl is-active fail2ban | grep -qiw "active"
    print_check $? "fail2ban is running"

    # Check that the sshd jail is actually responding and monitoring something
    if fail2ban-client status sshd >/dev/null 2>&1; then
        # Additionally check whether journalmatch or logpath is present
        journal_match=$(fail2ban-client get sshd journalmatch 2>/dev/null || true)
        logpath=$(fail2ban-client get sshd logpath 2>/dev/null || true)

        if [[ -n "$journal_match" && "$journal_match" != *"(none)"* ]] || \
           [[ -n "$logpath" && "$logpath" != *"No file is currently monitored"* ]]; then
            print_check 0 "fail2ban is monitoring SSH logs"
        else
            print_check 1 "fail2ban jail is running, but no log source detected"
        fi
    else
        print_check 1 "fail2ban sshd jail is not responding"
    fi

    systemctl is-enabled fail2ban | grep -qi "enabled"
    print_check $? "fail2ban service is enabled on boot"

    # nftables should not normally be enabled when using UFW
    nftables_enabled=0
    systemctl is-enabled nftables.service >/dev/null 2>&1 && nftables_enabled=1
    systemctl is-active  nftables.service >/dev/null 2>&1 && nftables_enabled=1

    if [ "$nftables_enabled" -eq 1 ]; then
        print_check 2 "${L_YELLOW}nftables.service is enabled/active.${NC}"
        echo -e "      It can conflict with UFW (and sometimes with fail2ban)."
        echo -e "      Consider disabling it: systemctl disable --now nftables"
    else
        # print_check 0 "nftables is not enabled"
        :
    fi
fi

sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -qi "bbr"
print_check $? "TCP congestion control set to BBR"

sysctl net.core.default_qdisc 2>/dev/null | grep -qiw "fq"
print_check $? "Default qdisc set to FQ"

# Finishing
# Server info summary
pad() { printf "%-30.30s" "$1"; }
echo -e "\n  ${BLUE}- - - - - - - - - - - - - -${NC}"
echo -e "    ${GREEN}Server setup completed${NC}"
echo -e "  ${BLUE}- - - - - - - - - - - - - -${NC}"
echo -e "  Hostname : $(pad "$(hostname)")"
echo -e "  OS       : $(pad "$(. /etc/os-release && echo "$PRETTY_NAME")")"
echo -e "  Kernel   : $(pad "$(uname -r)")"
echo -e "  Uptime   : $(pad "$(uptime -p | sed 's/up //')")"
echo -e "  CPU      : $(pad "$(nproc) cores")"
echo -e "  RAM      : $(pad "$(free -h | awk '/^Mem/{print $2}')")"
echo -e "  Disk     : $(pad "$(df -h / | awk 'NR==2{print $2}')")"
echo -e "  ${BLUE}- - - - - - - - - - - - - -${NC}"

# Get server IP to form connection link
server_ip=$(curl -s --max-time 5 ident.me || { hostname -I | awk '{print $1}'; })

# Count script runs using hitscounter.dev
api_url="https://hitscounter.dev/api/hit?url=https%3A%2F%2Fraw.githubusercontent.com%2Faiovin%2Flazy-vps%2Frefs%2Fheads%2Fmain%2Fsetup.sh"

if [[ "$NOHIT" == "yes" ]]; then
    total_runs="disabled"
else
    hit_response=$(curl -s --max-time 10 "$api_url" 2>/dev/null || true)
    total_runs=$(grep -oP '<title>\K[0-9]+ / [0-9]+' <<< "$hit_response" | awk '{print $3}' || true)
    if ! [[ "$total_runs" =~ ^[0-9]+$ ]]; then
        total_runs="unavailable"
    fi
fi

echo -e "\nTotal script runs - $total_runs. Thanks for using it!"

echo -e "\nYour connection command:"

if [[ "$AUTH_METHOD" == "key" ]]; then
    echo -e "${PURPLE}ssh -i ~/.ssh/$new_hostname/id_ed25519_$new_hostname -p $new_ssh_port $new_user_name@$server_ip${NC}"
elif [[ "$AUTH_METHOD" == "password" ]]; then
    echo -e "${PURPLE}ssh -p $new_ssh_port $new_user_name@$server_ip${NC}"
fi

echo
echo -e "To enhance usability, you can add the following lines in your ${YELLOW}SSH configuration file${NC} (~/.ssh/config):"
echo
echo -e "${YELLOW}Host $new_hostname"
echo -e "    HostName $server_ip"
echo -e "    ServerAliveInterval 30"
echo -e "    ServerAliveCountMax 3"
echo -e "    User $new_user_name"
echo -e "    Port $new_ssh_port${NC}"

[[ "$AUTH_METHOD" == "key" ]] && echo -e "    ${YELLOW}IdentityFile ~/.ssh/$new_hostname/id_ed25519_$new_hostname${NC}"

echo
echo -e "Afterwards, you can connect to the server using the command '${YELLOW}ssh $new_hostname${NC}'\n"

# Warning to check connection
echo -e "\033[1;31mAttention!${NC}"
echo "Do not disconnect from the current session until you test the new connection."
echo "Make sure it works. After that, reboot the server."

if [[ "$AUTH_METHOD" == "password" ]]; then
    echo
    echo -e "${L_YELLOW}Security notice (password authentication):${NC}"
    echo "Your password is now the only barrier to SSH access, and it is also used for sudo."
    echo "fail2ban slows down brute-force attacks, but it cannot protect a weak password."
fi

echo -e "
${L_YELLOW}Note:${NC} For an additional security check of your server,
you can run the ${BLUE}VPS-Audit${NC} script developed by Vernu.
This tool provides an extra layer of verification for various aspects of your system's security.

${BLUE}curl -Ls https://raw.githubusercontent.com/vernu/vps-audit/main/vps-audit.sh | sudo bash${NC}"
