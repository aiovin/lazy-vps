#!/bin/bash
# https://github.com/aiovin/lazy-vps

# Enable strict mode, but don't exit the script on errors
set -uo pipefail

# Function to handle errors
handle_error() {
    echo -e "\033[31mSomething went wrong on line $1.\033[0m Please describe the issue here: https://kutt.it/problem"
}

# Set trap to catch errors and call the error handling function, but don't exit the script
trap 'handle_error $LINENO' ERR

# System check
if ! [ -d "/run/systemd/system" ] || ! [ "$(ps -p 1 -o comm=)" = "systemd" ]; then
    echo "This script requires a systemd-based system (Ubuntu/Debian)."
    exit 1
fi

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root or with root privileges." 
  exit 1
fi

# A variable to run the script without script run counter (for creator's test purpose)
NOHIT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -nohit) NOHIT="yes" ;;
        -*)   echo "Invalid option: $1"; exit 1 ;;
    esac
    shift
done

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
L_YELLOW='\033[1;33m'
RED='\033[0;31m'
PURPLE='\033[95m'
BLUE='\033[1;34m'
NC='\033[0m' # No Color

# Install necessary packages
echo "Updating the system.."

apt-get update >/dev/null
apt-get upgrade -y >/dev/null

echo -e "Starting server setup..\n"

# Меняем root пароль
echo "Changing the root password."
while true; do
    while true; do
        read -sp "Enter a new password for root: " root_password
        echo
        if [ -z "$root_password" ]; then
            echo -e "\nError: Password cannot be empty. Try again."
        else
            break
        fi
    done

    while true; do
        read -sp "Repeat the new password for root: " root_password_confirm
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
echo -e "\nCreating a new user."
while true; do
    read -p "Enter username: " new_user_name
    
    if [ -z "$new_user_name" ]; then
        echo -e "\nError: Username cannot be empty. Try again."
        continue
    fi
    
    if [[ ! "$new_user_name" =~ ^[a-zA-Z_][a-zA-Z0-9_-]*$ ]]; then
        echo -e "\nError: Username contains invalid characters. Username can only contain letters, numbers, hyphens, and underscores. It must also start with a letter or underscore. Try again."
    else
        break
    fi
done

echo
while true; do
    while true; do
        read -sp "Set a password for user $new_user_name: " new_user_password
        echo
        if [ -z "$new_user_password" ]; then
            echo -e "\nError: Password cannot be empty. Try again."
        else
            break
        fi
    done

    while true; do
        read -sp "Repeat the password for user $new_user_name: " new_user_password_confirm
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
    read -p "Enter a new SSH port (between 1024 and 65535). Press Enter to generate a random port: " new_ssh_port

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
read -p "Specify the timezone (e.g., Europe/Moscow). For reference, visit: https://wikipedia.org/wiki/List_of_tz_database_time_zones). Press Enter to set UTC by default: " timezone
timezone=${timezone:-"Etc/UTC"}
echo "Timezone set to: $timezone"

# Set a new server name
current_hostname=$(hostname)
echo
while true; do
    read -p "Enter a new hostname (Press Enter to keep '$current_hostname'): " new_hostname

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
    read -p "Enter your public SSH key (Right-click to paste from clipboard): " public_ssh_key

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

# Нагло устанавливаем максимальный размер системных журналов не спрашивая пользователя. (Зачем, есть же logrotate? Не забыть удалить это..)
journal_system_max_use='250M'

echo
read -p "Do you want to configure ntfy notifications about server startup? (y/n, Enter for 'n') " setup_ntfy
setup_ntfy=${setup_ntfy:-n}

if [[ "$setup_ntfy" =~ ^[Yy]$ ]]; then
    read -p "Enter tag for ntfy (Press Enter to set 'computer'): " ntfy_startup_tag
    ntfy_startup_tag=${ntfy_startup_tag:-'computer'}
    read -p "Enter your ntfy topic (Press Enter to generate 'server-startup-<6-random-digits>'): " ntfy_startup_topic
    ntfy_startup_topic=${ntfy_startup_topic:-"server-startup-$(shuf -i 100000-999999 -n 1)"}
    echo "Startup ntfy notifications with tag '$ntfy_startup_tag' and topic '$ntfy_startup_topic' has configured."
    setup_ntfy="yes"
else
    echo "The server startup notifications will not be set up."
    setup_ntfy="no"
fi

echo
read -p "Do you want to configure ntfy notifications about low disk space? (y/n, Enter for 'n'): " setup_disk_monitor
setup_disk_monitor=${setup_disk_monitor:-n}

if [[ "$setup_disk_monitor" =~ ^[Yy]$ ]]; then
    read -p "Enter your ntfy topic (Press Enter to generate 'server-misc-<6-random-digits>'): " ntfy_disk_topic
    ntfy_disk_topic=${ntfy_disk_topic:-"server-misc-$(shuf -i 100000-999999 -n 1)"}
    read -p "Enter threshold from 0 to 100 (percent) at which the notification will be sent. Press Enter for '90': " disk_threshold
    disk_threshold=${disk_threshold:-90}

    while [[ "$disk_threshold" -lt 0 || "$disk_threshold" -gt 100 ]]; do
        echo -e "\nError: Threshold must be between 0 and 100."
        read -p "Enter threshold for low disk space notifications: " disk_threshold
    done

    echo -e "\nntfy notifications to '$ntfy_disk_topic' when disk space reaches $disk_threshold% has configured."
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
    read -p "Begin server configuration? (y/n): " confirm
    case $confirm in
        [Yy]* ) echo "Great, lets start.."; break;;
        [Nn]* ) echo -e "Exit.\n"; exit 0;;
        * ) echo -e "\nPlease enter 'y' to begin server configuration or 'n' to exit.";;
    esac
done
echo

progress_tag=">"

# Function to install basic utilities
install_packages() {
    echo -e "${GREEN}[$progress_tag]${NC} Installing basic utilities: $*"
    apt-get install -y "$@" >/dev/null 2>&1
}

# Install basic utilities
install_packages \
    sudo \
    nano \
    ufw \
    curl \
    htop \
    gzip \
    logrotate \
    bash-completion \
    jq \
    neofetch

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
echo -e "${GREEN}[$progress_tag]${NC} Creating a new user '$new_user_name'.."
if ! id "$new_user_name" &>/dev/null; then
    useradd -m -s /bin/bash "$new_user_name"
    echo "$new_user_name:$new_user_password" | chpasswd
    usermod -aG sudo "$new_user_name"
else
    echo -e "${YELLOW}[WARN]${NC} User '$new_user_name' already exist, skipping.."
fi

# Configuring SSH
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

echo -e "${GREEN}[$progress_tag]${NC} Configuring SSH.."
# echo "[NOTE] The backup of the SSH config is stored in '/etc/ssh/sshd_config.bak'"

# The first parameter is the one we are searching for, the second is the replacement, and the third is the file to modify
replace_config "Port" "Port $new_ssh_port" "/etc/ssh/sshd_config"
replace_config "PermitRootLogin" "PermitRootLogin no" "/etc/ssh/sshd_config"
replace_config "PasswordAuthentication" "PasswordAuthentication no" "/etc/ssh/sshd_config"
replace_config "PubkeyAuthentication" "PubkeyAuthentication yes" "/etc/ssh/sshd_config"

# Adding SSH key
user_ssh_dir="/home/$new_user_name/.ssh"
echo -e "${GREEN}[$progress_tag]${NC} Adding SSH key.."
mkdir -p "$user_ssh_dir"
echo "$public_ssh_key" > "$user_ssh_dir/authorized_keys"
chmod 700 "$user_ssh_dir"
chmod 600 "$user_ssh_dir/authorized_keys"
chown -R "$new_user_name:$new_user_name" "$user_ssh_dir"

# Commenting duplicates in 50-cloud-init.conf (if the file exists)
cloud_init_file="/etc/ssh/sshd_config.d/50-cloud-init.conf"
if [ -f "$cloud_init_file" ]; then
    sed -i -E 's/^(Port|PermitRootLogin|PubkeyAuthentication|PasswordAuthentication)/# \1/' "$cloud_init_file"
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
    ["alias cls="]="alias cls='clear'"
    ["alias сды="]="alias сды='clear'"
    ["alias act="]="alias act='source venv/bin/activate'"
    ["alias x="]="alias x='exit'"
    ["export EDITOR="]="export EDITOR=nano"
    ["alias tb="]='alias tb="nc termbin.com 9999"'
    ["listen()"]='listen() { sudo ss -tulnp | grep ":$1"; }'
    ["alias wtt="]='alias wtt="curl -s wttr.in/Moscow?format=\"%l:+%t+%C+(Feels+like+%f)\n\""'
    ["alias zenquote="]='alias zenquote="curl -s \"https://zenquotes.io/api/random\" | jq -r \".[0].q\""'
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
echo -e "${GREEN}[$progress_tag]${NC} Configuring TCP BBR.."
{
    echo "net.core.default_qdisc=fq"
    echo "net.ipv4.tcp_congestion_control=bbr"
} | tee /etc/sysctl.d/90-bbr.conf >/dev/null

sysctl -p /etc/sysctl.d/90-bbr.conf >/dev/null

# Systemd Journal
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
ExecStart=/bin/sh -c '/usr/bin/curl -H "prio:default" -H "tags:${ntfy_startup_tag:-system}" -d "\$(hostname) started" "https://ntfy.sh/${ntfy_startup_topic}"'
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
    touch ${scripts_dir}/low-disk-space-notify.sh
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
output=\$(df -H | grep -E "\s\${mount}$")
if [ -n "\$output" ]; then
  usep=\$(echo "\$output" | awk '{ print \$5}' | cut -d'%' -f1)
  if [ "\$usep" -ge \$THRESHOLD ]; then
    echo "\$(date): Disk usage on \$(hostname) for \$mount is \$usep%"
    curl -H "Title: \$(hostname) running out of space" \\
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
systemctl restart ssh >/dev/null
systemctl enable ssh >/dev/null 2>&1

ufw reload >/dev/null
ufw --force enable >/dev/null

# Clear sensitive variable from memory
unset root_password new_user_password public_ssh_key

echo
runuser -u $new_user_name -- neofetch

print_check() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}[OK]${NC} $2"
    else
        echo -e "${RED}[FAIL]${NC} $2"
    fi
}

# Small check of main server settings
echo -e "Completion check..\n"

systemctl is-enabled ssh | grep -q "enabled"
print_check $? "SSH server is set to enabled"

ufw status | grep -q "Status: active"
print_check $? "UFW is running"

grep -q "^Port $new_ssh_port" /etc/ssh/sshd_config
print_check $? "SSH port: $new_ssh_port"

ufw status | grep -q "$new_ssh_port/tcp"
print_check $? "Port $new_ssh_port is open"

systemctl is-enabled ufw | grep -q "enabled"
print_check $? "UFW is set to enabled"

grep -q "^PermitRootLogin no" /etc/ssh/sshd_config
print_check $? "Root login disabled"

grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config
print_check $? "Password authentication disabled"

grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config
print_check $? "SSH key authentication enabled"

[ -f "/home/$new_user_name/.ssh/authorized_keys" ] && [ -s "/home/$new_user_name/.ssh/authorized_keys" ]
print_check $? "Public SSH key successfully added to user $new_user_name"

# Ensure conflicting settings are commented out
echo "Contents of 50-cloud-init.conf:"
if [ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]; then
    sed 's/^/    /' /etc/ssh/sshd_config.d/50-cloud-init.conf
else
    echo -e "\e[31m[FAIL]\e[0m File 50-cloud-init.conf not found"
fi

sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"
check_status=$?
print_check $check_status "TCP congestion control set to BBR"

# Finishing

# Get server IP to form connection link
server_ip=$(curl -s --max-time 5 ident.me || hostname -I | awk '{print $1}')

# Count script runs using hitscounter.dev
if ! mktemp -u --suffix=RRC &>/dev/null; then
    count_file=$(mktemp)
else
    count_file=$(mktemp --suffix=RRC)
fi

api_url="https://hitscounter.dev/api/hit?url=https%3A%2F%2Fraw.githubusercontent.com%2Faiovin%2Flazy-vps%2Frefs%2Fheads%2Fmain%2Fsetup-ba.sh"

if [[ "$NOHIT" == "yes" ]]; then
    total_runs="disabled"
else
    curl -s --max-time 10 "$api_url" > "$count_file" 2>/dev/null
    total_runs=$(grep -oP '<title>\K[0-9]+ / [0-9]+' "$count_file" | awk '{print $3}')
    if ! [[ "$total_runs" =~ ^[0-9]+$ ]]; then
        total_runs="smth_went_wrong_lol"
    fi
fi

echo -e "\n${GREEN}Server setup completed.${NC}"
echo "Total script runs - $total_runs. Thanks for using it!"

echo -e "\nYour connection command:"
echo -e "${PURPLE}ssh -i ~/.ssh/$new_hostname/id_ed25519_$new_hostname -p $new_ssh_port $new_user_name@$server_ip${NC}"
echo
echo -e "To enhance usability, you can add the following lines in your ${YELLOW}SSH configuration file${NC} (~/.ssh/config):"
echo
echo -e "${YELLOW}Host $new_hostname"
echo -e "    HostName $server_ip"
echo -e "    ServerAliveInterval 30"
echo -e "    ServerAliveCountMax 3"
echo -e "    User $new_user_name"
echo -e "    Port $new_ssh_port"
echo -e "    IdentityFile ~/.ssh/$new_hostname/id_ed25519_$new_hostname${NC}"
echo
echo -e "Afterwards, you can connect to the server using the command '${YELLOW}ssh $new_hostname${NC}'\n"

# Warning to check connection
echo -e "\033[1;31mAttention!${NC}"
echo "Do not disconnect from the current session until you test the new connection."
echo "Make sure it works. After that, reboot the server."
# Perhaps you shouldn't..
# echo -e "\nVisit author's site: https://150452.xyz"

echo -e "
${L_YELLOW}Note:${NC} For an additional security check of your server,
you can run the ${BLUE}VPS-Audit${NC} script developed by Vernu.
This tool provides an extra layer of verification for various aspects of your system's security.

${BLUE}curl -Ls https://raw.githubusercontent.com/vernu/vps-audit/main/vps-audit.sh | sudo bash${NC}"
