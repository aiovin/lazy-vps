#!/bin/bash
# https://github.com/aiovin/lazy-vps

# Strict error handling
set -euo pipefail
trap 'echo -e "\033[31mSomething went wrong on line $LINENO.\033[0m Please describe the issue here: https://kutt.it/problem"; exit 1' ERR

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

# Install necessary packages
echo "Updating the system and installing dependencies.."
apt update && apt upgrade -y && apt install ansible python3 python3-passlib -y

# Create working directory for Ansible
echo -e "\nCreating Ansible working directory (/root/ansible).."
mkdir -p /root/ansible
cd /root/ansible

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
echo -e "You can use these commands for \e[1;34mPowerShell\e[0m:"
echo
echo "# Create a folder."
echo -e "\e[1;34mif (-not (Test-Path -Path \$env:USERPROFILE\.ssh\\\\$new_hostname)) {\e[0m"
echo -e "\e[1;34m    New-Item -Path \$env:USERPROFILE\.ssh\\\\$new_hostname -ItemType Directory\e[0m"
echo -e "\e[1;34m}\e[0m"
echo
echo "# Generate an SSH key pair."
echo -e "\e[1;34mssh-keygen -t ed25519 -f \$env:USERPROFILE\\.ssh\\\\$new_hostname\\id_ed25519_$new_hostname\e[0m"
echo
echo "# Copy the public key to clipboard."
echo -e "\e[1;34mGet-Content ~/.ssh/$new_hostname/id_ed25519_$new_hostname.pub | clip\e[0m"
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
    ntfy_startup_tag=""
    ntfy_startup_topic=""
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
    echo "By default '/' is monitored. Add other mount points if needed lated:"
    echo "/home/$new_user_name/scripts/low-disk-space-notify.sh"
    setup_disk_monitor="yes"
else
    echo "The script will not be installed."
    ntfy_disk_topic=""
    disk_threshold=""
    setup_disk_monitor="no"
fi

# Request Vault password
echo
while true; do
    while true; do
        read -sp "Set a Vault password (you'll need to enter it once below to run Ansible): " vault_password
        echo
        if [ -z "$vault_password" ]; then
            echo -e "\nError: Vault password cannot be empty. Try again."
        else
            break
        fi
    done

    while true; do
        read -sp "Repeat Vault password: " vault_password_confirm
        echo
        if [ -z "$vault_password_confirm" ]; then
            echo -e "\nError: Vault password confirmation cannot be empty. Try again."
        else
            break
        fi
    done

    if [ "$vault_password" != "$vault_password_confirm" ]; then
        echo -e "\nPasswords do not match. Try again."
    else
        echo "Vault password successfully set."
        break
    fi
done

# Create a temporary file with Vault password
vault_password_file=$(mktemp)
echo "$vault_password" > "$vault_password_file"

# Create encrypted file
echo -e "\nCreating secrets.yml.."
cat > secrets.yml <<EOL
new_user_name: "$new_user_name"
new_user_password: "$new_user_password"
new_ssh_port: "$new_ssh_port"
root_password: "$root_password"
timezone: "$timezone"
new_hostname: "$new_hostname"
public_ssh_key: "$public_ssh_key"
journal_system_max_use: "$journal_system_max_use"
EOL

# Add variables to secrets.yml only if they were created
[[ -n "$ntfy_startup_tag" ]] && echo "ntfy_startup_tag: \"$ntfy_startup_tag\"" >> secrets.yml
[[ -n "$ntfy_startup_topic" ]] && echo "ntfy_startup_topic: \"$ntfy_startup_topic\"" >> secrets.yml

[[ -n "$ntfy_disk_topic" ]] && echo "ntfy_disk_topic: \"$ntfy_disk_topic\"" >> secrets.yml
[[ -n "$disk_threshold" ]] && echo "disk_threshold: \"$disk_threshold\"" >> secrets.yml

# Encrypt file
ansible-vault encrypt --vault-password-file "$vault_password_file" secrets.yml

# Clear sensitive variable from memory
unset root_password new_user_password vault_password

# Remove temporary file with password
rm -f "$vault_password_file"
echo "secrets.yml successfully created."

echo "Creating inventory_file.yml and setup_server.yml.."

# Create inventory_file.yml
cat > inventory_file.yml <<EOL
localhost ansible_connection=local
EOL

# Create playbook setup_server.yml
cat > setup_server.yml <<'EOL'
---
- hosts: all
  become: yes
  vars_files:
    - secrets.yml

  tasks:
    - block:
        - name: Updating package list
          apt:
            update_cache: yes
            cache_valid_time: 3600

        - name: Installing basic utilities
          apt:
            name:
              - sudo
              - nano
              - ufw
              - htop
              - gzip
              - logrotate
              - python3-pip
              - python3-venv
              - bash-completion
              - neofetch
            state: present

        - name: Changing root password
          user:
            name: root
            password: "{{ root_password | password_hash('sha512') }}"

        - name: Creating a new user
          user:
            name: "{{ new_user_name }}"
            password: "{{ new_user_password | password_hash('sha512') }}"
            shell: /bin/bash
            create_home: yes

        - name: Adding new user to sudo group
          user:
            name: "{{ new_user_name }}"
            groups: sudo
            append: yes

        - name: Creating .ssh directory for the new user
          file:
            path: "/home/{{ new_user_name }}/.ssh"
            state: directory
            owner: "{{ new_user_name }}"
            group: "{{ new_user_name }}"
            mode: '0700'

        - name: Adding SSH key to authorized_keys
          authorized_key:
            user: "{{ new_user_name }}"
            key: "{{ public_ssh_key }}"
            state: present

        - name: Setting permissions on authorized_keys
          file:
            path: "/home/{{ new_user_name }}/.ssh/authorized_keys"
            state: file
            owner: "{{ new_user_name }}"
            group: "{{ new_user_name }}"
            mode: '0600'

        - name: Changing SSH port
          lineinfile:
            path: /etc/ssh/sshd_config
            regexp: '^#?Port'
            line: 'Port {{ new_ssh_port }}'
            state: present

        - name: Opening new SSH port
          ufw:
            rule: limit
            port: "{{ new_ssh_port }}"
            proto: tcp
            state: enabled

        - name: Disabling root login
          lineinfile:
            path: /etc/ssh/sshd_config
            regexp: '^#?PermitRootLogin'
            line: 'PermitRootLogin no'
            state: present

        - name: Disabling password authentication
          lineinfile:
            path: /etc/ssh/sshd_config
            regexp: '^#?PasswordAuthentication'
            line: 'PasswordAuthentication no'
            state: present

        - name: Enabling SSH key authentication
          lineinfile:
            path: /etc/ssh/sshd_config
            regexp: '^#?PubkeyAuthentication'
            line: 'PubkeyAuthentication yes'
            state: present

        - name: Checking for 50-cloud-init.conf
          stat:
            path: /etc/ssh/sshd_config.d/50-cloud-init.conf
          register: cloud_init_file

        - name: Commenting out possible duplicate entries in 50-cloud-init.conf
          replace:
            path: /etc/ssh/sshd_config.d/50-cloud-init.conf
            regexp: '^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)'
            replace: '# \1'
          when: cloud_init_file.stat.exists

        - name: Adding useful aliases to ~/.bashrc
          blockinfile:
            path: "/home/{{ new_user_name }}/.bashrc"
            marker: "# {mark} ANSIBLE MANAGED ALIASES"
            block: |
              alias cls='clear'
              alias сды='clear'
              alias act='source venv/bin/activate'
              alias x='exit'
              export EDITOR=nano

        - name: Configuring timezone
          timezone:
            name: "{{ timezone }}"
            ignoreerrors: true

        - name: Changing hostname
          hostname:
            name: "{{ new_hostname }}"

        - name: Updating /etc/hosts
          lineinfile:
            path: /etc/hosts
            regexp: '^127.0.1.1'
            line: '127.0.1.1 {{ new_hostname }}'
            state: present

        - name: Changing TCP Congestion Control
          sysctl:
            name: net.core.default_qdisc
            value: fq
            state: present
            reload: yes
            ignoreerrors: true

        - name: Applying BBR changes
          sysctl:
            name: net.ipv4.tcp_congestion_control
            value: bbr
            state: present
            reload: yes
            ignoreerrors: true

        - name: Setting limits on maximum size of system logs
          lineinfile:
            path: /etc/systemd/journald.conf
            regexp: '^#?SystemMaxUse='
            line: 'SystemMaxUse={{ journal_system_max_use }}'
            state: present

        - name: Restarting journald service
          service:
            name: systemd-journald
            state: restarted

        - name: Creating systemd service startup-notify.service
          copy:
            dest: /etc/systemd/system/startup-notify.service
            content: |
              [Unit]
              Description=Send notification on startup
              After=network.target

              [Service]
              Type=oneshot
              ExecStart=/usr/bin/curl -H "prio:default" -H "tags:{{ ntfy_startup_tag }}" -d "{{ new_hostname }} has successfully started" ntfy.sh/{{ ntfy_startup_topic }}
              User=root

              [Install]
              WantedBy=multi-user.target
          when: ntfy_startup_topic is defined

        - name: Enabling startup-notify.service
          systemd:
            name: startup-notify.service
            enabled: yes
          when: ntfy_startup_topic is defined

        - name: Creating user scripts folder (~/scripts)
          file:
            path: /home/{{ new_user_name }}/scripts
            state: directory
            owner: "{{ new_user_name }}"
            group: "{{ new_user_name }}"
            mode: '0755'
          when: ntfy_disk_topic is defined

        - name: Creating low-disk-space-notify.sh script
          copy:
            dest: /home/{{ new_user_name }}/scripts/low-disk-space-notify.sh
            mode: 0755
            owner: "{{ new_user_name }}"
            group: "{{ new_user_name }}"
            content: |
              #!/bin/sh
              PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

              # Disk usage threshold (in percent)
              THRESHOLD={{ disk_threshold }}

              # List of monitored mount points (space-separated)
              MONITORED_MOUNTS="/"

              # Checking usage of specified disks
              for mount in $MONITORED_MOUNTS; do
                output=$(df -H | grep -E "\s${mount}$")
                if [ -n "$output" ]; then
                  usep=$(echo "$output" | awk '{ print $5}' | cut -d'%' -f1)
                  if [ "$usep" -ge $THRESHOLD ]; then
                    echo "$(date): Disk usage on $(hostname) for $mount is $usep%"
                    curl \
                      -H "Title: {{ new_hostname }} running out of space" \
                      -H "Priority: high" \
                      -H "Tags: warning" \
                      -d "{{ new_hostname }} is almost out of disk space on $mount ($usep%)" \
                      https://ntfy.sh/{{ ntfy_disk_topic }} >/dev/null 2>&1
                  fi
                else
                  echo "$(date): Mount point $mount not found on {{ new_hostname }}"
                fi
              done
          when: ntfy_disk_topic is defined

        - name: Creating systemd service low-disk-space-notify.sh.service
          copy:
            dest: /etc/systemd/system/low-disk-space-notify.service
            mode: 0644
            owner: root
            group: root
            content: |
              [Unit]
              Description=Disk Usage Monitor Service
              After=network.target

              [Service]
              Type=simple
              User={{ new_user_name }}
              ExecStart=/home/{{ new_user_name }}/scripts/low-disk-space-notify.sh
              Restart=on-failure

              [Install]
              WantedBy=multi-user.target
          when: ntfy_disk_topic is defined

        - name: Creating low-disk-space-notify.timer (every 15 minutes)
          copy:
            dest: /etc/systemd/system/low-disk-space-notify.timer
            mode: 0644
            owner: root
            group: root
            content: |
              [Unit]
              Description=Run Disk Usage Monitor every 15 minutes

              [Timer]
              OnCalendar=*:0/15
              Persistent=true

              [Install]
              WantedBy=timers.target
          when: ntfy_disk_topic is defined

        - name: Reloading systemd daemon
          systemd:
            daemon_reload: yes

        - name: Enabling low-disk-space-notify.timer
          systemd:
            name: low-disk-space-notify.timer
            enabled: yes
            state: started
          when: ntfy_disk_topic is defined

        - name: Checking logrotate installation
          find:
            paths: /etc/logrotate.d/
            patterns: "*"
            file_type: file
          register: logrotate_d_files

        - name: Information about logrotate
          debug:
            msg: >
              Your logrotate configurations in /etc/logrotate.d/:
              {{
                logrotate_d_files.files | map(attribute='path') | map('basename') | list | join(', ')
              }}.
              Don't forget to add log rotation for your applications.
              More info: https://kutt.it/logrotate 
          when: logrotate_d_files.files is defined and logrotate_d_files.files

        - name: Restarting SSH service
          service:
            name: ssh
            state: restarted
            enabled: yes
          become: yes

        - name: Activating UFW service
          systemd:
            name: ufw
            state: started
            enabled: yes
          become: yes

        - name: skip
          debug:
            msg: Вот такого точно не произойдет!
          when: not (logrotate_d_files.files is defined and logrotate_d_files.files)

      rescue:
        - debug:
            msg: "Something went wrong. Please describe the issue here: https://kutt.it/problem"
EOL
echo "Done."

# Display entered data for confirmation
echo -e "\nPlease confirm your setup:"
echo
echo "New user name: $new_user_name"
echo "SSH port: $new_ssh_port"
echo "Timezone: $timezone"
echo "New hostname: $new_hostname"
echo "Startup notifications: $setup_ntfy"
echo "Low disk spase notifications: $setup_disk_monitor"

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
    read -p "Are all the details correct? (y/n): " confirm
    case $confirm in
        [Yy]* ) echo "Great, running the Ansible playbook to configure the server.."; break;;
        [Nn]* ) echo -e "Exit.\n"; exit 0;;
        * ) echo -e "\nPlease enter 'y' to continue or 'n' to exit.";;
    esac
done
echo

# Run playbook
ansible-playbook -i inventory_file.yml setup_server.yml --diff --ask-vault-pass

runuser -u $new_user_name -- neofetch

print_check() {
    if [ $1 -eq 0 ]; then
        echo -e "\e[32m[OK]\e[0m $2"
    else
        echo -e "\e[31m[FAIL]\e[0m $2"
    fi
}

# Small check of main server settings
echo -e "Checking Ansible work..\n"

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

# Temporarily turning off strict error checking to prevent the script from crashing on some virtual machines
{
    set +e
    sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"
    check_status=$?
    set -e
} || check_status=1

print_check $check_status "TCP congestion control set to BBR"

# Finishing
# Get server IP to form connection link
server_ip=$(curl -s --max-time 5 ident.me || hostname -I | awk '{print $1}')

# Count script runs using hits.seeyoufarm.com
declare total_runs
if ! mktemp -u --suffix=RRC &>/dev/null; then
    count_file=$(mktemp)
else
    count_file=$(mktemp --suffix=RRC)
fi

curl -s --max-time 10 "https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fraw.githubusercontent.com%2Faiovin%2Flazy-vps%2Frefs%2Fheads%2Fmain%2Fsetup.sh&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=hits&edge_flat=false" > "$count_file" || true
total_runs=$(cat "$count_file" | tail -3 | head -n 1 | awk '{print $7}')

if ! [[ "$total_runs" =~ ^[0-9]+$ ]]; then
    total_runs="smth_went_wrong_lol"
fi

echo -e "\n\e[0;32mServer setup completed.\e[0m"
echo "Total script runs - $total_runs. Thanks for using it!"

echo -e "\nYour connection command:"
echo -e "\e[95mssh -i ~/.ssh/$new_hostname/id_ed25519_$new_hostname -p $new_ssh_port $new_user_name@$server_ip\e[0m"
echo
echo -e "To enhance usability, you can add the following lines in your \e[33mSSH configuration file\e[0m (~/.ssh/config):"
echo
echo -e "\e[33mHost $new_hostname"
echo -e "    HostName $server_ip"
echo -e "    ServerAliveInterval 30"
echo -e "    ServerAliveCountMax 3"
echo -e "    User $new_user_name"
echo -e "    Port $new_ssh_port"
echo -e "    IdentityFile ~/.ssh/$new_hostname/id_ed25519_$new_hostname\e[0m"
echo
echo -e "Afterwards, you can connect to the server using the command '\e[33mssh $new_hostname\e[0m'\n"

# Warning to check connection
echo -e "\033[1;31mAttention!\033[0m"
echo "Do not disconnect from the current session until you test the new connection."
echo "Make sure it works. After that, reboot the server."
# Perhaps you shouldn't..
# echo -e "\nVisit author's site: https://150452.xyz"

echo -e "
\033[1;33mNote:\033[0m For an additional security check of your server,
you can run the \e[1;34mVPS-Audit\e[0m script developed by Vernu.
This tool provides an extra layer of verification for various aspects of your system's security.

\e[1;34mcurl -Ls https://raw.githubusercontent.com/vernu/vps-audit/main/vps-audit.sh | sudo bash\e[0m"
