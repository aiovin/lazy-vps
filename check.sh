#!/usr/bin/env bash
# VPS Security Check

GREEN='\033[0;32m'
RED='\033[0;31m'
L_YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m'

print_check() {
    if [ "$1" -eq 0 ]; then
        echo -e "${GREEN}[ OK ]${NC} $2"
    elif [ "$1" -eq 2 ]; then
        echo -e "${L_YELLOW}[WARN]${NC} $2"
    else
        echo -e "${RED}[FAIL]${NC} $2"
    fi
}

print_info() {
    echo -e "${L_YELLOW}[INFO]${NC} $1"
}

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root or with root privileges." 
  exit 1
fi

echo -e "${BLUE}=== VPS Security Check ===${NC}\n"

sshd_conf=$(sshd -T 2>/dev/null)

# --- SSH ---
echo -e "${BLUE}SSH${NC}"

ssh_port=$(awk '/^port /{print $2}' <<< "$sshd_conf")
if [ -z "$ssh_port" ]; then
    print_check 1 "Could not determine SSH port from 'sshd -T'"
    exit 1
fi
print_info "SSH port: $ssh_port"

ss -tlnp | grep sshd | grep -qE ":$ssh_port( |$)"
print_check $? "sshd is listening on port $ssh_port"

iptables -S | grep -qE -- "--dport $ssh_port( |$)"
print_check $? "Port $ssh_port is open in the kernel firewall"

grep -qiw "permitrootlogin no" <<< "$sshd_conf"
print_check $? "Root login disabled"

pw_auth=$(awk '/^passwordauthentication /{print $2}' <<< "$sshd_conf")
if [ "$pw_auth" = "no" ]; then
    print_check 0 "Password authentication disabled"
elif command -v fail2ban-client >/dev/null 2>&1; then
    print_info "Password authentication is ENABLED (fail2ban is installed)"
else
    print_check 2 "Password authentication is ENABLED and fail2ban is not installed"
fi

kbd_auth=$(awk '/^kbdinteractiveauthentication /{print $2}' <<< "$sshd_conf")
if [ "$kbd_auth" = "no" ]; then
    print_check 0 "Keyboard-interactive authentication disabled"
elif [ "$pw_auth" = "no" ]; then
    print_check 1 "Keyboard-interactive authentication is ENABLED: password login is still possible"
else
    print_info "Keyboard-interactive authentication is enabled (password mode)."
    echo "       Disable it if you later switch to key authentication."
fi

grep -qiw "pubkeyauthentication yes" <<< "$sshd_conf"
print_check $? "Public key authentication enabled"

if systemctl is-enabled ssh 2>/dev/null | grep -qi "enabled" || \
   systemctl is-enabled ssh.socket 2>/dev/null | grep -qi "enabled"; then
    print_check 0 "SSH service (or socket) enabled on boot"
else
    print_check 1 "SSH service (or socket) enabled on boot"
fi

echo

# --- UFW ---
echo -e "${BLUE}UFW${NC}"

ufw status 2>/dev/null | grep -qi "Status: active"
print_check $? "UFW is active"

systemctl is-enabled ufw 2>/dev/null | grep -qi "enabled"
print_check $? "UFW enabled on boot"

LC_ALL=C ufw status verbose 2>/dev/null | grep -qi "deny (incoming)"
print_check $? "UFW default policy is deny (incoming)"

echo -e "${L_YELLOW}[INFO]${NC} SSH Port status:"
ufw status 2>/dev/null | grep -E "ALLOW|LIMIT" | grep -E "(^| )$ssh_port/" | sed 's/^/       /'

echo

# --- fail2ban ---
echo -e "${BLUE}fail2ban${NC}"

if command -v fail2ban-client >/dev/null 2>&1; then
    systemctl is-active fail2ban 2>/dev/null | grep -qiw "active"
    print_check $? "fail2ban is running"

    systemctl is-enabled fail2ban 2>/dev/null | grep -qi "enabled"
    print_check $? "fail2ban is enabled on boot"

    if fail2ban-client status sshd >/dev/null 2>&1; then
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

    if ! command -v nft >/dev/null 2>&1; then
        print_check 2 "nft not found: fail2ban may be unable to apply bans if it uses nftables"
    fi

    nftables_enabled=0
    systemctl is-enabled nftables.service >/dev/null 2>&1 && nftables_enabled=1
    systemctl is-active  nftables.service >/dev/null 2>&1 && nftables_enabled=1

    if [ "$nftables_enabled" -eq 1 ]; then
        print_check 2 "nftables.service is enabled/active (can conflict with UFW/fail2ban)"
        print_info "Consider: systemctl disable --now nftables"
    else
        print_check 0 "nftables.service is not enabled"
    fi
else
    print_info "fail2ban is not installed (expected in key-only mode)"
fi

echo

# --- TCP BBR ---
echo -e "${BLUE}Network${NC}"

sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -qi "bbr"
print_check $? "TCP congestion control: BBR"

sysctl net.core.default_qdisc 2>/dev/null | grep -qiw "fq"
print_check $? "Default qdisc: fq"

echo
