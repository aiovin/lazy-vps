#!/usr/bin/env bash
# VPS Security Check

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[1;34m'
NC='\033[0m'

print_check() {
    if [ "$1" -eq 0 ]; then
        echo -e "${GREEN}[OK]${NC}   $2"
    else
        echo -e "${RED}[FAIL]${NC} $2"
    fi
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root or with root privileges." 
  exit 1
fi

echo -e "${BLUE}=== VPS Security Check ===${NC}\n"

# --- SSH ---
echo -e "${BLUE}SSH${NC}"

ssh_port=$(sshd -T 2>/dev/null | awk '/^port /{print $2}')
print_info "SSH port: ${ssh_port:-unknown}"

sshd -T 2>/dev/null | grep -i permitrootlogin | grep -qiw "no"
print_check $? "Root login disabled"

sshd -T 2>/dev/null | grep -i passwordauthentication | grep -qiw "no"
print_check $? "Password authentication disabled"

sshd -T 2>/dev/null | grep -i pubkeyauthentication | grep -qiw "yes"
print_check $? "Public key authentication enabled"

systemctl is-enabled ssh 2>/dev/null | grep -qi "enabled"
print_check $? "SSH service enabled on boot"

echo

# --- UFW ---
echo -e "${BLUE}UFW${NC}"

ufw status 2>/dev/null | grep -qi "Status: active"
print_check $? "UFW is active"

systemctl is-enabled ufw 2>/dev/null | grep -qi "enabled"
print_check $? "UFW enabled on boot"

grep "DEFAULT_INPUT_POLICY" /etc/default/ufw 2>/dev/null | grep -qi "DROP"
print_check $? "Default incoming policy: DROP"

echo -e "${YELLOW}[INFO]${NC} SSH Port status:"
ufw status 2>/dev/null | grep -E "ALLOW|LIMIT" | grep "$ssh_port" | sed 's/^/       /'

echo

# --- TCP BBR ---
echo -e "${BLUE}Network${NC}"

sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -qi "bbr"
print_check $? "TCP congestion control: BBR"

sysctl net.core.default_qdisc 2>/dev/null | grep -qiw "fq"
print_check $? "Default qdisc: fq"

echo
