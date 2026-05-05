#!/bin/bash

# Linux Security Audit Tool
# This script scans for security vulnerabilities including weak passwords,
# open ports, and misconfigured permissions.
# Requirements: nmap, fail2ban, auditd, sudo privileges

# Color codes for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if script is running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: This script must be run as root${NC}"
  echo "Please run with sudo: sudo $0"
  exit 1
fi

# Function to check if required tools are installed
check_requirements() {
  echo -e "${BLUE}=== Checking Required Tools ===${NC}"
  local missing_tools=()

  for tool in nmap fail2ban-client auditctl; do
    if ! command -v $tool &> /dev/null; then
      missing_tools+=($tool)
    fi
  done

  if [ ${#missing_tools[@]} -ne 0 ]; then
    echo -e "${RED}Error: The following required tools are missing:${NC}"
    for tool in "${missing_tools[@]}"; do
      echo "  - $tool"
    done
    echo -e "${YELLOW}Please install the missing tools and try again.${NC}"
    echo "You can typically install them using:"
    echo "  apt install nmap fail2ban auditd"
    echo "  or"
    echo "  yum install nmap fail2ban audit"
    exit 1
  else
    echo -e "${GREEN}All required tools are installed.${NC}"
  fi
}

# Function to generate report file
setup_report() {
  REPORT_DIR="/var/log/security-audit"
  TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
  REPORT_FILE="$REPORT_DIR/security-audit-$TIMESTAMP.log"
  
  mkdir -p "$REPORT_DIR"
  
  echo "Linux Security Audit Report" > "$REPORT_FILE"
  echo "Generated on: $(date)" >> "$REPORT_FILE"
  echo "System: $(hostname)" >> "$REPORT_FILE"
  echo "Kernel: $(uname -r)" >> "$REPORT_FILE"
  echo "----------------------------------------" >> "$REPORT_FILE"
  
  echo -e "${GREEN}Report will be saved to: $REPORT_FILE${NC}"
  return 0
}

# Function to log findings
log_finding() {
  local severity="$1"
  local message="$2"
  
  # Determine severity indicator
  local indicator=""
  case "$severity" in
    high)   indicator="[HIGH]   " ;;
    medium) indicator="[MEDIUM] " ;;
    low)    indicator="[LOW]    " ;;
    info)   indicator="[INFO]   " ;;
    *)      indicator="[UNKNOWN]" ;;
  esac
  
  # Log to report file
  echo "$indicator $message" >> "$REPORT_FILE"
  
  # Display to console with color
  case "$severity" in
    high)   echo -e "${RED}$indicator $message${NC}" ;;
    medium) echo -e "${YELLOW}$indicator $message${NC}" ;;
    low)    echo -e "${BLUE}$indicator $message${NC}" ;;
    info)   echo -e "$indicator $message" ;;
    *)      echo -e "$indicator $message" ;;
  esac
}

# Function to scan open ports
scan_open_ports() {
  echo -e "\n${BLUE}=== Scanning Open Ports ===${NC}"
  echo -e "Running scan (this might take a while)..."
  
  # Log header
  echo -e "\n-- OPEN PORTS SCAN --" >> "$REPORT_FILE"
  
  # Get IP addresses for local interfaces
  local_ips=$(hostname -I)
  
  for ip in $local_ips; do
    # Skip loopback and IPv6
    if [[ "$ip" == "127.0.0.1" || "$ip" == *":"* ]]; then
      continue
    fi
    
    log_finding "info" "Scanning IP: $ip"
    
    # Run nmap scan
    nmap_result=$(nmap -sS -T4 $ip)
    echo "$nmap_result" >> "$REPORT_FILE"
    
    # Parse open ports
    open_ports=$(echo "$nmap_result" | grep "open" | grep -v "filtered")
    
    if [ -n "$open_ports" ]; then
      log_finding "medium" "Found open ports on $ip:"
      echo "$open_ports" | while read line; do
        port=$(echo "$line" | awk '{print $1}')
        service=$(echo "$line" | awk '{print $3}')
        
        # Evaluate risk based on service
        if [[ "$port" == "22/tcp" || "$port" == "3389/tcp" ]]; then
          log_finding "high" "Remote access port open: $port ($service)"
        elif [[ "$port" == "80/tcp" || "$port" == "443/tcp" ]]; then
          log_finding "low" "Web service port open: $port ($service)"
        else
          log_finding "medium" "Port open: $port ($service)"
        fi
      done
    else
      log_finding "info" "No concerning open ports found on $ip"
    fi
  done
}

# Function to check password policies
check_password_policies() {
  echo -e "\n${BLUE}=== Checking Password Policies ===${NC}"
  
  # Log header
  echo -e "\n-- PASSWORD POLICY CHECKS --" >> "$REPORT_FILE"
  
  # Check shadow password aging
  echo "Password aging configuration:" >> "$REPORT_FILE"
  grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE" /etc/login.defs >> "$REPORT_FILE"
  
  PASS_MAX_DAYS=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
  
  if [ -n "$PASS_MAX_DAYS" ] && [ "$PASS_MAX_DAYS" -gt 90 ]; then
    log_finding "medium" "Password maximum age ($PASS_MAX_DAYS days) exceeds recommended 90 days"
  else
    log_finding "info" "Password maximum age setting is acceptable: $PASS_MAX_DAYS days"
  fi
  
  # Check for users with empty passwords
  empty_passwords=$(cat /etc/shadow | grep '::')
  if [ -n "$empty_passwords" ]; then
    log_finding "high" "Users with empty passwords found!"
    echo "$empty_passwords" | cut -d: -f1 >> "$REPORT_FILE"
  else
    log_finding "info" "No users with empty passwords found"
  fi
  
  # Check PAM password quality
  if [ -f /etc/pam.d/common-password ]; then
    pam_file="/etc/pam.d/common-password"
  elif [ -f /etc/pam.d/system-auth ]; then
    pam_file="/etc/pam.d/system-auth"
  else
    pam_file=""
  fi
  
  if [ -n "$pam_file" ]; then
    pam_pwquality=$(grep "pam_pwquality.so\|pam_cracklib.so" "$pam_file")
    echo "PAM password quality settings:" >> "$REPORT_FILE"
    echo "$pam_pwquality" >> "$REPORT_FILE"
    
    if [ -z "$pam_pwquality" ]; then
      log_finding "high" "No password quality requirements found in PAM configuration"
    else
      # Check minimum length
      min_len=$(echo "$pam_pwquality" | grep -o "minlen=[0-9]*" | cut -d= -f2)
      if [ -z "$min_len" ] || [ "$min_len" -lt 8 ]; then
        log_finding "medium" "Weak minimum password length: ${min_len:-not set}"
      else
        log_finding "info" "Good minimum password length: $min_len"
      fi
    fi
  else
    log_finding "medium" "Could not locate PAM password configuration file"
  fi
}

# Function to check file permissions
check_file_permissions() {
  echo -e "\n${BLUE}=== Checking File Permissions ===${NC}"
  
  # Log header
  echo -e "\n-- FILE PERMISSION CHECKS --" >> "$REPORT_FILE"
  
  # Check world-writable files
  echo "Scanning for world-writable files (this may take some time)..."
  world_writable=$(find / -type f -perm -002 -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" 2>/dev/null)
  
  if [ -n "$world_writable" ]; then
    writable_count=$(echo "$world_writable" | wc -l)
    log_finding "high" "Found $writable_count world-writable files!"
    echo "First 20 world-writable files:" >> "$REPORT_FILE"
    echo "$world_writable" | head -20 >> "$REPORT_FILE"
  else
    log_finding "info" "No world-writable files found"
  fi
  
  # Check SUID files
  echo "Scanning for SUID files..."
  suid_files=$(find / -type f -perm -4000 -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null)
  
  if [ -n "$suid_files" ]; then
    suid_count=$(echo "$suid_files" | wc -l)
    log_finding "medium" "Found $suid_count SUID files"
    echo "SUID files found:" >> "$REPORT_FILE"
    echo "$suid_files" >> "$REPORT_FILE"
    
    # Check for unusual SUID files (excluding common ones)
    common_suid="/bin/ping\|/bin/su\|/bin/mount\|/usr/bin/passwd\|/usr/bin/sudo"
    unusual_suid=$(echo "$suid_files" | grep -v "$common_suid")
    
    if [ -n "$unusual_suid" ]; then
      unusual_count=$(echo "$unusual_suid" | wc -l)
      log_finding "high" "Found $unusual_count potentially unusual SUID files"
      echo "Unusual SUID files:" >> "$REPORT_FILE"
      echo "$unusual_suid" >> "$REPORT_FILE"
    fi
  else
    log_finding "info" "No SUID files found"
  fi
  
  # Check SSH configuration
  if [ -f /etc/ssh/sshd_config ]; then
    echo -e "\nChecking SSH configuration..."
    # Check root login
    root_login=$(grep "^PermitRootLogin" /etc/ssh/sshd_config)
    if [[ "$root_login" == *"yes"* ]]; then
      log_finding "high" "SSH root login is permitted!"
    else
      log_finding "info" "SSH root login is properly restricted"
    fi
    
    # Check password authentication
    pass_auth=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config)
    if [[ "$pass_auth" == *"yes"* ]]; then
      log_finding "medium" "SSH password authentication is enabled"
    else
      log_finding "info" "SSH password authentication is disabled (key-based auth only)"
    fi
  fi
}

# Function to check fail2ban status
check_fail2ban() {
  echo -e "\n${BLUE}=== Checking Fail2Ban Configuration ===${NC}"
  
  # Log header
  echo -e "\n-- FAIL2BAN CHECKS --" >> "$REPORT_FILE"
  
  # Check if fail2ban is running
  fail2ban_status=$(systemctl is-active fail2ban 2>/dev/null)
  
  if [ "$fail2ban_status" != "active" ]; then
    log_finding "high" "Fail2Ban is not running!"
    return
  fi
  
  log_finding "info" "Fail2Ban is active"
  
  # Get fail2ban status
  echo "Retrieving Fail2Ban status..."
  fail2ban_info=$(fail2ban-client status 2>/dev/null)
  echo "$fail2ban_info" >> "$REPORT_FILE"
  
  # Get jails
  jails=$(fail2ban-client status | grep "Jail list" | sed 's/^.*://' | sed 's/,//g')
  
  if [ -z "$jails" ]; then
    log_finding "medium" "No active Fail2Ban jails found"
  else
    log_finding "info" "Active Fail2Ban jails: $jails"
    
    # Check each jail
    for jail in $jails; do
      echo -e "\nJail: $jail" >> "$REPORT_FILE"
      jail_info=$(fail2ban-client status "$jail")
      echo "$jail_info" >> "$REPORT_FILE"
      
      # Extract banned IPs
      banned=$(echo "$jail_info" | grep "Currently banned" | grep -oE "[0-9]+")
      
      if [ "$banned" -gt 0 ]; then
        log_finding "medium" "Jail '$jail' has $banned banned IP(s)"
      else
        log_finding "info" "Jail '$jail' has no banned IPs"
      fi
    done
  fi
}

# Function to check audit daemon configuration
check_auditd() {
  echo -e "\n${BLUE}=== Checking Audit Daemon Configuration ===${NC}"
  
  # Log header
  echo -e "\n-- AUDITD CHECKS --" >> "$REPORT_FILE"
  
  # Check if auditd is running
  auditd_status=$(systemctl is-active auditd 2>/dev/null)
  
  if [ "$auditd_status" != "active" ]; then
    log_finding "high" "Audit daemon (auditd) is not running!"
    return
  fi
  
  log_finding "info" "Audit daemon is active"
  
  # Check audit rules
  echo "Checking audit rules..."
  auditd_rules=$(auditctl -l)
  echo "$auditd_rules" >> "$REPORT_FILE"
  
  # Check for key monitoring rules
  if ! echo "$auditd_rules" | grep -q "/etc/passwd"; then
    log_finding "medium" "No audit rule for monitoring /etc/passwd"
  else
    log_finding "info" "Audit rule for /etc/passwd exists"
  fi
  
  if ! echo "$auditd_rules" | grep -q "exec"; then
    log_finding "medium" "No audit rule for monitoring program execution"
  else
    log_finding "info" "Audit rules for program execution exist"
  fi
  
  # Check audit log file
  if [ -f /var/log/audit/audit.log ]; then
    log_size=$(du -h /var/log/audit/audit.log | awk '{print $1}')
    log_finding "info" "Audit log file size: $log_size"
    
    # Check recent authentication failures
    auth_failures=$(ausearch -m USER_AUTH -sv no -i 2>/dev/null | wc -l)
    if [ "$auth_failures" -gt 0 ]; then
      log_finding "medium" "Found $auth_failures recent authentication failures"
    else
      log_finding "info" "No recent authentication failures found"
    fi
  else
    log_finding "medium" "Audit log file not found at /var/log/audit/audit.log"
  fi
}

# Function to check for common vulnerabilities
check_vulnerabilities() {
  echo -e "\n${BLUE}=== Checking for Common Vulnerabilities ===${NC}"
  
  # Log header
  echo -e "\n-- VULNERABILITY CHECKS --" >> "$REPORT_FILE"
  
  # Check for kernel vulnerabilities
  echo "Checking kernel version..."
  kernel_version=$(uname -r)
  log_finding "info" "Current kernel version: $kernel_version"
  
  # Check for common services with known vulnerabilities
  echo "Checking common services..."
  
  # Check SSH version
  if command -v ssh &> /dev/null; then
    ssh_version=$(ssh -V 2>&1 | cut -d' ' -f1)
    log_finding "info" "SSH version: $ssh_version"
  fi
  
  # Check Apache version
  if command -v apache2 &> /dev/null || command -v httpd &> /dev/null; then
    if command -v apache2 &> /dev/null; then
      apache_version=$(apache2 -v | grep "Server version" | cut -d/ -f2 | awk '{print $1}')
    else
      apache_version=$(httpd -v | grep "Server version" | cut -d/ -f2 | awk '{print $1}')
    fi
    log_finding "info" "Apache version: $apache_version"
    
    # Check for older vulnerable versions
    if [[ "$apache_version" =~ ^2\.[0-3]\. ]]; then
      log_finding "high" "Apache version $apache_version may have known vulnerabilities"
    fi
  fi
  
  # Check PHP version
  if command -v php &> /dev/null; then
    php_version=$(php -v | head -n1 | cut -d' ' -f2)
    log_finding "info" "PHP version: $php_version"
    
    # Check for older vulnerable versions
    if [[ "$php_version" =~ ^5\. ]]; then
      log_finding "high" "PHP version $php_version is outdated and has known vulnerabilities"
    elif [[ "$php_version" =~ ^7\.[0-1]\. ]]; then
      log_finding "medium" "PHP version $php_version may have security issues"
    fi
  fi
  
  # Check for vulnerable packages with known CVEs
  echo "Checking for outdated packages..."
  
  # Different commands for different package managers
  if command -v apt &> /dev/null; then
    outdated_packages=$(apt list --upgradable 2>/dev/null | grep -v "Listing..." | wc -l)
    if [ "$outdated_packages" -gt 0 ]; then
      log_finding "medium" "Found $outdated_packages outdated packages"
      apt list --upgradable 2>/dev/null | grep -v "Listing..." | head -10 >> "$REPORT_FILE"
    else
      log_finding "info" "No outdated packages found"
    fi
  elif command -v yum &> /dev/null; then
    outdated_packages=$(yum check-update --quiet | wc -l)
    if [ "$outdated_packages" -gt 0 ]; then
      log_finding "medium" "Found $outdated_packages outdated packages"
      yum check-update --quiet | head -10 >> "$REPORT_FILE"
    else
      log_finding "info" "No outdated packages found"
    fi
  fi
}

# Function to check firewall configuration
check_firewall() {
  echo -e "\n${BLUE}=== Checking Firewall Configuration ===${NC}"
  
  # Log header
  echo -e "\n-- FIREWALL CHECKS --" >> "$REPORT_FILE"
  
  # Check if firewall is active
  firewall_active=false
  
  # Check UFW
  if command -v ufw &> /dev/null; then
    ufw_status=$(ufw status | grep "Status:" | awk '{print $2}')
    if [ "$ufw_status" = "active" ]; then
      log_finding "info" "UFW firewall is active"
      firewall_active=true
      
      # Log UFW rules
      echo "UFW rules:" >> "$REPORT_FILE"
      ufw status verbose >> "$REPORT_FILE"
      
      # Check for any allow rules
      allow_rules=$(ufw status | grep "ALLOW" | wc -l)
      if [ "$allow_rules" -gt 5 ]; then
        log_finding "medium" "UFW has $allow_rules ALLOW rules. Consider reducing exposed services."
      fi
    else
      log_finding "high" "UFW is installed but not active"
    fi
  fi
  
  # Check iptables
  if ! $firewall_active && command -v iptables &> /dev/null; then
    iptables_rules=$(iptables -L -n | grep -v "Chain" | grep -v "target" | grep -v "^$" | wc -l)
    if [ "$iptables_rules" -gt 0 ]; then
      log_finding "info" "iptables firewall is configured with $iptables_rules rules"
      firewall_active=true
      
      # Log iptables rules
      echo "iptables rules:" >> "$REPORT_FILE"
      iptables -L -n >> "$REPORT_FILE"
      
      # Check for default policies
      input_policy=$(iptables -L INPUT | head -n1 | awk '{print $4}')
      if [ "$input_policy" != "DROP" ]; then
        log_finding "medium" "iptables INPUT chain policy is not set to DROP"
      fi
    fi
  fi
  
  # Check firewalld
  if ! $firewall_active && command -v firewall-cmd &> /dev/null; then
    firewalld_status=$(firewall-cmd --state 2>/dev/null)
    if [ "$firewalld_status" = "running" ]; then
      log_finding "info" "firewalld is active"
      firewall_active=true
      
      # Log firewalld rules
      echo "firewalld configuration:" >> "$REPORT_FILE"
      firewall-cmd --list-all >> "$REPORT_FILE"
      
      # Check for public services
      public_services=$(firewall-cmd --zone=public --list-services | wc -w)
      if [ "$public_services" -gt 3 ]; then
        log_finding "medium" "firewalld has $public_services public services. Consider reducing exposed services."
      fi
    else
      log_finding "high" "firewalld is installed but not active"
    fi
  fi
  
  if ! $firewall_active; then
    log_finding "high" "No active firewall detected on the system"
  fi
}

# Function to generate summary of findings
generate_summary() {
  echo -e "\n${BLUE}=== Generating Summary ===${NC}"
  
  # Log header
  echo -e "\n-- SUMMARY OF FINDINGS --" >> "$REPORT_FILE"
  
  # Count findings by severity
  high_findings=$(grep -c "\[HIGH\]" "$REPORT_FILE")
  medium_findings=$(grep -c "\[MEDIUM\]" "$REPORT_FILE")
  low_findings=$(grep -c "\[LOW\]" "$REPORT_FILE")
  
  # Generate summary
  echo "High severity issues: $high_findings" >> "$REPORT_FILE"
  echo "Medium severity issues: $medium_findings" >> "$REPORT_FILE"
  echo "Low severity issues: $low_findings" >> "$REPORT_FILE"
  
  # Display summary
  echo -e "${RED}High severity issues: $high_findings${NC}"
  echo -e "${YELLOW}Medium severity issues: $medium_findings${NC}"
  echo -e "${BLUE}Low severity issues: $low_findings${NC}"
  
  # Provide overall assessment
  if [ "$high_findings" -gt 0 ]; then
    echo -e "\n${RED}OVERALL ASSESSMENT: CRITICAL SECURITY ISSUES FOUND${NC}"
    echo "Please address high severity issues immediately to protect your system."
    echo "OVERALL ASSESSMENT: CRITICAL SECURITY ISSUES FOUND" >> "$REPORT_FILE"
  elif [ "$medium_findings" -gt 0 ]; then
    echo -e "\n${YELLOW}OVERALL ASSESSMENT: SECURITY IMPROVEMENTS NEEDED${NC}"
    echo "Please address medium severity issues to enhance your system security."
    echo "OVERALL ASSESSMENT: SECURITY IMPROVEMENTS NEEDED" >> "$REPORT_FILE"
  else
    echo -e "\n${GREEN}OVERALL ASSESSMENT: SYSTEM APPEARS SECURE${NC}"
    echo "Continue to monitor and maintain your system security."
    echo "OVERALL ASSESSMENT: SYSTEM APPEARS SECURE" >> "$REPORT_FILE"
  fi
  
  echo -e "\nFull report available at: $REPORT_FILE"
}

# Main execution
main() {
  echo -e "${BLUE}====================================${NC}"
  echo -e "${BLUE}      Linux Security Audit Tool     ${NC}"
  echo -e "${BLUE}====================================${NC}"
  
  # Check requirements
  check_requirements
  
  # Setup report file
  setup_report
  
  # Run security checks
  scan_open_ports
  check_password_policies
  check_file_permissions
  check_fail2ban
  check_auditd
  check_vulnerabilities
  check_firewall
  
  # Generate summary
  generate_summary
}

# Run main function
main
