#!/bin/bash

# Website Downtime Notifier
# This script monitors websites and sends email alerts when downtime is detected
# Requirements: curl, mailx/mail/sendmail, internet connection

# Color codes for output formatting
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration - modify these variables
WEBSITES=("https://example.com" "https://example.org" "https://example.net")
CHECK_INTERVAL=300  # Time between checks in seconds (default: 5 minutes)
RETRIES=3           # Number of retries before confirming downtime
RETRY_DELAY=30      # Seconds between retries
EMAIL_TO="admin@example.com"
EMAIL_FROM="monitor@example.com"
TIMEOUT=10          # Curl timeout in seconds
LOG_FILE="/var/log/website-monitor.log"
STATUS_DIR="/var/lib/website-monitor"
HTTP_SUCCESS_CODES="200|301|302"  # Acceptable HTTP status codes

# Function to check if required tools are installed
check_requirements() {
  echo -e "${BLUE}=== Checking Required Tools ===${NC}"
  local missing_tools=()

  for tool in curl mail; do
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
    echo "  apt install curl mailutils"
    echo "  or"
    echo "  yum install curl mailx"
    exit 1
  else
    echo -e "${GREEN}All required tools are installed.${NC}"
  fi
}

# Function to initialize directories and files
initialize() {
  # Create log directory if it doesn't exist
  LOG_DIR=$(dirname "$LOG_FILE")
  mkdir -p "$LOG_DIR"
  
  # Create status directory if it doesn't exist
  mkdir -p "$STATUS_DIR"
  
  # Initialize status files for websites
  for website in "${WEBSITES[@]}"; do
    # Generate a filename-safe website name
    SITE_ID=$(echo "$website" | sed 's/[^a-zA-Z0-9]/_/g')
    STATUS_FILE="$STATUS_DIR/$SITE_ID.status"
    
    # If status file doesn't exist, create it with UP status
    if [ ! -f "$STATUS_FILE" ]; then
      echo "UP" > "$STATUS_FILE"
    fi
  done
  
  echo -e "${GREEN}Initialization complete.${NC}"
  log_message "INFO" "Website downtime notifier started"
}

# Function to log messages
log_message() {
  local level="$1"
  local message="$2"
  local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
  
  echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
  
  # Also print to console if not in quiet mode
  if [ "$QUIET" != "true" ]; then
    case "$level" in
      "ERROR") echo -e "${RED}[$timestamp] [$level] $message${NC}" ;;
      "WARNING") echo -e "${YELLOW}[$timestamp] [$level] $message${NC}" ;;
      "SUCCESS") echo -e "${GREEN}[$timestamp] [$level] $message${NC}" ;;
      *) echo -e "${BLUE}[$timestamp] [$level] $message${NC}" ;;
    esac
  fi
}

# Function to send email notification
send_notification() {
  local website="$1"
  local status="$2"
  local details="$3"
  local subject=""
  local body=""
  
  if [ "$status" == "DOWN" ]; then
    subject="ALERT: Website $website is DOWN"
    body="The website $website appears to be down.\n\nDetails:\n$details\n\nTimestamp: $(date)"
  else
    subject="RESOLVED: Website $website is back UP"
    body="The website $website is back online.\n\nDetails:\n$details\n\nTimestamp: $(date)"
  fi
  
  # Try to send mail using various available commands
  if command -v mail &> /dev/null; then
    echo -e "$body" | mail -s "$subject" -r "$EMAIL_FROM" "$EMAIL_TO"
  elif command -v mailx &> /dev/null; then
    echo -e "$body" | mailx -s "$subject" -r "$EMAIL_FROM" "$EMAIL_TO"
  elif command -v sendmail &> /dev/null; then
    echo -e "Subject: $subject\nFrom: $EMAIL_FROM\nTo: $EMAIL_TO\n\n$body" | sendmail -t
  else
    log_message "ERROR" "No mail program found. Unable to send notification."
    return 1
  fi
  
  if [ $? -eq 0 ]; then
    log_message "INFO" "Notification email sent for $website ($status)"
    return 0
  else
    log_message "ERROR" "Failed to send notification email for $website"
    return 1
  fi
}

# Function to check a single website
check_website() {
  local website="$1"
  local SITE_ID=$(echo "$website" | sed 's/[^a-zA-Z0-9]/_/g')
  local STATUS_FILE="$STATUS_DIR/$SITE_ID.status"
  local current_status=$(cat "$STATUS_FILE")
  local check_result=""
  local http_code=""
  local details=""
  local success=false
  
  # First attempt
  log_message "INFO" "Checking website: $website"
  
  # Loop for retries
  for ((i=1; i<=RETRIES; i++)); do
    # Get HTTP status code and response time
    response=$(curl -o /dev/null -s -w "%{http_code} %{time_total}s" --max-time "$TIMEOUT" "$website")
    http_code=$(echo "$response" | cut -d' ' -f1)
    response_time=$(echo "$response" | cut -d' ' -f2)
    
    # Check if HTTP code indicates success
    if echo "$http_code" | grep -E "$HTTP_SUCCESS_CODES" > /dev/null; then
      success=true
      details="HTTP Status: $http_code, Response Time: $response_time"
      break
    else
      if [ $i -lt $RETRIES ]; then
        log_message "WARNING" "Retry $i/$RETRIES: Website $website returned HTTP $http_code, waiting $RETRY_DELAY seconds..."
        sleep "$RETRY_DELAY"
      else
        details="HTTP Status: $http_code, Response Time: $response_time"
      fi
    fi
  done
  
  # Determine status based on check result
  if [ "$success" = true ]; then
    check_result="UP"
  else
    check_result="DOWN"
  fi
  
  # Compare with previous status and take action if changed
  if [ "$check_result" != "$current_status" ]; then
    if [ "$check_result" == "DOWN" ]; then
      log_message "ERROR" "Website $website is DOWN! $details"
      send_notification "$website" "DOWN" "$details"
    else
      log_message "SUCCESS" "Website $website is back UP! $details"
      send_notification "$website" "UP" "$details"
    fi
    
    # Update status file
    echo "$check_result" > "$STATUS_FILE"
  else
    # Just log the current status without notification
    if [ "$check_result" == "UP" ]; then
      log_message "INFO" "Website $website is UP. $details"
    else
      log_message "WARNING" "Website $website is still DOWN. $details"
    fi
  fi
}

# Function to display usage information
show_usage() {
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  -h, --help              Display this help message"
  echo "  -q, --quiet             Run in quiet mode (no console output)"
  echo "  -i, --interval SECONDS  Set check interval in seconds (default: $CHECK_INTERVAL)"
  echo "  -r, --retries NUM       Set number of retries (default: $RETRIES)"
  echo "  -d, --delay SECONDS     Set delay between retries in seconds (default: $RETRY_DELAY)"
  echo "  -t, --timeout SECONDS   Set curl timeout in seconds (default: $TIMEOUT)"
  echo "  -o, --once              Run checks once and exit (don't loop)"
  echo "  -w, --websites URLS     Comma-separated list of websites to monitor"
  echo "  -e, --email EMAIL       Email address to send notifications to"
  echo "  -f, --from EMAIL        Email address to send notifications from"
  echo "  -l, --log FILE          Log file location (default: $LOG_FILE)"
  echo ""
  echo "Example:"
  echo "  $0 --websites https://example.com,https://example.org --email admin@example.com --interval 600"
}

# Parse command line arguments
parse_args() {
  QUIET=false
  RUN_ONCE=false
  
  while [[ $# -gt 0 ]]; do
    case $1 in
      -h|--help)
        show_usage
        exit 0
        ;;
      -q|--quiet)
        QUIET=true
        shift
        ;;
      -i|--interval)
        CHECK_INTERVAL="$2"
        shift 2
        ;;
      -r|--retries)
        RETRIES="$2"
        shift 2
        ;;
      -d|--delay)
        RETRY_DELAY="$2"
        shift 2
        ;;
      -t|--timeout)
        TIMEOUT="$2"
        shift 2
        ;;
      -o|--once)
        RUN_ONCE=true
        shift
        ;;
      -w|--websites)
        IFS=',' read -r -a WEBSITES <<< "$2"
        shift 2
        ;;
      -e|--email)
        EMAIL_TO="$2"
        shift 2
        ;;
      -f|--from)
        EMAIL_FROM="$2"
        shift 2
        ;;
      -l|--log)
        LOG_FILE="$2"
        shift 2
        ;;
      *)
        echo "Unknown option: $1"
        show_usage
        exit 1
        ;;
    esac
  done
}

# Main function
main() {
  # Parse command line arguments
  parse_args "$@"
  
  # Display banner
  if [ "$QUIET" != "true" ]; then
    echo -e "${BLUE}==================================${NC}"
    echo -e "${BLUE}    Website Downtime Notifier     ${NC}"
    echo -e "${BLUE}==================================${NC}"
    echo "Monitoring ${#WEBSITES[@]} websites every $CHECK_INTERVAL seconds"
    echo "Sending alerts to: $EMAIL_TO"
    echo "Log file: $LOG_FILE"
    echo -e "${BLUE}==================================${NC}"
  fi
  
  # Check requirements
  check_requirements
  
  # Initialize directories and files
  initialize
  
  # Main monitoring loop
  while true; do
    # Check each website
    for website in "${WEBSITES[@]}"; do
      check_website "$website"
    done
    
    # Exit if run once mode is enabled
    if [ "$RUN_ONCE" = true ]; then
      log_message "INFO" "Finished one-time check of all websites"
      break
    fi
    
    # Wait for next check interval
    if [ "$QUIET" != "true" ]; then
      echo -e "${BLUE}Waiting $CHECK_INTERVAL seconds until next check...${NC}"
    fi
    sleep "$CHECK_INTERVAL"
  done
}

# Run main function with all arguments
main "$@"
