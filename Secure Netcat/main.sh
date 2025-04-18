#!/bin/bash
# SB - A secure shell-based netcat clone
# Usage: sb [host] [port] or sb -l [port]
# Version 2.0 - Security and functionality enhanced

# Make sure we exit cleanly on unexpected termination
set -o pipefail

# Show usage and exit
show_usage() {
    echo "SB - Secure shell-based netcat clone"
    echo "Usage:"
    echo "  Client mode: sb [options] <host> <port>"
    echo "  Server mode: sb -l [options] <port>"
    echo "Options:"
    echo "  -l          Listen mode (server)"
    echo "  -v          Verbose mode"
    echo "  -t <secs>   Connection timeout (default: none)"
    echo "  -e <cmd>    Execute command after connection (disabled in secure mode)"
    echo "  -u          Use UDP instead of TCP"
    echo "  -s <src>    Source IP address"
    echo "  -w <secs>   Idle timeout (wait time)"
    echo "  -z          Zero-I/O mode (scanning)"
    echo "  -n          No DNS lookups"
    echo "  -h          Show this help message"
    exit 1
}

# Function to clean up resources before exit
cleanup() {
    log "Cleaning up resources..."
    
    # Kill any child processes that might be running
    if [ -n "$CLIENT_PID" ]; then
        kill $CLIENT_PID 2>/dev/null || true
    fi
    
    if [ -n "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
    fi
    
    # Clean up any named pipes or temporary files
    rm -f "$FIFO_IN" "$FIFO_OUT" "$TEMP_FILE" 2>/dev/null || true
    
    # Close any open file descriptors
    for fd in {3..10}; do
        exec {fd}>&- 2>/dev/null || true
    done
    
    log "Exited safely"
    exit 0
}

# Parse command line arguments
LISTEN_MODE=false
VERBOSE=false
TIMEOUT=""
WAIT_TIMEOUT=""
EXEC_CMD=""
USE_UDP=false
SOURCE_IP=""
ZERO_IO=false
NO_DNS=false
SECURE_MODE=true  # Default to secure mode which disables command execution

# Setup trap for clean exit
trap cleanup EXIT INT TERM HUP PIPE

# Parse options
while getopts "lvt:e:us:w:znh" opt; do
    case $opt in
        l) LISTEN_MODE=true ;;
        v) VERBOSE=true ;;
        t) TIMEOUT="$OPTARG" ;;
        e) 
           if $SECURE_MODE; then
               echo "Warning: Command execution (-e) is disabled in secure mode"
           else
               EXEC_CMD="$OPTARG" 
           fi
           ;;
        u) USE_UDP=true ;;
        s) SOURCE_IP="$OPTARG" ;;
        w) WAIT_TIMEOUT="$OPTARG" ;;
        z) ZERO_IO=true ;;
        n) NO_DNS=true ;;
        h) show_usage ;;
        *) show_usage ;;
    esac
done

# Shift past the options
shift $((OPTIND-1))

# Check arguments based on mode
if $LISTEN_MODE; then
    # Listen mode requires exactly one argument (port)
    if [ $# -ne 1 ]; then
        echo "Error: Listen mode requires exactly one argument (port)"
        show_usage
    fi
    PORT=$1
else
    # Client mode requires exactly two arguments (host and port)
    if [ $# -ne 2 ]; then
        echo "Error: Client mode requires exactly two arguments (host and port)"
        show_usage
    fi
    HOST=$1
    PORT=$2
fi

# Generate a random identifier for this session to prevent predictable filenames
SESSION_ID=$(head -c 8 /dev/urandom | xxd -p)
if [ -z "$SESSION_ID" ]; then
    # Fallback if xxd is not available
    SESSION_ID="$$_$RANDOM"
fi

# Setup secure temporary files in /dev/shm if available (RAM-based filesystem), or fallback to /tmp
if [ -d "/dev/shm" ] && [ -w "/dev/shm" ]; then
    TEMP_DIR="/dev/shm"
else
    TEMP_DIR="/tmp"
fi

# Create secure FIFOs with unpredictable names and proper permissions
FIFO_IN="$TEMP_DIR/sb_fifo_in_$SESSION_ID"
FIFO_OUT="$TEMP_DIR/sb_fifo_out_$SESSION_ID"
TEMP_FILE="$TEMP_DIR/sb_temp_$SESSION_ID"

# Validate port number
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "Error: Port must be a valid number between 1 and 65535"
    exit 1
fi

# Validate timeout values if provided
if [ -n "$TIMEOUT" ] && ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]]; then
    echo "Error: Timeout must be a valid number of seconds"
    exit 1
fi

if [ -n "$WAIT_TIMEOUT" ] && ! [[ "$WAIT_TIMEOUT" =~ ^[0-9]+$ ]]; then
    echo "Error: Wait timeout must be a valid number of seconds"
    exit 1
fi

# Function for secure logging
log() {
    if $VERBOSE; then
        echo "[SB] $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
    fi
}

# Check if we have the necessary tools
check_requirements() {
    # Check for required utilities
    if ! command -v mkfifo >/dev/null 2>&1; then
        echo "Error: 'mkfifo' is required but not found"
        exit 1
    fi
    
    # Check if /dev/tcp is available in this shell
    if [[ "$BASH_VERSION" < "3" ]]; then
        log "Warning: Bash version < 3 may not support /dev/tcp redirections"
    fi
    
    # Check which connection method to use
    CONNECTION_METHOD=""
    if command -v socat >/dev/null 2>&1; then
        CONNECTION_METHOD="socat"
    elif command -v nc >/dev/null 2>&1 || command -v netcat >/dev/null 2>&1; then
        CONNECTION_METHOD="nc"
    elif [[ "$BASH_VERSION" > "2" ]]; then
        CONNECTION_METHOD="bash"
    else
        echo "Error: Neither socat, nc, nor a suitable bash version found for network connections"
        exit 1
    fi
    
    log "Using connection method: $CONNECTION_METHOD"
    return 0
}

# Function to safely create FIFOs with proper permissions
create_secure_fifos() {
    # Create FIFOs with restricted permissions
    umask 077  # Only owner can read/write
    mkfifo "$FIFO_IN" || { echo "Error creating FIFO: $FIFO_IN"; exit 1; }
    mkfifo "$FIFO_OUT" || { echo "Error creating FIFO: $FIFO_OUT"; exit 1; }
    log "Created secure FIFOs: $FIFO_IN, $FIFO_OUT"
}

# Function to handle server mode
server_mode() {
    local port=$1
    log "Starting server on port $port..."
    
    # Create secure FIFOs for communication
    create_secure_fifos
    
    # Prepare protocol (TCP/UDP)
    local proto_opt=""
    if $USE_UDP; then
        proto_opt="udp"
        log "Using UDP protocol"
    else
        proto_opt="tcp"
        log "Using TCP protocol"
    fi
    
    # Start listening based on available tools
    case "$CONNECTION_METHOD" in
        socat)
            local socat_opts="-d -d"
            
            # Build the socat command with appropriate options
            if $USE_UDP; then
                cmd="socat $socat_opts UDP-LISTEN:$port,fork,reuseaddr STDIO"
            else
                cmd="socat $socat_opts TCP-LISTEN:$port,fork,reuseaddr STDIO"
            fi
            
            # Add timeout if specified
            if [ -n "$TIMEOUT" ]; then
                cmd="${cmd},connect-timeout=$TIMEOUT"
            fi
            
            # Add wait timeout if specified
            if [ -n "$WAIT_TIMEOUT" ]; then
                cmd="${cmd},idle-timeout=$WAIT_TIMEOUT"
            fi
            
            # Execute with proper redirection
            if $ZERO_IO; then
                log "Zero-I/O mode: testing connection only"
                eval "$cmd" > /dev/null 2>&1
                if [ $? -eq 0 ]; then
                    log "Connection successful"
                else
                    log "Connection failed"
                fi
            else
                log "Executing: $cmd"
                eval "$cmd" < "$FIFO_OUT" > "$FIFO_IN" &
                SERVER_PID=$!
                
                # Handle data transfer
                cat "$FIFO_IN" &
                INPUT_PID=$!
                cat > "$FIFO_OUT"
                
                # Wait for processes to complete
                wait $SERVER_PID $INPUT_PID 2>/dev/null || true
            fi
            ;;
            
        nc)
            local nc_cmd=$(command -v nc || command -v netcat)
            local nc_opts=""
            
            # Check if this nc supports -q option for EOF handling
            if $nc_cmd -h 2>&1 | grep -q -- "-q"; then
                nc_opts="-q 0"
            fi
            
            # Build nc command with appropriate options
            cmd="$nc_cmd $nc_opts"
            
            if $USE_UDP; then
                cmd="$cmd -u"
            fi
            
            # Add listen mode flags (different versions of nc use different flags)
            if $nc_cmd -h 2>&1 | grep -q -- "-l -p"; then
                cmd="$cmd -l -p $port"
            else
                cmd="$cmd -l $port"
            fi
            
            # Add timeout if specified
            if [ -n "$WAIT_TIMEOUT" ]; then
                if $nc_cmd -h 2>&1 | grep -q -- "-w"; then
                    cmd="$cmd -w $WAIT_TIMEOUT"
                fi
            fi
            
            # Add no-DNS option if specified
            if $NO_DNS; then
                if $nc_cmd -h 2>&1 | grep -q -- "-n"; then
                    cmd="$cmd -n"
                fi
            fi
            
            # Execute with proper redirection
            if $ZERO_IO; then
                log "Zero-I/O mode: testing connection only"
                eval "$cmd" > /dev/null 2>&1
                if [ $? -eq 0 ]; then
                    log "Connection successful"
                else
                    log "Connection failed"
                fi
            else
                log "Executing: $cmd"
                eval "$cmd" < "$FIFO_OUT" > "$FIFO_IN" &
                SERVER_PID=$!
                
                # Handle data transfer
                cat "$FIFO_IN" &
                INPUT_PID=$!
                cat > "$FIFO_OUT"
                
                # Wait for processes to complete
                wait $SERVER_PID $INPUT_PID 2>/dev/null || true
            fi
            ;;
            
        bash)
            if $USE_UDP; then
                echo "Error: UDP is not supported with bash /dev/tcp method"
                exit 1
            fi
            
            log "Using bash built-in /dev/tcp for listening"
            
            # This is tricky with bash, need to use a temporary server script
            cat > "$TEMP_FILE" << EOF
#!/bin/bash
# Temporary server script
exec 3<>/dev/tcp/0.0.0.0/$port
cat <&3 > "$FIFO_IN" &
cat "$FIFO_OUT" >&3
EOF
            chmod 700 "$TEMP_FILE"
            
            # Execute the temporary server script
            "$TEMP_FILE" &
            SERVER_PID=$!
            
            # Handle data transfer
            cat "$FIFO_IN" &
            INPUT_PID=$!
            cat > "$FIFO_OUT"
            
            # Wait for processes to complete
            wait $SERVER_PID $INPUT_PID 2>/dev/null || true
            ;;
    esac
    
    log "Server connection closed"
}

# Function to handle client mode
client_mode() {
    local host=$1
    local port=$2
    
    # Handle no DNS lookup option
    if $NO_DNS; then
        # Check if the host looks like an IP address
        if ! [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            log "Converting hostname to IP due to -n option"
            # Try to resolve using getent which is safer than external commands
            if command -v getent >/dev/null 2>&1; then
                IP=$(getent hosts "$host" | awk '{print $1}' | head -n1)
                if [ -n "$IP" ]; then
                    host=$IP
                    log "Resolved to IP: $host"
                else
                    log "Warning: Could not resolve hostname, using as-is"
                fi
            fi
        fi
    fi
    
    log "Connecting to $host:$port..."
    
    # Create secure FIFOs for communication
    create_secure_fifos
    
    # Prepare protocol (TCP/UDP)
    local proto_opt=""
    if $USE_UDP; then
        proto_opt="udp"
        log "Using UDP protocol"
    else
        proto_opt="tcp"
        log "Using TCP protocol"
    fi
    
    # Connect based on available tools
    case "$CONNECTION_METHOD" in
        socat)
            local socat_opts="-d -d"
            
            # Build the socat command with appropriate options
            if $USE_UDP; then
                cmd="socat $socat_opts STDIO UDP:$host:$port"
            else
                cmd="socat $socat_opts STDIO TCP:$host:$port"
            fi
            
            # Add source IP if specified
            if [ -n "$SOURCE_IP" ]; then
                cmd="${cmd},bind=$SOURCE_IP"
            fi
            
            # Add timeout if specified
            if [ -n "$TIMEOUT" ]; then
                cmd="${cmd},connect-timeout=$TIMEOUT"
            fi
            
            # Add wait timeout if specified
            if [ -n "$WAIT_TIMEOUT" ]; then
                cmd="${cmd},idle-timeout=$WAIT_TIMEOUT"
            fi
            
            # Execute with proper redirection
            if $ZERO_IO; then
                log "Zero-I/O mode: testing connection only"
                eval "$cmd" > /dev/null 2>&1
                if [ $? -eq 0 ]; then
                    echo "Connection to $host:$port successful"
                else
                    echo "Connection to $host:$port failed"
                fi
            else
                log "Executing: $cmd"
                eval "$cmd" < "$FIFO_OUT" > "$FIFO_IN" &
                CLIENT_PID=$!
                
                # Handle data transfer
                cat "$FIFO_IN" &
                INPUT_PID=$!
                cat > "$FIFO_OUT"
                
                # Wait for processes to complete
                wait $CLIENT_PID $INPUT_PID 2>/dev/null || true
            fi
            ;;
            
        nc)
            local nc_cmd=$(command -v nc || command -v netcat)
            local nc_opts=""
            
            # Build nc command with appropriate options
            cmd="$nc_cmd"
            
            if $USE_UDP; then
                cmd="$cmd -u"
            fi
            
            # Add source IP if specified
            if [ -n "$SOURCE_IP" ]; then
                if $nc_cmd -h 2>&1 | grep -q -- "-s"; then
                    cmd="$cmd -s $SOURCE_IP"
                fi
            fi
            
            # Add timeout if specified
            if [ -n "$WAIT_TIMEOUT" ]; then
                if $nc_cmd -h 2>&1 | grep -q -- "-w"; then
                    cmd="$cmd -w $WAIT_TIMEOUT"
                fi
            fi
            
            # Add no-DNS option if specified
            if $NO_DNS; then
                if $nc_cmd -h 2>&1 | grep -q -- "-n"; then
                    cmd="$cmd -n"
                fi
            fi
            
            # Add zero I/O option if specified
            if $ZERO_IO; then
                if $nc_cmd -h 2>&1 | grep -q -- "-z"; then
                    cmd="$cmd -z"
                fi
            fi
            
            # Complete the command with host and port
            cmd="$cmd $host $port"
            
            # Execute with proper redirection
            if $ZERO_IO; then
                log "Zero-I/O mode: testing connection only"
                eval "$cmd" > /dev/null 2>&1
                if [ $? -eq 0 ]; then
                    echo "Connection to $host:$port successful"
                else
                    echo "Connection to $host:$port failed"
                fi
            else
                log "Executing: $cmd"
                eval "$cmd" < "$FIFO_OUT" > "$FIFO_IN" &
                CLIENT_PID=$!
                
                # Handle data transfer
                cat "$FIFO_IN" &
                INPUT_PID=$!
                cat > "$FIFO_OUT"
                
                # Wait for processes to complete
                wait $CLIENT_PID $INPUT_PID 2>/dev/null || true
            fi
            ;;
            
        bash)
            if $USE_UDP; then
                echo "Error: UDP is not supported with bash /dev/tcp method"
                exit 1
            fi
            
            log "Using bash built-in /dev/tcp"
            
            # Test connection first in zero I/O mode
            if $ZERO_IO; then
                log "Zero-I/O mode: testing connection only"
                (exec 3<>/dev/tcp/$host/$port) >/dev/null 2>&1
                if [ $? -eq 0 ]; then
                    echo "Connection to $host:$port successful"
                else
                    echo "Connection to $host:$port failed"
                fi
                exit 0
            fi
            
            # For regular mode, create a background process for data transfer
            {
                # Timeout handling is tricky with pure bash
                if [ -n "$TIMEOUT" ]; then
                    log "Warning: Connection timeout not fully supported with bash method"
                fi
                
                # Attempt to establish connection
                exec 3<>/dev/tcp/$host/$port
                if [ $? -ne 0 ]; then
                    log "Connection failed"
                    exit 1
                fi
                
                # Forward input/output
                cat <&3 > "$FIFO_IN" &
                READER_PID=$!
                cat "$FIFO_OUT" >&3
                
                # Wait for the reader to finish
                wait $READER_PID 2>/dev/null || true
                
                # Close the file descriptor
                exec 3>&-
            } &
            CLIENT_PID=$!
            
            # Handle data transfer in the main process
            cat "$FIFO_IN" &
            INPUT_PID=$!
            cat > "$FIFO_OUT"
            
            # Wait for processes to complete
            wait $CLIENT_PID $INPUT_PID 2>/dev/null || true
            ;;
    esac
    
    log "Client connection closed"
}

# Main execution
check_requirements

if $LISTEN_MODE; then
    server_mode "$PORT"
else
    client_mode "$HOST" "$PORT"
fi
