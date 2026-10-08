#!/bin/bash

# SSH Alert Enhanced - Secure SSH Connection Monitoring Tool
# =========================================================
# Enhanced version with Python key parser integration
# Author: SSH Alert System
# Version: 1.1.0

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="/etc/ssh-alert/config.conf"
RATE_LIMIT_DIR="/run/ssh-alert/rate-limit"
KEY_PARSER="${SCRIPT_DIR}/key-parser.py"

# Load configuration
load_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi
    
    # Source configuration file
    source "$CONFIG_FILE"
    export SSH_AUTHORIZED_KEYS_PATH SSH_AUTH_LOG_PATH PARSE_AUTH_LOG_FOR_FINGERPRINTS
    
    # Validate required settings
    if [[ -z "${TELEGRAM_BOT_TOKEN:-}" ]]; then
        log_error "TELEGRAM_BOT_TOKEN is not set in configuration"
        exit 1
    fi
    
    if [[ -z "${TELEGRAM_CHAT_ID:-}" ]]; then
        log_error "TELEGRAM_CHAT_ID is not set in configuration"
        exit 1
    fi
}

# Logging functions
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if [[ "${LOG_LEVEL:-INFO}" == "DEBUG" ]] || [[ "$level" != "DEBUG" ]]; then
        echo "[$timestamp] [$level] $message" >> "${LOG_FILE:-/var/log/ssh-alert.log}"
    fi
    
    if [[ "$level" == "ERROR" ]]; then
        echo "ERROR: $message" >&2
    elif [[ "$level" == "DEBUG" ]] && [[ "${LOG_LEVEL:-INFO}" == "DEBUG" ]]; then
        echo "DEBUG: $message" >&2
    fi
}

log_info() { log "INFO" "$@"; }
log_warning() { log "WARNING" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { log "DEBUG" "$@"; }

# Format only the notification time using the selected IANA time zone.
format_notification_time() {
    local notification_timezone="${NOTIFICATION_TIMEZONE:-UTC}"
    if [[ ! "$notification_timezone" =~ ^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$ ]] || \
       [[ ! -f "/usr/share/zoneinfo/$notification_timezone" ]]; then
        log_warning "Invalid NOTIFICATION_TIMEZONE: $notification_timezone; using UTC"
        notification_timezone="UTC"
    fi
    TZ="$notification_timezone" date '+%Y-%m-%d %H:%M:%S %Z (%z)'
}

# Rate limiting functions
check_rate_limit() {
    local key="$1"
    local limit_seconds="${2:-300}"
    
    local key_hash
    key_hash=$(printf '%s' "$key" | python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')
    local rate_file="${RATE_LIMIT_DIR}/${key_hash}"

    umask 077
    mkdir -p "$RATE_LIMIT_DIR" || return 2
    # Wait only for the same account/IP/key. Other connections run independently.
    exec 200>"${rate_file}.lock" || return 2
    flock 200 || return 2
    RATE_LIMIT_FILE="$rate_file"
    
    if [[ -f "$rate_file" ]]; then
        local last_notification=$(cat "$rate_file")
        local current_time=$(date +%s)
        [[ "$last_notification" =~ ^[0-9]+$ ]] || last_notification=0
        local time_diff=$((current_time - last_notification))
        
        if [[ $time_diff -lt $limit_seconds ]]; then
            log_debug "Rate limit active for key: $key (${time_diff}s ago, limit: ${limit_seconds}s)"
            return 1
        fi
    fi
    
    return 0
}

# IP address utilities
is_local_ip() {
    local ip="$1"
    
    if [[ "${IGNORE_LOCAL_IPS:-true}" != "true" ]]; then
        return 1
    fi
    
    # Check against common local IP ranges
    local local_ranges="${LOCAL_IP_RANGES:-192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.0/8}"
    
    IFS=',' read -ra RANGES <<< "$local_ranges"
    for range in "${RANGES[@]}"; do
        if ip_in_range "$ip" "$range"; then
            return 0
        fi
    done
    
    return 1
}

ip_in_range() {
    local ip="$1"
    local range="$2"
    
    # Simple CIDR check for common ranges
    case "$range" in
        "192.168.0.0/16")
            [[ "$ip" =~ ^192\.168\. ]]
            ;;
        "10.0.0.0/8")
            [[ "$ip" =~ ^10\. ]]
            ;;
        "172.16.0.0/12")
            [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]
            ;;
        "127.0.0.0/8")
            [[ "$ip" =~ ^127\. ]]
            ;;
        *)
            return 1
            ;;
    esac
}

# Check if key comment should be excluded from alerts
is_key_excluded() {
    local key_comment="$1"
    
    # If no exclusions configured, allow all
    if [[ -z "${EXCLUDED_KEY_COMMENTS:-}" ]]; then
        return 1
    fi
    
    # Check if key comment is in the exclusion list
    IFS=',' read -ra EXCLUDED <<< "$EXCLUDED_KEY_COMMENTS"
    for excluded_comment in "${EXCLUDED[@]}"; do
        # Trim whitespace
        excluded_comment=$(echo "$excluded_comment" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
        # Check for exact match or wildcard match
        if [[ "$key_comment" == "$excluded_comment" ]] || [[ "$key_comment" == *"$excluded_comment"* ]]; then
            log_debug "Key comment '$key_comment' is excluded from alerts"
            return 0
        fi
    done
    
    return 1
}

# Check if IP address should be excluded from alerts
is_ip_excluded() {
    local ip_address="$1"
    
    # If no exclusions configured, allow all
    if [[ -z "${EXCLUDED_IPS:-}" ]]; then
        return 1
    fi
    
    # Check if IP is in the exclusion list
    IFS=',' read -ra EXCLUDED <<< "$EXCLUDED_IPS"
    for excluded_ip in "${EXCLUDED[@]}"; do
        # Trim whitespace
        excluded_ip=$(echo "$excluded_ip" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
        # Check for exact match
        if [[ "$ip_address" == "$excluded_ip" ]]; then
            log_debug "IP address '$ip_address' is excluded from alerts"
            return 0
        fi
    done
    
    return 1
}

# Check if username should be excluded from alerts
is_username_excluded() {
    local username="$1"
    
    # If no exclusions configured, allow all
    if [[ -z "${EXCLUDED_USERNAMES:-}" ]]; then
        return 1
    fi
    
    # Check if username is in the exclusion list
    IFS=',' read -ra EXCLUDED <<< "$EXCLUDED_USERNAMES"
    for excluded_user in "${EXCLUDED[@]}"; do
        # Trim whitespace
        excluded_user=$(echo "$excluded_user" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
        # Check for exact match
        if [[ "$username" == "$excluded_user" ]]; then
            log_debug "Username '$username' is excluded from alerts"
            return 0
        fi
    done
    
    return 1
}

# Enhanced connection information gathering
get_connection_info() {
    if [[ ! -f "$KEY_PARSER" ]]; then
        log_warning "Python key parser not found, using fallback method"
        get_connection_info_fallback
        return
    fi
    
    # Use Python parser for enhanced information
    local connection_info
    if connection_info=$(python3 "$KEY_PARSER" get-info 2>/dev/null); then
        echo "$connection_info"
    else
        log_warning "Python parser failed, using fallback method"
        get_connection_info_fallback
    fi
}

get_connection_info_fallback() {
    # Fallback method using environment variables
    local ip_address=""
    local username=""
    local connection_type=""
    
    # Get IP address
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        ip_address=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    elif [[ -n "${SSH_CLIENT:-}" ]]; then
        ip_address=$(echo "$SSH_CLIENT" | awk '{print $1}')
    else
        ip_address="unknown"
    fi
    
    # Get username
    username="${SSH_LOGIN_USER:-${USER:-$(whoami)}}"
    
    # Get connection type
    if [[ -n "${SSH_TTY:-}" ]]; then
        connection_type="Interactive shell"
    elif [[ -n "${SSH_ORIGINAL_COMMAND:-}" ]]; then
        connection_type="Command execution"
    elif [[ -n "${SSH_TUNNEL:-}" ]]; then
        connection_type="Tunnel"
    else
        connection_type="Command execution"
    fi

    python3 - "$ip_address" "$username" "$connection_type" "${SSH_USER:-}" <<'PY'
import json, sys
print(json.dumps(dict(zip(('ip_address', 'username', 'connection_type', 'ssh_user'), sys.argv[1:]))))
PY
}

# Enhanced key information gathering
get_key_info() {
    local ip_address="$1"
    local username="$2"
    local source_port="${3:-}"
    
    if [[ ! -f "$KEY_PARSER" ]]; then
        echo '{"fingerprint": "unknown", "comment": "unknown"}'
        return
    fi
    
    # Try to get key info using the new method
    local key_info
    if key_info=$(python3 "$KEY_PARSER" find-key-by-connection "$ip_address" "$username" "$source_port" 2>/dev/null); then
        echo "$key_info" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    result = {
        'fingerprint': data.get('fingerprint', 'unknown'),
        'comment': data.get('comment', 'unknown'),
        'ssh_user': data.get('options', {}).get('SSH_USER', '')
    }
    print(json.dumps(result))
except:
    print('{\"fingerprint\": \"unknown\", \"comment\": \"unknown\"}')
"
        return
    fi
    
    # Missing authentication evidence must not be replaced with an arbitrary key.
    echo '{"fingerprint": "unknown", "comment": "unknown"}'
}

# Telegram notification functions
send_telegram_message() {
    local message="$1"
    local disable_notification="${2:-false}"
    
    local url="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage"
    
    local attempt=1
    local max_attempts="${TELEGRAM_RETRY_ATTEMPTS:-3}"
    local retry_delay="${TELEGRAM_RETRY_DELAY:-5}"
    
    while [[ $attempt -le $max_attempts ]]; do
        log_debug "Sending Telegram message (attempt $attempt/$max_attempts)"
        
        local response
        response=$(curl -s -w "\n%{http_code}" -X POST "$url" \
            --data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
            --data-urlencode "text=${message}" \
            --data-urlencode "disable_notification=${disable_notification}" \
            --connect-timeout 10 --max-time 30) || response="${response:-}"
        local http_code=$(echo "$response" | tail -n1)
        local body=$(echo "$response" | head -n -1)
        
        if [[ "$http_code" == "200" ]]; then
            log_info "Telegram notification sent successfully"
            return 0
        else
            log_warning "Telegram API error (HTTP $http_code): $body"
            if [[ $attempt -lt $max_attempts ]]; then
                log_info "Retrying in ${retry_delay} seconds..."
                sleep "$retry_delay"
            fi
        fi
        
        ((attempt++))
    done
    
    log_error "Failed to send Telegram notification after $max_attempts attempts"
    return 1
}

# JSON logging function
log_json_event() {
    local event_data="$1"
    
    if [[ "${JSON_LOGGING:-false}" == "true" ]]; then
        local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        local json_log_entry=$(echo "$event_data" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    data['timestamp'] = '$timestamp'
    data['event_type'] = 'ssh_connection'
    print(json.dumps(data))
except:
    print('{\"timestamp\": \"$timestamp\", \"event_type\": \"ssh_connection\", \"error\": \"json_parse_failed\"}')
")
        echo "$json_log_entry" >> "${LOG_FILE:-/var/log/ssh-alert.log}"
    fi
}

# Main notification function
send_ssh_alert() (
    local connection_info="$1"
    local key_info="$2"
    
    # Parse connection info
    local ip_address=$(echo "$connection_info" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('ip_address', 'unknown'))")
    local username=$(echo "$connection_info" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('username', 'unknown'))")
    local connection_type=$(echo "$connection_info" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('connection_type', 'unknown'))")
    local ssh_user=$(echo "$connection_info" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('ssh_user') or '')")
    
    # Fix username if it's None or unknown
    if [[ "$username" == "None" || "$username" == "unknown" || -z "$username" || "$username" == "null" ]]; then
        username="${SSH_LOGIN_USER:-$(whoami)}"
    fi
    local login_username="$username"
    
    # Parse key info
    local key_fingerprint=$(echo "$key_info" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('fingerprint', 'unknown'))")
    local key_comment=$(echo "$key_info" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('comment', 'unknown'))")
    local key_ssh_user=$(echo "$key_info" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('ssh_user') or '')")
    
    # Use SSH_USER from key if available
    if [[ -n "$key_ssh_user" ]]; then
        username="$key_ssh_user"
    elif [[ -n "$ssh_user" ]]; then
        username="$ssh_user"
    fi
    
    # Skip local IPs if configured
    if is_local_ip "$ip_address"; then
        log_debug "Skipping notification for local IP: $ip_address"
        return 0
    fi
    
    # Check if IP address is excluded from alerts
    if is_ip_excluded "$ip_address"; then
        log_info "Skipping notification for excluded IP address: $ip_address"
        return 0
    fi
    
    # Check if username is excluded from alerts
    if is_username_excluded "$login_username" || is_username_excluded "$username"; then
        log_info "Skipping notification for excluded username: $username"
        return 0
    fi
    
    # Check if key comment is excluded from alerts
    if is_key_excluded "$key_comment"; then
        log_debug "Skipping notification for excluded key comment: $key_comment"
        return 0
    fi
    
    # Check notification settings based on connection type
    case "$connection_type" in
        "Interactive shell")
            if [[ "${NOTIFY_INTERACTIVE_SESSIONS:-true}" != "true" ]]; then
                log_debug "Interactive sessions notifications disabled"
                return 0
            fi
            ;;
        "Tunnel")
            if [[ "${NOTIFY_TUNNELS:-false}" != "true" ]]; then
                log_debug "Tunnel notifications disabled"
                return 0
            fi
            ;;
        "Command execution")
            if [[ "${NOTIFY_COMMANDS:-false}" != "true" ]]; then
                log_debug "Command execution notifications disabled"
                return 0
            fi
            ;;
    esac
    
    # Deduplicate only the same account, source IP and key.
    local rate_key="${login_username}|${ip_address}|${key_fingerprint}"
    local rate_limit_seconds="${RATE_LIMIT_PER_IP:-300}"
    
    if [[ "$connection_type" == "Tunnel" ]]; then
        rate_limit_seconds="${RATE_LIMIT_PER_KEY:-60}"
    fi
    
    if check_rate_limit "$rate_key" "$rate_limit_seconds"; then
        :
    else
        local rate_status=$?
        if [[ $rate_status -ne 1 ]]; then
            log_error "Could not access rate limiting state"
            return "$rate_status"
        fi
        log_debug "Rate limit active for $rate_key"
        return 0
    fi
    
    # Prepare notification message
    local server_name="${SERVER_NAME:-$(hostname)}"
    local server_domain="${SERVER_DOMAIN:-}"
    local full_server_name="$server_name"
    
    if [[ -n "$server_domain" ]]; then
        full_server_name="${server_name}.${server_domain}"
    fi
    
    # Get server IP addresses (external and local)
    local external_ip=""
    local local_ip=""
    
    # Get external IP
    if command -v curl >/dev/null 2>&1; then
        external_ip=$(curl -fsS --connect-timeout 5 --max-time 10 https://ifconfig.me 2>/dev/null || curl -fsS --connect-timeout 5 --max-time 10 https://ifconfig.co 2>/dev/null || curl -fsS --connect-timeout 5 --max-time 10 https://icanhazip.com 2>/dev/null || true)
    elif command -v wget >/dev/null 2>&1; then
        external_ip=$(wget -qO- --timeout=10 https://ifconfig.me 2>/dev/null || wget -qO- --timeout=10 https://ifconfig.co 2>/dev/null || true)
    fi
    
    # Get local IP
    if command -v hostname >/dev/null 2>&1 && hostname -I >/dev/null 2>&1; then
        local_ip=$(hostname -I | awk '{print $1}')
    elif command -v ip >/dev/null 2>&1; then
        local_ip=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' | head -1)
    elif command -v ifconfig >/dev/null 2>&1; then
        local_ip=$(ifconfig | grep -oP 'inet \K(?:[0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v '127.0.0.1' | head -1)
    fi
    
    # Fallback for local IP
    if [[ -z "$local_ip" ]]; then
        local_ip="127.0.0.1"
    fi
    
    # Format server IPs
    local server_ip="$local_ip"
    if [[ -n "$external_ip" && "$external_ip" != "$local_ip" ]]; then
        server_ip="$external_ip / $local_ip"
    fi
    
    local person_info=""
    if [[ -n "$key_comment" && "$key_comment" != "unknown" ]]; then
        person_info="$key_comment"
    else
        person_info="$username"
    fi
    
    local message="🔐 SSH Login Alert:
Host IP: $server_ip
Host: $full_server_name
Person: $person_info
IP: $ip_address
Type: $connection_type
Key: ${key_fingerprint}
Time: $(format_notification_time)"
    
    # Determine if notification should be silent
    local disable_sound="false"
    if [[ "$connection_type" == "Tunnel" ]] && [[ "${DISABLE_NOTIFICATION_SOUND_FOR_TUNNELS:-true}" == "true" ]]; then
        disable_sound="true"
    fi
    
    # Send notification
    if ! send_telegram_message "$message" "$disable_sound"; then
        return 1
    fi
    date +%s > "$RATE_LIMIT_FILE" || return 1
    
    # Log the event
    log_info "SSH alert sent: $username@$full_server_name from $ip_address ($connection_type)"
    
    # JSON logging
    local event_data
    event_data=$(python3 - "$connection_info" "$key_info" "$full_server_name" "$username" "$disable_sound" <<'PY'
import sys, json
data = json.loads(sys.argv[1])
data.update(json.loads(sys.argv[2]))
data.update(server_name=sys.argv[3], username=sys.argv[4], notification_sent=True,
            sound_disabled=sys.argv[5] == 'true')
print(json.dumps(data))
PY
)
    log_json_event "$event_data"
)

# Main function
main() {
    # Load configuration
    load_config
    
    log_debug "SSH Alert Enhanced script started"
    
    # Get connection information
    local connection_info
    connection_info=$(get_connection_info)
    
    # Parse basic info for key lookup
    local ip_address=$(echo "$connection_info" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('ip_address', 'unknown'))")
    local username=$(echo "$connection_info" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('username', 'unknown'))")
    local source_port=$(echo "$connection_info" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('port', ''))")
    
    # Get key information
    local key_info
    key_info=$(get_key_info "$ip_address" "$username" "$source_port")
    
    # Send alert
    send_ssh_alert "$connection_info" "$key_info"
    
    log_debug "SSH Alert Enhanced script completed"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
