#!/bin/bash

###############################################################################
# ELK Stack Update Script (Elasticsearch & Kibana)
# Description : Automates upgrade process for ELK Stack
# Author      : g_ourmet
# Version     : 0.8.3
# Notes       : POSIX-compliant, safe, extendable
###############################################################################

#=============================#
#        Script version       #
#=============================#
SCRIPT_VERSION="0.8.3-beta"

#=============================#
#        Color Setup         #
#=============================#
COLOR_RESET="\033[0m"
COLOR_INFO="\033[1;34m"         # Blue
COLOR_WARN="\033[0;33m"         # Yellow/Orange
COLOR_ERROR="\033[0;31m"        # Red
COLOR_DO="\033[38;5;151m"       # Mintgreen

#=============================#
#      Logging Function      #
#=============================#
LOG_DIR="/var/log/elk-update"
mkdir -p "$LOG_DIR" || {
    printf "${COLOR_ERROR}[ERROR]${COLOR_RESET} Cannot create log directory: %s\n" "$LOG_DIR"
    exit 1
}
LOG_FILE="$LOG_DIR/update_elk_$(date '+%Y%m%d_%H%M%S').log"

log_msg() {
    level="$1"
    shift
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    case "$level" in
        INFO)   printf "${COLOR_INFO}[%s] %s${COLOR_RESET}\n" "$level" "$*" ;;
        WARN)   printf "${COLOR_WARN}[%s] %s${COLOR_RESET}\n" "$level" "$*" ;;
        ERROR)  printf "${COLOR_ERROR}[%s] %s${COLOR_RESET}\n" "$level" "$*" ;;
        DO)     printf "${COLOR_DO}[%s] %s${COLOR_RESET}\n" "$level" "$*" ;;
        *)      printf "[%s] %s\n" "$level" "$*" ;;
    esac
    printf "[%s] [%s] %s\n" "$timestamp" "$level" "$*" >> "$LOG_FILE"
}

#=============================#
#         ASCII Banner        #
#=============================#
print_banner() {
    cat << "EOF"
8888888888 888                   888    d8b          d8b          888
888        888                   888    Y8P          Y8P          888
888        888                   888                              888
8888888    888  .d88b.   .d8888b 888888 888 88888b.  888  .d88b.  88888b.  888  888
888        888 d8P  Y8b d88P"    888    888 888 "88b 888 d88P"88b 888 "88b 888  888
888        888 88888888 888      888    888 888  888 888 888  888 888  888 888  888
888        888 Y8b.     Y88b.    Y88b.  888 888  888 888 Y88b 888 888  888 Y88b 888
8888888888 888  "Y8888   "Y8888P  "Y888 888 888  888 888  "Y88888 888  888  "Y88888
                                                              888               888
                                                         Y8b d88P          Y8b d88P
                                                          "Y88P"            "Y88P"
EOF
    printf "version: ${SCRIPT_VERSION}"
    printf " "
}

#=============================#
#     Show Help Function     #
#=============================#
show_help() {
    print_banner
    cat << EOF
Usage: $0 [OPTIONS]

Required Parameters:
  -a, --api-key     <API_KEY>        API key for authentication
  -v, --version     <VERSION>        Target ELK version (e.g., 8.18.1)
  -eip, --es-ip     <IP>             Elasticsearch IP address

Optional Parameters:
  -esp, --es-port   <PORT>           Elasticsearch port (default: 9200)
  -kip, --kb-ip     <IP>             Kibana IP address (default: same as --es-ip)
  -kp, --kb-port    <PORT>           Kibana port (default: 5601)
  -d, --debug                        Enables the debug mode for logging.
  -wt, --wait-time  <SECONDS>        Optional wait time before shutdown (default: 120s)

  -h, --help                         Show this help message and exit
EOF
}

# show help banner without banner, if an required parameter is missing or misstyped.
show_help_quiet() {
    print_banner
    cat << EOF
Usage: $0 [OPTIONS]
Use -h or --help to display full help with banner and details.
EOF
}

#=============================#
#   Parameter Initialization #
#=============================#
API_KEY=""
VERSION=""
ES_IP=""
ES_PORT="9200"
KB_IP=""
KB_PORT="5601"
DEBUG_MODE=0
DEBUG_LOG="$LOG_DIR/debug_elk_$(date '+%Y%m%d_%H%M%S').log"
WAIT_TIME=120
ES_START_WAIT=120
DRY_RUN=0

#=============================#
#   Parse CLI Arguments      #
#=============================#
while [ "$#" -gt 0 ]; do
    case "$1" in
        -a|--api-key)
            API_KEY="$2"; shift 2 ;;
        -v|--version)
            VERSION="$2"; shift 2 ;;
        -eip|--es-ip)
            ES_IP="$2"; shift 2 ;;
        -esp|--es-port)
            ES_PORT="$2"; shift 2 ;;
        -kip|--kb-ip)
            KB_IP="$2"; shift 2 ;;
        -kp|--kb-port)
            KB_PORT="$2"; shift 2 ;;
        -wt|--wait-time)
            WAIT_TIME="$2"
            if ! printf "%s" "$WAIT_TIME" | grep -Eq '^[0-9]+$' || [ "$WAIT_TIME" -le 0 ]; then
                log_msg "ERROR" "Invalid wait time: $WAIT_TIME"
                exit 1
            fi
            shift 2 ;;
        -d|--debug)
            DEBUG_MODE=1; shift ;;
        -h|--help)
            show_help; exit 0 ;;
        -dr|--dry-run)
            DRY_RUN=1; shift ;;
        *)
            log_msg "ERROR" "Unknown parameter: $1"
            show_help_quiet
            exit 1 ;;
    esac
done

#=============================#
#   Parameter Validation     #
#=============================#
if [ -z "$API_KEY" ] || [ -z "$VERSION" ] || [ -z "$ES_IP" ]; then
    log_msg "ERROR" "Missing required parameters."
    show_help
    exit 1
fi
[ -z "$KB_IP" ] && KB_IP="$ES_IP"

#=============================#
#     Start of Script        #
#=============================#
print_banner
log_msg "DO" "Starting ELK update process"
log_msg "INFO" "Target Version: $VERSION"
log_msg "INFO" "Elasticsearch: ${ES_IP}:${ES_PORT}"
log_msg "INFO" "Kibana: ${KB_IP}:${KB_PORT}"

#=============================#
# Support function for curl   #
#=============================#
call_api() {
    method="$1"
    url="$2"
    header="$3"
    data="$4"

    if [ "$DEBUG_MODE" -eq 1 ]; then
        log_msg "INFO" "Debug: calling $method $url"
        [ -n "$data" ] && body_option="-d $data" || body_option=""
        curl -sk -i -X "$method" "$url" \
            -H "Authorization: ApiKey $API_KEY" \
            -H "Content-Type: application/json" \
            $body_option >> "$DEBUG_LOG" 2>&1
        status=$(tail -n 1 "$DEBUG_LOG" | grep -o '[0-9]\{3\}$')
    else
        if [ -n "$data" ]; then
            status=$(curl -sk -o /dev/null -w "%{http_code}" \
                -X "$method" "$url" \
                -H "Authorization: ApiKey $API_KEY" \
                -H "Content-Type: application/json" \
                -d "$data")
        else
            status=$(curl -sk -o /dev/null -w "%{http_code}" \
                -X "$method" "$url" \
                -H "Authorization: ApiKey $API_KEY")
        fi
    fi
    echo "$status"
}

#=============================#
#  Validate API-Key Function #
#=============================#
validate_api_key() {
    log_msg "INFO" "Validating API key with Elasticsearch (_cluster/settings)..."
    es_status=$(curl -sk -o /dev/null -w "%{http_code}" \
        --request GET \
        "https://${ES_IP}:${ES_PORT}/_cluster/settings" \
        -H "Authorization: ApiKey $API_KEY")

    if [ "$es_status" -eq 200 ]; then
        log_msg "INFO" "API key valid for Elasticsearch."
    else
        log_msg "ERROR" "API key validation failed for Elasticsearch (HTTP $es_status)."
        exit 2
    fi

    log_msg "INFO" "Validating API key with Kibana (/api/status)..."
    kb_status=$(curl -sk -o /dev/null -w "%{http_code}" \
        --request GET \
        "https://${KB_IP}:${KB_PORT}/api/status" \
        -H "Authorization: ApiKey $API_KEY")

    if [ "$kb_status" -eq 200 ]; then
        log_msg "INFO" "API key valid for Kibana."
    else
        log_msg "ERROR" "API key validation failed for Kibana (HTTP $kb_status)."
        exit 3
    fi
}

#=============================#
#  Prepare Elasticsearch      #
#=============================#
prepare_elasticsearch() {
    log_msg "INFO" "Preparing Elasticsearch cluster for upgrade..."

    # 1. Disable shard allocation
    log_msg "INFO" "Disabling shard allocation..."
    payload='{"persistent":{"cluster.routing.allocation.enable":"none"}}'
    status=$(call_api "PUT" "https://${ES_IP}:${ES_PORT}/_cluster/settings" "" "$payload")
    if [ "$status" -ne 200 ]; then
        log_msg "ERROR" "Failed to disable shard allocation (HTTP $status). Aborting."
        exit 3
    fi
    log_msg "INFO" "Shard allocation disabled."

    # 2. Flush
    log_msg "INFO" "Flushing indices..."
    status=$(call_api "POST" "https://${ES_IP}:${ES_PORT}/_flush" "" "")
    if [ "$status" -ne 200 ]; then
        log_msg "ERROR" "Failed to flush indices (HTTP $status). Aborting."
        exit 4
    fi
    log_msg "INFO" "Flush completed."
}

wait_after_preparation() {
    log_msg "INFO" "Waiting ${WAIT_TIME}s to let cluster apply shard allocation setting..."
    sleep "$WAIT_TIME"
    log_msg "INFO" "Wait complete. Proceeding with shutdown."
}

#=============================#
#     Stop Services           #
#=============================#
stop_services() {
    log_msg "INFO" "Stopping Elasticsearch and Kibana services..."

    for service in elasticsearch kibana; do
        log_msg "INFO" "Checking if $service is active..."
        if systemctl is-active --quiet "$service"; then
            log_msg "INFO" "Stopping $service..."
            if systemctl stop "$service"; then
                log_msg "INFO" "$service stopped successfully."
            else
                log_msg "ERROR" "Failed to stop $service. Aborting."
                exit 5
            fi
        else
            log_msg "WARN" "$service is not active. Skipping stop."
        fi
    done
}

#=============================#
#   Check ELK APT Repository  #
#=============================#
check_repo() {
    local major_version="${VERSION%%.*}"
    local repo_file="elastic-${major_version}.x.list"
    local REPO_PATH="/etc/apt/sources.list.d/$repo_file"
    local expected_url="https://artifacts.elastic.co/packages/${major_version}.x/apt"
    local expected_dist="stable"
    local expected_component="main"
    local expected_keyring="elastic-archive-keyring.gpg"

    if [ ! -f "$REPO_PATH" ]; then
        log_msg "ERROR" "Repository file $REPO_PATH not found"
        exit 13
    fi

    local actual_line
    actual_line=$(grep -vE '^\s*#|^\s*$' "$REPO_PATH" | head -n1)

    if [[ "$actual_line" =~ deb\ \[.*signed-by=/usr/share/keyrings/([a-zA-Z0-9._-]+)\.gpg.*\]\ https://artifacts.elastic.co/packages/([0-9]+)\.x/apt\ stable\ main ]]; then
        local found_keyring="${BASH_REMATCH[1]}"
        local found_version="${BASH_REMATCH[2]}"

        if [[ "$found_keyring" != "elastic-archive-keyring" ]]; then
            log_msg "ERROR" "Unexpected keyring: $found_keyring.gpg"
            exit 14
        fi

        if [[ "$found_version" != "$major_version" ]]; then
            log_msg "ERROR" "Repository version mismatch: expected ${major_version}.x, found ${found_version}.x"
            exit 15
        fi

        log_msg "INFO" "Repository configuration is valid"
    else
        log_msg "ERROR" "Repository line in $REPO_PATH does not match expected format"
        echo "[ERROR] Found: $actual_line"
        exit 16
    fi
}

#=============================#
#   Upgrade ELK Components    #
#=============================#
upgrade_elk_components() {
    log_msg "DO" "Updating apt sources..."
    if apt update >> "$LOG_FILE" 2>&1; then
        log_msg "INFO" "APT sources updated successfully."
    else
        log_msg "ERROR" "Failed to update APT sources."
        exit 6
    fi

    log_msg "DO" "Installing Elasticsearch version $VERSION..."
    if apt install -y "elasticsearch=$VERSION" >> "$LOG_FILE" 2>&1; then
        log_msg "INFO" "Elasticsearch $VERSION installed successfully."
    else
        log_msg "ERROR" "Failed to install Elasticsearch $VERSION"
        exit 7
    fi

    log_msg "DO" "Installing Kibana version $VERSION..."
    if apt install -y "kibana=$VERSION" >> "$LOG_FILE" 2>&1; then
        log_msg "INFO" "Kibana $VERSION installed successfully."
    else
        log_msg "ERROR" "Failed to install Kibana $VERSION"
        exit 8
    fi
}

#=============================#
#   Start Elasticsearch       #
#=============================#
start_elasticsearch() {
    log_msg "DO" "Starting Elasticsearch service..."
    if systemctl start elasticsearch; then
        log_msg "INFO" "Elasticsearch service started."
    else
        log_msg "ERROR" "Failed to start Elasticsearch service."
        exit 20
    fi

    log_msg "DO" "Waiting ${ES_START_WAIT}s for Elasticsearch to initialize..."
    sleep "$ES_START_WAIT"
}

#===============================#
#   Reactivate Shard Allocation #
#===============================#
reactivate_shard_allocation() {
    log_msg "DO" "Reactivating shard allocation..."
    response=$(curl -sk -o /dev/null -w "%{http_code}" \
        -X PUT "https://${ES_IP}:${ES_PORT}/_cluster/settings" \
        -H "Authorization: ApiKey $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{
            "persistent": {
                "cluster.routing.allocation.enable": null
            }
        }')

    if [ "$response" -ne 200 ]; then
        log_msg "ERROR" "Failed to reactivate shard allocation (HTTP $response)"
        exit 22
    fi

    log_msg "INFO" "Shard allocation reactivated."

    log_msg "DO" "Waiting 60 seconds for cluster to reassign shards..."
    sleep 60
}

#===============================#
#   Elasticsearch Health-Check  #
#===============================#
check_elasticsearch_health() {
    log_msg "INFO" "Checking Elasticsearch cluster health..."
    max_attempts=30
    attempt=1

    while :; do
        health=$(curl -sk -H "Authorization: ApiKey $API_KEY" \
            "https://${ES_IP}:${ES_PORT}/_cluster/health" | grep -o '"status":"[a-z]*"' | cut -d':' -f2 | tr -d '"')

        log_msg "INFO" "Cluster health: $health (attempt $attempt/$max_attempts)"

        if [ "$health" = "green" ]; then
            log_msg "DO" "Elasticsearch cluster is healthy (green)."
            break
        fi

        if [ "$attempt" -ge "$max_attempts" ]; then
            log_msg "ERROR" "Cluster health check failed after $max_attempts attempts."
            exit 23
        fi

        attempt=$((attempt + 1))
        sleep 5
    done
}

#=============================#
#     Start Kibana            #
#     & Health-Check          #
#=============================#
start_kibana_and_check_health() {
    log_msg "DO" "Starting Kibana service..."

    if systemctl start kibana; then
        log_msg "INFO" "Kibana service started."
    else
        log_msg "ERROR" "Failed to start Kibana service."
        exit 30
    fi

    log_msg "INFO" "Waiting for Kibana to become available..."

    max_attempts=30
    attempt=1

    while :; do
        # Hole Kibana Status
        status=$(curl -sk -H "Authorization: ApiKey $API_KEY" \
            "https://${KB_IP}:${KB_PORT}/api/status" \
            | grep -o '"level":"[a-z]*"' | cut -d':' -f2 | tr -d '"')

        #log_msg "INFO" "Kibana status: $status (attempt $attempt/$max_attempts)"
        echo -ne "\r${COLOR_INFO}[INFO] Kibana status: $status (attempt $attempt/$max_attempts)${COLOR_RESET}"

        if [ -n "$status" ] && { [ "$status" = "available" ] || [ "$status" = "green" ]; }; then
            log_msg "INFO" "Kibana is available."
            echo ""
            break
        fi

        if [ "$attempt" -ge "$max_attempts" ]; then
            log_msg "ERROR" "Kibana did not become available after $max_attempts attempts."
            exit 31
        fi

        attempt=$((attempt + 1))
        sleep 5
    done
}

#=============================#
#     Valide ELK version      #
#=============================#
validate_elk_version() {
    log_msg "DO" "Checking if ELK version $VERSION is available via APT..."

    if ! apt-cache madison elasticsearch | grep -q "$VERSION"; then
        log_msg "ERROR" "Elasticsearch version $VERSION not available in apt-cache."
        exit 40
    fi

    if ! apt-cache madison kibana | grep -q "$VERSION"; then
        log_msg "ERROR" "Kibana version $VERSION not available in apt-cache."
        exit 41
    fi

    log_msg "INFO" "Version $VERSION is available for both Elasticsearch and Kibana."
}

#=============================#
#     Check ELK version       #
#=============================#
check_installed_version() {
    es_installed=$(dpkg-query -W -f='${Version}' elasticsearch 2>/dev/null)
    kb_installed=$(dpkg-query -W -f='${Version}' kibana 2>/dev/null)

    if [ "$es_installed" = "$VERSION" ] && [ "$kb_installed" = "$VERSION" ]; then
        log_msg "INFO" "Elasticsearch and Kibana are already at version $VERSION. No update needed."
        exit 0
    fi

    if [ "$DEBUG_MODE" -eq 1 ]; then
        log_msg "INFO" "Currently installed: Elasticsearch=$es_installed, Kibana=$kb_installed"
    fi
}

#=============================#
#     Cleanup temp files      #
#=============================#
cleanup_temp_files() {
    log_msg "DO" "Cleaning up temporary files..."

    # Beispiel: Alte Debug-Logs löschen (>5 Stück)
    find /var/log/elk-update/ -name "debug_elk_*.log" | sort -r | awk 'NR>5' | while read -r old; do
        log_msg "INFO" "Removing old debug log: $old"
        rm -f "$old"
    done
}

#=============================#
#     Exit Summary            #
#=============================#
exit_summary() {
    log_msg "INFO" "--------------------------------------------------"
    log_msg "INFO" "ELK Stack successfully updated to version $VERSION"
    log_msg "INFO" "Elasticsearch IP: $ES_IP:$ES_PORT"
    log_msg "INFO" "Kibana IP:        $KB_IP:$KB_PORT"
    log_msg "INFO" "API Key:          Validated OK"
    log_msg "INFO" "--------------------------------------------------"
}

#=============================#
#     Call Auth Function     #
#=============================#
validate_api_key
check_repo
validate_elk_version
check_installed_version

prepare_elasticsearch
wait_after_preparation
stop_services
upgrade_elk_components
start_elasticsearch
reactivate_shard_allocation
check_elasticsearch_health
start_kibana_and_check_health

cleanup_temp_files
exit_summary
exit 0
