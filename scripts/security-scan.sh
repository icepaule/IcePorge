#!/bin/bash
# =============================================================================
# IcePorge Security Scan Script
# Comprehensive security scanning using TruffleHog and custom patterns
#
# Author: IcePorge Project (GitHub: Icepaule)
# License: MIT with Attribution
#
# Usage: /opt/iceporge/scripts/security-scan.sh [OPTIONS]
#
# Options:
#   --local          Scan local repositories only
#   --github         Scan GitHub repositories (requires gh auth)
#   --all            Scan both local and GitHub
#   --target TARGET  Scan a specific target (path or owner/repo)
#   --type TYPE      Target type: git, github_repo, github_org, filesystem
#   --from-config    Read targets from trufflehog-targets.yaml
#   --json           Output results in JSON format
#   --report FILE    Write report to file
#   --notify         Send Pushover notification on findings
#   --only-verified  Only report verified secrets (default for GitHub)
#   --test-pushover  Send a test Pushover notification and exit
#   --verbose        Show detailed output
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ICEPORGE_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$ICEPORGE_DIR/config"
LOG_FILE="/var/log/iceporge-security.log"
REPORT_DIR="$ICEPORGE_DIR/status"
HOSTNAME=$(hostname)

# Ensure log file is writable, fallback to local if not
if [ ! -w "$LOG_FILE" ] 2>/dev/null; then
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="$ICEPORGE_DIR/status/security-scan.log"
fi
touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/iceporge-security.log"

# Defaults
SCAN_LOCAL=false
SCAN_GITHUB=false
SCAN_TARGET=""
TARGET_TYPE=""
FROM_CONFIG=false
JSON_OUTPUT=false
REPORT_FILE=""
NOTIFY=false
ONLY_VERIFIED=false
TEST_PUSHOVER=false
VERBOSE=false
TARGETS_CONFIG="$CONFIG_DIR/trufflehog-targets.yaml"

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --local) SCAN_LOCAL=true; shift ;;
        --github) SCAN_GITHUB=true; shift ;;
        --all) SCAN_LOCAL=true; SCAN_GITHUB=true; shift ;;
        --target) SCAN_TARGET="$2"; shift 2 ;;
        --type) TARGET_TYPE="$2"; shift 2 ;;
        --from-config) FROM_CONFIG=true; shift ;;
        --json) JSON_OUTPUT=true; shift ;;
        --report) REPORT_FILE="$2"; shift 2 ;;
        --notify) NOTIFY=true; shift ;;
        --only-verified) ONLY_VERIFIED=true; shift ;;
        --test-pushover) TEST_PUSHOVER=true; shift ;;
        --verbose) VERBOSE=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Default to scanning both if none specified
if ! $SCAN_LOCAL && ! $SCAN_GITHUB; then
    SCAN_LOCAL=true
    SCAN_GITHUB=true
fi

# Logging
log() {
    local level="$1"; shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $msg" | tee -a "$LOG_FILE"
}

log_verbose() {
    $VERBOSE && log "DEBUG" "$@"
}

# Load Pushover configuration
load_pushover_config() {
    if [ -f "$CONFIG_DIR/pushover.yaml" ]; then
        PUSHOVER_ENABLED=$(grep -A1 "^pushover:" "$CONFIG_DIR/pushover.yaml" | grep "enabled:" | awk '{print $2}' | tr -d '"')
        PUSHOVER_TOKEN=$(grep "app_token:" "$CONFIG_DIR/pushover.yaml" | awk '{print $2}' | tr -d '"')
        PUSHOVER_USER=$(grep "user_key:" "$CONFIG_DIR/pushover.yaml" | awk '{print $2}' | tr -d '"')
    fi
}

# Send Pushover notification
send_pushover() {
    local title="$1"
    local message="$2"
    local priority="${3:-0}"

    if [ "$PUSHOVER_ENABLED" != "true" ] || [ -z "$PUSHOVER_TOKEN" ] || [ "$PUSHOVER_TOKEN" = "YOUR_PUSHOVER_APP_TOKEN" ]; then
        log_verbose "Pushover not configured, skipping notification"
        return 0
    fi

    curl -s \
        --form-string "token=$PUSHOVER_TOKEN" \
        --form-string "user=$PUSHOVER_USER" \
        --form-string "title=$title" \
        --form-string "message=$message" \
        --form-string "priority=$priority" \
        --form-string "sound=siren" \
        https://api.pushover.net/1/messages.json > /dev/null 2>&1 || true
}

# Load secrets from config
load_secrets() {
    if [ -f "$CONFIG_DIR/secrets.yaml" ]; then
        # Extract secret values from YAML
        SECRETS=$(grep -A2 "^  - name:" "$CONFIG_DIR/secrets.yaml" | grep "value:" | awk -F'"' '{print $2}')
    fi
}

# Test Pushover notification
test_pushover() {
    load_pushover_config
    if [ "$PUSHOVER_ENABLED" != "true" ] || [ -z "$PUSHOVER_TOKEN" ]; then
        echo -e "${RED}Pushover not configured${NC}"
        exit 1
    fi
    send_pushover "IcePorge Security Scanner" "Test-Nachricht vom Security Scanner auf $HOSTNAME" 0
    echo -e "${GREEN}Test notification sent${NC}"
    exit 0
}

# Scan a single target
scan_single_target() {
    local target="$1"
    local type="$2"
    local only_verified="${3:-false}"
    local findings=0

    log "INFO" "Scanning target: $target (type: $type)"

    local cmd="trufflehog"
    local args=""

    case "$type" in
        github_repo)
            cmd="$cmd github --repo=$target"
            ;;
        github_org)
            cmd="$cmd github --org=$target"
            ;;
        git)
            if [[ "$target" != file://* ]]; then
                target="file://$target"
            fi
            cmd="$cmd git $target"
            ;;
        filesystem)
            cmd="$cmd filesystem $target"
            ;;
        *)
            # Auto-detect type
            if [[ "$target" == */* ]] && [[ "$target" != /* ]]; then
                cmd="$cmd github --repo=$target"
            elif [ -d "$target/.git" ]; then
                cmd="$cmd git file://$target"
            elif [ -d "$target" ]; then
                cmd="$cmd filesystem $target"
            else
                log "ERROR" "Cannot determine target type for: $target"
                return 1
            fi
            ;;
    esac

    [ "$only_verified" = "true" ] && cmd="$cmd --only-verified"
    $JSON_OUTPUT && cmd="$cmd --json"

    log_verbose "Running: $cmd"

    local output
    output=$($cmd 2>&1) || true

    if [ -n "$output" ] && [ "$output" != "" ]; then
        local count=0
        if $JSON_OUTPUT; then
            count=$(echo "$output" | jq -s 'length' 2>/dev/null || echo "0")
        else
            count=$(echo "$output" | grep -c "Detector" 2>/dev/null || echo "0")
        fi
        # Ensure count is a valid number
        count=${count//[^0-9]/}
        count=${count:-0}

        if [ "$count" -gt 0 ]; then
            echo -e "${RED}[!] Found $count secrets in $target${NC}"
            echo "$output"
            findings=$count
        else
            echo -e "${GREEN}[+] No secrets found in $target${NC}"
        fi
    else
        echo -e "${GREEN}[+] No secrets found in $target${NC}"
    fi

    return $findings
}

# Scan targets from config file
scan_from_config() {
    local total_findings=0

    if [ ! -f "$TARGETS_CONFIG" ]; then
        log "ERROR" "Targets config not found: $TARGETS_CONFIG"
        return 1
    fi

    log "INFO" "Loading targets from: $TARGETS_CONFIG"

    # Parse YAML and scan enabled targets
    local current_section=""
    local current_name=""
    local current_target=""
    local current_type=""
    local current_enabled=""
    local current_verified=""

    while IFS= read -r line || [ -n "$line" ]; do
        # Detect section
        if [[ "$line" =~ ^github_targets: ]]; then
            current_section="github"
        elif [[ "$line" =~ ^local_targets: ]]; then
            current_section="local"
        elif [[ "$line" =~ ^filesystem_targets: ]]; then
            current_section="filesystem"
        elif [[ "$line" =~ ^external_targets: ]]; then
            current_section="external"
        fi

        # Parse target entries
        if [[ "$line" =~ ^[[:space:]]*-[[:space:]]*name:[[:space:]]*\"?([^\"]+)\"? ]]; then
            # Save previous target if complete
            if [ -n "$current_target" ] && [ "$current_enabled" = "true" ]; then
                echo -e "\n${CYAN}=== Scanning: $current_name ===${NC}"
                scan_single_target "$current_target" "$current_type" "$current_verified" || total_findings=$((total_findings + $?))
            fi
            # Start new target
            current_name="${BASH_REMATCH[1]}"
            current_target=""
            current_type=""
            current_enabled=""
            current_verified=""
        elif [[ "$line" =~ ^[[:space:]]+target:[[:space:]]*\"?([^\"]+)\"? ]]; then
            current_target="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^[[:space:]]+type:[[:space:]]*(.+) ]]; then
            current_type="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^[[:space:]]+enabled:[[:space:]]*(.+) ]]; then
            current_enabled="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^[[:space:]]+only_verified:[[:space:]]*(.+) ]]; then
            current_verified="${BASH_REMATCH[1]}"
        fi
    done < "$TARGETS_CONFIG"

    # Don't forget the last target
    if [ -n "$current_target" ] && [ "$current_enabled" = "true" ]; then
        echo -e "\n${CYAN}=== Scanning: $current_name ===${NC}"
        scan_single_target "$current_target" "$current_type" "$current_verified" || total_findings=$((total_findings + $?))
    fi

    return $total_findings
}

# Check if TruffleHog is installed
check_trufflehog() {
    if ! command -v trufflehog &>/dev/null; then
        log "ERROR" "TruffleHog not installed. Install with:"
        log "ERROR" "  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"
        exit 1
    fi
}

# Scan local repository
scan_local_repo() {
    local repo_path="$1"
    local repo_name=$(basename "$repo_path")
    local findings=0

    log_verbose "Scanning local repo: $repo_path"

    if [ ! -d "$repo_path/.git" ]; then
        log_verbose "Not a git repository: $repo_path"
        return 0
    fi

    # Run TruffleHog on local repo
    local result=$(trufflehog git "file://$repo_path" --json 2>/dev/null || true)

    if [ -n "$result" ]; then
        local count=$(echo "$result" | jq -s 'length' 2>/dev/null || echo "0")
        if [ "$count" -gt 0 ]; then
            findings=$count
            echo -e "${RED}[!] Found $count secrets in $repo_name${NC}"

            if ! $JSON_OUTPUT; then
                echo "$result" | jq -r '.DetectorName + ": " + .SourceMetadata.Data.Git.file + ":" + (.SourceMetadata.Data.Git.line | tostring)' 2>/dev/null | head -10
            fi
        fi
    fi

    return $findings
}

# Scan GitHub organization
scan_github() {
    log "INFO" "Scanning GitHub organization: icepaule"

    local findings_file=$(mktemp)

    # Run TruffleHog on GitHub org
    trufflehog github --org=icepaule --json 2>/dev/null > "$findings_file" || true

    local total=$(cat "$findings_file" | jq -s 'length' 2>/dev/null || echo "0")
    local verified=$(cat "$findings_file" | jq -s '[.[] | select(.Verified == true)] | length' 2>/dev/null || echo "0")

    if [ "$total" -gt 0 ]; then
        echo -e "${RED}[!] GitHub Scan Results:${NC}"
        echo -e "    Total findings: $total"
        echo -e "    Verified secrets: $verified"

        if ! $JSON_OUTPUT; then
            echo ""
            echo "Verified secrets:"
            cat "$findings_file" | jq -r 'select(.Verified == true) | "  - " + .DetectorName + ": " + .SourceMetadata.Data.Github.repository + " (" + .SourceMetadata.Data.Github.file + ")"' 2>/dev/null | sort -u
        fi

        # Copy results to report
        if [ -n "$REPORT_FILE" ]; then
            cp "$findings_file" "$REPORT_FILE"
        fi

        # Send notification
        if $NOTIFY && [ "$verified" -gt 0 ]; then
            send_pushover "IcePorge Security Alert" "Found $verified verified secrets in GitHub repositories!" 1
        fi
    else
        echo -e "${GREEN}[+] No secrets found in GitHub repositories${NC}"
    fi

    rm -f "$findings_file"
    return $verified
}

# Scan local repositories based on hostname
scan_all_local() {
    local total_findings=0
    declare -A REPOS

    case "$HOSTNAME" in
        capev2|cape*)
            REPOS=(
                ["/opt/iceporge"]="IcePorge"
                ["/opt/mwdb-core"]="IcePorge-MWDB-Stack"
                ["/opt/mwdb-feeder"]="IcePorge-MWDB-Feeder"
                ["/opt/cape-feed"]="IcePorge-CAPE-Feed"
                ["/mnt/cape-data/cape-mailer"]="IcePorge-CAPE-Mailer"
                ["/opt/iceporge-cockpit"]="IcePorge-Cockpit"
            )
            ;;
        ki01|ki*)
            REPOS=(
                ["/opt/ghidra-orchestrator"]="IcePorge-Ghidra-Orchestrator"
                ["/opt/malware-rag"]="IcePorge-Malware-RAG"
            )
            ;;
    esac

    log "INFO" "Scanning ${#REPOS[@]} local repositories on $HOSTNAME"

    for repo_path in "${!REPOS[@]}"; do
        if [ -d "$repo_path" ]; then
            scan_local_repo "$repo_path" || total_findings=$((total_findings + $?))
        fi
    done

    return $total_findings
}

# Custom pattern check (in addition to TruffleHog)
check_custom_patterns() {
    local repo_path="$1"
    local findings=0

    log_verbose "Running custom pattern check on: $repo_path"

    # Check for known secrets from config
    load_secrets

    for secret in $SECRETS; do
        if [ -n "$secret" ] && [ ${#secret} -gt 10 ]; then
            if grep -rq "$secret" "$repo_path" --include="*.md" --include="*.txt" --include="*.yaml" --include="*.json" 2>/dev/null; then
                echo -e "${RED}[!] Known secret found in $repo_path${NC}"
                findings=$((findings + 1))
            fi
        fi
    done

    return $findings
}

# Generate summary report
generate_report() {
    local local_findings="$1"
    local github_findings="$2"
    local report_file="${REPORT_FILE:-$REPORT_DIR/security-scan-$(date +%Y%m%d_%H%M%S).json}"

    mkdir -p "$(dirname "$report_file")"

    cat > "$report_file" << EOF
{
    "scan_date": "$(date -Iseconds)",
    "hostname": "$HOSTNAME",
    "scanner_version": "$(trufflehog --version 2>&1 | head -1)",
    "results": {
        "local_findings": $local_findings,
        "github_findings": $github_findings,
        "total_findings": $((local_findings + github_findings))
    },
    "status": "$([ $((local_findings + github_findings)) -eq 0 ] && echo 'clean' || echo 'findings')"
}
EOF

    log "INFO" "Report saved to: $report_file"
}

# Main
main() {
    log "INFO" "========== IcePorge Security Scan Started =========="

    check_trufflehog
    load_pushover_config

    # Handle test-pushover
    if $TEST_PUSHOVER; then
        test_pushover
    fi

    local local_findings=0
    local github_findings=0
    local config_findings=0
    local target_findings=0

    # Scan specific target
    if [ -n "$SCAN_TARGET" ]; then
        echo -e "\n${YELLOW}=== Scanning Specific Target ===${NC}\n"
        scan_single_target "$SCAN_TARGET" "$TARGET_TYPE" "$ONLY_VERIFIED" || target_findings=$?
    # Scan from config file
    elif $FROM_CONFIG; then
        echo -e "\n${YELLOW}=== Scanning Targets from Config ===${NC}\n"
        scan_from_config || config_findings=$?
    else
        # Scan local repositories
        if $SCAN_LOCAL; then
            echo -e "\n${YELLOW}=== Scanning Local Repositories ===${NC}\n"
            scan_all_local || local_findings=$?
        fi

        # Scan GitHub
        if $SCAN_GITHUB; then
            echo -e "\n${YELLOW}=== Scanning GitHub (icepaule) ===${NC}\n"
            scan_github || github_findings=$?
        fi
    fi

    local total_findings=$((local_findings + github_findings + config_findings + target_findings))

    # Summary
    echo -e "\n${YELLOW}=== Summary ===${NC}"
    if [ -n "$SCAN_TARGET" ]; then
        echo "Target findings: $target_findings"
    elif $FROM_CONFIG; then
        echo "Config findings: $config_findings"
    else
        echo "Local findings:  $local_findings"
        echo "GitHub findings: $github_findings"
    fi
    echo "Total:           $total_findings"

    # Generate report if requested
    if [ -n "$REPORT_FILE" ] || $JSON_OUTPUT; then
        generate_report "$local_findings" "$github_findings"
    fi

    # Send notification if findings
    if $NOTIFY && [ $total_findings -gt 0 ]; then
        send_pushover "IcePorge Security Scan" "Found $total_findings potential secrets on $HOSTNAME. Check logs for details." 1
    fi

    log "INFO" "========== Security Scan Complete =========="

    # Exit with error if findings
    [ $total_findings -eq 0 ]
}

main "$@"
