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
#   --json           Output results in JSON format
#   --report FILE    Write report to file
#   --notify         Send Pushover notification on findings
#   --verbose        Show detailed output
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ICEPORGE_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$ICEPORGE_DIR/config"
LOG_FILE="/var/log/iceporge-security.log"
REPORT_DIR="$ICEPORGE_DIR/status"
HOSTNAME=$(hostname)

# Defaults
SCAN_LOCAL=false
SCAN_GITHUB=false
JSON_OUTPUT=false
REPORT_FILE=""
NOTIFY=false
VERBOSE=false

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --local) SCAN_LOCAL=true; shift ;;
        --github) SCAN_GITHUB=true; shift ;;
        --all) SCAN_LOCAL=true; SCAN_GITHUB=true; shift ;;
        --json) JSON_OUTPUT=true; shift ;;
        --report) REPORT_FILE="$2"; shift 2 ;;
        --notify) NOTIFY=true; shift ;;
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

    local local_findings=0
    local github_findings=0

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

    # Summary
    echo -e "\n${YELLOW}=== Summary ===${NC}"
    echo "Local findings:  $local_findings"
    echo "GitHub findings: $github_findings"
    echo "Total:           $((local_findings + github_findings))"

    # Generate report if requested
    if [ -n "$REPORT_FILE" ] || $JSON_OUTPUT; then
        generate_report "$local_findings" "$github_findings"
    fi

    # Send notification if findings
    if $NOTIFY && [ $((local_findings + github_findings)) -gt 0 ]; then
        send_pushover "IcePorge Security Scan" "Found $((local_findings + github_findings)) potential secrets. Check logs for details." 1
    fi

    log "INFO" "========== Security Scan Complete =========="

    # Exit with error if findings
    [ $((local_findings + github_findings)) -eq 0 ]
}

main "$@"
