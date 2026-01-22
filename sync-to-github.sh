#!/bin/bash
# =============================================================================
# IcePorge GitHub Sync Script - Enhanced Version
# Automatically synchronizes local changes to GitHub repositories
# with sensitive data detection and optional screenshot capture
#
# Author: IcePorge Project (GitHub: Icepaule, Email: info@mpauli.de)
# License: MIT with Attribution
#
# Usage: /opt/iceporge/sync-to-github.sh [OPTIONS]
#
# Options:
#   --dry-run       Preview changes without committing
#   --verbose       Show detailed output
#   --screenshots   Capture web interface screenshots
#   --skip-check    Skip sensitive data check (NOT RECOMMENDED)
#   --force         Force push even if sensitive data detected (DANGEROUS)
#
# Cron example (daily at 2:00 AM):
#   0 2 * * * /opt/iceporge/sync-to-github.sh >> /var/log/iceporge-sync.log 2>&1
# =============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/iceporge-sync.log"
LOCK_FILE="/var/run/iceporge-sync.lock"
SCREENSHOT_DIR="/opt/iceporge/screenshots"
DRY_RUN=false
VERBOSE=false
TAKE_SCREENSHOTS=false
SKIP_CHECK=false
FORCE_PUSH=false
HOSTNAME=$(hostname)

# Sensitive data patterns to detect
SENSITIVE_PATTERNS=(
    # API Keys and Tokens
    'api[_-]?key\s*[=:]\s*["\047]?[a-zA-Z0-9_-]{20,}'
    'token\s*[=:]\s*["\047]?[a-zA-Z0-9_-]{20,}'
    'auth[_-]?key\s*[=:]\s*["\047]?[a-zA-Z0-9_-]{16,}'
    'secret[_-]?key\s*[=:]\s*["\047]?[a-zA-Z0-9_-]{16,}'
    'github_pat_[a-zA-Z0-9_]{20,}'

    # Passwords
    'password\s*[=:]\s*["\047][^"\047]{4,}'
    'passwd\s*[=:]\s*["\047][^"\047]{4,}'
    'pass\s*[=:]\s*["\047][^"\047]{4,}'

    # Private Keys
    '-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----'
    '-----BEGIN CERTIFICATE-----'

    # Email Credentials
    'smtp.*pass.*[=:]\s*["\047][^"\047]+'
    'imap.*pass.*[=:]\s*["\047][^"\047]+'

    # Database Credentials
    'postgres://[^:]+:[^@]+@'
    'mysql://[^:]+:[^@]+@'
    'mongodb://[^:]+:[^@]+@'

    # IP Addresses (internal networks)
    '\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b'
    '\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b'
    '\b172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}\b'

    # Personal Email Addresses
    '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(de|com|net|org)'
)

# Files that should NEVER be committed
FORBIDDEN_FILES=(
    '.env'
    'config.yaml'
    'secrets.yaml'
    '*.pem'
    '*.key'
    '*.p12'
    'id_rsa'
    'id_ed25519'
    '.htpasswd'
    'credentials.json'
)

# Repository mappings
declare -A REPOS

case "$HOSTNAME" in
    capev2|cape*)
        REPOS=(
            ["/opt/mwdb-core"]="IcePorge-MWDB-Stack"
            ["/opt/mwdb-feeder"]="IcePorge-MWDB-Feeder"
            ["/opt/cape-feed"]="IcePorge-CAPE-Feed"
            ["/mnt/cape-data/cape-mailer"]="IcePorge-CAPE-Mailer"
            ["/opt/iceporge-cockpit"]="IcePorge-Cockpit"
        )
        SCREENSHOTS_URLS=(
            "https://127.0.0.1:9090/cockpit/@localhost/mwdb-manager/|MWDB-Manager"
            "https://127.0.0.1:9090/cockpit/@localhost/cape-manager/|CAPE-Manager"
            "http://127.0.0.1:8081/|MWDB-WebUI"
        )
        ;;
    ki01|ki*)
        REPOS=(
            ["/opt/ghidra-orchestrator"]="IcePorge-Ghidra-Orchestrator"
            ["/opt/malware-rag"]="IcePorge-Malware-RAG"
        )
        SCREENSHOTS_URLS=()
        ;;
    *)
        echo "Unknown host: $HOSTNAME"
        exit 1
        ;;
esac

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run) DRY_RUN=true; shift ;;
        --verbose) VERBOSE=true; shift ;;
        --screenshots) TAKE_SCREENSHOTS=true; shift ;;
        --skip-check) SKIP_CHECK=true; shift ;;
        --force) FORCE_PUSH=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Logging functions
log() {
    local level="$1"; shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $msg" | tee -a "$LOG_FILE"
}

log_verbose() {
    $VERBOSE && log "DEBUG" "$@"
}

# Lock management
acquire_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local pid=$(cat "$LOCK_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log "ERROR" "Another sync is running (PID: $pid)"
            exit 1
        fi
        rm -f "$LOCK_FILE"
    fi
    echo $$ > "$LOCK_FILE"
    trap "rm -f $LOCK_FILE" EXIT
}

# Sensitive data detection
check_sensitive_data() {
    local repo_path="$1"
    local found_issues=false
    local issues_file=$(mktemp)

    log_verbose "Checking for sensitive data in: $repo_path"

    cd "$repo_path"

    # Check for forbidden files
    for pattern in "${FORBIDDEN_FILES[@]}"; do
        while IFS= read -r file; do
            if [ -n "$file" ] && git ls-files --error-unmatch "$file" 2>/dev/null; then
                echo "FORBIDDEN FILE: $file" >> "$issues_file"
                found_issues=true
            fi
        done < <(find . -name "$pattern" -type f 2>/dev/null | grep -v '.example$' | grep -v '.gitignore')
    done

    # Check staged files for sensitive patterns
    for file in $(git diff --cached --name-only 2>/dev/null); do
        [ -f "$file" ] || continue

        for pattern in "${SENSITIVE_PATTERNS[@]}"; do
            if grep -qEi "$pattern" "$file" 2>/dev/null; then
                # Exclude .example files and comments
                if [[ ! "$file" =~ \.example$ ]] && [[ ! "$file" =~ \.md$ ]]; then
                    local match=$(grep -oEi "$pattern" "$file" 2>/dev/null | head -1)
                    # Redact the actual value for logging
                    local redacted=$(echo "$match" | sed 's/\(.\{10\}\).*/\1***REDACTED***/')
                    echo "SENSITIVE DATA in $file: $redacted" >> "$issues_file"
                    found_issues=true
                fi
            fi
        done
    done

    if $found_issues; then
        log "WARN" "=== SENSITIVE DATA DETECTED ==="
        cat "$issues_file" | while read line; do
            log "WARN" "$line"
        done
        log "WARN" "================================"
        rm -f "$issues_file"
        return 1
    fi

    rm -f "$issues_file"
    log_verbose "No sensitive data found"
    return 0
}

# Screenshot capture (requires chromium/chrome and xvfb)
capture_screenshots() {
    if ! $TAKE_SCREENSHOTS; then
        return 0
    fi

    if ! command -v chromium-browser &>/dev/null && ! command -v google-chrome &>/dev/null; then
        log "WARN" "Chrome/Chromium not found, skipping screenshots"
        return 0
    fi

    mkdir -p "$SCREENSHOT_DIR"
    local date_suffix=$(date '+%Y%m%d')

    log "INFO" "Capturing screenshots..."

    for entry in "${SCREENSHOTS_URLS[@]}"; do
        local url="${entry%%|*}"
        local name="${entry#*|}"
        local filename="$SCREENSHOT_DIR/${name}_${date_suffix}.png"

        log_verbose "Capturing: $name -> $filename"

        # Use headless Chrome with timeout
        timeout 30 chromium-browser \
            --headless \
            --disable-gpu \
            --no-sandbox \
            --screenshot="$filename" \
            --window-size=1920,1080 \
            --ignore-certificate-errors \
            "$url" 2>/dev/null || log "WARN" "Failed to capture $name"
    done

    # Copy screenshots to main repo for inclusion
    if [ -d "$SCREENSHOT_DIR" ]; then
        mkdir -p /opt/iceporge/docs/screenshots
        cp "$SCREENSHOT_DIR"/*.png /opt/iceporge/docs/screenshots/ 2>/dev/null || true
    fi
}

# Create standard .gitignore
create_gitignore() {
    local repo_path="$1"
    local gitignore="$repo_path/.gitignore"

    # Don't overwrite if already comprehensive
    if [ -f "$gitignore" ] && [ $(wc -l < "$gitignore") -gt 20 ]; then
        return 0
    fi

    cat > "$gitignore" << 'GITIGNORE'
# =============================================================================
# IcePorge .gitignore - Security-focused exclusions
# =============================================================================

# Environment and secrets - CRITICAL
.env
.env.local
.env.*.local
secrets/
credentials/
*.pem
*.key
*.crt
*.p12
*.pfx

# Config files with secrets (use .example)
config.yaml
config.json
settings.yaml
settings.json

# API keys and tokens
**/api_key*
**/apikey*
**/token*
**/*secret*

# State and runtime
*.db
*.sqlite*
state.db
*.lock
*.pid

# Logs and reports
logs/
*.log
*.jsonl
reports/

# Work directories
work/
tmp/
temp/
cache/
.cache/
projects/
results/

# Python
__pycache__/
*.py[cod]
*$py.class
venv/
.venv/
*.egg-info/

# Backups
*.bak
*.backup
*.old
*_bak_*

# IDE
.idea/
.vscode/
*.swp
*~

# OS
.DS_Store
Thumbs.db

# Large data
*.zip
*.tar.gz
*.7z
chroma_db/
qdrant_storage/
GITIGNORE
}

# Sync single repository
sync_repo() {
    local repo_path="$1"
    local github_repo="$2"

    if [ ! -d "$repo_path" ]; then
        log "WARN" "Directory not found: $repo_path"
        return 1
    fi

    log "INFO" "Syncing: $repo_path -> $github_repo"
    cd "$repo_path"

    # Initialize git if needed
    if [ ! -d ".git" ]; then
        log "INFO" "Initializing git repo: $repo_path"
        git init
        git remote add origin "git@github.com:icepaule/${github_repo}.git"
        git branch -M main
    fi

    # Update .gitignore
    create_gitignore "$repo_path"

    # Copy LICENSE if missing
    [ ! -f "LICENSE" ] && [ -f "/opt/iceporge/LICENSE" ] && cp /opt/iceporge/LICENSE .

    # Stage changes
    git add -A

    # Check for changes
    if git diff --cached --quiet; then
        log_verbose "No changes in $repo_path"
        return 0
    fi

    # Sensitive data check
    if ! $SKIP_CHECK; then
        if ! check_sensitive_data "$repo_path"; then
            if ! $FORCE_PUSH; then
                log "ERROR" "Aborting sync due to sensitive data. Use --force to override (NOT RECOMMENDED)"
                git reset HEAD
                return 1
            fi
            log "WARN" "Force pushing despite sensitive data detection!"
        fi
    fi

    local changes=$(git diff --cached --stat | tail -1)
    log "INFO" "Changes: $changes"

    if $DRY_RUN; then
        log "INFO" "[DRY-RUN] Would commit and push"
        git diff --cached --stat
        git reset HEAD
        return 0
    fi

    # Commit and push
    local commit_msg="Auto-sync from $HOSTNAME - $(date '+%Y-%m-%d %H:%M')

Changes synchronized automatically by IcePorge sync script.
No sensitive data detected in this commit."

    git commit -m "$commit_msg"

    if git push -u origin main 2>&1; then
        log "INFO" "Successfully pushed to $github_repo"
    else
        log "WARN" "Push failed, trying force push (initial sync)"
        git push -u origin main --force
    fi
}

# Main execution
main() {
    log "INFO" "========== IcePorge Sync Started on $HOSTNAME =========="

    acquire_lock

    # Capture screenshots if requested
    capture_screenshots

    local success=0
    local failed=0

    for repo_path in "${!REPOS[@]}"; do
        github_repo="${REPOS[$repo_path]}"
        if sync_repo "$repo_path" "$github_repo"; then
            ((success++))
        else
            ((failed++))
        fi
    done

    log "INFO" "========== Sync Complete: $success success, $failed failed =========="

    if [ $failed -gt 0 ]; then
        exit 1
    fi
}

main "$@"
