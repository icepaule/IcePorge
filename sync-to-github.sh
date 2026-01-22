#!/bin/bash
# =============================================================================
# IcePorge GitHub Sync Script
# Automatically synchronizes local changes to GitHub repositories
#
# Author: IcePorge Project (GitHub: Icepaule)
# Usage: /opt/iceporge/sync-to-github.sh [--dry-run] [--verbose]
#
# Cron example (daily at 2:00 AM):
#   0 2 * * * /opt/iceporge/sync-to-github.sh >> /var/log/iceporge-sync.log 2>&1
# =============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/iceporge-sync.log"
LOCK_FILE="/var/run/iceporge-sync.lock"
DRY_RUN=false
VERBOSE=false
HOSTNAME=$(hostname)

# Repository mappings: local_path:github_repo
declare -A REPOS

# Detect which server we're on and configure repos accordingly
case "$HOSTNAME" in
    capev2|cape*)
        REPOS=(
            ["/opt/mwdb-core"]="IcePorge-MWDB-Stack"
            ["/opt/mwdb-feeder"]="IcePorge-MWDB-Feeder"
            ["/opt/cape-feed"]="IcePorge-CAPE-Feed"
            ["/mnt/cape-data/cape-mailer"]="IcePorge-CAPE-Mailer"
            ["/usr/share/cockpit/cape-manager"]="IcePorge-Cockpit"
            ["/usr/share/cockpit/mwdb-manager"]="IcePorge-Cockpit"
        )
        ;;
    ki01|ki*)
        REPOS=(
            ["/opt/ghidra-orchestrator"]="IcePorge-Ghidra-Orchestrator"
            ["/opt/malware-rag"]="IcePorge-Malware-RAG"
        )
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
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Logging function
log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $msg" | tee -a "$LOG_FILE"
}

log_verbose() {
    if $VERBOSE; then
        log "DEBUG" "$@"
    fi
}

# Lock to prevent concurrent runs
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

# Create standard .gitignore for security
create_gitignore() {
    local repo_path="$1"
    local gitignore="$repo_path/.gitignore"

    cat > "$gitignore" << 'GITIGNORE'
# =============================================================================
# IcePorge .gitignore - Security-focused exclusions
# =============================================================================

# Environment and secrets
.env
*.env.local
.env.*.local
secrets/
credentials/
*.pem
*.key
*.crt
*.p12
*.pfx

# API keys and tokens
**/api_key*
**/apikey*
**/token*
**/*secret*
**/*password*

# Configuration with secrets (use .example versions)
config.yaml
config.json
settings.yaml
settings.json

# State and runtime data
*.db
*.sqlite
*.sqlite3
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

# Python
__pycache__/
*.py[cod]
*$py.class
.Python
*.egg-info/
.eggs/
venv/
.venv/
ENV/

# Docker
docker-compose.override.yml

# IDE
.idea/
.vscode/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Backup files
*.bak
*.backup
*.old

# Quarantine and processed files
quarantine/
processed/
GITIGNORE
}

# Initialize git repo if needed
init_repo() {
    local repo_path="$1"
    local github_repo="$2"

    if [ ! -d "$repo_path/.git" ]; then
        log "INFO" "Initializing git repo: $repo_path"
        cd "$repo_path"
        git init
        git remote add origin "git@github.com:icepaule/${github_repo}.git"
        git branch -M main
    fi
}

# Sync a single repository
sync_repo() {
    local repo_path="$1"
    local github_repo="$2"

    if [ ! -d "$repo_path" ]; then
        log "WARN" "Directory not found: $repo_path"
        return 1
    fi

    log "INFO" "Syncing: $repo_path -> $github_repo"
    cd "$repo_path"

    # Initialize if needed
    init_repo "$repo_path" "$github_repo"

    # Create/update .gitignore
    create_gitignore "$repo_path"

    # Copy LICENSE if not exists
    if [ ! -f "$repo_path/LICENSE" ] && [ -f "/opt/iceporge/LICENSE" ]; then
        cp /opt/iceporge/LICENSE "$repo_path/"
    fi

    # Check for changes
    git add -A

    if git diff --cached --quiet; then
        log_verbose "No changes in $repo_path"
        return 0
    fi

    # Count changes
    local added=$(git diff --cached --numstat | wc -l)
    local files_changed=$(git diff --cached --name-only | head -10 | tr '\n' ', ')

    log "INFO" "Found $added changed files: ${files_changed%,}"

    if $DRY_RUN; then
        log "INFO" "[DRY-RUN] Would commit and push changes"
        git diff --cached --stat
        git reset HEAD
        return 0
    fi

    # Commit
    local commit_msg="Auto-sync from $HOSTNAME - $(date '+%Y-%m-%d %H:%M')"
    git commit -m "$commit_msg"

    # Push
    if git push -u origin main 2>&1; then
        log "INFO" "Successfully pushed to $github_repo"
    else
        # Try force push if remote has different history (first push after LICENSE)
        log "WARN" "Normal push failed, trying with --force (initial sync)"
        git push -u origin main --force
    fi
}

# Main execution
main() {
    log "INFO" "========== IcePorge Sync Started on $HOSTNAME =========="

    acquire_lock

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
}

main "$@"
