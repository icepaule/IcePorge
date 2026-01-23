#!/bin/bash
# =============================================================================
# IcePorge Website Sync Script
# Syncs static website content to webserver
#
# Usage: /opt/iceporge/scripts/sync-website.sh [--full|--status-only]
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEBSERVER="mpauli@46.4.142.234"
WEBSERVER_PATH="/var/www/mpauli.de"
LOCAL_SCREENSHOTS="/opt/iceporge/docs/screenshots"
LOCAL_DOCS="/mnt/cape-data/cape-mailer/docs/samples"
WEBSITE_FILE="/tmp/iceporge-website.html"

MODE="${1:-full}"

# =============================================================================
# SECURITY CHECK - Scan for sensitive data before upload
# =============================================================================
# Allowed domains (will not be flagged)
# Includes owner domains + RFC 2606 reserved example domains (and subdomains)
ALLOWED_DOMAINS="mpauli\.de|paulis\.net|thesoc\.de|([a-z0-9.-]+\.)?example\.(com|org|net|de)"

check_sensitive_data() {
    local file="$1"
    local filename=$(basename "$file")
    local errors=0

    echo "  Scanning: $filename"

    # Check for internal hostnames (capev2, ki01, etc.)
    if grep -qiE '\b(capev2|ki01|cape-server|mwdb-server)\b' "$file" 2>/dev/null; then
        echo "    [BLOCKED] Internal hostnames found (capev2, ki01, etc.)"
        grep -niE '\b(capev2|ki01|cape-server|mwdb-server)\b' "$file" | head -5
        errors=$((errors + 1))
    fi

    # Check for internal domain names (*.local, *.internal)
    if grep -qiE '\.(local|internal|lan)\b' "$file" 2>/dev/null; then
        echo "    [BLOCKED] Internal domains found (.local, .internal)"
        grep -niE '\.(local|internal|lan)\b' "$file" | head -5
        errors=$((errors + 1))
    fi

    # Check for IP addresses (except localhost, documentation IPs, and version numbers in meta tags)
    # Filter out: 127.0.0.1, RFC 5737 doc IPs (192.0.2.x, 198.51.100.x, 203.0.113.x), 0.0.0.0
    # Also filter version numbers (detected by context like "content=" or small first octet patterns)
    local ip_matches=$(grep -oE '\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b' "$file" 2>/dev/null | \
       grep -vE '^(127\.0\.0\.1|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|0\.0\.0\.0|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' | \
       grep -vE '^[0-9]{1,2}\.[0-9]\.[0-9]\.[0-9]$' || true)
    if [ -n "$ip_matches" ]; then
        echo "    [BLOCKED] Real IP addresses found (not documentation IPs)"
        grep -noE '\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b' "$file" | \
            grep -vE '127\.0\.0\.1|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|0\.0\.0\.0|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.' | \
            grep -vE ':[0-9]{1,2}\.[0-9]\.[0-9]\.[0-9]$' | head -5
        errors=$((errors + 1))
    fi

    # Check for email addresses (except allowed domains)
    if grep -oiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' "$file" 2>/dev/null | \
       grep -viE "@($ALLOWED_DOMAINS)" | grep -qE '.'; then
        echo "    [BLOCKED] Email addresses from non-allowed domains found"
        grep -noiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' "$file" | \
            grep -viE "@($ALLOWED_DOMAINS)" | head -5
        errors=$((errors + 1))
    fi

    # Check for passwords, API keys, secrets
    if grep -qiE '(password|passwd|api[_-]?key|secret[_-]?key|auth[_-]?token|bearer)\s*[:=]\s*["\047]?[a-zA-Z0-9+/=_-]{8,}' "$file" 2>/dev/null; then
        echo "    [BLOCKED] Potential passwords/API keys found"
        grep -niE '(password|passwd|api[_-]?key|secret[_-]?key|auth[_-]?token|bearer)\s*[:=]' "$file" | head -5
        errors=$((errors + 1))
    fi

    # Check for SSH connection strings with usernames
    if grep -qE '[a-zA-Z0-9_]+@[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$file" 2>/dev/null; then
        echo "    [BLOCKED] SSH connection strings (user@IP) found"
        grep -nE '[a-zA-Z0-9_]+@[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$file" | head -5
        errors=$((errors + 1))
    fi

    # Check for private paths
    if grep -qE '(/home/[a-zA-Z0-9_]+|/root/)' "$file" 2>/dev/null; then
        # Allow documentation paths like /opt, /var, /etc
        if grep -E '(/home/[a-zA-Z0-9_]+|/root/)' "$file" | grep -qvE '(example|sample|doc)'; then
            echo "    [BLOCKED] Private paths found (/home/user, /root)"
            grep -nE '(/home/[a-zA-Z0-9_]+|/root/)' "$file" | head -5
            errors=$((errors + 1))
        fi
    fi

    return $errors
}

security_scan() {
    echo ""
    echo "=== SECURITY SCAN - Checking for sensitive data ==="
    local total_errors=0

    # Scan main website file
    if [ -f "$WEBSITE_FILE" ]; then
        if ! check_sensitive_data "$WEBSITE_FILE"; then
            total_errors=$((total_errors + 1))
        fi
    fi

    # Scan documents directory
    if [ -d "$LOCAL_DOCS" ]; then
        shopt -s nullglob
        for doc in "$LOCAL_DOCS"/*.html "$LOCAL_DOCS"/*.htm "$LOCAL_DOCS"/*.txt; do
            [ -f "$doc" ] || continue
            if ! check_sensitive_data "$doc"; then
                total_errors=$((total_errors + 1))
            fi
        done
        shopt -u nullglob
    fi

    echo ""
    if [ $total_errors -gt 0 ]; then
        echo "=== SECURITY SCAN FAILED ==="
        echo "Found $total_errors file(s) with sensitive data!"
        echo "Please anonymize the data before uploading."
        echo ""
        echo "Rules:"
        echo "  - Replace internal hostnames (capev2, ki01) with generic names"
        echo "  - Mask IP addresses (XXX.x.x.x) except documentation IPs"
        echo "  - Remove/mask email addresses (except @mpauli.de, @paulis.net, @thesoc.de)"
        echo "  - Remove passwords, API keys, secrets"
        echo "  - Replace SSH connection strings"
        echo ""
        return 1
    else
        echo "=== SECURITY SCAN PASSED ==="
        echo ""
        return 0
    fi
}

echo "=== IcePorge Website Sync ==="
echo "Mode: $MODE"
echo "Webserver: $WEBSERVER"
echo ""

# Test connection
if ! ssh -o ConnectTimeout=10 -o BatchMode=yes "$WEBSERVER" "echo Connection OK" 2>/dev/null; then
    echo "ERROR: Cannot connect to webserver"
    exit 1
fi

sync_full() {
    # RUN SECURITY SCAN BEFORE UPLOAD
    if ! security_scan; then
        echo "UPLOAD ABORTED due to security issues!"
        exit 1
    fi

    echo "Creating directories on webserver..."
    ssh "$WEBSERVER" "mkdir -p $WEBSERVER_PATH/iceporge-images $WEBSERVER_PATH/iceporge-status $WEBSERVER_PATH/iceporge-docs"

    echo "Syncing main HTML page..."
    rsync -avz "$WEBSITE_FILE" "$WEBSERVER:$WEBSERVER_PATH/automated-threat-intelligence-malware-analysis-platform.html"

    echo "Syncing screenshots..."
    if [ -d "$LOCAL_SCREENSHOTS" ]; then
        rsync -avz "$LOCAL_SCREENSHOTS/" "$WEBSERVER:$WEBSERVER_PATH/iceporge-images/"
    else
        echo "WARNING: Screenshots directory not found: $LOCAL_SCREENSHOTS"
    fi

    echo "Syncing sample documents..."
    if [ -d "$LOCAL_DOCS" ]; then
        rsync -avz "$LOCAL_DOCS/" "$WEBSERVER:$WEBSERVER_PATH/iceporge-docs/"
    else
        echo "WARNING: Docs directory not found: $LOCAL_DOCS"
    fi

    echo "Setting permissions..."
    ssh "$WEBSERVER" "chmod -R 755 $WEBSERVER_PATH/iceporge-images $WEBSERVER_PATH/iceporge-status $WEBSERVER_PATH/iceporge-docs 2>/dev/null || true"

    echo ""
    echo "=== Full sync complete ==="
    echo "Website: https://www.mpauli.de/automated-threat-intelligence-malware-analysis-platform.html"
}

sync_status() {
    echo "Collecting and syncing status..."
    "$SCRIPT_DIR/collect-status.sh"
}

case "$MODE" in
    --full|full)
        sync_full
        sync_status
        ;;
    --status-only|status)
        sync_status
        ;;
    --scan|scan)
        security_scan
        ;;
    *)
        echo "Usage: $0 [--full|--status-only|--scan]"
        exit 1
        ;;
esac

echo ""
echo "Done!"
