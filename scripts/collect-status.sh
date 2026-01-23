#!/bin/bash
# =============================================================================
# IcePorge Status Collector
# Extracts live status data from Cockpit data sources and syncs to webserver
#
# Usage: /opt/iceporge/scripts/collect-status.sh
# Cron:  */5 * * * * /opt/iceporge/scripts/collect-status.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATUS_DIR="/opt/iceporge/status"
WEBSERVER="mpauli@46.4.142.234"
WEBSERVER_PATH="/var/www/mpauli.de/iceporge-status"

mkdir -p "$STATUS_DIR"

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
echo "[$TIMESTAMP] Starting status collection..."

# =============================================================================
# Data Collection - Same sources as Cockpit dashboards
# =============================================================================

# --- Feeder Statistics (from SQLite) ---
FEEDER_DB="/opt/mwdb-feeder/work/state.db"

if [ -f "$FEEDER_DB" ]; then
    TOTAL_PROCESSED=$(sqlite3 "$FEEDER_DB" 'SELECT COUNT(*) FROM processed;' 2>/dev/null || echo "0")
    TODAY_UPLOADED=$(sqlite3 "$FEEDER_DB" "SELECT COUNT(*) FROM processed WHERE date(processed_at)=date('now') AND mwdb_uploaded=1;" 2>/dev/null || echo "0")
    URLHAUS=$(sqlite3 "$FEEDER_DB" "SELECT COUNT(*) FROM processed WHERE source='urlhaus' AND mwdb_uploaded=1;" 2>/dev/null || echo "0")
    HYBRID_ANALYSIS=$(sqlite3 "$FEEDER_DB" "SELECT COUNT(*) FROM processed WHERE source='hybrid_analysis' AND mwdb_uploaded=1;" 2>/dev/null || echo "0")
else
    TOTAL_PROCESSED=0
    TODAY_UPLOADED=0
    URLHAUS=0
    HYBRID_ANALYSIS=0
fi

echo "Feeder Stats: Total=$TOTAL_PROCESSED, Today=$TODAY_UPLOADED, URLhaus=$URLHAUS, Hybrid=$HYBRID_ANALYSIS"

# --- CAPE Statistics (from PostgreSQL via cockpit_api.py) ---
CAPE_STATS=$(sudo -u postgres python3 /opt/CAPEv2/utils/cockpit_api.py stats 2>/dev/null)

if [ -n "$CAPE_STATS" ] && echo "$CAPE_STATS" | python3 -c "import sys, json; json.load(sys.stdin)" 2>/dev/null; then
    CAPE_TOTAL=$(echo "$CAPE_STATS" | python3 -c "import sys, json; print(json.load(sys.stdin).get('total', 0))")
    CAPE_RUNNING=$(echo "$CAPE_STATS" | python3 -c "import sys, json; print(json.load(sys.stdin).get('running', 0))")
    CAPE_COMPLETED=$(echo "$CAPE_STATS" | python3 -c "import sys, json; print(json.load(sys.stdin).get('completed_24h', 0))")
    CAPE_FAILED=$(echo "$CAPE_STATS" | python3 -c "import sys, json; print(json.load(sys.stdin).get('failed', 0))")
else
    CAPE_TOTAL=0
    CAPE_RUNNING=0
    CAPE_COMPLETED=0
    CAPE_FAILED=0
fi

# Calculate pending (total - completed - failed - running)
CAPE_PENDING=$((CAPE_TOTAL - CAPE_COMPLETED - CAPE_FAILED - CAPE_RUNNING))
[ $CAPE_PENDING -lt 0 ] && CAPE_PENDING=0

echo "CAPE Stats: Total=$CAPE_TOTAL, Running=$CAPE_RUNNING, Completed24h=$CAPE_COMPLETED, Failed=$CAPE_FAILED, Pending=$CAPE_PENDING"

# --- System Status ---
DISK_USAGE=$(df -h /mnt/cape-data 2>/dev/null | tail -1 | awk '{print $5}' || echo "0%")
DISK_TOTAL=$(df -h /mnt/cape-data 2>/dev/null | tail -1 | awk '{print $2}' || echo "0G")
DISK_USED=$(df -h /mnt/cape-data 2>/dev/null | tail -1 | awk '{print $3}' || echo "0G")

# Service status
CAPE_SERVICE=$(systemctl is-active cape.service 2>/dev/null || echo "unknown")
CAPE_WEB=$(systemctl is-active cape-web.service 2>/dev/null || echo "unknown")
MWDB_STATUS=$(docker ps --filter "name=mwdb" --format "{{.Status}}" 2>/dev/null | head -1)
[ -z "$MWDB_STATUS" ] && MWDB_STATUS="stopped"
echo "$MWDB_STATUS" | grep -qi "up" && MWDB_SERVICE="running" || MWDB_SERVICE="stopped"

# VM status
VM_RUNNING=$(VBoxManage list runningvms 2>/dev/null | wc -l || echo "0")

echo "System: Disk=$DISK_USAGE ($DISK_USED/$DISK_TOTAL), CAPE=$CAPE_SERVICE, MWDB=$MWDB_SERVICE, VMs=$VM_RUNNING"

# =============================================================================
# Generate JSON
# =============================================================================

cat > "$STATUS_DIR/status.json" << EOF
{
    "timestamp": "$TIMESTAMP",
    "hostname": "sandbox-server",
    "feeder": {
        "total_processed": $TOTAL_PROCESSED,
        "today_uploaded": $TODAY_UPLOADED,
        "urlhaus": $URLHAUS,
        "hybrid_analysis": $HYBRID_ANALYSIS
    },
    "cape": {
        "total_tasks": $CAPE_TOTAL,
        "pending": $CAPE_PENDING,
        "running": $CAPE_RUNNING,
        "completed_24h": $CAPE_COMPLETED,
        "failed": $CAPE_FAILED
    },
    "system": {
        "disk_usage": "$DISK_USAGE",
        "disk_total": "$DISK_TOTAL",
        "disk_used": "$DISK_USED",
        "cape_service": "$CAPE_SERVICE",
        "cape_web": "$CAPE_WEB",
        "mwdb_service": "$MWDB_SERVICE",
        "vms_running": $VM_RUNNING
    }
}
EOF

echo "Status JSON generated: $STATUS_DIR/status.json"

# =============================================================================
# Sync to webserver
# =============================================================================

echo "Syncing to webserver..."
if ssh -o ConnectTimeout=5 -o BatchMode=yes "$WEBSERVER" "mkdir -p $WEBSERVER_PATH" 2>/dev/null; then
    rsync -az --timeout=60 "$STATUS_DIR/" "$WEBSERVER:$WEBSERVER_PATH/" 2>/dev/null && \
        echo "[$TIMESTAMP] Status synced successfully" || echo "[$TIMESTAMP] Rsync failed"
else
    echo "[$TIMESTAMP] Webserver unreachable"
fi
