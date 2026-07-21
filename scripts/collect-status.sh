#!/bin/bash
# IcePorge Status Collector - live data für das Dashboard
# Cron: */5 * * * * /opt/iceporge/scripts/collect-status.sh

set -euo pipefail

STATUS_DIR="/opt/iceporge/status"
LOCKFILE="$STATUS_DIR/collect.lock"
LOGFILE="$STATUS_DIR/collect.log"
CAPE_DB="/opt/CAPEv2/db/cuckoo.db"
CAPE_FEED_DB="/opt/iceporge/components/IcePorge-CAPE-Feed/work/state.db"

mkdir -p "$STATUS_DIR"

# Parallelausführung verhindern
exec 200>"$LOCKFILE"
flock -n 200 || exit 0

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOGFILE"; }
log "Starting status collection"

# --- CAPE Stats via SQLite ---
if [ -f "$CAPE_DB" ]; then
    CAPE_TOTAL=$(sqlite3 "$CAPE_DB" "SELECT COUNT(*) FROM tasks;" 2>/dev/null || echo 0)
    CAPE_REPORTED=$(sqlite3 "$CAPE_DB" "SELECT COUNT(*) FROM tasks WHERE status='reported';" 2>/dev/null || echo 0)
    CAPE_PENDING=$(sqlite3 "$CAPE_DB" "SELECT COUNT(*) FROM tasks WHERE status='pending';" 2>/dev/null || echo 0)
    CAPE_RUNNING=$(sqlite3 "$CAPE_DB" "SELECT COUNT(*) FROM tasks WHERE status='running';" 2>/dev/null || echo 0)
    CAPE_FAILED=$(sqlite3 "$CAPE_DB" "SELECT COUNT(*) FROM tasks WHERE status IN ('failed_reporting','failed_analysis','failed_processing');" 2>/dev/null || echo 0)
    CAPE_ADDED_24H=$(sqlite3 "$CAPE_DB" "SELECT COUNT(*) FROM tasks WHERE added_on >= datetime('now','-24 hours');" 2>/dev/null || echo 0)
    CAPE_COMPLETED_24H=$(sqlite3 "$CAPE_DB" "SELECT COUNT(*) FROM tasks WHERE status='reported' AND completed_on >= datetime('now','-24 hours');" 2>/dev/null || echo 0)
else
    CAPE_TOTAL=0; CAPE_REPORTED=0; CAPE_PENDING=0; CAPE_RUNNING=0
    CAPE_FAILED=0; CAPE_ADDED_24H=0; CAPE_COMPLETED_24H=0
fi

# --- Feeder Stats via SQLite (CAPE-Feed) ---
if [ -f "$CAPE_FEED_DB" ]; then
    FEED_TOTAL=$(sqlite3 "$CAPE_FEED_DB" "SELECT COUNT(*) FROM seen;" 2>/dev/null || echo 0)
    FEED_TODAY=$(sqlite3 "$CAPE_FEED_DB" "SELECT COUNT(*) FROM seen WHERE date(last_seen)=date('now');" 2>/dev/null || echo 0)
    FEED_7D=$(sqlite3 "$CAPE_FEED_DB" "SELECT COUNT(*) FROM seen WHERE last_seen >= datetime('now','-7 days');" 2>/dev/null || echo 0)
else
    FEED_TOTAL=0; FEED_TODAY=0; FEED_7D=0
fi

# --- MWDB Docker Container ---
MWDB_RUNNING=$(docker ps --filter "name=mwdb" --format "{{.Names}}" 2>/dev/null | wc -l)
KARTON_RUNNING=$(docker ps --filter "name=karton" --format "{{.Names}}" 2>/dev/null | wc -l)

# --- Disk Usage ---
DISK_PCT=$(df /opt/CAPEv2/storage 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%' || echo 0)
DISK_USED=$(df -h /opt/CAPEv2/storage 2>/dev/null | tail -1 | awk '{print $3}' || echo "?")
DISK_TOTAL=$(df -h /opt/CAPEv2/storage 2>/dev/null | tail -1 | awk '{print $2}' || echo "?")
DISK_FREE=$(df -h /opt/CAPEv2/storage 2>/dev/null | tail -1 | awk '{print $4}' || echo "?")

# --- Service Status ---
svc_status() { systemctl is-active "$1" 2>/dev/null || echo "inactive"; }
CAPE_SVC=$(svc_status cape)
CAPE_WEB=$(svc_status cape-web)
CAPE_PROC=$(svc_status cape-processor)
ICEPORGE_WEB=$(svc_status iceporge-web)
MONGOD=$(svc_status mongod)
NGINX=$(svc_status nginx)
SURICATA=$(svc_status suricata)

# --- Malware Stats aus Reports ---
STORAGE="/opt/CAPEv2/storage/analyses"
REPORTS_WITH_SIGS=$(find "$STORAGE" -name "report.json" -newer "$STATUS_DIR/health.json" 2>/dev/null | wc -l || echo 0)

# Overall Status bestimmen
OVERALL="ok"
[ "$CAPE_SVC" != "active" ] && OVERALL="degraded"
[ "$MWDB_RUNNING" -lt 3 ] && OVERALL="degraded"
[ "$DISK_PCT" -gt 90 ] && OVERALL="critical"

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

cat > "$STATUS_DIR/health.json" << EOF
{
    "timestamp": "$TIMESTAMP",
    "overall_status": "$OVERALL",
    "components": {
        "cape": {
            "status": "$CAPE_SVC",
            "web": "$CAPE_WEB",
            "processor": "$CAPE_PROC"
        },
        "mwdb": {
            "containers_running": $MWDB_RUNNING,
            "karton_running": $KARTON_RUNNING
        },
        "iceporge": {
            "web": "$ICEPORGE_WEB",
            "mongod": "$MONGOD"
        },
        "infrastructure": {
            "nginx": "$NGINX",
            "suricata": "$SURICATA"
        }
    },
    "cape_stats": {
        "total_tasks": $CAPE_TOTAL,
        "reported": $CAPE_REPORTED,
        "pending": $CAPE_PENDING,
        "running": $CAPE_RUNNING,
        "failed": $CAPE_FAILED,
        "added_24h": $CAPE_ADDED_24H,
        "completed_24h": $CAPE_COMPLETED_24H
    },
    "feeder_stats": {
        "total_seen": $FEED_TOTAL,
        "seen_today": $FEED_TODAY,
        "seen_7d": $FEED_7D
    },
    "disk": {
        "percent_used": $DISK_PCT,
        "used": "$DISK_USED",
        "total": "$DISK_TOTAL",
        "free": "$DISK_FREE"
    }
}
EOF

log "Done: CAPE=$CAPE_REPORTED reported, $CAPE_PENDING pending, Disk=${DISK_PCT}%"
