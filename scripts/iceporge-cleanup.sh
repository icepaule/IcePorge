#!/bin/bash
# IcePorge Automatic Cleanup System
# Bereinigt alte Analysen und hält Speicherplatz frei
# Reports und MISP IOCs bleiben erhalten

set -euo pipefail

LOGFILE="/opt/iceporge/status/cleanup.log"
LOCKFILE="/opt/iceporge/status/cleanup.lock"

# Konfiguration
ANALYSES_DIR="/mnt/cape-data/storage/analyses"
REPORTS_DIR="/opt/cape-mailer/reports"
CAPE_REPORTS_DIR="/mnt/cape-data/storage/analyses"

# Schwellenwerte
MAX_ANALYSES_AGE_DAYS=30           # Analysen älter als X Tage löschen
MAX_ANALYSES_COUNT=200             # Maximal X Analysen behalten
MIN_FREE_SPACE_GB=100              # Mindestens X GB frei halten
EMERGENCY_FREE_SPACE_GB=50         # Unter X GB sofortige Bereinigung

# Lock um parallele Ausführung zu verhindern
exec 200>"$LOCKFILE"
flock -n 200 || { echo "Cleanup bereits aktiv"; exit 1; }

log() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $*" | tee -a "$LOGFILE"
}

get_free_space_gb() {
    df /mnt/cape-data --output=avail 2>/dev/null | tail -1 | awk '{print int($1/1048576)}'
}

get_analyses_count() {
    ls -d "$ANALYSES_DIR"/*/ 2>/dev/null | wc -l || echo 0
}

# Archiviere wichtige Reports bevor Analyse gelöscht wird
archive_analysis_report() {
    local analysis_id="$1"
    local analysis_dir="$ANALYSES_DIR/$analysis_id"
    local archive_dir="/mnt/cape-data/archived_reports"

    mkdir -p "$archive_dir"

    # Kopiere HTML Report falls vorhanden
    if [[ -f "$analysis_dir/reports/report.html" ]]; then
        cp "$analysis_dir/reports/report.html" "$archive_dir/cape_${analysis_id}.html" 2>/dev/null || true
    fi

    # Kopiere JSON Report (komprimiert) falls vorhanden
    if [[ -f "$analysis_dir/reports/report.json" ]]; then
        gzip -c "$analysis_dir/reports/report.json" > "$archive_dir/cape_${analysis_id}_report.json.gz" 2>/dev/null || true
    fi

    # Extrahiere und speichere IOCs
    if [[ -f "$analysis_dir/reports/report.json" ]]; then
        python3 -c "
import json, sys
try:
    with open('$analysis_dir/reports/report.json') as f:
        data = json.load(f)
    iocs = {
        'analysis_id': $analysis_id,
        'malscore': data.get('malscore', 0),
        'target': data.get('target', {}).get('file', {}).get('name', 'unknown'),
        'sha256': data.get('target', {}).get('file', {}).get('sha256', ''),
        'signatures': [s.get('name') for s in data.get('signatures', [])],
        'network': {
            'hosts': [h.get('ip') for h in data.get('network', {}).get('hosts', [])],
            'domains': [d.get('domain') for d in data.get('network', {}).get('domains', [])]
        }
    }
    with open('$archive_dir/cape_${analysis_id}_iocs.json', 'w') as f:
        json.dump(iocs, f, indent=2)
except Exception as e:
    pass
" 2>/dev/null || true
    fi
}

# Lösche eine Analyse nach Archivierung
delete_analysis() {
    local analysis_id="$1"
    local analysis_dir="$ANALYSES_DIR/$analysis_id"

    if [[ -d "$analysis_dir" ]]; then
        # Erst archivieren
        archive_analysis_report "$analysis_id"

        # Dann löschen
        rm -rf "$analysis_dir"
        log "Analyse $analysis_id gelöscht (Report archiviert)"
        return 0
    fi
    return 1
}

# Bereinige alte Analysen basierend auf Alter
cleanup_by_age() {
    local max_age_days="$1"
    local deleted=0

    log "Suche Analysen älter als $max_age_days Tage..."

    for analysis_dir in "$ANALYSES_DIR"/*/; do
        [[ -d "$analysis_dir" ]] || continue

        local analysis_id=$(basename "$analysis_dir")
        [[ "$analysis_id" =~ ^[0-9]+$ ]] || continue  # Nur numerische IDs

        # Prüfe Alter anhand des Verzeichnisses
        local age_days=$(( ($(date +%s) - $(stat -c %Y "$analysis_dir")) / 86400 ))

        if [[ "$age_days" -gt "$max_age_days" ]]; then
            delete_analysis "$analysis_id"
            ((deleted++))
        fi
    done

    log "$deleted Analysen wegen Alter gelöscht"
}

# Bereinige überzählige Analysen (behalte nur die neuesten)
cleanup_by_count() {
    local max_count="$1"
    local current_count=$(get_analyses_count)
    local deleted=0

    if [[ "$current_count" -gt "$max_count" ]]; then
        local to_delete=$((current_count - max_count))
        log "Lösche $to_delete überzählige Analysen (aktuell: $current_count, max: $max_count)"

        # Sortiere nach ID (älteste zuerst) und lösche
        for analysis_id in $(ls -d "$ANALYSES_DIR"/*/ 2>/dev/null | xargs -I{} basename {} | grep -E '^[0-9]+$' | sort -n | head -n "$to_delete"); do
            delete_analysis "$analysis_id"
            ((deleted++))
        done

        log "$deleted Analysen wegen Überzahl gelöscht"
    fi
}

# Notfall-Bereinigung bei kritisch niedrigem Speicherplatz
emergency_cleanup() {
    local target_free_gb="$1"
    local current_free=$(get_free_space_gb)
    local deleted=0

    log "NOTFALL: Speicherplatz kritisch ($current_free GB). Ziel: $target_free_gb GB"

    # Lösche die ältesten Analysen bis genug Platz frei ist
    for analysis_id in $(ls -d "$ANALYSES_DIR"/*/ 2>/dev/null | xargs -I{} basename {} | grep -E '^[0-9]+$' | sort -n); do
        current_free=$(get_free_space_gb)
        [[ "$current_free" -ge "$target_free_gb" ]] && break

        delete_analysis "$analysis_id"
        ((deleted++))

        # Alle 10 Löschungen Speicher prüfen
        if (( deleted % 10 == 0 )); then
            current_free=$(get_free_space_gb)
            log "Fortschritt: $deleted gelöscht, $current_free GB frei"
        fi
    done

    log "Notfall-Bereinigung abgeschlossen: $deleted Analysen gelöscht, $(get_free_space_gb) GB frei"
}

# Bereinige alte Logs
cleanup_logs() {
    log "Bereinige alte Logs..."

    # cape-mailer Logs älter als 30 Tage löschen
    find /opt/cape-mailer/logs -name "*.log.gz" -mtime +30 -delete 2>/dev/null || true
    find /opt/cape-mailer/logs -name "*.log" -mtime +7 -exec gzip {} \; 2>/dev/null || true

    # CAPE Logs rotieren
    find /opt/CAPEv2/log -name "*.log" -size +100M -exec truncate -s 10M {} \; 2>/dev/null || true

    # IcePorge Monitor Logs
    if [[ -f /opt/iceporge/status/monitor.log ]] && [[ $(stat -c %s /opt/iceporge/status/monitor.log 2>/dev/null || echo 0) -gt 10485760 ]]; then
        mv /opt/iceporge/status/monitor.log /opt/iceporge/status/monitor.log.1
        gzip /opt/iceporge/status/monitor.log.1 2>/dev/null || true
    fi

    log "Log-Bereinigung abgeschlossen"
}

# Bereinige temporäre Dateien
cleanup_temp() {
    log "Bereinige temporäre Dateien..."

    # cape-mailer work Verzeichnis
    find /opt/cape-mailer/work -type d -mtime +1 -exec rm -rf {} \; 2>/dev/null || true

    # CAPE temporäre Dateien
    find /mnt/cape-data/storage/cuckoo-tmp -type f -mtime +1 -delete 2>/dev/null || true

    log "Temp-Bereinigung abgeschlossen"
}

# Hauptfunktion
main() {
    local mode="${1:-auto}"

    log "=== IcePorge Cleanup gestartet (Modus: $mode) ==="

    local free_space=$(get_free_space_gb)
    local analyses_count=$(get_analyses_count)

    log "Status: $free_space GB frei, $analyses_count Analysen"

    # Notfall-Modus bei kritisch niedrigem Speicher
    if [[ "$free_space" -lt "$EMERGENCY_FREE_SPACE_GB" ]]; then
        emergency_cleanup "$MIN_FREE_SPACE_GB"
    fi

    case "$mode" in
        auto)
            # Automatische Bereinigung
            cleanup_by_age "$MAX_ANALYSES_AGE_DAYS"
            cleanup_by_count "$MAX_ANALYSES_COUNT"
            cleanup_logs
            cleanup_temp
            ;;
        aggressive)
            # Aggressive Bereinigung - mehr löschen
            cleanup_by_age 14  # 14 Tage statt 30
            cleanup_by_count 100  # 100 statt 200
            cleanup_logs
            cleanup_temp
            ;;
        emergency)
            # Nur Notfall-Bereinigung
            emergency_cleanup "$MIN_FREE_SPACE_GB"
            ;;
        logs-only)
            cleanup_logs
            cleanup_temp
            ;;
        *)
            echo "Usage: $0 [auto|aggressive|emergency|logs-only]"
            exit 1
            ;;
    esac

    free_space=$(get_free_space_gb)
    analyses_count=$(get_analyses_count)
    log "=== Cleanup abgeschlossen: $free_space GB frei, $analyses_count Analysen ==="
}

main "$@"
