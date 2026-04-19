#!/bin/bash
# IcePorge Monitoring & Auto-Repair System
# Überwacht alle Komponenten des IcePorge Malware-Analyse-Ökosystems
# und führt automatische Reparaturen durch

set -euo pipefail

LOGFILE="/opt/iceporge/status/monitor.log"
STATUSFILE="/opt/iceporge/status/health.json"
LOCKFILE="/opt/iceporge/status/monitor.lock"
ALERT_THRESHOLD_DISK=90  # Prozent
ALERT_THRESHOLD_DISK_CRITICAL=95
MIN_FREE_SPACE_MB=10000  # 10GB minimum

# Farben für Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Lock um parallele Ausführung zu verhindern
exec 200>"$LOCKFILE"
flock -n 200 || { echo "Monitor bereits aktiv"; exit 1; }

mkdir -p /opt/iceporge/status

log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $msg" >> "$LOGFILE"
    echo "[$timestamp] [$level] $msg" >&2
}

# ==================== HEALTH CHECKS ====================

check_cape_services() {
    local status="ok"
    local services=("cape" "cape-processor" "cape-web" "cape-rooter" "cape-static")
    local failed_services=()

    for svc in "${services[@]}"; do
        if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
            failed_services+=("$svc")
            status="critical"
        fi
    done

    if [[ ${#failed_services[@]} -gt 0 ]]; then
        log "ERROR" "CAPE Services ausgefallen: ${failed_services[*]}"
        for svc in "${failed_services[@]}"; do
            repair_cape_service "$svc"
        done
    fi

    echo "$status"
}

check_docker_containers() {
    local status="ok"
    local expected_containers=(
        "mwdb" "mwdb-web" "mwdb-postgres" "mwdb-redis" "mwdb-minio"
        "karton-system" "karton-dashboard" "karton-classifier"
        "karton-archive-extractor" "karton-mwdb-reporter" "karton-cape-submitter"
        "mwdb-feeder" "cape-feed"
    )
    local failed_containers=()

    for container in "${expected_containers[@]}"; do
        if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
            failed_containers+=("$container")
            status="critical"
        fi
    done

    if [[ ${#failed_containers[@]} -gt 0 ]]; then
        log "ERROR" "Docker Container nicht laufend: ${failed_containers[*]}"
        repair_docker_containers
    fi

    echo "$status"
}

check_disk_space() {
    local status="ok"
    local cape_data_usage=$(df /mnt/cape-data --output=pcent 2>/dev/null | tail -1 | tr -d ' %')
    local cape_data_avail=$(df /mnt/cape-data --output=avail 2>/dev/null | tail -1)
    local cape_data_avail_mb=$((cape_data_avail / 1024))

    if [[ "$cape_data_usage" -ge "$ALERT_THRESHOLD_DISK_CRITICAL" ]]; then
        log "CRITICAL" "Speicherplatz kritisch! /mnt/cape-data: ${cape_data_usage}% belegt"
        status="critical"
        repair_disk_space
    elif [[ "$cape_data_usage" -ge "$ALERT_THRESHOLD_DISK" ]]; then
        log "WARNING" "Speicherplatz niedrig: /mnt/cape-data: ${cape_data_usage}% belegt"
        status="warning"
    fi

    if [[ "$cape_data_avail_mb" -lt "$MIN_FREE_SPACE_MB" ]]; then
        log "WARNING" "Weniger als ${MIN_FREE_SPACE_MB}MB frei auf /mnt/cape-data (${cape_data_avail_mb}MB)"
        if [[ "$status" != "critical" ]]; then
            status="warning"
        fi
    fi

    echo "$status"
}

check_vms() {
    local status="ok"
    local vm_net_status=$(virsh net-info cape-isolated 2>/dev/null | grep "Active:" | awk '{print $2}')

    if [[ "$vm_net_status" != "yes" ]]; then
        log "ERROR" "VM-Netzwerk cape-isolated nicht aktiv"
        status="critical"
        repair_vm_network
    fi

    # Prüfe ob VMs im "paused" oder "crashed" Zustand sind
    local crashed_vms=$(virsh list --all | grep -E "paused|crashed|in shutdown" | awk '{print $2}')
    if [[ -n "$crashed_vms" ]]; then
        log "ERROR" "VMs im fehlerhaften Zustand: $crashed_vms"
        status="warning"
        for vm in $crashed_vms; do
            repair_vm "$vm"
        done
    fi

    echo "$status"
}

check_karton_pipeline() {
    local status="ok"

    # Prüfe Karton Dashboard
    local karton_response=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8082/ 2>/dev/null || echo "000")
    if [[ "$karton_response" != "200" ]]; then
        log "ERROR" "Karton Dashboard nicht erreichbar (HTTP $karton_response)"
        status="warning"
    fi

    echo "$status"
}

check_mwdb() {
    local status="ok"

    local mwdb_response=$(curl -s http://127.0.0.1:8081/api/server 2>/dev/null)
    if [[ -z "$mwdb_response" ]] || ! echo "$mwdb_response" | grep -q "server_version"; then
        log "ERROR" "MWDB API nicht erreichbar"
        status="critical"
        repair_docker_containers
    fi

    echo "$status"
}

check_cape_web() {
    local status="ok"

    local cape_response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/ 2>/dev/null || echo "000")
    if [[ "$cape_response" != "200" && "$cape_response" != "302" ]]; then
        log "ERROR" "CAPE Web UI nicht erreichbar (HTTP $cape_response)"
        status="critical"
    fi

    echo "$status"
}

check_cape_mailer() {
    local status="ok"

    # Prüfe ob Timer aktiv ist
    if ! systemctl is-active --quiet cape-mailer.timer 2>/dev/null; then
        log "WARNING" "cape-mailer.timer nicht aktiv"
        status="warning"
        systemctl start cape-mailer.timer 2>/dev/null || true
    fi

    # Prüfe letzte Ausführung
    local last_run=$(systemctl show cape-mailer.service --property=ExecMainExitTimestamp 2>/dev/null | cut -d= -f2)
    if [[ -n "$last_run" && "$last_run" != "n/a" ]]; then
        log "INFO" "cape-mailer letzte Ausführung: $last_run"
    fi

    echo "$status"
}

check_gpu_server() {
    local status="ok"
    local gpu_host="10.10.0.210"

    if ! ping -c 1 -W 2 "$gpu_host" &>/dev/null; then
        log "WARNING" "GPU-Server ($gpu_host) nicht erreichbar"
        status="warning"
    else
        local ollama_response=$(curl -s -m 5 "http://${gpu_host}:11434/api/tags" 2>/dev/null || echo "")
        if [[ -z "$ollama_response" ]]; then
            log "WARNING" "Ollama auf GPU-Server nicht erreichbar"
            status="warning"
        fi
    fi

    echo "$status"
}

# ==================== REPAIR FUNCTIONS ====================

repair_cape_service() {
    local service="$1"
    log "INFO" "Versuche $service zu reparieren..."

    systemctl restart "$service" 2>/dev/null
    sleep 3

    if systemctl is-active --quiet "$service"; then
        log "INFO" "$service erfolgreich neu gestartet"
    else
        log "ERROR" "$service konnte nicht gestartet werden"
    fi
}

repair_docker_containers() {
    log "INFO" "Versuche Docker Container zu reparieren..."

    # Versuche in mwdb-core Verzeichnis zu wechseln und compose up
    if [[ -d /opt/mwdb-core ]]; then
        cd /opt/mwdb-core
        docker compose up -d 2>/dev/null || docker-compose up -d 2>/dev/null || true
        log "INFO" "Docker compose up ausgeführt"
    fi
}

repair_disk_space() {
    log "INFO" "Starte automatische Speicherplatzbereinigung..."

    local analyses_dir="/mnt/cape-data/storage/analyses"
    local num_analyses=$(ls -d "$analyses_dir"/*/ 2>/dev/null | wc -l)

    if [[ "$num_analyses" -gt 50 ]]; then
        # Lösche die ältesten 20% der Analysen
        local to_delete=$((num_analyses / 5))
        log "INFO" "Lösche $to_delete älteste Analysen..."

        ls -d "$analyses_dir"/*/ 2>/dev/null | \
            xargs -d '\n' -I{} basename {} | \
            grep -E '^[0-9]+$' | \
            sort -n | \
            head -n "$to_delete" | \
            while read id; do
                rm -rf "$analyses_dir/$id" 2>/dev/null && log "INFO" "Analyse $id gelöscht"
            done

        log "INFO" "Speicherplatzbereinigung abgeschlossen"
    else
        log "WARNING" "Zu wenige Analysen für automatische Bereinigung"
    fi
}

repair_vm_network() {
    log "INFO" "Versuche VM-Netzwerk zu reparieren..."

    virsh net-start cape-isolated 2>/dev/null || true
    sleep 2

    if virsh net-info cape-isolated 2>/dev/null | grep -q "Active:.*yes"; then
        log "INFO" "VM-Netzwerk erfolgreich gestartet"
    else
        log "ERROR" "VM-Netzwerk konnte nicht gestartet werden"
    fi
}

repair_vm() {
    local vm="$1"
    log "INFO" "Versuche VM $vm zu reparieren..."

    virsh destroy "$vm" 2>/dev/null || true
    sleep 2
    virsh snapshot-revert "$vm" capesnap 2>/dev/null || true

    log "INFO" "VM $vm auf Snapshot zurückgesetzt"
}

# ==================== MAIN ====================

main() {
    local mode="${1:-check}"
    local overall_status="ok"
    local timestamp=$(date -Iseconds)

    log "INFO" "=== IcePorge Monitor gestartet (Modus: $mode) ==="

    # Health Checks durchführen
    declare -A health_results

    health_results[cape_services]=$(check_cape_services)
    health_results[docker_containers]=$(check_docker_containers)
    health_results[disk_space]=$(check_disk_space)
    health_results[vms]=$(check_vms)
    health_results[karton_pipeline]=$(check_karton_pipeline)
    health_results[mwdb]=$(check_mwdb)
    health_results[cape_web]=$(check_cape_web)
    health_results[cape_mailer]=$(check_cape_mailer)
    health_results[gpu_server]=$(check_gpu_server)

    # Bestimme Gesamtstatus
    for key in "${!health_results[@]}"; do
        if [[ "${health_results[$key]}" == "critical" ]]; then
            overall_status="critical"
            break
        elif [[ "${health_results[$key]}" == "warning" && "$overall_status" == "ok" ]]; then
            overall_status="warning"
        fi
    done

    # Status als JSON speichern
    cat > "$STATUSFILE" << EOF
{
    "timestamp": "$timestamp",
    "overall_status": "$overall_status",
    "components": {
        "cape_services": "${health_results[cape_services]}",
        "docker_containers": "${health_results[docker_containers]}",
        "disk_space": "${health_results[disk_space]}",
        "vms": "${health_results[vms]}",
        "karton_pipeline": "${health_results[karton_pipeline]}",
        "mwdb": "${health_results[mwdb]}",
        "cape_web": "${health_results[cape_web]}",
        "cape_mailer": "${health_results[cape_mailer]}",
        "gpu_server": "${health_results[gpu_server]}"
    },
    "disk_usage": {
        "cape_data_percent": $(df /mnt/cape-data --output=pcent 2>/dev/null | tail -1 | tr -d ' %'),
        "cape_data_avail_gb": $(echo "scale=1; $(df /mnt/cape-data --output=avail 2>/dev/null | tail -1) / 1048576" | bc)
    },
    "analyses_count": $(ls /mnt/cape-data/storage/analyses/ 2>/dev/null | grep -E '^[0-9]+$' | wc -l)
}
EOF

    log "INFO" "=== Gesamtstatus: $overall_status ==="

    # Ausgabe für CLI
    if [[ "$mode" == "status" ]]; then
        echo ""
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║           IcePorge System Health Status                       ║"
        echo "╠══════════════════════════════════════════════════════════════╣"
        for key in "${!health_results[@]}"; do
            local val="${health_results[$key]}"
            local color="$GREEN"
            [[ "$val" == "warning" ]] && color="$YELLOW"
            [[ "$val" == "critical" ]] && color="$RED"
            printf "║  %-25s: ${color}%-10s${NC}                    ║\n" "$key" "$val"
        done
        echo "╠══════════════════════════════════════════════════════════════╣"
        local status_color="$GREEN"
        [[ "$overall_status" == "warning" ]] && status_color="$YELLOW"
        [[ "$overall_status" == "critical" ]] && status_color="$RED"
        printf "║  GESAMTSTATUS: ${status_color}%-15s${NC}                           ║\n" "$overall_status"
        echo "╚══════════════════════════════════════════════════════════════╝"
    fi

    # Exit code basierend auf Status
    case "$overall_status" in
        critical) exit 2 ;;
        warning) exit 1 ;;
        *) exit 0 ;;
    esac
}

main "$@"
