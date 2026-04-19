#!/bin/bash
# =============================================================================
# IcePorge Installation Script
# =============================================================================
# Automated installation of the IcePorge Malware Analysis Ecosystem
#
# Usage:
#   sudo ./install-iceporge.sh [OPTIONS]
#
# Options:
#   --config FILE    Use specified config file (default: config.env)
#   --component X    Install only specific component (cape|mwdb|mailer|web|all)
#   --skip-deps      Skip dependency installation
#   --dry-run        Show what would be done without executing
#   --help           Show this help
#
# Author: Michael Pauli <info@mpauli.de>
# =============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Defaults
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.env"
COMPONENT="all"
SKIP_DEPS=false
DRY_RUN=false
ICEPORGE_DIR="/opt/iceporge"
CAPE_DIR="/opt/CAPEv2"
MAILER_DIR="/opt/cape-mailer"
LOG_FILE="/var/log/iceporge-install.log"

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "$level" in
        INFO)  echo -e "${GREEN}[INFO]${NC} $msg" ;;
        WARN)  echo -e "${YELLOW}[WARN]${NC} $msg" ;;
        ERROR) echo -e "${RED}[ERROR]${NC} $msg" ;;
        STEP)  echo -e "\n${CYAN}=== $msg ===${NC}" ;;
    esac

    echo "[$timestamp] [$level] $msg" >> "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log ERROR "This script must be run as root"
        exit 1
    fi
}

check_ubuntu() {
    if ! grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
        log WARN "This script is designed for Ubuntu. Proceeding anyway..."
    fi

    local version=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2)
    log INFO "Detected Ubuntu version: $version"
}

load_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log ERROR "Config file not found: $CONFIG_FILE"
        log INFO "Copy config.env.example to config.env and edit it"
        exit 1
    fi

    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    log INFO "Loaded configuration from $CONFIG_FILE"
}

# -----------------------------------------------------------------------------
# Dependency Installation
# -----------------------------------------------------------------------------

install_base_deps() {
    log STEP "Installing base dependencies"

    apt-get update
    apt-get install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release \
        software-properties-common \
        git \
        python3 \
        python3-pip \
        python3-venv \
        jq \
        htop \
        iotop \
        net-tools \
        dnsutils \
        whois \
        geoip-bin \
        geoip-database \
        wireguard \
        iptables-persistent

    log INFO "Base dependencies installed"
}

install_docker() {
    log STEP "Installing Docker"

    if command -v docker &>/dev/null; then
        log INFO "Docker already installed"
        return
    fi

    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list

    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

    systemctl enable docker
    systemctl start docker

    log INFO "Docker installed and started"
}

install_kvm() {
    log STEP "Installing KVM/libvirt for CAPE"

    apt-get install -y \
        qemu-kvm \
        libvirt-daemon-system \
        libvirt-clients \
        bridge-utils \
        virtinst \
        virt-manager \
        libguestfs-tools

    systemctl enable libvirtd
    systemctl start libvirtd

    log INFO "KVM/libvirt installed"
}

# -----------------------------------------------------------------------------
# WireGuard Setup (Secure Ollama Connection)
# -----------------------------------------------------------------------------

setup_wireguard() {
    log STEP "Setting up WireGuard VPN"

    if [[ "${WG_ENABLED:-false}" != "true" ]]; then
        log INFO "WireGuard disabled in config, skipping"
        return
    fi

    cat > /etc/wireguard/wg-ollama.conf << EOF
[Interface]
PrivateKey = ${WG_CLIENT_PRIVATE_KEY}
Address = ${WG_CLIENT_ADDRESS}

[Peer]
PublicKey = ${WG_SERVER_PUBLIC_KEY}
Endpoint = ${WG_SERVER_IP}:${WG_SERVER_PORT}
AllowedIPs = ${WG_ALLOWED_IPS}
PersistentKeepalive = 25
EOF

    chmod 600 /etc/wireguard/wg-ollama.conf

    systemctl enable wg-quick@wg-ollama
    systemctl start wg-quick@wg-ollama

    log INFO "WireGuard tunnel configured for Ollama access"
}

# -----------------------------------------------------------------------------
# Component Installation
# -----------------------------------------------------------------------------

install_cape() {
    log STEP "Installing CAPE Sandbox"

    if [[ "${CAPE_ENABLED:-true}" != "true" ]]; then
        log INFO "CAPE disabled in config, skipping"
        return
    fi

    # Clone CAPE if not exists
    if [[ ! -d "$CAPE_DIR" ]]; then
        git clone https://github.com/kevoreilly/CAPEv2.git "$CAPE_DIR"
    fi

    cd "$CAPE_DIR"

    # Create cape user
    if ! id cape &>/dev/null; then
        useradd -m -s /bin/bash cape
        usermod -aG kvm,libvirt cape
    fi

    # Install CAPE dependencies
    pip3 install -r requirements.txt

    # Configure CAPE
    cp conf/cuckoo.conf.default conf/cuckoo.conf
    cp conf/auxiliary.conf.default conf/auxiliary.conf
    cp conf/processing.conf.default conf/processing.conf
    cp conf/reporting.conf.default conf/reporting.conf

    # Update reporting.conf with AI settings
    if [[ "${AI_BACKEND}" == "ollama" ]] || [[ "${AI_BACKEND}" == "both" ]]; then
        sed -i "s|^ollama_host = .*|ollama_host = ${OLLAMA_API_URL}|" conf/reporting.conf
        sed -i "s|^ollama_model = .*|ollama_model = ${OLLAMA_MODEL}|" conf/reporting.conf
    fi

    # Create data directory
    mkdir -p "${CAPE_DATA_DIR}"/{storage,log}
    chown -R cape:cape "${CAPE_DATA_DIR}"

    log INFO "CAPE Sandbox installed"
}

install_mwdb() {
    log STEP "Installing MWDB Stack"

    if [[ "${MWDB_ENABLED:-true}" != "true" ]]; then
        log INFO "MWDB disabled in config, skipping"
        return
    fi

    local MWDB_DIR="/opt/mwdb-stack"

    if [[ ! -d "$MWDB_DIR" ]]; then
        git clone https://github.com/icepaule/IcePorge-MWDB-Stack.git "$MWDB_DIR"
    fi

    cd "$MWDB_DIR"

    # Create .env for MWDB
    cat > .env << EOF
MWDB_ADMIN_PASSWORD=${MWDB_ADMIN_PASSWORD}
MWDB_POSTGRES_PASSWORD=${MWDB_POSTGRES_PASSWORD}
MWDB_SECRET_KEY=${MWDB_SECRET_KEY}
MINIO_ROOT_USER=${MINIO_ROOT_USER}
MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD}
EOF

    chmod 600 .env

    # Start MWDB stack
    docker compose up -d

    log INFO "MWDB Stack installed and started"
}

install_cape_mailer() {
    log STEP "Installing CAPE-Mailer"

    if [[ "${MAILER_ENABLED:-true}" != "true" ]]; then
        log INFO "CAPE-Mailer disabled in config, skipping"
        return
    fi

    if [[ ! -d "$MAILER_DIR" ]]; then
        git clone https://github.com/icepaule/IcePorge-CAPE-Mailer.git "$MAILER_DIR"
    fi

    cd "$MAILER_DIR"

    # Install dependencies
    pip3 install -r requirements.txt 2>/dev/null || pip3 install flask imapclient pyyaml requests beautifulsoup4

    # Create config
    cat > config.yaml << EOF
imap:
  server: "${MAILER_IMAP_SERVER}"
  port: ${MAILER_IMAP_PORT}
  user: "${MAILER_IMAP_USER}"
  password: "${MAILER_IMAP_PASSWORD}"
  ssl: ${MAILER_IMAP_SSL}
  folder: "${MAILER_IMAP_FOLDER}"

smtp:
  server: "${MAILER_SMTP_SERVER}"
  port: ${MAILER_SMTP_PORT}
  user: "${MAILER_SMTP_USER}"
  password: "${MAILER_SMTP_PASSWORD}"
  tls: ${MAILER_SMTP_TLS}
  notify_email: "${MAILER_NOTIFY_EMAIL}"

cape:
  api_url: "${CAPE_WEB_URL}/api"

ollama:
  api_url: "${OLLAMA_API_URL}"
  model: "${OLLAMA_MODEL}"
  timeout: ${OLLAMA_TIMEOUT}

bedrock:
  enabled: $([ "${AI_BACKEND}" == "bedrock" ] || [ "${AI_BACKEND}" == "both" ] && echo "true" || echo "false")
  region: "${AWS_REGION}"
  model_id: "${BEDROCK_MODEL_ID}"
  max_tokens: ${BEDROCK_MAX_TOKENS}
EOF

    chmod 600 config.yaml

    # Create systemd service
    cat > /etc/systemd/system/cape-mailer.service << EOF
[Unit]
Description=CAPE Mailer - Email-based Phishing Analysis
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${MAILER_DIR}
ExecStart=/usr/bin/python3 ${MAILER_DIR}/bin/cape_mailer.py
Restart=always
RestartSec=60
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable cape-mailer

    log INFO "CAPE-Mailer installed"
}

install_web_dashboard() {
    log STEP "Installing IcePorge Web Dashboard"

    if [[ "${WEB_ENABLED:-true}" != "true" ]]; then
        log INFO "Web Dashboard disabled in config, skipping"
        return
    fi

    mkdir -p "${ICEPORGE_DIR}/webapp/templates"

    # Install Flask
    pip3 install flask flask-cors

    # Create systemd service
    cat > /etc/systemd/system/iceporge-web.service << EOF
[Unit]
Description=IcePorge Web Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${ICEPORGE_DIR}/webapp
ExecStart=/usr/bin/python3 ${ICEPORGE_DIR}/webapp/app.py
Restart=always
RestartSec=5
Environment=FLASK_ENV=production

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable iceporge-web

    log INFO "Web Dashboard installed"
}

# -----------------------------------------------------------------------------
# AI Backend Setup
# -----------------------------------------------------------------------------

setup_ai_backend() {
    log STEP "Setting up AI Backend"

    mkdir -p "${ICEPORGE_DIR}/ai"

    # Create AI provider abstraction
    cat > "${ICEPORGE_DIR}/ai/llm_provider.py" << 'PYTHON'
#!/usr/bin/env python3
"""
IcePorge LLM Provider Abstraction
Supports: Ollama (on-premise), AWS Bedrock
"""

import os
import json
import logging
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger(__name__)


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    def analyze(self, prompt: str, context: str = "") -> str:
        """Analyze content using LLM."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider is available."""
        pass


class OllamaProvider(LLMProvider):
    """Ollama LLM provider (on-premise via WireGuard)."""

    def __init__(self, api_url: str, model: str = "llama3.1:8b", timeout: int = 120):
        self.api_url = api_url.rstrip('/')
        self.model = model
        self.timeout = timeout

    def analyze(self, prompt: str, context: str = "") -> str:
        import requests

        full_prompt = f"{context}\n\n{prompt}" if context else prompt

        try:
            response = requests.post(
                f"{self.api_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": full_prompt,
                    "stream": False
                },
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json().get("response", "")
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            raise

    def is_available(self) -> bool:
        import requests
        try:
            response = requests.get(f"{self.api_url}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False


class BedrockProvider(LLMProvider):
    """AWS Bedrock LLM provider."""

    def __init__(self, region: str, model_id: str, max_tokens: int = 4096):
        self.region = region
        self.model_id = model_id
        self.max_tokens = max_tokens
        self._client = None

    @property
    def client(self):
        if self._client is None:
            import boto3
            self._client = boto3.client(
                'bedrock-runtime',
                region_name=self.region
            )
        return self._client

    def analyze(self, prompt: str, context: str = "") -> str:
        full_prompt = f"{context}\n\n{prompt}" if context else prompt

        # Claude model format
        if "anthropic.claude" in self.model_id:
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": self.max_tokens,
                "messages": [
                    {"role": "user", "content": full_prompt}
                ]
            }
        else:
            # Generic format for other models
            body = {
                "prompt": full_prompt,
                "max_tokens": self.max_tokens
            }

        try:
            response = self.client.invoke_model(
                modelId=self.model_id,
                body=json.dumps(body),
                contentType="application/json",
                accept="application/json"
            )

            response_body = json.loads(response['body'].read())

            # Extract response based on model type
            if "anthropic.claude" in self.model_id:
                return response_body.get("content", [{}])[0].get("text", "")
            else:
                return response_body.get("completion", response_body.get("generated_text", ""))

        except Exception as e:
            logger.error(f"Bedrock error: {e}")
            raise

    def is_available(self) -> bool:
        try:
            # Simple connectivity check
            self.client.list_foundation_models(maxResults=1)
            return True
        except:
            return False


class LLMProviderFactory:
    """Factory to create and manage LLM providers."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._providers = {}
            cls._instance._primary = None
        return cls._instance

    def register_ollama(self, api_url: str, model: str = "llama3.1:8b",
                        timeout: int = 120, primary: bool = False):
        """Register Ollama provider."""
        provider = OllamaProvider(api_url, model, timeout)
        self._providers['ollama'] = provider
        if primary or self._primary is None:
            self._primary = 'ollama'
        logger.info(f"Registered Ollama provider: {api_url}")

    def register_bedrock(self, region: str, model_id: str,
                         max_tokens: int = 4096, primary: bool = False):
        """Register AWS Bedrock provider."""
        provider = BedrockProvider(region, model_id, max_tokens)
        self._providers['bedrock'] = provider
        if primary or self._primary is None:
            self._primary = 'bedrock'
        logger.info(f"Registered Bedrock provider: {model_id}")

    def get_provider(self, name: Optional[str] = None) -> LLMProvider:
        """Get a specific or primary provider."""
        if name:
            return self._providers.get(name)
        return self._providers.get(self._primary)

    def analyze(self, prompt: str, context: str = "",
                provider: Optional[str] = None) -> str:
        """Analyze using specified or primary provider with fallback."""
        providers_to_try = []

        if provider:
            providers_to_try.append(provider)

        if self._primary and self._primary not in providers_to_try:
            providers_to_try.append(self._primary)

        for name in self._providers:
            if name not in providers_to_try:
                providers_to_try.append(name)

        for name in providers_to_try:
            p = self._providers.get(name)
            if p and p.is_available():
                try:
                    logger.info(f"Using {name} provider for analysis")
                    return p.analyze(prompt, context)
                except Exception as e:
                    logger.warning(f"{name} failed: {e}, trying next...")

        raise RuntimeError("No LLM provider available")


# Convenience function
def get_llm() -> LLMProviderFactory:
    """Get the LLM provider factory instance."""
    return LLMProviderFactory()


if __name__ == "__main__":
    # Test
    factory = get_llm()

    # Example registration (use environment variables in production)
    ollama_url = os.getenv("OLLAMA_API_URL", "http://10.10.0.210:11434")
    factory.register_ollama(ollama_url, primary=True)

    if os.getenv("AWS_REGION"):
        factory.register_bedrock(
            os.getenv("AWS_REGION"),
            os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0")
        )

    print(f"Ollama available: {factory.get_provider('ollama').is_available()}")
PYTHON

    chmod +x "${ICEPORGE_DIR}/ai/llm_provider.py"

    log INFO "AI backend abstraction layer created"
}

# -----------------------------------------------------------------------------
# Monitoring Setup
# -----------------------------------------------------------------------------

setup_monitoring() {
    log STEP "Setting up monitoring and auto-repair"

    mkdir -p "${ICEPORGE_DIR}/scripts" "${ICEPORGE_DIR}/status"

    # Copy monitoring script if exists, otherwise create minimal version
    if [[ ! -f "${ICEPORGE_DIR}/scripts/iceporge-monitor.sh" ]]; then
        cat > "${ICEPORGE_DIR}/scripts/iceporge-monitor.sh" << 'BASH'
#!/bin/bash
# IcePorge Health Monitor
# Checks system health and attempts auto-repair

STATUS_FILE="/opt/iceporge/status/health.json"

check_service() {
    local name="$1"
    local service="$2"
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        echo "ok"
    else
        systemctl restart "$service" 2>/dev/null
        sleep 2
        systemctl is-active --quiet "$service" 2>/dev/null && echo "repaired" || echo "critical"
    fi
}

check_docker() {
    local name="$1"
    local container="$2"
    if docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        echo "ok"
    else
        docker start "$container" 2>/dev/null
        sleep 3
        docker ps --format '{{.Names}}' | grep -q "^${container}$" && echo "repaired" || echo "critical"
    fi
}

# Build status JSON
{
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"overall_status\": \"ok\","
    echo "  \"components\": {"
    echo "    \"cape\": \"$(check_service cape cape)\","
    echo "    \"mwdb\": \"$(check_docker mwdb mwdb-core)\","
    echo "    \"web\": \"$(check_service web iceporge-web)\""
    echo "  }"
    echo "}"
} > "$STATUS_FILE"
BASH
        chmod +x "${ICEPORGE_DIR}/scripts/iceporge-monitor.sh"
    fi

    # Create systemd timer
    cat > /etc/systemd/system/iceporge-monitor.timer << EOF
[Unit]
Description=IcePorge Health Monitor Timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=${MONITOR_INTERVAL_MINUTES:-5}min
AccuracySec=1min

[Install]
WantedBy=timers.target
EOF

    cat > /etc/systemd/system/iceporge-monitor.service << EOF
[Unit]
Description=IcePorge Health Monitor

[Service]
Type=oneshot
ExecStart=${ICEPORGE_DIR}/scripts/iceporge-monitor.sh check
EOF

    systemctl daemon-reload
    systemctl enable iceporge-monitor.timer
    systemctl start iceporge-monitor.timer

    log INFO "Monitoring configured"
}

# -----------------------------------------------------------------------------
# Firewall Configuration
# -----------------------------------------------------------------------------

setup_firewall() {
    log STEP "Configuring firewall"

    if [[ "${FIREWALL_ENABLED:-true}" != "true" ]]; then
        log INFO "Firewall configuration disabled, skipping"
        return
    fi

    # Allow SSH
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT -m comment --comment "SSH"

    # Allow IcePorge Web
    iptables -A INPUT -p tcp --dport ${WEB_PORT:-8085} -j ACCEPT -m comment --comment "IcePorge-Web"

    # Allow CAPE Web (localhost only by default)
    iptables -A INPUT -p tcp --dport 8000 -s 127.0.0.1 -j ACCEPT -m comment --comment "CAPE-Web-Local"

    # Allow MWDB Web (localhost only by default)
    iptables -A INPUT -p tcp --dport 8081 -s 127.0.0.1 -j ACCEPT -m comment --comment "MWDB-Web-Local"

    # Allow WireGuard
    if [[ "${WG_ENABLED:-false}" == "true" ]]; then
        iptables -A INPUT -p udp --dport 51820 -j ACCEPT -m comment --comment "WireGuard"
    fi

    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Save rules
    iptables-save > /etc/iptables/rules.v4

    log INFO "Firewall configured"
}

# -----------------------------------------------------------------------------
# Main Installation
# -----------------------------------------------------------------------------

show_help() {
    cat << EOF
IcePorge Installation Script

Usage: sudo ./install-iceporge.sh [OPTIONS]

Options:
  --config FILE     Use specified config file (default: config.env)
  --component X     Install only: cape, mwdb, mailer, web, ai, monitoring, all
  --skip-deps       Skip dependency installation
  --dry-run         Show what would be done
  --help            Show this help

Examples:
  # Full installation
  sudo ./install-iceporge.sh --config my-config.env

  # Install only CAPE
  sudo ./install-iceporge.sh --component cape

  # Dry run
  sudo ./install-iceporge.sh --dry-run
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --component)
                COMPONENT="$2"
                shift 2
                ;;
            --skip-deps)
                SKIP_DEPS=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log ERROR "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

main() {
    parse_args "$@"

    echo -e "${CYAN}"
    echo "=============================================="
    echo "  IcePorge Installation"
    echo "  Malware Analysis Ecosystem"
    echo "=============================================="
    echo -e "${NC}"

    check_root
    check_ubuntu

    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"

    load_config

    if [[ "$DRY_RUN" == "true" ]]; then
        log INFO "DRY RUN - No changes will be made"
        log INFO "Would install component: $COMPONENT"
        exit 0
    fi

    if [[ "$SKIP_DEPS" != "true" ]]; then
        install_base_deps
        install_docker

        if [[ "$COMPONENT" == "all" ]] || [[ "$COMPONENT" == "cape" ]]; then
            install_kvm
        fi
    fi

    # Setup WireGuard for secure Ollama connection
    if [[ "$COMPONENT" == "all" ]] || [[ "$COMPONENT" == "ai" ]]; then
        setup_wireguard
        setup_ai_backend
    fi

    case "$COMPONENT" in
        cape)
            install_cape
            ;;
        mwdb)
            install_mwdb
            ;;
        mailer)
            install_cape_mailer
            ;;
        web)
            install_web_dashboard
            ;;
        ai)
            setup_ai_backend
            ;;
        monitoring)
            setup_monitoring
            ;;
        all)
            install_cape
            install_mwdb
            install_cape_mailer
            install_web_dashboard
            setup_monitoring
            setup_firewall
            ;;
    esac

    log STEP "Installation Complete"

    echo -e "\n${GREEN}Installation completed successfully!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Review configuration in $CONFIG_FILE"
    echo "  2. Start services: systemctl start cape-mailer iceporge-web"
    echo "  3. Access dashboard: http://$(hostname -I | awk '{print $1}'):${WEB_PORT:-8085}"
    echo ""
    echo "Logs: $LOG_FILE"
}

main "$@"
