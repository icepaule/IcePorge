# Secure Ollama Connection via WireGuard

Diese Anleitung beschreibt die sichere Verbindung zwischen einem AWS IcePorge Server und einem On-Premise Ollama GPU Server über WireGuard VPN.

## Architektur

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              INTERNET                                    │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        │                                               │
        ▼                                               ▼
┌───────────────────┐                       ┌───────────────────────┐
│   AWS VPC         │                       │   On-Premise          │
│                   │                       │                       │
│ ┌───────────────┐ │     WireGuard VPN     │ ┌───────────────────┐ │
│ │ IcePorge      │◄├───────────────────────┤►│ GPU Server        │ │
│ │ 10.200.200.2  │ │   UDP 51820           │ │ 10.200.200.1      │ │
│ └───────────────┘ │                       │ │ 10.10.0.210       │ │
│                   │                       │ └───────────────────┘ │
└───────────────────┘                       │         │             │
                                            │         ▼             │
                                            │ ┌───────────────────┐ │
                                            │ │ Ollama            │ │
                                            │ │ :11434            │ │
                                            │ └───────────────────┘ │
                                            └───────────────────────┘
```

## Vorteile von WireGuard

- **Verschlüsselt**: Alle Daten zwischen AWS und On-Premise sind verschlüsselt
- **Schnell**: Minimaler Overhead durch modernes Protokoll
- **Einfach**: Nur ein UDP Port (51820) muss geöffnet werden
- **Stabil**: Automatische Reconnection bei Verbindungsabbruch
- **Sicher**: Keine Ollama-API im Internet exponiert

---

## Schritt 1: On-Premise Server (mit Ollama)

### 1.1 WireGuard installieren

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y wireguard

# CentOS/RHEL
sudo yum install -y epel-release
sudo yum install -y wireguard-tools
```

### 1.2 Keys generieren

```bash
# Server Keys
wg genkey | sudo tee /etc/wireguard/server_private.key | wg pubkey | sudo tee /etc/wireguard/server_public.key
sudo chmod 600 /etc/wireguard/server_private.key

# Keys anzeigen (für spätere Verwendung)
echo "Server Private Key:"
sudo cat /etc/wireguard/server_private.key
echo ""
echo "Server Public Key (für AWS Client):"
cat /etc/wireguard/server_public.key
```

### 1.3 Server Konfiguration erstellen

```bash
# Private Key auslesen
PRIVATE_KEY=$(sudo cat /etc/wireguard/server_private.key)

sudo cat > /etc/wireguard/wg0.conf << EOF
[Interface]
# WireGuard VPN Address für diesen Server
Address = 10.200.200.1/24

# Port auf dem WireGuard lauscht
ListenPort = 51820

# Server Private Key
PrivateKey = ${PRIVATE_KEY}

# Optional: NAT für interne Netzwerke
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# AWS IcePorge Client
# PUBLIC_KEY wird später durch den AWS Key ersetzt
[Peer]
PublicKey = AWS_CLIENT_PUBLIC_KEY_PLACEHOLDER
AllowedIPs = 10.200.200.2/32
EOF

sudo chmod 600 /etc/wireguard/wg0.conf
```

### 1.4 Firewall öffnen

```bash
# iptables
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT -m comment --comment "WireGuard"
sudo iptables-save | sudo tee /etc/iptables/rules.v4

# Oder ufw
sudo ufw allow 51820/udp comment 'WireGuard'

# Router/NAT: Port UDP 51820 an diesen Server weiterleiten!
```

### 1.5 Ollama für WireGuard Interface erlauben

```bash
# Ollama sollte auf allen Interfaces lauschen oder spezifisch auf dem WireGuard Interface
# In /etc/systemd/system/ollama.service.d/override.conf:
sudo mkdir -p /etc/systemd/system/ollama.service.d
sudo cat > /etc/systemd/system/ollama.service.d/override.conf << 'EOF'
[Service]
Environment="OLLAMA_HOST=0.0.0.0"
EOF

sudo systemctl daemon-reload
sudo systemctl restart ollama
```

---

## Schritt 2: AWS IcePorge Server

### 2.1 WireGuard installieren

```bash
sudo apt-get update
sudo apt-get install -y wireguard
```

### 2.2 Client Keys generieren

```bash
# Client Keys
wg genkey | sudo tee /etc/wireguard/client_private.key | wg pubkey | sudo tee /etc/wireguard/client_public.key
sudo chmod 600 /etc/wireguard/client_private.key

# Keys anzeigen
echo "Client Private Key:"
sudo cat /etc/wireguard/client_private.key
echo ""
echo "Client Public Key (für On-Premise Server):"
cat /etc/wireguard/client_public.key
```

### 2.3 Client Konfiguration erstellen

```bash
# Private Key auslesen
PRIVATE_KEY=$(sudo cat /etc/wireguard/client_private.key)

# Variablen anpassen!
ONPREM_PUBLIC_IP="DEINE_OEFFENTLICHE_IP"           # z.B. 203.0.113.50
ONPREM_SERVER_PUBKEY="ONPREM_SERVER_PUBLIC_KEY"    # Von Schritt 1.2
OLLAMA_INTERNAL_NETWORK="10.10.0.0/24"             # Internes Netzwerk mit Ollama

sudo cat > /etc/wireguard/wg-ollama.conf << EOF
[Interface]
# WireGuard VPN Address für AWS Client
Address = 10.200.200.2/32

# Client Private Key
PrivateKey = ${PRIVATE_KEY}

# On-Premise Server
[Peer]
PublicKey = ${ONPREM_SERVER_PUBKEY}
Endpoint = ${ONPREM_PUBLIC_IP}:51820
AllowedIPs = 10.200.200.0/24, ${OLLAMA_INTERNAL_NETWORK}

# Keepalive für NAT-Traversal
PersistentKeepalive = 25
EOF

sudo chmod 600 /etc/wireguard/wg-ollama.conf
```

### 2.4 WireGuard starten

```bash
# Aktivieren und starten
sudo systemctl enable wg-quick@wg-ollama
sudo systemctl start wg-quick@wg-ollama

# Status prüfen
sudo wg show
```

---

## Schritt 3: On-Premise Server finalisieren

### 3.1 AWS Client Public Key eintragen

```bash
# AWS Client Public Key in die Konfiguration eintragen
AWS_CLIENT_PUBKEY="DER_AWS_CLIENT_PUBLIC_KEY"  # Von Schritt 2.2

sudo sed -i "s|AWS_CLIENT_PUBLIC_KEY_PLACEHOLDER|${AWS_CLIENT_PUBKEY}|" /etc/wireguard/wg0.conf

# WireGuard starten
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0

# Status prüfen
sudo wg show
```

---

## Schritt 4: Verbindung testen

### Auf AWS Server

```bash
# Ping zum On-Premise WireGuard Interface
ping -c 3 10.200.200.1

# Ping zum Ollama Server (internes Netzwerk)
ping -c 3 10.10.0.210

# Ollama API testen
curl -s http://10.10.0.210:11434/api/tags | jq

# Ollama Modell testen
curl -s http://10.10.0.210:11434/api/generate \
  -d '{"model": "llama3.1:8b", "prompt": "Hello", "stream": false}' | jq
```

---

## Schritt 5: IcePorge Konfiguration

### In `/opt/iceporge/install/config.env`:

```bash
# AI Backend
AI_BACKEND="ollama"  # oder "both" für Ollama + Bedrock

# Ollama über WireGuard Tunnel
OLLAMA_API_URL="http://10.10.0.210:11434"
OLLAMA_MODEL="llama3.1:8b"
OLLAMA_TIMEOUT="120"

# WireGuard
WG_ENABLED="true"
```

### In `/opt/cape-mailer/config.yaml`:

```yaml
ollama:
  api_url: "http://10.10.0.210:11434"
  model: "llama3.1:8b"
  timeout: 120
```

---

## Troubleshooting

### WireGuard Status prüfen

```bash
# Interface Status
sudo wg show

# Letzte Handshake Zeit (sollte < 2 Minuten sein)
sudo wg show wg-ollama latest-handshakes

# Logs
sudo journalctl -u wg-quick@wg-ollama -f
```

### Verbindung funktioniert nicht

```bash
# 1. Firewall auf On-Premise prüfen
sudo iptables -L INPUT -n | grep 51820

# 2. Port von außen erreichbar?
nc -zvu ONPREM_PUBLIC_IP 51820

# 3. Keys korrekt?
# Auf AWS:
cat /etc/wireguard/client_public.key
# Muss mit dem Peer PublicKey auf On-Premise übereinstimmen

# 4. Routing prüfen
ip route | grep 10.10.0
```

### Ollama antwortet nicht

```bash
# 1. Ollama läuft?
systemctl status ollama

# 2. Ollama lauscht auf allen Interfaces?
ss -tlnp | grep 11434

# 3. Firewall auf Ollama Server?
sudo iptables -L INPUT -n | grep 11434
```

---

## Automatischer Reconnect

WireGuard verbindet sich automatisch wieder, wenn:
- Der PersistentKeepalive aktiv ist (alle 25 Sekunden)
- Der Endpoint erreichbar ist

Für zusätzliche Überwachung:

```bash
# Cron Job für Connectivity Check
cat > /etc/cron.d/wireguard-check << 'EOF'
*/5 * * * * root ping -c 1 -W 5 10.10.0.210 > /dev/null || systemctl restart wg-quick@wg-ollama
EOF
```

---

## Sicherheitshinweise

1. **Private Keys niemals teilen** - Jeder Server hat seinen eigenen Private Key
2. **Public IP schützen** - Nur notwendige Ports öffnen (SSH, WireGuard)
3. **Keys rotieren** - Bei Verdacht auf Kompromittierung neue Keys generieren
4. **Logs überwachen** - Ungewöhnliche Verbindungsversuche beachten
