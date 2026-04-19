# IcePorge AWS Deployment via CloudShell

Schritt-für-Schritt Anleitung zur Installation von IcePorge auf einem AWS Ubuntu Server direkt aus der AWS CloudShell.

## Voraussetzungen

- AWS Account mit EC2-Berechtigung
- AWS CloudShell Zugang
- SSH Key Pair in AWS (oder erstellen wir einen)

---

## Phase 1: EC2 Instance erstellen (CloudShell)

Öffne AWS CloudShell und führe folgende Befehle aus:

```bash
# =============================================================================
# VARIABLEN ANPASSEN
# =============================================================================
export AWS_REGION="eu-central-1"
export INSTANCE_NAME="iceporge-sandbox"
export KEY_NAME="iceporge-key"
export INSTANCE_TYPE="t3.2xlarge"        # 8 vCPU, 32 GB RAM (für CAPE)
export VOLUME_SIZE="500"                  # GB für Analysen
export YOUR_IP="0.0.0.0/0"               # Für Produktion: Deine IP/32

# =============================================================================
# SSH KEY ERSTELLEN (falls nicht vorhanden)
# =============================================================================
if ! aws ec2 describe-key-pairs --key-names "$KEY_NAME" 2>/dev/null; then
    aws ec2 create-key-pair \
        --key-name "$KEY_NAME" \
        --query 'KeyMaterial' \
        --output text > ~/.ssh/${KEY_NAME}.pem
    chmod 600 ~/.ssh/${KEY_NAME}.pem
    echo "SSH Key erstellt: ~/.ssh/${KEY_NAME}.pem"
fi

# =============================================================================
# SECURITY GROUP ERSTELLEN
# =============================================================================
VPC_ID=$(aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" \
    --query 'Vpcs[0].VpcId' --output text)

SG_ID=$(aws ec2 create-security-group \
    --group-name "iceporge-sg" \
    --description "IcePorge Security Group" \
    --vpc-id "$VPC_ID" \
    --query 'GroupId' --output text 2>/dev/null || \
    aws ec2 describe-security-groups \
        --filters "Name=group-name,Values=iceporge-sg" \
        --query 'SecurityGroups[0].GroupId' --output text)

# Firewall-Regeln
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
    --protocol tcp --port 22 --cidr "$YOUR_IP" 2>/dev/null || true
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
    --protocol tcp --port 8085 --cidr "$YOUR_IP" 2>/dev/null || true
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
    --protocol udp --port 51820 --cidr "$YOUR_IP" 2>/dev/null || true

echo "Security Group: $SG_ID"

# =============================================================================
# UBUNTU 24.04 AMI FINDEN
# =============================================================================
AMI_ID=$(aws ec2 describe-images \
    --owners 099720109477 \
    --filters "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" \
              "Name=state,Values=available" \
    --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
    --output text)

echo "Ubuntu AMI: $AMI_ID"

# =============================================================================
# EC2 INSTANCE STARTEN
# =============================================================================
INSTANCE_ID=$(aws ec2 run-instances \
    --image-id "$AMI_ID" \
    --instance-type "$INSTANCE_TYPE" \
    --key-name "$KEY_NAME" \
    --security-group-ids "$SG_ID" \
    --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=$VOLUME_SIZE,VolumeType=gp3}" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$INSTANCE_NAME}]" \
    --query 'Instances[0].InstanceId' \
    --output text)

echo "Instance gestartet: $INSTANCE_ID"

# Warten bis Instance läuft
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID"

# Public IP abrufen
PUBLIC_IP=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text)

echo ""
echo "=============================================="
echo "  EC2 Instance bereit!"
echo "=============================================="
echo "  Instance ID: $INSTANCE_ID"
echo "  Public IP:   $PUBLIC_IP"
echo "  SSH Key:     ~/.ssh/${KEY_NAME}.pem"
echo ""
echo "  SSH Verbindung:"
echo "  ssh -i ~/.ssh/${KEY_NAME}.pem ubuntu@$PUBLIC_IP"
echo "=============================================="
```

---

## Phase 2: IcePorge Installation (via SSH)

Verbinde dich mit der Instance und führe das Setup aus:

```bash
# Von CloudShell aus SSH-Verbindung herstellen
ssh -i ~/.ssh/${KEY_NAME}.pem ubuntu@$PUBLIC_IP

# ============================================================================
# AB HIER AUF DEM EC2 SERVER
# ============================================================================

# Root werden
sudo -i

# =============================================================================
# SYSTEM UPDATE
# =============================================================================
apt-get update && apt-get upgrade -y

# =============================================================================
# ICEPORGE REPOSITORY KLONEN
# =============================================================================
git clone https://github.com/icepaule/IcePorge.git /opt/iceporge
cd /opt/iceporge

# =============================================================================
# KONFIGURATION ERSTELLEN
# =============================================================================
cp install/config.env.example install/config.env
chmod 600 install/config.env

# Konfiguration bearbeiten (WICHTIG!)
nano install/config.env

# =============================================================================
# INSTALLATION STARTEN
# =============================================================================
chmod +x install/install-iceporge.sh
./install/install-iceporge.sh --config install/config.env
```

---

## Phase 3: WireGuard für Ollama (On-Premise Verbindung)

### 3.1 Auf dem On-Premise Server (mit Ollama)

```bash
# WireGuard installieren
apt-get install -y wireguard

# Keys generieren
wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
chmod 600 /etc/wireguard/server_private.key

# Server Public Key anzeigen (für AWS config)
cat /etc/wireguard/server_public.key

# Konfiguration erstellen
cat > /etc/wireguard/wg0.conf << 'EOF'
[Interface]
Address = 10.200.200.1/24
ListenPort = 51820
PrivateKey = INHALT_VON_server_private.key

# AWS IcePorge Server
[Peer]
PublicKey = AWS_CLIENT_PUBLIC_KEY_HIER
AllowedIPs = 10.200.200.2/32
EOF

# Port in Router/Firewall öffnen: UDP 51820
# WireGuard starten
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0
```

### 3.2 Auf dem AWS Server

```bash
# Keys generieren
wg genkey | tee /etc/wireguard/client_private.key | wg pubkey > /etc/wireguard/client_public.key
chmod 600 /etc/wireguard/client_private.key

# Client Public Key anzeigen (für On-Premise config)
cat /etc/wireguard/client_public.key

# Konfiguration erstellen
cat > /etc/wireguard/wg-ollama.conf << 'EOF'
[Interface]
Address = 10.200.200.2/32
PrivateKey = INHALT_VON_client_private.key

[Peer]
PublicKey = ONPREM_SERVER_PUBLIC_KEY_HIER
Endpoint = DEINE_OEFFENTLICHE_IP:51820
AllowedIPs = 10.10.0.0/24
PersistentKeepalive = 25
EOF

# WireGuard starten
systemctl enable wg-quick@wg-ollama
systemctl start wg-quick@wg-ollama

# Verbindung testen
ping -c 3 10.10.0.210

# Ollama testen
curl http://10.10.0.210:11434/api/tags
```

---

## Phase 4: AWS Bedrock einrichten

### 4.1 IAM Role für EC2 erstellen (CloudShell)

```bash
# =============================================================================
# IAM ROLE FÜR BEDROCK ERSTELLEN
# =============================================================================

# Trust Policy
cat > /tmp/trust-policy.json << 'EOF'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF

# Bedrock Policy
cat > /tmp/bedrock-policy.json << 'EOF'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "bedrock:InvokeModel",
                "bedrock:InvokeModelWithResponseStream",
                "bedrock:ListFoundationModels",
                "bedrock:GetFoundationModel"
            ],
            "Resource": "*"
        }
    ]
}
EOF

# Role erstellen
aws iam create-role \
    --role-name IcePorgeBedrockRole \
    --assume-role-policy-document file:///tmp/trust-policy.json

# Policy erstellen und anhängen
aws iam put-role-policy \
    --role-name IcePorgeBedrockRole \
    --policy-name BedrockAccess \
    --policy-document file:///tmp/bedrock-policy.json

# Instance Profile erstellen
aws iam create-instance-profile --instance-profile-name IcePorgeProfile
aws iam add-role-to-instance-profile \
    --instance-profile-name IcePorgeProfile \
    --role-name IcePorgeBedrockRole

# An EC2 Instance anhängen
aws ec2 associate-iam-instance-profile \
    --instance-id "$INSTANCE_ID" \
    --iam-instance-profile Name=IcePorgeProfile

echo "Bedrock IAM Role konfiguriert!"
```

### 4.2 Bedrock Model Access aktivieren

```bash
# In AWS Console:
# 1. Gehe zu Amazon Bedrock
# 2. Model access -> Manage model access
# 3. Aktiviere: Anthropic Claude 3 Sonnet (oder gewünschtes Modell)
# 4. Submit und warten auf Genehmigung
```

### 4.3 Bedrock in IcePorge config aktivieren

```bash
# Auf dem EC2 Server
nano /opt/iceporge/install/config.env

# Ändern:
AI_BACKEND="both"    # oder "bedrock" für nur Bedrock
AWS_REGION="eu-central-1"
BEDROCK_MODEL_ID="anthropic.claude-3-sonnet-20240229-v1:0"
```

---

## Phase 5: Services starten

```bash
# =============================================================================
# ALLE SERVICES STARTEN
# =============================================================================

# CAPE-Mailer
systemctl start cape-mailer
systemctl status cape-mailer

# Web Dashboard
systemctl start iceporge-web
systemctl status iceporge-web

# Monitoring
systemctl start iceporge-monitor.timer
systemctl list-timers | grep iceporge

# MWDB Stack (Docker)
cd /opt/mwdb-stack && docker compose up -d

# Status prüfen
/opt/iceporge/scripts/iceporge-monitor.sh check
cat /opt/iceporge/status/health.json | jq
```

---

## Phase 6: Zugriff testen

```bash
# Von CloudShell aus
echo "Dashboard: http://$PUBLIC_IP:8085"

# Oder lokal mit SSH Tunnel
ssh -i ~/.ssh/${KEY_NAME}.pem -L 8085:localhost:8085 ubuntu@$PUBLIC_IP

# Dann im Browser: http://localhost:8085
```

---

## Schnellreferenz: Alle CloudShell Befehle

```bash
# =============================================================================
# KOMPLETTES SETUP IN EINEM BLOCK (CloudShell)
# =============================================================================

# Variablen
export AWS_REGION="eu-central-1"
export INSTANCE_NAME="iceporge-sandbox"
export KEY_NAME="iceporge-key"
export INSTANCE_TYPE="t3.2xlarge"
export VOLUME_SIZE="500"

# Key erstellen
aws ec2 create-key-pair --key-name "$KEY_NAME" \
    --query 'KeyMaterial' --output text > ~/.ssh/${KEY_NAME}.pem
chmod 600 ~/.ssh/${KEY_NAME}.pem

# Security Group
VPC_ID=$(aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" \
    --query 'Vpcs[0].VpcId' --output text)
SG_ID=$(aws ec2 create-security-group --group-name "iceporge-sg" \
    --description "IcePorge" --vpc-id "$VPC_ID" --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
    --protocol tcp --port 22 --cidr "0.0.0.0/0"
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
    --protocol tcp --port 8085 --cidr "0.0.0.0/0"
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
    --protocol udp --port 51820 --cidr "0.0.0.0/0"

# AMI finden
AMI_ID=$(aws ec2 describe-images --owners 099720109477 \
    --filters "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" \
    --query 'sort_by(Images, &CreationDate)[-1].ImageId' --output text)

# Instance starten
INSTANCE_ID=$(aws ec2 run-instances --image-id "$AMI_ID" \
    --instance-type "$INSTANCE_TYPE" --key-name "$KEY_NAME" \
    --security-group-ids "$SG_ID" \
    --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=$VOLUME_SIZE,VolumeType=gp3}" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$INSTANCE_NAME}]" \
    --query 'Instances[0].InstanceId' --output text)

aws ec2 wait instance-running --instance-ids "$INSTANCE_ID"
PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

echo "SSH: ssh -i ~/.ssh/${KEY_NAME}.pem ubuntu@$PUBLIC_IP"
echo "Dashboard: http://$PUBLIC_IP:8085"
```

---

## Troubleshooting

### SSH Verbindung schlägt fehl
```bash
# Key-Permissions prüfen
chmod 600 ~/.ssh/${KEY_NAME}.pem

# Security Group prüfen
aws ec2 describe-security-groups --group-ids "$SG_ID"
```

### Bedrock Model nicht verfügbar
```bash
# Verfügbare Modelle auflisten
aws bedrock list-foundation-models --query 'modelSummaries[*].modelId'

# Model Access Status prüfen
aws bedrock get-foundation-model-availability --model-identifier anthropic.claude-3-sonnet-20240229-v1:0
```

### WireGuard Tunnel funktioniert nicht
```bash
# Status prüfen
wg show

# Logs
journalctl -u wg-quick@wg-ollama -f

# Firewall auf On-Premise Server prüfen
iptables -L INPUT -n | grep 51820
```

---

## Kosten-Übersicht (geschätzt)

| Ressource | Typ | Kosten/Monat (eu-central-1) |
|-----------|-----|----------------------------|
| EC2 | t3.2xlarge | ~$120 |
| EBS | 500 GB gp3 | ~$45 |
| Bedrock | Claude 3 Sonnet | ~$0.003/1K input tokens |
| Transfer | Ausgehend | ~$0.09/GB |

**Tipp:** Für Tests t3.large ($30/Monat) verwenden, für Produktion t3.2xlarge.
