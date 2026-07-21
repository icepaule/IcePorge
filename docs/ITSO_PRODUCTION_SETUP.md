# IcePorge Production Deployment Guide

**Last Updated:** 2026-07-21

This document describes a production deployment of IcePorge with CAPE integration, automated analysis workflows, and AI-powered threat analysis.

---

## Architecture Overview

### Components

1. **Self-Healing System**
   - Monitors critical services (MongoDB, CAPE Web)
   - Auto-restarts on failure
   - Handles common issues (log permissions, connection timeouts)

2. **Mail-based Analysis Workflow**
   - Receives suspicious attachments via email
   - Submits to CAPE sandbox automatically
   - Generates AI-powered analysis reports
   - Sends results back to submitter

3. **Auto AI-Trigger**
   - Monitors CAPE tasks for high-risk samples
   - Triggers deep analysis for Malscore >= 7.0
   - Uses LLM for forensic analysis

4. **Web Interface**
   - Browse all CAPE analyses
   - Trigger on-demand deep analysis
   - Extract payloads and IOCs
   - View network behavior and dropped files

---

## Installation

### 1. Self-Healing Setup

Create monitoring script:

\`\`\`bash
cat > /opt/scripts/cape_selfhealing.sh << 'EOF'
#!/bin/bash
LOG_FILE="/var/log/cape_selfhealing.log"
MONGODB_SERVICE="mongod"
CAPE_WEB_SERVICE="cape-web"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] \$1" | tee -a "\$LOG_FILE"
}

# MongoDB Check
if ! systemctl is-active --quiet "\$MONGODB_SERVICE"; then
    log "ERROR: MongoDB down, restarting..."
    if [ -f /var/log/mongodb/mongod.log ]; then
        chown mongodb:mongodb /var/log/mongodb/mongod.log
    fi
    systemctl start "\$MONGODB_SERVICE"
    sleep 5
    systemctl is-active --quiet "\$MONGODB_SERVICE" && log "SUCCESS: MongoDB restarted" || log "CRITICAL: MongoDB failed to start"
fi

# CAPE Web Check
if ! systemctl is-active --quiet "\$CAPE_WEB_SERVICE"; then
    log "ERROR: CAPE Web down, restarting..."
    systemctl restart "\$CAPE_WEB_SERVICE"
    sleep 3
    systemctl is-active --quiet "\$CAPE_WEB_SERVICE" && log "SUCCESS: CAPE Web restarted" || log "CRITICAL: CAPE Web failed to start"
fi

log "INFO: Health check completed"
EOF

chmod +x /opt/scripts/cape_selfhealing.sh
\`\`\`

Add cronjob (every 5 minutes):
\`\`\`bash
(crontab -l 2>/dev/null; echo "*/5 * * * * /opt/scripts/cape_selfhealing.sh") | crontab -
\`\`\`

### 2. Mail-based Workflow

Configure in \`components/IcePorge-CAPE-Mailer/config.yaml\`:

\`\`\`yaml
imap:
  host: your-mail-server.example.com
  port: 993
  ssl: true
  user: analysis@example.com
  pass: your-password
  folder: INBOX
  check_interval: 300

smtp:
  host: your-mail-server.example.com
  port: 587
  starttls: true
  user: analysis@example.com
  pass: your-password
  from: "Security Analysis <analysis@example.com>"

cape:
  api_url: http://localhost:8000
  submit_timeout: 900

bedrock:
  enabled: true
  region: eu-central-1
  model_id: eu.anthropic.claude-sonnet-4-6
  analyze_attachments: true

access_control:
  allowed_domains:
    - example.com
    - trusted-partner.com
\`\`\`

### 3. Auto AI-Trigger Service

Create service script:

\`\`\`bash
cat > /opt/iceporge/auto_ai_trigger.py << 'EOF'
#!/usr/bin/env python3
import time
import logging
import requests
from pymongo import MongoClient

CAPE_MONGO_URI = "mongodb://localhost:27017/"
ICEPORGE_API = "http://localhost:8085"
CHECK_INTERVAL = 300
MALSCORE_THRESHOLD = 7.0

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_and_trigger():
    try:
        client = MongoClient(CAPE_MONGO_URI, serverSelectionTimeoutMS=5000)
        db = client["cape"]
        
        high_risk_tasks = db.tasks.find({
            "status": "reported",
            "malscore": {"\$gte": MALSCORE_THRESHOLD}
        }).sort("id", -1).limit(20)
        
        for task in high_risk_tasks:
            task_id = task.get("id")
            logger.info(f"Triggering AI analysis for task {task_id}")
            
            try:
                resp = requests.post(
                    f"{ICEPORGE_API}/api/analyze/bedrock",
                    json={"task_id": task_id, "priority": "high"},
                    timeout=30
                )
                if resp.status_code in [200, 202]:
                    logger.info(f"AI analysis started for {task_id}")
            except Exception as e:
                logger.debug(f"Task {task_id}: {e}")
            
            time.sleep(2)
            
    except Exception as e:
        logger.error(f"Error: {e}")

if __name__ == "__main__":
    while True:
        check_and_trigger()
        time.sleep(CHECK_INTERVAL)
EOF

chmod +x /opt/iceporge/auto_ai_trigger.py
\`\`\`

Create systemd service:

\`\`\`bash
cat > /etc/systemd/system/iceporge-ai-trigger.service << 'EOF'
[Unit]
Description=IcePorge AI Auto-Trigger for High-Risk Tasks
After=network.target mongod.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/iceporge
ExecStart=/usr/bin/python3 /opt/iceporge/auto_ai_trigger.py
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable iceporge-ai-trigger
systemctl start iceporge-ai-trigger
\`\`\`

---

## Troubleshooting

### MongoDB Issues
\`\`\`bash
systemctl status mongod
chown mongodb:mongodb /var/log/mongodb/mongod.log
systemctl start mongod
\`\`\`

### CAPE Web Not Responding
\`\`\`bash
systemctl restart cape-web
journalctl -u cape-web -n 50
\`\`\`

### Mail Workflow
\`\`\`bash
systemctl status cape-mailer
journalctl -u cape-mailer -f
\`\`\`

### AI Analysis
\`\`\`bash
systemctl status iceporge-ai-trigger
aws bedrock list-foundation-models --region eu-central-1 --by-provider anthropic
\`\`\`

---

## Monitoring

### Service Status
\`\`\`bash
systemctl status mongod cape-web cape-mailer iceporge-ai-trigger
\`\`\`

### Log Files
- \`/var/log/cape_selfhealing.log\` - Self-healing events
- \`/var/log/iceporge/access.log\` - Web requests
- \`/var/log/iceporge/error.log\` - Application errors
- \`/var/log/mongodb/mongod.log\` - Database logs

### CAPE Task Status
\`\`\`bash
mongo cape --eval "db.tasks.find({status: 'reported'}).count()"
mongo cape --eval "db.tasks.find({status: 'failed_reporting'}).count()"
\`\`\`

---

## Security Considerations

- All attachments analyzed in isolated sandbox environment
- LLM processing uses AWS Bedrock in EU region (GDPR compliant)
- Access control via allowed domain whitelist
- No data leaves configured region

---

## Performance

### Typical Analysis Times
- Static analysis: 1-2 minutes
- Behavioral analysis: 5-10 minutes
- AI report generation: 30-60 seconds
- Total (email to report): 10-15 minutes

---

## AWS Bedrock Configuration

Model: \`eu.anthropic.claude-sonnet-4-6\`  
Region: \`eu-central-1\`

Ensure IAM role has \`bedrock:InvokeModel\` permission for the model.
