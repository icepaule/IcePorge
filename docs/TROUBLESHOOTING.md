# IcePorge Troubleshooting Guide

This document covers common issues, their root causes, and verified solutions for the IcePorge malware analysis platform.

## Table of Contents

- [CAPE Analysis Issues](#cape-analysis-issues)
  - [NULL PE Data in Reports](#null-pe-data-in-reports)
  - [Entropy Parse Error](#entropy-parse-error)
  - [Gunicorn Worker Timeout](#gunicorn-worker-timeout)
  - [Ghidra Analysis Timeout](#ghidra-analysis-timeout)
- [CAPE Web Interface Issues](#cape-web-interface-issues)
  - [LookupError: deleted status](#lookuperror-deleted-status)
- [Python Code Changes Not Loading](#python-code-changes-not-loading)
- [Service Management](#service-management)

---

## CAPE Analysis Issues

### NULL PE Data in Reports

**Symptom:**
- AI analysis shows `pe_machine: null`, `filename: null`
- PE sections missing from reports
- Empty data in `/cape/<id>/llm` API responses

**Root Cause:**
The code was extracting PE data from the wrong location in CAPE's JSON structure. CAPE stores PE headers in `target.file.pe`, but the code was looking in `static.pe`.

**Solution:**

Edit `/opt/iceporge/ai/cape_analyzer.py` around line 253:

```python
# BEFORE (BROKEN):
static = lite.get('static', {})
pe = static.get('pe', {}) if isinstance(static, dict) else {}

# AFTER (FIXED):
target = lite.get('target', {}).get('file', {})
pe = target.get('pe', {}) if isinstance(target, dict) else {}
```

Additionally, CAPE uses `machine_type` instead of `machine`:

```python
# BEFORE:
data['pe']['machine'] = pe.get('machine', '')

# AFTER:
data['pe']['machine'] = pe.get('machine_type', pe.get('machine', ''))
```

**Verification:**
```bash
cd /opt/iceporge && python3 << 'EOF'
import sys
sys.path.insert(0, '/opt/iceporge/ai')
from cape_analyzer import extract_cape_data
result = extract_cape_data('/opt/CAPEv2/storage/analyses/<ID>', skip_ghidra=True)
print(f"PE Machine: {result.get('pe', {}).get('machine')}")
# Should show: IMAGE_FILE_MACHINE_I386
EOF
```

---

### Entropy Parse Error

**Symptom:**
```
ValueError: Unknown format code 'f' for object of type 'str'
lite.json parse error for /opt/CAPEv2/storage/analyses/XXXX
```

**Root Cause:**
CAPE stores section entropy as a **string** (e.g., `"6.59"`) instead of a float. When the code tried to format it with `f"{entropy:.1f}"`, Python raised a ValueError.

**Solution:**

Edit `/opt/iceporge/ai/cape_analyzer.py` around line 264:

```python
# BEFORE (BROKEN):
data['pe']['sections'] = [
    f"{s.get('name','?')} (entropy: {s.get('entropy',0):.1f})"
    for s in secs[:10] if isinstance(s, dict)
]

# AFTER (FIXED):
data['pe']['sections'] = []
for s in secs[:10]:
    if isinstance(s, dict):
        name = s.get('name', '?')
        entropy = s.get('entropy', 0)
        try:
            entropy_val = float(entropy) if entropy else 0.0
            data['pe']['sections'].append(f"{name} (entropy: {entropy_val:.1f})")
        except (ValueError, TypeError):
            data['pe']['sections'].append(f"{name} (entropy: ?)")
```

**Verification:**
After fix, logs should show no more "Unknown format code" errors, and sections should display correctly:
```
['.text (entropy: 6.6)', '.rdata (entropy: 5.5)', '.data (entropy: 5.1)']
```

---

### Gunicorn Worker Timeout

**Symptom:**
```
[CRITICAL] WORKER TIMEOUT (pid:XXXXX)
HTTP 500 error after 6 minutes
TypeError: Failed to fetch
```

**Root Cause:**
Gunicorn's default worker timeout (360s/6 minutes) is too short for Ghidra analysis, which can take 10-15 minutes for complex binaries.

**Solution:**

Edit `/etc/systemd/system/iceporge-web.service`:

```ini
# BEFORE:
--timeout 360

# AFTER:
--timeout 900
```

Apply changes:
```bash
systemctl daemon-reload
systemctl restart iceporge-web.service
```

**Verification:**
```bash
systemctl status iceporge-web.service | grep timeout
# Should show: --timeout 900
```

---

### Ghidra Analysis Timeout

**Symptom:**
Ghidra decompilation times out after 5 minutes, even for large executables.

**Root Cause:**
The subprocess timeout was set to 300 seconds, insufficient for complex binaries.

**Solution:**

Edit `/opt/iceporge/ai/cape_analyzer.py` around line 672:

```python
# BEFORE:
cmd, capture_output=True, text=True, timeout=300

# AFTER:
cmd, capture_output=True, text=True, timeout=600
```

**Note:** Some very large binaries (>3MB) may still timeout. Consider skipping Ghidra for these or increasing to 900s.

---

## CAPE Web Interface Issues

### LookupError: deleted status

**Symptom:**
```
LookupError: 'deleted' is not among the defined enum values.
Enum name: status_type. Possible values: banned, pending, running, ..., failed_reporting
```

**Root Cause:**
The CAPE database contains tasks with `status='deleted'`, but this value is not defined in the SQLAlchemy status enum in `/opt/CAPEv2/lib/cuckoo/core/data/task.py`.

**Solution:**

Update the database to change invalid status values:

```bash
sqlite3 /opt/CAPEv2/db/cuckoo.db "UPDATE tasks SET status='banned' WHERE status='deleted';"
```

**Verification:**
```bash
sqlite3 /opt/CAPEv2/db/cuckoo.db "SELECT COUNT(*) FROM tasks WHERE status='deleted';"
# Should return: 0
```

Access `https://cape.thesoc.de/analysis/` - the LookupError should be gone.

---

## Python Code Changes Not Loading

**Symptom:**
- Code changes in `/opt/iceporge/ai/cape_analyzer.py` don't take effect
- Old behavior persists despite edits
- `importlib.reload()` doesn't help

**Root Cause:**
Python compiles modules to `.pyc` bytecode files stored in `__pycache__/` directories. These are not automatically invalidated when the source `.py` file changes. Additionally, Gunicorn workers cache imported modules in memory.

**Solution:**

After **every** code change to IcePorge Python files:

```bash
# 1. Delete ALL Python cache files
rm -rf /opt/iceporge/ai/__pycache__/
rm -rf /opt/iceporge/webapp/__pycache__/
rm -rf /opt/iceporge/scripts/__pycache__/

# 2. Restart the web service
systemctl restart iceporge-web.service

# 3. Verify service is running
systemctl status iceporge-web.service
```

**Verification:**
```bash
# Check .pyc modification time is AFTER your source file edit
stat /opt/iceporge/ai/cape_analyzer.py | grep Modify
stat /opt/iceporge/ai/__pycache__/cape_analyzer.cpython-312.pyc | grep Modify
# .pyc should be newer than .py
```

**Automation:**
Add to your deployment script:

```bash
#!/bin/bash
# deploy-iceporge-updates.sh

echo "Deploying IcePorge code updates..."

# Clear caches
find /opt/iceporge -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null

# Restart services
systemctl restart iceporge-web.service
systemctl status iceporge-web.service --no-pager

echo "✅ Deployment complete. Cache cleared and service restarted."
```

---

## Service Management

### Restart All IcePorge Services

```bash
# Web Dashboard
systemctl restart iceporge-web.service

# CAPE Sandbox
systemctl restart cape.service
systemctl restart cape-processor.service
systemctl restart cape-web.service

# MWDB Stack (Docker)
cd /opt/iceporge/components/IcePorge-MWDB-Stack
docker-compose restart
```

### Check Service Status

```bash
# IcePorge Dashboard
systemctl status iceporge-web.service

# CAPE Services
systemctl status cape.service
systemctl status cape-processor.service

# MWDB Containers
docker ps | grep mwdb
```

### View Logs

```bash
# IcePorge Web
journalctl -u iceporge-web.service -f

# IcePorge Access Log
tail -f /var/log/iceporge/access.log

# IcePorge Error Log
tail -f /var/log/iceporge/error.log

# CAPE Logs
tail -f /opt/CAPEv2/log/cuckoo.log
tail -f /opt/CAPEv2/log/web.log
```

---

## Getting Help

If you encounter issues not covered here:

1. **Check logs** in `/var/log/iceporge/` and `/opt/CAPEv2/log/`
2. **Search existing issues** on GitHub
3. **Open a new issue** with:
   - Full error message
   - Log excerpts
   - Steps to reproduce
   - System information (`uname -a`, CAPE version)

**GitHub Issues:** https://github.com/icepaule/IcePorge/issues
**Email:** info@mpauli.de
