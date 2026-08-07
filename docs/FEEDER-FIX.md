# MWDB-Feeder Fix - API Authentication Issue

**Status:** ⚠️ **BLOCKED - Requires New API Keys**  
**Date:** 2026-08-07

---

## Problem

The MWDB-Feeder and CAPE-Feed services are running but **not fetching any malware samples**. Both show continuous `403 Forbidden` / `Unauthorized` errors.

### Error Logs

**MWDB-Feeder:**
```
ERROR URLhaus fetch error: 403 Client Error: Forbidden for url: https://urlhaus-api.abuse.ch/v1/payloads/recent/?limit=50
ERROR ThreatFox fetch error: 403 Client Error: Forbidden for url: https://threatfox-api.abuse.ch/api/v1/
```

**CAPE-Feed:**
```
{"error": "MalwareBazaar: Unauthorized/Forbidden (403) - check MB_AUTH_KEY / Auth-Key header"}
```

---

## Root Cause

abuse.ch has changed their API authentication requirements:

1. **URLhaus API** - Now requires POST requests instead of GET
2. **ThreatFox API** - Requires valid API key in specific format
3. **MalwareBazaar API** - No longer allows unauthenticated access
4. **Current API Keys** - The keys in `.env` files are **invalid or expired**:
   ```
   URLHAUS_AUTH_KEY=1a13b8a9ec9429ae13570003ccbc2157c7810d460b5e0c0a
   THREATFOX_AUTH_KEY=1a13b8a9ec9429ae13570003ccbc2157c7810d460b5e0c0a
   ```

---

## Solution

### Step 1: Get New API Keys from abuse.ch

Visit **https://abuse.ch/api/** and register/login to get fresh API keys for:

- ✅ URLhaus API Key
- ✅ ThreatFox API Key  
- ✅ MalwareBazaar API Key

**Important:** All three services now require authenticated access!

### Step 2: Update MWDB-Feeder Configuration

Edit `/opt/iceporge/components/IcePorge-MWDB-Feeder/.env`:

```bash
# Replace with your NEW keys from https://abuse.ch/api/
URLHAUS_AUTH_KEY=your_new_urlhaus_key_here
THREATFOX_AUTH_KEY=your_new_threatfox_key_here
MALWAREBAZAAR_AUTH_KEY=your_new_malwarebazaar_key_here
```

### Step 3: Update CAPE-Feed Configuration

Edit `/opt/iceporge/components/IcePorge-CAPE-Feed/.env`:

```bash
# Add the same MalwareBazaar key
MB_AUTH_KEY=your_new_malwarebazaar_key_here
```

### Step 4: Fix URLhaus Request Method

The code was using GET but abuse.ch now requires POST.

**File:** `/opt/iceporge/components/IcePorge-MWDB-Feeder/app/feeder.py`  
**Line:** 257

**Before:**
```python
resp = self.session.get(
    f"https://urlhaus-api.abuse.ch/v1/payloads/recent/?limit={limit}",
    timeout=30
)
```

**After:**
```python
resp = self.session.post(
    "https://urlhaus-api.abuse.ch/v1/payloads/recent/",
    data={'selector': 'time'},
    timeout=30
)
```

**Status:** ✅ Already fixed in code (committed 2026-08-07)

### Step 5: Rebuild and Restart Services

```bash
# Rebuild MWDB-Feeder container with fixed code
cd /opt/iceporge/components/IcePorge-MWDB-Feeder
docker compose build --no-cache
docker compose up -d

# Restart CAPE-Feed
cd /opt/iceporge/components/IcePorge-CAPE-Feed
docker compose restart

# Check logs
docker logs mwdb-feeder --tail 50 -f
docker logs cape-feed --tail 50 -f
```

Expected output:
```
INFO: URLhaus: fetched 50 recent payloads
INFO: ThreatFox: fetched 25 malware IOCs
INFO: MalwareBazaar: fetched 100 recent samples
```

---

## Verification

### Test API Keys Manually

```bash
# Test URLhaus
curl -X POST "https://urlhaus-api.abuse.ch/v1/payloads/recent/" \
  -H "Auth-Key: YOUR_KEY_HERE" \
  -d "selector=time"

# Expected: {"query_status":"ok","payloads":[...]}

# Test ThreatFox
curl -X POST "https://threatfox-api.abuse.ch/api/v1/" \
  -H "Auth-Key: YOUR_KEY_HERE" \
  -H "Content-Type: application/json" \
  -d '{"query":"get_iocs","days":1}'

# Expected: {"query_status":"ok","data":[...]}

# Test MalwareBazaar
curl -X POST "https://mb-api.abuse.ch/api/v1/" \
  -H "Auth-Key: YOUR_KEY_HERE" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "query=get_recent&selector=time"

# Expected: {"query_status":"ok","data":[...]}
```

### Check CAPE Recent Analyses

After 10-15 minutes, check https://cape.thesoc.de/analysis/:
- New analyses should appear with tags like `urlhaus`, `threatfox`, `malwarebazaar`
- Filenames will be SHA256 hashes
- Malscore > 0 for real malware

### Check MWDB Dashboard

Visit http://localhost:8081/ (or your MWDB URL):
- Recent uploads should appear
- Tags: `feed:urlhaus`, `feed:threatfox`, etc.
- Karton pipeline should process them automatically

---

## Alternative: Manual Sample Upload

If API keys cannot be obtained immediately, you can manually upload samples:

```bash
# Download sample from any source
wget https://example.com/sample.exe -O /tmp/sample.exe

# Submit to CAPE directly
curl -F "file=@/tmp/sample.exe" http://localhost:8000/tasks/create/file

# Or submit to MWDB
mwdb upload /tmp/sample.exe --tag manual
```

---

## Code Changes

### File: `app/feeder.py` (Line 257)

```diff
  def fetch_recent(self, limit: int = 50) -> List[Dict]:
      """Fetch recent payloads from URLhaus."""
      if not self.cfg.urlhaus_enabled:
          return []

      try:
-         # URLhaus API: GET request with Auth-Key header
-         resp = self.session.get(
-             f"https://urlhaus-api.abuse.ch/v1/payloads/recent/?limit={limit}",
+         # URLhaus API: POST request with data payload
+         resp = self.session.post(
+             "https://urlhaus-api.abuse.ch/v1/payloads/recent/",
+             data={'selector': 'time'},
              timeout=30
          )
```

---

## Future Improvements

1. **API Key Validation on Startup**
   - Test keys before entering polling loop
   - Fail fast with clear error message

2. **Rate Limiting Handling**
   - Detect 429 responses
   - Implement exponential backoff

3. **Fallback Sources**
   - VirusTotal Intelligence API
   - Hybrid Analysis Public Feed
   - ANY.RUN Public Submissions

4. **Health Monitoring**
   - Expose Prometheus metrics
   - Alert on >1 hour without samples

---

## Status Summary

| Service | Status | Action Required |
|---------|--------|-----------------|
| **MWDB-Feeder** | ⚠️ Running but failing | Get new abuse.ch API keys |
| **CAPE-Feed** | ⚠️ Running but failing | Get new abuse.ch API keys |
| **MWDB Stack** | ✅ Running | None |
| **CAPE Sandbox** | ✅ Running | None |
| **Karton Pipeline** | ✅ Running | None |

**BLOCKED:** Cannot fetch samples until new API keys are obtained from https://abuse.ch/api/

---

## Contact

- **abuse.ch Support:** https://abuse.ch/contact/
- **API Documentation:** https://abuse.ch/api/
- **Registration:** https://auth.abuse.ch/

**Estimated Time to Fix:** 10 minutes (after API keys obtained)

---

**Document Version:** 1.0  
**Last Updated:** 2026-08-07  
**Author:** Claude Code (Anthropic)
