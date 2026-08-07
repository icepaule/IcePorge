# 🔑 abuse.ch API-Key Anleitung

**Problem:** Alle vorhandenen API-Keys sind ungültig.  
**Lösung:** Neuen Key bei abuse.ch generieren.

---

## ✅ **SCHRITT-FÜR-SCHRITT ANLEITUNG**

### **1. Login/Registrierung**

**Option A: Du hast bereits einen Account**
```
🌐 https://auth.abuse.ch/login/
```
→ Login mit Email + Passwort

**Option B: Noch kein Account**
```
🌐 https://auth.abuse.ch/register/
```
→ Registrierung (kostenlos)  
→ Email-Verifizierung abwarten  
→ Dann Login

---

### **2. API-Key generieren**

Nach erfolgreichem Login:

1. **Profil-Menü** öffnen (rechts oben, Dein Username)
2. Klick auf **"API Keys"** oder **"Settings"**
3. Button: **"Generate New API Key"** oder **"Create API Key"**
4. **Key kopieren** (Format: `a1b2c3d4e5f6...`, ca. 40 Zeichen)

⚠️ **WICHTIG:** Der Key gilt für **ALLE** abuse.ch Services:
- ✅ URLhaus
- ✅ ThreatFox
- ✅ MalwareBazaar

---

### **3. Key in IcePorge eintragen**

**Option A: Sende mir den Key**
→ Ich trage ihn automatisch ein und teste alles!

**Option B: Manuell eintragen**

```bash
# 1. MWDB-Feeder Config bearbeiten
nano /opt/iceporge/components/IcePorge-MWDB-Feeder/.env

# Ersetze diese Zeilen:
URLHAUS_AUTH_KEY=DEIN_NEUER_KEY_HIER
THREATFOX_AUTH_KEY=DEIN_NEUER_KEY_HIER
MALWAREBAZAAR_AUTH_KEY=DEIN_NEUER_KEY_HIER

# 2. CAPE-Feed Config bearbeiten
nano /opt/iceporge/components/IcePorge-CAPE-Feed/.env

# Ersetze diese Zeile:
MB_AUTH_KEY=DEIN_NEUER_KEY_HIER

# 3. Services neu starten
cd /opt/iceporge/components/IcePorge-MWDB-Feeder
docker compose restart

cd /opt/iceporge/components/IcePorge-CAPE-Feed
docker compose restart

# 4. Logs prüfen (sollte nach ~10 Sekunden Samples zeigen)
docker logs mwdb-feeder --tail 20 -f
```

**Erwartete Ausgabe:**
```
INFO: URLhaus: fetched 50 recent payloads
INFO: ThreatFox: fetched 25 malware IOCs
INFO: MalwareBazaar: fetched 100 recent samples
INFO: Uploaded to MWDB: sha256_abc123...
```

---

## 🧪 **Key testen (vor Eintragen)**

```bash
# Ersetze YOUR_KEY_HERE mit Deinem neuen Key
API_KEY="YOUR_KEY_HERE"

# Test MalwareBazaar
curl -X POST "https://mb-api.abuse.ch/api/v1/" \
  -H "Auth-Key: $API_KEY" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "query=get_recent&selector=time&limit=1"

# Erwartete Response:
# {"query_status":"ok","data":[...]}
```

Wenn `"query_status":"ok"` → ✅ Key funktioniert!  
Wenn `"unknown_auth_key"` → ❌ Key falsch eingegeben

---

## 📊 **Nach Key-Update: Verifikation**

### **1. Check Recent Analyses**

```bash
# Warte 10-15 Minuten, dann:
# https://cape.thesoc.de/analysis/

# Sollte neue Einträge zeigen mit Tags:
#   - urlhaus
#   - threatfox
#   - malwarebazaar
```

### **2. Check MWDB Dashboard**

```bash
# http://localhost:8081/
# oder https://mwdb.thesoc.de/

# Sollte neue Samples zeigen mit Tags:
#   - feed:urlhaus
#   - feed:threatfox
#   - feed:malwarebazaar
```

### **3. Check Container Logs**

```bash
# Keine Errors mehr:
docker logs mwdb-feeder --tail 50
docker logs cape-feed --tail 50

# Stattdessen:
# ✅ "fetched X payloads"
# ✅ "uploaded to MWDB"
# ✅ "submitted to CAPE"
```

---

## ⚠️ **Troubleshooting**

### **Problem: Key funktioniert nicht**

1. **Key nochmal kopieren** (kein Leerzeichen am Anfang/Ende!)
2. **Prüfen ob Key aktiviert** ist (abuse.ch Dashboard)
3. **Firewall-Test:**
   ```bash
   curl -I https://mb-api.abuse.ch/
   # Sollte "HTTP/2 301" oder "200" zeigen
   ```

### **Problem: Logs zeigen immer noch Errors**

```bash
# Container komplett neu bauen
cd /opt/iceporge/components/IcePorge-MWDB-Feeder
docker compose down
docker compose build --no-cache
docker compose up -d

cd /opt/iceporge/components/IcePorge-CAPE-Feed
docker compose down
docker compose up -d
```

### **Problem: Keine neuen Analysen in CAPE**

1. **Check MWDB-Feeder:** Lädt er Samples hoch?
   ```bash
   docker logs mwdb-feeder | grep -i "uploaded\|success"
   ```

2. **Check Karton Pipeline:** Leitet er an CAPE weiter?
   ```bash
   docker logs karton-cape-submitter | tail -20
   ```

3. **Check CAPE Queue:**
   ```bash
   curl -s http://localhost:8000/apiv2/tasks/list/1/ | jq '.data | length'
   # Sollte > 0 sein wenn Samples in Queue
   ```

---

## 📞 **Support**

- **abuse.ch Support:** https://abuse.ch/contact/
- **IcePorge GitHub:** https://github.com/icepaule/IcePorge/issues
- **Email:** info@mpauli.de

---

## 🎯 **Schnell-Check:**

```bash
# Alles OK?
docker ps | grep -E "(mwdb-feeder|cape-feed)" && \
docker logs mwdb-feeder --tail 5 && \
docker logs cape-feed --tail 5
```

Wenn Du **"fetched X payloads"** siehst → ✅ **FUNKTIONIERT!**

---

**Erstellt:** 2026-08-07  
**Autor:** Claude Code (Anthropic)
