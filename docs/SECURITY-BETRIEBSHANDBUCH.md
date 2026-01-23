# IcePorge Security-Betriebshandbuch

---

**Dokumenteninformationen**

| Attribut | Wert |
|----------|------|
| Dokumentenversion | 1.0 |
| Erstellungsdatum | 2026-01-23 |
| Letzte Änderung | 2026-01-23 |
| Klassifizierung | INTERN |
| Zielgruppe | IT-Sicherheit / DevSecOps |

---

## Inhaltsverzeichnis

1. [Übersicht](#1-übersicht)
2. [TruffleHog Security-Scanning](#2-trufflehog-security-scanning)
3. [Secret-Maskierung beim GitHub-Push](#3-secret-maskierung-beim-github-push)
4. [Pushover-Benachrichtigungen](#4-pushover-benachrichtigungen)
5. [Konfigurationsdateien](#5-konfigurationsdateien)
6. [Notfall-Prozeduren](#6-notfall-prozeduren)

---

## 1. Übersicht

Das IcePorge Security-System schützt vor versehentlicher Veröffentlichung sensibler Daten (API-Keys, Passwörter, interne IPs) in GitHub-Repositories.

### 1.1 Komponenten

| Komponente | Zweck | Pfad |
|------------|-------|------|
| TruffleHog | Secret-Scanning in Git-Repos | `/usr/local/bin/trufflehog` |
| security-scan.sh | Automatisierter Security-Scan | `/opt/iceporge/scripts/security-scan.sh` |
| sync-to-github.sh | GitHub-Sync mit Maskierung | `/opt/iceporge/sync-to-github.sh` |
| secrets.yaml | Zu maskierende Secrets | `/opt/iceporge/config/secrets.yaml` |
| pushover.yaml | Benachrichtigungs-Config | `/opt/iceporge/config/pushover.yaml` |

---

## 2. TruffleHog Security-Scanning

### 2.1 Installation

TruffleHog wurde via Official Installer installiert:

```bash
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

**Aktuelle Version:** v3.92.5

### 2.2 Manueller Scan

**Einzelnes Repository scannen:**
```bash
trufflehog git file:///path/to/repo
```

**GitHub-Organisation scannen:**
```bash
trufflehog github --org=icepaule --only-verified
```

**Mit JSON-Ausgabe für SIEM:**
```bash
trufflehog github --org=icepaule --json > /var/log/trufflehog-scan.json
```

### 2.3 Automatisierter Scan

**Vollständiger Scan aller Repositories:**
```bash
/opt/iceporge/scripts/security-scan.sh --all --notify
```

**Optionen:**
| Option | Beschreibung |
|--------|--------------|
| `--local` | Nur lokale Repositories scannen |
| `--github` | Nur GitHub scannen |
| `--all` | Beides scannen |
| `--notify` | Pushover-Benachrichtigung bei Funden |
| `--json` | JSON-Ausgabe |
| `--verbose` | Detaillierte Ausgabe |

### 2.4 Cron-Einrichtung (Empfohlen)

```bash
# Täglicher Security-Scan um 03:00 Uhr
0 3 * * * /opt/iceporge/scripts/security-scan.sh --all --notify >> /var/log/iceporge-security.log 2>&1
```

---

## 3. Secret-Maskierung beim GitHub-Push

### 3.1 Funktionsweise

Das `sync-to-github.sh` Script maskiert automatisch alle in `/opt/iceporge/config/secrets.yaml` definierten Secrets vor dem Push zu GitHub.

**Beispiel-Maskierung:**
- Original: `api_key: "31aa81e7ad1531be39626d24283f727d66a394be59bc3cebdb8a855ce58d16a3"`
- Maskiert: `api_key: "<MASKED_VIRUSTOTAL_KEY>"`

### 3.2 Neue Secrets hinzufügen

Datei `/opt/iceporge/config/secrets.yaml` bearbeiten:

```yaml
secrets:
  - name: "NEW_API_KEY"
    value: "der-geheime-schlüssel"
    description: "Beschreibung des Keys"
    rotate_url: "https://service.com/apikeys"
    config_location: "/pfad/zur/config.yaml"
```

### 3.3 Maskierung testen (Dry-Run)

```bash
/opt/iceporge/sync-to-github.sh --dry-run --verbose
```

---

## 4. Pushover-Benachrichtigungen

### 4.1 Konfiguration

Datei `/opt/iceporge/config/pushover.yaml`:

```yaml
pushover:
  enabled: true
  app_token: "YOUR_APP_TOKEN"
  user_key: "YOUR_USER_KEY"
  priority:
    error: 1      # High
    warning: 0    # Normal
    info: -1      # Low
```

### 4.2 Benachrichtigungs-Events

| Event | Priority | Beschreibung |
|-------|----------|--------------|
| Sync-Fehler | 1 (High) | Push zu GitHub fehlgeschlagen |
| Secrets gefunden | 1 (High) | TruffleHog hat Secrets entdeckt |
| Security-Scan abgeschlossen | 0 (Normal) | Täglicher Scan ohne Funde |

### 4.3 Manueller Test

```bash
# Pushover-Test
PUSHOVER_TOKEN=$(grep "app_token:" /opt/iceporge/config/pushover.yaml | awk '{print $2}' | tr -d '"')
PUSHOVER_USER=$(grep "user_key:" /opt/iceporge/config/pushover.yaml | awk '{print $2}' | tr -d '"')
curl -s --form-string "token=$PUSHOVER_TOKEN" --form-string "user=$PUSHOVER_USER" \
  --form-string "title=Test" --form-string "message=Test-Nachricht" \
  https://api.pushover.net/1/messages.json
```

---

## 5. Konfigurationsdateien

### 5.1 Übersicht

| Datei | Zweck | In Git? |
|-------|-------|---------|
| `/opt/iceporge/config/pushover.yaml` | Pushover-Credentials | NEIN |
| `/opt/iceporge/config/secrets.yaml` | Zu maskierende Secrets | NEIN |
| `/opt/iceporge/config/pushover.example.yaml` | Beispiel-Config | JA |
| `/opt/iceporge/config/secrets.example.yaml` | Beispiel-Config | JA |

### 5.2 Backup

```bash
# Wichtige Configs sichern (verschlüsselt)
tar -czf - /opt/iceporge/config/*.yaml | gpg -c > /backup/iceporge-config-$(date +%Y%m%d).tar.gz.gpg
```

---

## 6. Notfall-Prozeduren

### 6.1 Secret wurde versehentlich auf GitHub gepusht

**Sofortmaßnahmen:**

1. **Secret sofort rotieren** (neuen Key generieren)
   ```bash
   # Siehe /opt/iceporge/config/secrets.yaml für Rotate-URLs
   ```

2. **Git-History bereinigen mit BFG:**
   ```bash
   # Secret-Text in Datei speichern
   echo "geheimer-schlüssel" > /tmp/secrets-to-remove.txt

   # BFG ausführen
   cd /pfad/zum/repo
   bfg --replace-text /tmp/secrets-to-remove.txt --no-blob-protection .

   # Garbage Collection
   git reflog expire --expire=now --all
   git gc --prune=now --aggressive

   # Force Push
   git push origin main --force
   ```

3. **GitHub-Releases löschen** (falls betroffen):
   ```bash
   gh release list --repo icepaule/REPO_NAME
   gh release delete vX.X.X --repo icepaule/REPO_NAME --yes
   ```

4. **Bei verifizierten Secrets: GitHub Support kontaktieren**
   - Verwaiste Commits werden von GitHub gecacht
   - Support-Ticket: https://support.github.com

### 6.2 Security-Scan schlägt fehl

1. **Logs prüfen:**
   ```bash
   tail -100 /var/log/iceporge-security.log
   ```

2. **TruffleHog manuell testen:**
   ```bash
   trufflehog --version
   trufflehog git file:///opt/iceporge --only-verified
   ```

3. **Bei Netzwerkproblemen:**
   ```bash
   # GitHub-Connectivity prüfen
   gh auth status
   ```

### 6.3 Kontakte

| Rolle | Kontakt |
|-------|---------|
| Repository-Owner | info@mpauli.de |
| Security-Alerts | Pushover-Benachrichtigung |

---

## Anhang: API-Key Rotation Checklist

Nach Rotation eines API-Keys:

- [ ] Neuen Key in Anwendungs-Config eintragen
- [ ] `/opt/iceporge/config/secrets.yaml` mit neuem Key aktualisieren
- [ ] Anwendung neu starten / testen
- [ ] Alten Key bei Provider deaktivieren
- [ ] Security-Scan durchführen: `/opt/iceporge/scripts/security-scan.sh --all`

---

**Ende des Dokuments**
