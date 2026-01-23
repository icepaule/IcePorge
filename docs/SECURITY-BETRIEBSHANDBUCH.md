# IcePorge Security-Betriebshandbuch

---

**Dokumenteninformationen**

| Attribut | Wert |
|----------|------|
| Dokumentenversion | 1.1 |
| Erstellungsdatum | 2026-01-23 |
| Letzte Änderung | 2026-01-23 |
| Klassifizierung | INTERN |
| Zielgruppe | IT-Sicherheit / DevSecOps |

---

## Inhaltsverzeichnis

1. [Übersicht](#1-übersicht)
2. [TruffleHog Security-Scanning](#2-trufflehog-security-scanning)
3. [Cockpit Web-Interface](#3-cockpit-web-interface)
4. [Scan-Ziele konfigurieren](#4-scan-ziele-konfigurieren)
5. [Secret-Maskierung beim GitHub-Push](#5-secret-maskierung-beim-github-push)
6. [Pushover-Benachrichtigungen](#6-pushover-benachrichtigungen)
7. [Konfigurationsdateien](#7-konfigurationsdateien)
8. [Notfall-Prozeduren](#8-notfall-prozeduren)

**Weiterführende Dokumentation:** [TRUFFLEHOG-BETRIEBSHANDBUCH.md](TRUFFLEHOG-BETRIEBSHANDBUCH.md)

---

## 1. Übersicht

Das IcePorge Security-System schützt vor versehentlicher Veröffentlichung sensibler Daten (API-Keys, Passwörter, interne IPs) in GitHub-Repositories.

### 1.1 Komponenten

| Komponente | Zweck | Pfad |
|------------|-------|------|
| TruffleHog | Secret-Scanning Engine | `/usr/local/bin/trufflehog` |
| security-scan.sh | Automatisierter Security-Scan | `/opt/iceporge/scripts/security-scan.sh` |
| Cockpit-Plugin | Web-Interface für Scans | `/opt/iceporge-cockpit/security-scanner/` |
| trufflehog-targets.yaml | Konfigurierbare Scan-Ziele | `/opt/iceporge/config/trufflehog-targets.yaml` |
| sync-to-github.sh | GitHub-Sync mit Maskierung | `/opt/iceporge/sync-to-github.sh` |
| secrets.yaml | Zu maskierende Secrets | `/opt/iceporge/config/secrets.yaml` |
| pushover.yaml | Benachrichtigungs-Config | `/opt/iceporge/config/pushover.yaml` |

### 1.2 Architektur-Diagramm

```
┌─────────────────────────────────────────────────────────────────┐
│                 IcePorge Security System                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐ │
│  │  Cockpit Web UI  │  │  Cron Scheduler  │  │  CLI / Bash   │ │
│  │  (Port 9090)     │  │  (0 3 * * *)     │  │               │ │
│  └────────┬─────────┘  └────────┬─────────┘  └───────┬───────┘ │
│           └─────────────────────┼────────────────────┘          │
│                                 ▼                                │
│           ┌─────────────────────────────────────────┐           │
│           │         security-scan.sh                 │           │
│           │  • Target Management (YAML-Config)      │           │
│           │  • TruffleHog Wrapper                   │           │
│           │  • Pushover Integration                 │           │
│           └────────────────┬────────────────────────┘           │
│                            ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                   TruffleHog Engine                       │  │
│  ├────────────────┬────────────────┬────────────────────────┤  │
│  │ GitHub Scanner │  Git Scanner   │  Filesystem Scanner    │  │
│  └────────────────┴────────────────┴────────────────────────┘  │
│                            │                                     │
│           ┌────────────────┼────────────────┐                   │
│           ▼                ▼                ▼                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐    │
│  │ Console/Log │  │ JSON Report │  │ Pushover Alert      │    │
│  └─────────────┘  └─────────────┘  └─────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

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
| `--target TARGET` | Einzelnes Ziel scannen |
| `--type TYPE` | Ziel-Typ: git, github_repo, github_org, filesystem |
| `--from-config` | Ziele aus trufflehog-targets.yaml lesen |
| `--only-verified` | Nur verifizierte Secrets melden |
| `--notify` | Pushover-Benachrichtigung bei Funden |
| `--json` | JSON-Ausgabe |
| `--report FILE` | Report in Datei schreiben |
| `--test-pushover` | Pushover-Test senden |
| `--verbose` | Detaillierte Ausgabe |

**Beispiele:**
```bash
# Einzelnes GitHub-Repository scannen
/opt/iceporge/scripts/security-scan.sh --target icepaule/IcePorge --type github_repo

# Externe Organisation scannen
/opt/iceporge/scripts/security-scan.sh --target external-org --type github_org --only-verified

# Lokales Verzeichnis scannen
/opt/iceporge/scripts/security-scan.sh --target /etc/nginx --type filesystem
```

### 2.4 Cron-Einrichtung (Empfohlen)

```bash
# Täglicher Security-Scan um 03:00 Uhr
0 3 * * * /opt/iceporge/scripts/security-scan.sh --all --notify >> /var/log/iceporge-security.log 2>&1
```

---

## 3. Cockpit Web-Interface

### 3.1 Zugriff

**URL:** `https://<host>:9090/cockpit/@localhost/security-scanner/`

![Security Scanner Cockpit](../iceporge-cockpit/docs/screenshots/security-scanner.png)

### 3.2 Funktionen

| Tab | Funktionen |
|-----|------------|
| **Dashboard** | Quick-Scan-Buttons, Ziel-Statistiken, Live-Ausgabe |
| **Scan-Ziele** | Alle konfigurierten Ziele verwalten, aktivieren/deaktivieren |
| **Manueller Scan** | Beliebige Repositories scannen (auch externe) |
| **Scheduler** | Cron-Jobs grafisch verwalten, Presets |
| **Historie** | Scan-Logs und Berichte einsehen |
| **Einstellungen** | Pushover-Config, Standardwerte |

### 3.3 Quick Actions (Dashboard)

- **Lokale Repos scannen** - Scannt alle lokalen Git-Repositories
- **GitHub scannen** - Scannt die gesamte icepaule GitHub-Organisation
- **Alle Ziele scannen** - Vollständiger Scan aller konfigurierten Ziele

### 3.4 Externe Repositories scannen

Im Tab "Manueller Scan" können beliebige Repositories gescannt werden:

1. Scan-Typ wählen (GitHub Repo, GitHub Org, Lokales Git, Dateisystem)
2. Ziel eingeben (z.B. `microsoft/vscode` oder `/var/www`)
3. Optionen wählen (nur verifizierte Secrets, JSON-Ausgabe)
4. "Scan starten" klicken

---

## 4. Scan-Ziele konfigurieren

### 4.1 Konfigurationsdatei

**Pfad:** `/opt/iceporge/config/trufflehog-targets.yaml`

### 4.2 Ziel-Typen

| Typ | Beschreibung | Beispiel |
|-----|--------------|----------|
| `github_org` | Gesamte GitHub-Organisation | `icepaule` |
| `github_repo` | Einzelnes GitHub-Repository | `icepaule/IcePorge` |
| `git` | Lokales Git-Repository | `/opt/iceporge` |
| `filesystem` | Beliebiges Verzeichnis | `/etc/nginx` |

### 4.3 Beispiel-Konfiguration

```yaml
# Globale Einstellungen
settings:
  default_schedule: daily
  notify_on_findings: true
  only_verified: true

# GitHub Repositories
github_targets:
  - name: "IcePaule Organization"
    type: github_org
    target: "icepaule"
    schedule: daily
    enabled: true
    only_verified: true

  - name: "Externes Projekt"
    type: github_repo
    target: "owner/repo"
    schedule: weekly
    enabled: false

# Lokale Git Repositories
local_targets:
  - name: "IcePorge Local"
    type: git
    target: "/opt/iceporge"
    schedule: hourly
    enabled: true

# Dateisystem-Verzeichnisse
filesystem_targets:
  - name: "CAPE Config"
    type: filesystem
    target: "/opt/CAPEv2/conf"
    schedule: daily
    enabled: true
```

### 4.4 Schedule-Optionen

| Schedule | Beschreibung |
|----------|--------------|
| `disabled` | Kein automatischer Scan |
| `hourly` | Stündlich |
| `daily` | Täglich (03:00 Uhr) |
| `weekly` | Wöchentlich (Sonntag 03:00) |
| `monthly` | Monatlich (1. des Monats) |

### 4.5 Neues Ziel über Cockpit hinzufügen

1. Im Tab "Scan-Ziele" auf "+ Neues Ziel" klicken
2. Formular ausfüllen:
   - Ziel-Typ auswählen
   - Name und Pfad/URL eingeben
   - Schedule wählen
   - Optionen setzen
3. "Hinzufügen" klicken

---

## 5. Secret-Maskierung beim GitHub-Push

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

## 6. Pushover-Benachrichtigungen

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

## 7. Konfigurationsdateien

### 7.1 Übersicht

| Datei | Zweck | In Git? |
|-------|-------|---------|
| `/opt/iceporge/config/pushover.yaml` | Pushover-Credentials | NEIN |
| `/opt/iceporge/config/secrets.yaml` | Zu maskierende Secrets | NEIN |
| `/opt/iceporge/config/trufflehog-targets.yaml` | Scan-Ziele Konfiguration | NEIN |
| `/opt/iceporge/config/pushover.example.yaml` | Beispiel-Config | JA |
| `/opt/iceporge/config/secrets.example.yaml` | Beispiel-Config | JA |

### 7.2 Backup

```bash
# Wichtige Configs sichern (verschlüsselt)
tar -czf - /opt/iceporge/config/*.yaml | gpg -c > /backup/iceporge-config-$(date +%Y%m%d).tar.gz.gpg
```

---

## 8. Notfall-Prozeduren

### 8.1 Secret wurde versehentlich auf GitHub gepusht

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

### 8.2 Security-Scan schlägt fehl

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

### 8.3 Kontakte

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
