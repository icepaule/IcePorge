# TruffleHog Security Scanner - Betriebshandbuch

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
2. [Installation](#2-installation)
3. [Konfiguration](#3-konfiguration)
4. [Cockpit-Integration](#4-cockpit-integration)
5. [Kommandozeilen-Nutzung](#5-kommandozeilen-nutzung)
6. [Cron-Scheduler](#6-cron-scheduler)
7. [Scan-Typen](#7-scan-typen)
8. [Benachrichtigungen](#8-benachrichtigungen)
9. [Troubleshooting](#9-troubleshooting)
10. [Best Practices](#10-best-practices)

---

## 1. Übersicht

### 1.1 Zweck

Der TruffleHog Security Scanner ist ein automatisiertes System zur Erkennung von Secrets (API-Keys, Passwörter, Tokens, etc.) in:
- GitHub-Repositories (öffentlich und privat)
- Lokalen Git-Repositories
- Dateisystem-Verzeichnissen

### 1.2 Komponenten

| Komponente | Pfad | Beschreibung |
|------------|------|--------------|
| TruffleHog | `/usr/local/bin/trufflehog` | Secret-Scanning-Engine (v3.92.5) |
| Scan-Script | `/opt/iceporge/scripts/security-scan.sh` | Wrapper-Script mit erweiterten Funktionen |
| Ziel-Config | `/opt/iceporge/config/trufflehog-targets.yaml` | Konfigurierbare Scan-Ziele |
| Cockpit-Plugin | `/opt/iceporge-cockpit/security-scanner/` | Web-Interface |
| Log-Datei | `/var/log/iceporge-security.log` | Scan-Protokolle |

### 1.3 Architektur

```
┌─────────────────────────────────────────────────────────────────────┐
│                  TruffleHog Security Scanner                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌─────────────────┐    ┌─────────────────┐    ┌────────────────┐ │
│   │  Cockpit Web UI │    │  Cron Scheduler │    │  CLI Interface │ │
│   │  (Port 9090)    │    │  (0 3 * * *)    │    │  (Bash)        │ │
│   └────────┬────────┘    └────────┬────────┘    └───────┬────────┘ │
│            │                      │                      │          │
│            └──────────────────────┼──────────────────────┘          │
│                                   ▼                                  │
│            ┌──────────────────────────────────────────┐             │
│            │        security-scan.sh                   │             │
│            │  • Target Management                      │             │
│            │  • TruffleHog Wrapper                    │             │
│            │  • Pushover Integration                  │             │
│            └────────────────┬─────────────────────────┘             │
│                             ▼                                        │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │                    TruffleHog Engine                         │   │
│   ├─────────────────┬─────────────────┬─────────────────────────┤   │
│   │  GitHub Scanner │  Git Scanner    │  Filesystem Scanner     │   │
│   │  (API-basiert)  │  (file://)      │  (Verzeichnis)          │   │
│   └─────────────────┴─────────────────┴─────────────────────────┘   │
│                             │                                        │
│                             ▼                                        │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │                    Ausgabe / Reports                         │   │
│   ├─────────────────┬─────────────────┬─────────────────────────┤   │
│   │  Console/Log    │  JSON Reports   │  Pushover Alerts        │   │
│   └─────────────────┴─────────────────┴─────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Installation

### 2.1 TruffleHog installieren

```bash
# Official Installer
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Version prüfen
trufflehog --version
```

### 2.2 Cockpit-Plugin aktivieren

```bash
# Symlink erstellen (falls nicht vorhanden)
ln -sf /opt/iceporge-cockpit/security-scanner /usr/share/cockpit/security-scanner

# Cockpit neu laden
systemctl restart cockpit
```

### 2.3 Berechtigungen setzen

```bash
# Log-Datei
touch /var/log/iceporge-security.log
chmod 666 /var/log/iceporge-security.log

# Script ausführbar
chmod +x /opt/iceporge/scripts/security-scan.sh
```

---

## 3. Konfiguration

### 3.1 Ziel-Konfiguration (trufflehog-targets.yaml)

**Pfad:** `/opt/iceporge/config/trufflehog-targets.yaml`

```yaml
# Globale Einstellungen
settings:
  default_schedule: daily
  notify_on_findings: true
  only_verified: true
  max_concurrent: 2
  report_retention_days: 90

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

### 3.2 Ziel-Typen

| Typ | Beschreibung | Beispiel |
|-----|--------------|----------|
| `github_org` | Gesamte GitHub-Organisation | `icepaule` |
| `github_repo` | Einzelnes GitHub-Repository | `icepaule/IcePorge` |
| `git` | Lokales Git-Repository | `/opt/iceporge` |
| `filesystem` | Beliebiges Verzeichnis | `/etc/nginx` |

### 3.3 Schedule-Optionen

| Schedule | Beschreibung |
|----------|--------------|
| `disabled` | Kein automatischer Scan |
| `hourly` | Stündlich |
| `daily` | Täglich (Standard: 03:00) |
| `weekly` | Wöchentlich (Sonntag 03:00) |
| `monthly` | Monatlich (1. des Monats 03:00) |

---

## 4. Cockpit-Integration

### 4.1 Zugriff

**URL:** `https://<host>:9090/cockpit/@localhost/security-scanner/`

### 4.2 Dashboard

Das Dashboard zeigt:
- Anzahl konfigurierter Ziele (aktiv/inaktiv)
- Letzte Findings
- Cron-Status
- Live Scan-Ausgabe

**Quick Actions:**
- "Lokale Repos scannen" - Scannt alle lokalen Git-Repositories
- "GitHub scannen" - Scannt die icepaule GitHub-Organisation
- "Alle Ziele scannen" - Vollständiger Scan

### 4.3 Ziel-Verwaltung

Im Tab "Scan-Ziele":
- Übersicht aller konfigurierten Ziele
- Aktivieren/Deaktivieren von Zielen
- Einzelne Ziele manuell scannen
- Neue Ziele hinzufügen

### 4.4 Manueller Scan

Im Tab "Manueller Scan":
- Beliebige Repositories scannen (auch externe)
- Scan-Typ auswählen
- Optionen: nur verifizierte Secrets, JSON-Ausgabe

### 4.5 Scheduler

Im Tab "Scheduler":
- Aktuelle Cron-Jobs anzeigen
- Neue Cron-Jobs hinzufügen
- Presets: stündlich, täglich, wöchentlich, monatlich
- Standard-Cron einrichten/entfernen

---

## 5. Kommandozeilen-Nutzung

### 5.1 Basis-Befehle

```bash
# Alle Ziele scannen
/opt/iceporge/scripts/security-scan.sh --all

# Nur lokale Repositories
/opt/iceporge/scripts/security-scan.sh --local

# Nur GitHub
/opt/iceporge/scripts/security-scan.sh --github

# Mit Benachrichtigung
/opt/iceporge/scripts/security-scan.sh --all --notify
```

### 5.2 Einzelnes Ziel scannen

```bash
# GitHub Repository
/opt/iceporge/scripts/security-scan.sh --target icepaule/IcePorge --type github_repo

# GitHub Organisation
/opt/iceporge/scripts/security-scan.sh --target icepaule --type github_org

# Lokales Git Repository
/opt/iceporge/scripts/security-scan.sh --target /opt/iceporge --type git

# Dateisystem
/opt/iceporge/scripts/security-scan.sh --target /etc/nginx --type filesystem
```

### 5.3 Erweiterte Optionen

```bash
# Nur verifizierte Secrets
/opt/iceporge/scripts/security-scan.sh --all --only-verified

# JSON-Ausgabe
/opt/iceporge/scripts/security-scan.sh --all --json

# Report in Datei
/opt/iceporge/scripts/security-scan.sh --all --report /tmp/scan-report.json

# Verbose-Modus
/opt/iceporge/scripts/security-scan.sh --all --verbose

# Ziele aus Konfiguration
/opt/iceporge/scripts/security-scan.sh --from-config
```

### 5.4 TruffleHog direkt nutzen

```bash
# GitHub Repository
trufflehog github --repo=icepaule/IcePorge --only-verified

# GitHub Organisation
trufflehog github --org=icepaule --only-verified

# Lokales Repository
trufflehog git file:///opt/iceporge --only-verified

# Dateisystem
trufflehog filesystem /etc/nginx

# Mit JSON-Ausgabe
trufflehog github --org=icepaule --json > findings.json
```

---

## 6. Cron-Scheduler

### 6.1 Standard-Cron einrichten

```bash
# Täglicher Scan um 03:00 Uhr
(crontab -l 2>/dev/null | grep -v security-scan; echo "0 3 * * * /opt/iceporge/scripts/security-scan.sh --all --notify >> /var/log/iceporge-security.log 2>&1") | crontab -
```

### 6.2 Cron-Beispiele

```bash
# Stündlich (nur lokal)
0 * * * * /opt/iceporge/scripts/security-scan.sh --local >> /var/log/iceporge-security.log 2>&1

# Täglich um 03:00 (alle Ziele + Benachrichtigung)
0 3 * * * /opt/iceporge/scripts/security-scan.sh --all --notify >> /var/log/iceporge-security.log 2>&1

# Wöchentlich Sonntag 03:00 (GitHub)
0 3 * * 0 /opt/iceporge/scripts/security-scan.sh --github --notify >> /var/log/iceporge-security.log 2>&1

# Monatlich am 1. um 03:00 (vollständiger Report)
0 3 1 * * /opt/iceporge/scripts/security-scan.sh --all --notify --report /opt/iceporge/status/monthly-report.json >> /var/log/iceporge-security.log 2>&1
```

### 6.3 Cron-Jobs verwalten

```bash
# Alle Cron-Jobs anzeigen
crontab -l

# Security-Scan Cron-Jobs anzeigen
crontab -l | grep security-scan

# Cron-Jobs entfernen
crontab -l | grep -v security-scan | crontab -
```

---

## 7. Scan-Typen

### 7.1 GitHub-Scan

**Voraussetzungen:**
- GitHub CLI (`gh`) authentifiziert ODER
- GitHub Token in Umgebungsvariable `GITHUB_TOKEN`

**Scannt:**
- Alle Branches
- Commit-History
- Pull Requests (falls zugänglich)

**Empfohlene Optionen:**
```bash
trufflehog github --org=icepaule --only-verified
```

### 7.2 Git-Scan (Lokal)

**Scannt:**
- Vollständige Git-History
- Alle Branches
- Gelöschte Commits (falls erreichbar)

**Format:**
```bash
trufflehog git file:///pfad/zum/repo
```

### 7.3 Filesystem-Scan

**Scannt:**
- Alle Dateien im Verzeichnis (rekursiv)
- Keine Git-History (nur aktuelle Dateien)

**Anwendungsfälle:**
- Konfigurationsverzeichnisse
- Deployment-Artefakte
- Backup-Verzeichnisse

---

## 8. Benachrichtigungen

### 8.1 Pushover-Konfiguration

**Datei:** `/opt/iceporge/config/pushover.yaml`

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

### 8.2 Pushover testen

```bash
/opt/iceporge/scripts/security-scan.sh --test-pushover
```

### 8.3 Benachrichtigungs-Events

| Event | Priority | Beschreibung |
|-------|----------|--------------|
| Verifizierte Secrets gefunden | 1 (High) | Sofortige Benachrichtigung |
| Scan abgeschlossen mit Findings | 0 (Normal) | Zusammenfassung |
| Scan-Fehler | 1 (High) | Fehlermeldung |

---

## 9. Troubleshooting

### 9.1 Häufige Fehler

| Fehler | Ursache | Lösung |
|--------|---------|--------|
| `Permission denied: /var/log/...` | Log nicht schreibbar | `chmod 666 /var/log/iceporge-security.log` |
| `TruffleHog not installed` | Binary fehlt | TruffleHog installieren |
| `GitHub authentication required` | Keine Auth | `gh auth login` oder GITHUB_TOKEN setzen |
| `Cannot determine target type` | Falscher Pfad | `--type` Parameter angeben |

### 9.2 Log-Dateien prüfen

```bash
# Security-Scan Log
tail -100 /var/log/iceporge-security.log

# Nur Fehler
grep -i error /var/log/iceporge-security.log

# Nur Findings
grep -i "found\|secret" /var/log/iceporge-security.log
```

### 9.3 Manueller Debug

```bash
# Verbose-Modus
/opt/iceporge/scripts/security-scan.sh --local --verbose

# TruffleHog direkt mit Debug
trufflehog git file:///opt/iceporge --debug
```

### 9.4 GitHub-Authentifizierung

```bash
# Status prüfen
gh auth status

# Neu authentifizieren
gh auth login

# Token-basiert
export GITHUB_TOKEN="ghp_xxx..."
```

---

## 10. Best Practices

### 10.1 Scan-Strategie

1. **Lokale Repos:** Stündlich scannen (schnell, keine API-Limits)
2. **GitHub:** Täglich scannen (API-Rate-Limits beachten)
3. **Dateisystem:** Wöchentlich (kann langsam sein)

### 10.2 Findings behandeln

1. **Verifizierte Secrets:** Sofort rotieren!
2. **Unbestätigte Findings:** Manuell prüfen
3. **False Positives:** In `.trufflehogignore` aufnehmen

### 10.3 Secret-Rotation nach Fund

1. Neuen Key/Token generieren
2. In Anwendung aktualisieren
3. Alten Key bei Provider deaktivieren
4. Git-History bereinigen (BFG Repo Cleaner)
5. Erneut scannen

### 10.4 Präventiv

- Pre-commit Hooks einrichten
- CI/CD-Pipeline mit TruffleHog
- Secrets in Vault/Secret Manager
- `.gitignore` für sensible Dateien

---

## Anhang: Befehlsreferenz

```bash
# === Scan-Befehle ===
security-scan.sh --all                    # Alle Ziele
security-scan.sh --local                  # Nur lokal
security-scan.sh --github                 # Nur GitHub
security-scan.sh --target X --type Y      # Einzelnes Ziel
security-scan.sh --from-config            # Aus Konfiguration

# === Optionen ===
--only-verified     # Nur verifizierte Secrets
--json              # JSON-Ausgabe
--report FILE       # Report in Datei
--notify            # Pushover-Benachrichtigung
--verbose           # Detaillierte Ausgabe
--test-pushover     # Pushover testen

# === TruffleHog direkt ===
trufflehog github --org=ORG [--only-verified] [--json]
trufflehog github --repo=OWNER/REPO [--only-verified]
trufflehog git file:///PATH [--only-verified]
trufflehog filesystem /PATH [--only-verified]
```

---

**Ende des Dokuments**
