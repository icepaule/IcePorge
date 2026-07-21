#!/usr/bin/env python3
"""
IcePorge Web Dashboard
Flask-basierte Web-App für Phishing-Reports und System-Monitoring
"""

import os
import re
import json
import subprocess
import time as _time
from datetime import datetime, timedelta
from pathlib import Path

# Simple in-memory cache for expensive filesystem scans
_cache = {}
def _cached(key, ttl, fn):
    entry = _cache.get(key)
    if entry and (_time.monotonic() - entry[0]) < ttl:
        return entry[1]
    result = fn()
    _cache[key] = (_time.monotonic(), result)
    return result
from flask import Flask, render_template, send_file, jsonify, request, redirect, url_for, Response
from flask_cors import CORS

# LLM Analysis Integration
import sys
import logging
sys.path.insert(0, '/opt/iceporge/ai')
from llm_provider import LLMProviderFactory

logger = logging.getLogger(__name__)


app = Flask(__name__)
CORS(app)


@app.context_processor
def inject_globals():
    """Globale Template-Variablen."""
    return {
        'status': get_system_status(),
        'cape_url': CAPE_PUBLIC_URL,
        'mwdb_url': MWDB_PUBLIC_URL
    }


# Konfiguration
REPORTS_DIR = '/opt/cape-mailer/reports'
CAPE_REPORTS_DIR = '/opt/CAPEv2/storage/analyses'
STATUS_FILE = '/opt/iceporge/status/health.json'
CAPE_URL = 'http://localhost:8000'
MWDB_URL = 'http://localhost:8081'
# Public URLs (shown to users in web UI links)
CAPE_PUBLIC_URL = 'https://cape.thesoc.de'
MWDB_PUBLIC_URL = 'https://mwdb.thesoc.de'


def extract_header_analysis(content: str) -> dict:
    """Extrahiert SMTP-Header-Analyse aus einem Report."""
    analysis = {
        'sender': {},
        'routing_chain': [],
        'authentication': {},
        'security_systems': [],
        'recommendations': [],
        'anomalies': [],
        'origin': {}
    }

    # Sender Info
    sender_match = re.search(r'<td>Von</td><td>([^<]+)</td>', content)
    if sender_match:
        analysis['sender']['email'] = sender_match.group(1)

    display_match = re.search(r'<td>Display Name</td><td>([^<]*)</td>', content)
    if display_match:
        analysis['sender']['display_name'] = display_match.group(1)

    subject_match = re.search(r'<td>Betreff</td><td>([^<]+)</td>', content)
    if subject_match:
        analysis['sender']['subject'] = subject_match.group(1)

    origin_ip_match = re.search(r'<td>Originating IP</td><td>([^<]+)</td>', content)
    if origin_ip_match:
        analysis['origin']['ip'] = origin_ip_match.group(1)

    # Authentication (SPF/DKIM/DMARC)
    spf_match = re.search(r'<td>SPF</td><td[^>]*>([^<]+)</td><td>([^<]*)</td>', content)
    if spf_match:
        analysis['authentication']['spf'] = {
            'result': spf_match.group(1).strip(),
            'source': spf_match.group(2).strip()
        }

    dkim_match = re.search(r'<td>DKIM</td><td[^>]*>([^<]+)</td><td>([^<]*)</td>', content)
    if dkim_match:
        analysis['authentication']['dkim'] = {
            'result': dkim_match.group(1).strip(),
            'source': dkim_match.group(2).strip()
        }

    dmarc_match = re.search(r'<td>DMARC</td><td[^>]*>([^<]+)</td><td>([^<]*)</td>', content)
    if dmarc_match:
        analysis['authentication']['dmarc'] = {
            'result': dmarc_match.group(1).strip(),
            'source': dmarc_match.group(2).strip()
        }

    # Mail Routing Chain
    routing_rows = re.findall(
        r'<tr>\s*<td>(\d+)</td>\s*<td>([^<]*)</td>\s*<td>([^<]*)</td>\s*<td>([^<]*)</td>\s*<td>([^<]*)</td>\s*<td>([^<]*)</td>\s*</tr>',
        content
    )
    for row in routing_rows:
        analysis['routing_chain'].append({
            'hop': int(row[0]),
            'from_server': row[1].strip() or 'N/A',
            'to_server': row[2].strip() or 'N/A',
            'ips': row[3].strip() or 'N/A',
            'tls': row[4].strip() or 'N/A',
            'cipher': row[5].strip() or 'N/A'
        })

    # Security Systems
    security_tags = re.findall(r'<span class="tag">([^<]+)</span>', content)
    # Filter nur Security-relevante Tags
    security_systems = [t for t in security_tags if t.lower() in [
        'sophos', 'barracuda', 'cisco_esa', 'microsoft_atp', 'spamassassin',
        'postfix', 'exim', 'proofpoint', 'mimecast', 'fortimail', 'google',
        'sendmail', 'exchange', 'mailgun', 'rspamd', 'clamav'
    ]]
    analysis['security_systems'] = list(set(security_systems))

    # Security Recommendations
    rec_matches = re.findall(
        r'<div class="recommendation"[^>]*>.*?<strong[^>]*>([^<]+)</strong>.*?<p><strong>Issue:</strong>\s*([^<]+)</p>.*?<p><strong>Recommendation:</strong>\s*([^<]+)</p>',
        content, re.DOTALL
    )
    for rec in rec_matches:
        analysis['recommendations'].append({
            'component': rec[0].strip(),
            'issue': rec[1].strip(),
            'recommendation': rec[2].strip()
        })

    # TLS Status
    tls_match = re.search(r'<strong>TLS Encryption:</strong>\s*(✅|❌)\s*(\w+)', content)
    if tls_match:
        analysis['origin']['tls'] = tls_match.group(2)

    arc_match = re.search(r'<strong>ARC Headers:</strong>\s*(✅|❌)\s*(\w+)', content)
    if arc_match:
        analysis['origin']['arc'] = arc_match.group(2)

    # Security Issues
    issues_match = re.search(r'<strong>⚠️ Security Issues:</strong>\s*([^<]+)</p>', content)
    if issues_match:
        analysis['anomalies'].append(issues_match.group(1).strip())

    # Enhanced Analysis (wenn vorhanden)
    if 'Erweiterte Forensische Analyse' in content:
        analysis['enhanced'] = True

        # Geolocation
        geo_matches = re.findall(
            r'<td>(\d+\.\d+\.\d+\.\d+)</td>\s*<td>([^<]+)\s*\(([A-Z]{2})\)</td>\s*<td>([^<]+)</td>\s*<td[^>]*>([^<]+)</td>',
            content
        )
        analysis['geolocation'] = []
        for geo in geo_matches:
            analysis['geolocation'].append({
                'ip': geo[0],
                'country': geo[1].strip(),
                'country_code': geo[2],
                'city': geo[3].strip(),
                'isp': geo[4].strip() if len(geo) > 4 else 'Unknown'
            })

        # Brand Impersonation
        brand_match = re.search(r'Gefälschte Marke</td><td[^>]*>([^<]+)</td>', content)
        if brand_match:
            analysis['brand_impersonation'] = brand_match.group(1)

    return analysis


def get_phishing_reports(days=30, verdict_filter=None, min_score=0):
    """Lädt alle Phishing-Reports. Gecacht für 60s."""
    return _cached(f'phishing_{days}_{verdict_filter}_{min_score}', 60,
                   lambda: _fetch_phishing_reports(days, verdict_filter, min_score))

def _fetch_phishing_reports(days=30, verdict_filter=None, min_score=0):
    """Interne Implementierung ohne Cache."""
    reports = []
    cutoff = datetime.now() - timedelta(days=days)

    for report_file in Path(REPORTS_DIR).glob('phishing_*.html'):
        try:
            mtime = datetime.fromtimestamp(report_file.stat().st_mtime)
            if mtime < cutoff:
                continue

            report_id = report_file.stem.replace('phishing_', '')
            verdict, score, sender, subject, enhanced = 'unknown', 0, 'Unknown', 'Unknown', False

            # Bevorzuge JSON-Metadaten (zuverlässiger als HTML-Parsing)
            json_file = report_file.with_suffix('.json')
            if json_file.exists():
                try:
                    meta = json.loads(json_file.read_text(encoding='utf-8'))
                    verdict  = meta.get('verdict', 'unknown')
                    score    = float(meta.get('score', 0))
                    sender   = meta.get('sender', 'Unknown')
                    subject  = (meta.get('subject') or 'Unknown')[:80]
                    enhanced = False
                except Exception:
                    pass
            else:
                # Fallback: HTML per Regex parsen
                content = report_file.read_text(encoding='utf-8', errors='replace')
                m = re.search(r'Verdict:\s*(\w+)', content)
                if m:
                    verdict = m.group(1).lower()
                m = re.search(r'<span class="score"[^>]*>(\d+)/100</span>', content)
                if m:
                    score = int(m.group(1))
                m = re.search(r'<td>Von</td><td>([^<]+)</td>', content)
                if m:
                    sender = m.group(1)
                m = re.search(r'<td>Betreff</td><td>([^<]+)</td>', content)
                if m:
                    subject = m.group(1)[:80]
                enhanced = 'Erweiterte Forensische Analyse' in content

            # Filter anwenden
            if verdict_filter and verdict != verdict_filter.lower():
                continue
            if score < min_score:
                continue

            reports.append({
                'id': report_id,
                'filename': report_file.name,
                'timestamp': mtime.isoformat(),
                'date': mtime.strftime('%Y-%m-%d %H:%M'),
                'verdict': verdict,
                'score': score,
                'sender': sender,
                'subject': subject,
                'enhanced': enhanced,
            })

        except Exception:
            continue

    # Nach Datum sortieren (neueste zuerst)
    reports.sort(key=lambda x: x['timestamp'], reverse=True)
    return reports


def get_cape_analyses(days=7, limit=20):
    """Lädt die neuesten CAPE-Analysen. Gecacht für 60s, nur top-N IDs."""
    return _cached(f'cape_analyses_{days}_{limit}', 60, lambda: _fetch_cape_analyses(days, limit))

CAPE_DB_PATH = '/opt/CAPEv2/db/cuckoo.db'

_RE_MALSCORE = re.compile(r'"malscore"\s*:\s*([\d.]+)')
_RE_SHA256 = re.compile(r'"sha256"\s*:\s*"([a-f0-9]{64})"')
_RE_SIGNAME = re.compile(r'"name"\s*:\s*"([^"]+)"')

def _read_report_metadata(path):
    """Liest malscore, sha256 und Signaturennamen ohne vollständiges JSON-Parse.
    Strategie: Signaturennamen aus erstem 512kB (signatures beginnt bei ~1487),
               SHA256 aus erstem 200kB, malscore aus letztem 2MB."""
    malscore = 0.0
    sha = ''
    sig_names = []
    try:
        fsize = os.path.getsize(path)
        with open(path, 'rb') as f:
            # Erstes 512kB: Signaturennamen + SHA256
            head = f.read(524288).decode('utf-8', errors='replace')
            sha_m = _RE_SHA256.search(head)
            if sha_m:
                sha = sha_m.group(1)
            # Signaturennamen: erster Block enthält signatures-Sektion
            sig_names = _RE_SIGNAME.findall(head)[:20]

            # Letztes 2MB: malscore
            tail_size = min(2097152, fsize)
            f.seek(max(0, fsize - tail_size))
            tail = f.read().decode('utf-8', errors='replace')
            ms_m = _RE_MALSCORE.search(tail)
            if ms_m:
                malscore = float(ms_m.group(1))
    except Exception:
        pass
    return malscore, sha, sig_names

def _fetch_cape_analyses(days=7, limit=20):
    """Holt CAPE-Analysen aus SQLite-DB (schnell) + malscore aus report.json."""
    import sqlite3
    analyses = []
    try:
        conn = sqlite3.connect(f'file:{CAPE_DB_PATH}?mode=ro', uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("""
            SELECT t.id, t.target, t.completed_on, t.signatures_total, t.signatures_alert
            FROM tasks t
            WHERE t.status = 'reported'
              AND t.completed_on >= datetime('now', ? || ' days')
            ORDER BY t.id DESC
            LIMIT ?
        """, (f'-{days}', limit * 2))
        rows = c.fetchall()
        conn.close()
    except Exception:
        rows = []

    for row in rows:
        if len(analyses) >= limit:
            break
        try:
            task_id = row['id']
            completed = row['completed_on'] or ''
            filename = os.path.basename(row['target'] or 'Unknown')
            sigs = row['signatures_alert'] or row['signatures_total'] or 0

            # Malscore + SHA + Signaturennamen aus report.json (schneller Tail-Read)
            report_file = os.path.join(CAPE_REPORTS_DIR, str(task_id), 'reports', 'report.json')
            malscore = 0.0
            sha = ''
            sig_names = []
            if os.path.exists(report_file):
                try:
                    malscore, sha, sig_names = _read_report_metadata(report_file)
                    sigs = len(sig_names) if sig_names else sigs
                    if sig_names and (not filename or filename == 'Unknown'):
                        # Versuche Dateinamen aus tail zu lesen
                        pass
                except Exception:
                    pass

            date_str = completed[:16].replace('T', ' ') if completed else ''
            analyses.append({
                'id': task_id,
                'timestamp': completed,
                'date': date_str,
                'filename': filename,
                'malscore': malscore,
                'sha256': sha[:16] + '...' if sha else '',
                'sha256_full': sha,
                'signatures': sigs,
                'signature_names': sig_names[:10]
            })
        except Exception:
            continue

    # Fallback: wenn DB keine Ergebnisse (z.B. zu alter Zeitraum), top-IDs aus Filesystem
    if not analyses:
        analyses = _fetch_cape_analyses_filesystem(days, limit)

    return analyses


def _fetch_cape_analyses_filesystem(days=7, limit=20):
    """Fallback: neueste Analysen direkt aus dem Dateisystem."""
    cutoff = datetime.now() - timedelta(days=days)
    base_str = CAPE_REPORTS_DIR
    if not os.path.isdir(base_str):
        return []
    try:
        names = sorted([n for n in os.listdir(base_str) if n.isdigit()], key=int, reverse=True)
        names = names[:limit * 4]
    except Exception:
        return []
    analyses = []
    for name in names:
        if len(analyses) >= limit:
            break
        try:
            report_file = os.path.join(base_str, name, 'reports', 'report.json')
            if not os.path.exists(report_file):
                continue
            mtime = datetime.fromtimestamp(os.path.getmtime(report_file))
            if mtime < cutoff:
                continue
            with open(report_file, 'r') as f:
                data = json.load(f)
            target = data.get('target', {}).get('file', {})
            sha = target.get('sha256', '')
            analyses.append({
                'id': int(name),
                'timestamp': mtime.isoformat(),
                'date': mtime.strftime('%Y-%m-%d %H:%M'),
                'filename': target.get('name', 'Unknown'),
                'malscore': float(data.get('malscore', 0)),
                'sha256': sha[:16] + '...' if sha else '',
                'signatures': len(data.get('signatures', []))
            })
        except Exception:
            continue
    return analyses


def _fetch_cape_analyses_by_id(task_id: int) -> list:
    """Lädt eine einzelne Analyse direkt per ID — umgeht Limit und Cache."""
    import sqlite3 as _sqlite3
    try:
        conn = _sqlite3.connect(f'file:{CAPE_DB_PATH}?mode=ro', uri=True, timeout=5)
        conn.row_factory = _sqlite3.Row
        c = conn.cursor()
        c.execute("""
            SELECT t.id, t.target, t.completed_on, t.signatures_total, t.signatures_alert
            FROM tasks t
            WHERE t.id = ? AND t.status = 'reported'
        """, (task_id,))
        row = c.fetchone()
        conn.close()
    except Exception:
        row = None

    if not row:
        return []

    try:
        completed = row['completed_on'] or ''
        filename = os.path.basename(row['target'] or 'Unknown')
        sigs = row['signatures_alert'] or row['signatures_total'] or 0
        report_file = os.path.join(CAPE_REPORTS_DIR, str(task_id), 'reports', 'report.json')
        malscore, sha, sig_names = 0.0, '', []
        if os.path.exists(report_file):
            try:
                malscore, sha, sig_names = _read_report_metadata(report_file)
                sigs = len(sig_names) if sig_names else sigs
            except Exception:
                pass
        date_str = completed[:16].replace('T', ' ') if completed else ''
        return [{
            'id': task_id,
            'timestamp': completed,
            'date': date_str,
            'filename': filename,
            'malscore': malscore,
            'sha256': sha[:16] + '...' if sha else '',
            'sha256_full': sha,
            'signatures': sigs,
            'signature_names': sig_names[:10],
        }]
    except Exception:
        return []


def get_system_status():
    """Lädt Systemstatus aus health.json (alle 5 Min durch collect-status.sh aktualisiert)."""
    return _cached('system_status', 60, _fetch_system_status)

def _fetch_system_status():
    try:
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return {'overall_status': 'unknown', 'components': {}}


def get_statistics():
    """Berechnet Statistiken. Gecacht für 120s."""
    return _cached('statistics', 120, _fetch_statistics)

def _fetch_statistics():
    """Berechnet Statistiken aus Phishing-Reports und CAPE-Analysen."""
    reports = get_phishing_reports(days=30)

    # Phishing-Report-Statistiken
    phishing = {
        'total_reports': len(reports),
        'malicious': sum(1 for r in reports if r['verdict'] == 'malicious'),
        'suspicious': sum(1 for r in reports if r['verdict'] == 'suspicious'),
        'clean': sum(1 for r in reports if r['verdict'] in ['clean', 'likely_clean']),
        'avg_score': sum(r['score'] for r in reports) / len(reports) if reports else 0,
        'enhanced_count': sum(1 for r in reports if r['enhanced']),
    }

    # CAPE-Statistiken aus SQLite (schnell, nur Zähler)
    cape = {'total_30d': 0, 'total_7d': 0, 'high': 0, 'medium': 0, 'low': 0,
            'total_all': 0, 'failed': 0, 'avg_sigs': 0.0}
    try:
        import sqlite3
        conn = sqlite3.connect(f'file:{CAPE_DB_PATH}?mode=ro', uri=True, timeout=5)
        c = conn.cursor()
        c.execute("""SELECT
            SUM(CASE WHEN status='reported' AND completed_on >= datetime('now','-30 days') THEN 1 ELSE 0 END) as total_30d,
            SUM(CASE WHEN status='reported' AND completed_on >= datetime('now','-7 days') THEN 1 ELSE 0 END) as d7,
            SUM(CASE WHEN status IN ('failed_analysis','failed_processing','failed_reporting') THEN 1 ELSE 0 END) as failed,
            ROUND(AVG(CASE WHEN status='reported' AND completed_on >= datetime('now','-30 days')
                           THEN signatures_total ELSE NULL END), 1) as avg_sigs
          FROM tasks""")
        row = c.fetchone()
        conn.close()
        if row:
            cape['total_30d'] = row[0] or 0
            cape['total_7d'] = row[1] or 0
            cape['failed'] = row[2] or 0
            cape['avg_sigs'] = row[3] or 0.0
    except Exception:
        pass

    # Malscore-Verteilung aus lite.json (Sampling der letzten 100 Tasks)
    try:
        import re as _re
        _re_ms = re.compile(r'"malscore"\s*:\s*([\d.]+)')
        dirs = sorted([d for d in os.listdir(CAPE_REPORTS_DIR) if d.isdigit()], key=int, reverse=True)[:100]
        high = medium = low = 0
        for d in dirs:
            p = os.path.join(CAPE_REPORTS_DIR, d, 'reports', 'lite.json')
            if not os.path.exists(p):
                continue
            try:
                with open(p, 'rb') as f:
                    chunk = f.read(65536).decode('utf-8', errors='replace')
                m = _re_ms.search(chunk)
                if m:
                    ms = float(m.group(1))
                    if ms >= 7:
                        high += 1
                    elif ms >= 4:
                        medium += 1
                    else:
                        low += 1
            except Exception:
                continue
        cape['high'] = high
        cape['medium'] = medium
        cape['low'] = low
    except Exception:
        pass

    stats = {**phishing, 'cape': cape, 'by_day': {}}

    # Reports pro Tag (Phishing)
    for report in reports:
        day = report['date'][:10]
        if day not in stats['by_day']:
            stats['by_day'][day] = {'total': 0, 'malicious': 0}
        stats['by_day'][day]['total'] += 1
        if report['verdict'] == 'malicious':
            stats['by_day'][day]['malicious'] += 1

    return stats


# ==================== ROUTES ====================

@app.route('/')
def index():
    """Dashboard Startseite."""
    stats = get_statistics()
    status = get_system_status()
    recent_reports = get_phishing_reports(days=7)[:10]
    recent_analyses = get_cape_analyses(days=7)[:5]

    return render_template('index.html',
                           stats=stats,
                           status=status,
                           recent_reports=recent_reports,
                           recent_analyses=recent_analyses,
                           cape_url=CAPE_PUBLIC_URL,
                           mwdb_url=MWDB_PUBLIC_URL)


# Initialize LLM Provider
def load_config_env():
    """Load config.env into environment if not already set."""
    config_file = '/opt/iceporge/install/config.env'
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    value = value.strip('"').strip("'")
                    if key not in os.environ:
                        os.environ[key] = value

def init_llm():
    """Initialize LLM provider from config.env."""
    try:
        load_config_env()
        factory = LLMProviderFactory()
        ai_backend = os.getenv('AI_BACKEND', 'bedrock')
        
        if ai_backend == 'bedrock':
            region = os.getenv('AWS_REGION', 'eu-central-1')
            model_id = os.getenv('BEDROCK_MODEL_ID', 'eu.anthropic.claude-sonnet-4-5-20250929-v1:0')
            max_tokens = int(os.getenv('BEDROCK_MAX_TOKENS', '4096'))
            factory.register_bedrock(region=region, model_id=model_id, max_tokens=max_tokens, primary=True)
            logger.info(f"LLM initialized: Bedrock {model_id}")
        elif ai_backend == 'ollama':
            api_url = os.getenv('OLLAMA_API_URL', 'http://localhost:11434')
            model = os.getenv('OLLAMA_MODEL', 'llama3.1:8b')
            factory.register_ollama(api_url=api_url, model=model, primary=True)
            logger.info(f"LLM initialized: Ollama {model}")
        return factory.get_provider()
    except Exception as e:
        logger.error(f"LLM init failed: {e}")
        return None

llm_provider = init_llm()



@app.route('/reports')
def reports_list():
    """Report-Liste mit Filterung."""
    days = request.args.get('days', 30, type=int)
    verdict = request.args.get('verdict', None)
    min_score = request.args.get('min_score', 0, type=int)

    reports = get_phishing_reports(days=days, verdict_filter=verdict, min_score=min_score)

    return render_template('reports.html',
                           reports=reports,
                           days=days,
                           verdict=verdict,
                           min_score=min_score)


@app.route('/report/<report_id>')
def view_report(report_id):
    """Einzelnen Report anzeigen (Original HTML)."""
    report_file = Path(REPORTS_DIR) / f'phishing_{report_id}.html'

    if report_file.exists():
        return send_file(report_file)
    else:
        return "Report nicht gefunden", 404


@app.route('/report/<report_id>/analysis')
def view_report_analysis(report_id):
    """Detaillierte Analyse eines Reports — zeigt den vollständigen HTML-Report."""
    report_file = Path(REPORTS_DIR) / f'phishing_{report_id}.html'
    json_file   = Path(REPORTS_DIR) / f'phishing_{report_id}.json'

    if not report_file.exists():
        return "Report nicht gefunden", 404

    # Metadaten aus JSON
    meta = {}
    if json_file.exists():
        try:
            meta = json.loads(json_file.read_text(encoding='utf-8'))
        except Exception:
            pass

    # HTML-Report-Inhalt direkt einbetten
    report_html = report_file.read_text(encoding='utf-8')
    # Nur Body-Inhalt extrahieren damit base.html korrekt umschließt
    body_match = re.search(r'<body[^>]*>(.*?)</body>', report_html, re.DOTALL | re.IGNORECASE)
    report_body = body_match.group(1) if body_match else report_html

    return render_template('report_analysis.html',
                           report_id=report_id,
                           meta=meta,
                           report_body=report_body)


@app.route('/api/report/<report_id>/headers')
def api_report_headers(report_id):
    """API: Header-Analyse als JSON."""
    report_file = Path(REPORTS_DIR) / f'phishing_{report_id}.html'

    if not report_file.exists():
        return jsonify({'error': 'Report nicht gefunden'}), 404

    with open(report_file, 'r', encoding='utf-8') as f:
        content = f.read()

    return jsonify(extract_header_analysis(content))


def _strip_emoji_for_pdf(t: str) -> str:
    """Ersetzt Emoji durch Textäquivalente oder entfernt sie für PDF-Ausgabe."""
    replacements = [
        ('🔴', '[!]'), ('🟠', '[~]'), ('🟡', '[~]'), ('🟢', '[OK]'),
        ('⚠️', '[!]'), ('⚠', '[!]'), ('✅', '[OK]'), ('❌', '[FAIL]'),
        ('✓', '[OK]'), ('✗', '[FAIL]'), ('🔬', ''), ('🛡️', ''), ('🛡', ''),
        ('📋', ''), ('📎', ''), ('📧', ''), ('🌍', ''), ('🔐', ''), ('🔒', ''),
        ('🔑', ''), ('⬇', ''), ('🔄', ''), ('🤖', ''), ('🧠', ''), ('💀', ''),
        ('☠️', ''), ('📊', ''), ('📈', ''), ('📉', ''), ('🏴', ''), ('🚨', '[!]'),
        ('​', ''), ('‌', ''), ('‍', ''),
    ]
    for emoji, repl in replacements:
        t = t.replace(emoji, repl)
    t = re.sub(r'[\U00010000-\U0010ffff]', '', t)
    t = re.sub(r'[☀-⟿⬀-⯿]', '', t)
    return t


def _dark_to_light_html(html: str) -> str:
    """Konvertiert Dark-Theme-HTML zu druckbarem Light-Theme via Inline-Replacement."""
    _color_map = [
        ('background:#0f172a',                         'background:#ffffff'),
        ('background: #0f172a',                        'background:#ffffff'),
        ('background:#1e293b',                         'background:#f8fafc'),
        ('background: #1e293b',                        'background:#f8fafc'),
        ('background:#1e3a5f,#1e293b',                 'background:#1e3a5f,#1e4080'),
        ('background:linear-gradient(135deg,#1e3a5f,#1e293b)', 'background:#1e3a5f'),
        ('background:#334155',                         'background:#e2e8f0'),
        ('background: #334155',                        'background:#e2e8f0'),
        ('background:rgba(0,0,0,0.2)',                 'background:#f1f5f9'),
        ('background: rgba(0,0,0,0.2)',                'background:#f1f5f9'),
        ('border:1px solid #0f172a',                   'border:1px solid #dee2e6'),
        ('border: 1px solid #0f172a',                  'border:1px solid #dee2e6'),
        ('border:1px solid #334155',                   'border:1px solid #cbd5e1'),
        ('border: 1px solid #334155',                  'border:1px solid #cbd5e1'),
        ('border-bottom:1px solid #334155',            'border-bottom:1px solid #cbd5e1'),
        ('border-bottom:1px solid #0f172a',            'border-bottom:1px solid #dee2e6'),
        ('color:#e2e8f0',  'color:#1a1a2e'),
        ('color: #e2e8f0', 'color:#1a1a2e'),
        ('color:#94a3b8',  'color:#374151'),
        ('color: #94a3b8', 'color:#374151'),
        ('color:#64748b',  'color:#4b5563'),
        ('color: #64748b', 'color:#4b5563'),
        ('color:#475569',  'color:#374151'),
        ('color: #475569', 'color:#374151'),
        ('color:#fbbf24',  'color:#b45309'),
        ('color: #fbbf24', 'color:#b45309'),
        ('color:#0f172a',  'color:#1a1a2e'),
        ('color: #0f172a', 'color:#1a1a2e'),
    ]
    for old, new in _color_map:
        html = html.replace(old, new)
    return html


@app.route('/report/<report_id>/pdf')
def download_report_pdf(report_id):
    """Phishing-Report als PDF herunterladen."""
    report_file = Path(REPORTS_DIR) / f'phishing_{report_id}.html'
    if not report_file.exists():
        return "Report nicht gefunden", 404
    try:
        from weasyprint import HTML as WP_HTML, CSS
        raw = report_file.read_text(encoding='utf-8')
        html_content = _dark_to_light_html(_strip_emoji_for_pdf(raw))
        pdf_css = CSS(string='@page { margin: 1.5cm; size: A4; }')
        pdf_bytes = WP_HTML(string=html_content, base_url='/').write_pdf(stylesheets=[pdf_css])
        safe_id = re.sub(r'[^\w\-]', '_', report_id)[:50]
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename="phishing_{safe_id}.pdf"'}
        )
    except Exception as e:
        logger.error(f'PDF-Generierung fehlgeschlagen: {e}')
        return f"PDF-Generierung fehlgeschlagen: {e}", 500


@app.route('/cape/<int:analysis_id>/pdf')
def download_cape_pdf(analysis_id):
    """CAPE-Analyse als PDF herunterladen (LLM-Analyse + Metadaten)."""
    analysis_dir = Path(f'/opt/CAPEv2/storage/analyses/{analysis_id}')
    llm_cache = analysis_dir / 'reports' / 'llm_analysis.json'
    consolidated_cache = analysis_dir / 'reports' / 'consolidated_analysis.json'
    report_file = analysis_dir / 'reports' / 'report.json'
    if not analysis_dir.exists():
        return "Analyse nicht gefunden", 404

    use_consolidated = request.args.get('consolidated', '0') == '1' and consolidated_cache.exists()
    active_cache = consolidated_cache if use_consolidated else llm_cache

    try:
        from weasyprint import HTML as WP_HTML, CSS
        # LLM-Analyse laden
        llm_text = ''
        filename = f'Task {analysis_id}'
        malscore = 0.0
        child_analyses = []
        is_consolidated = False
        if active_cache.exists():
            cached = json.loads(active_cache.read_text(encoding='utf-8'))
            llm_text = cached.get('llm_analysis', '')
            filename = cached.get('filename', filename)
            malscore = cached.get('malscore', 0.0)
            child_analyses = cached.get('child_analyses', [])
            is_consolidated = cached.get('consolidated', False) or use_consolidated
        elif report_file.exists():
            llm_text = '(Analyse noch nicht durchgeführt — bitte zuerst Tiefenanalyse starten)'

        # Markdown → HTML für PDF
        import markdown as _md
        def md2html(t):
            if not t: return '<p>Keine Analyse verfügbar.</p>'
            t = _strip_emoji_for_pdf(t)
            return _md.markdown(t, extensions=['tables', 'fenced_code'])

        score_col = '#c0392b' if malscore >= 7 else ('#e67e22' if malscore >= 4 else '#27ae60')
        consolidated_badge = '<span style="display:inline-block;background:#5b21b6;color:white;padding:0.15rem 0.6rem;border-radius:4px;font-size:0.8rem;font-weight:700;margin-left:0.75rem;">KONSOLIDIERT</span>' if is_consolidated else ''

        # Child analyses HTML sections — Texte von Disk nachladen (im Cache nur id/filename/malscore)
        child_sections_html = ''
        if child_analyses:
            child_sections_html = '<hr style="margin:2rem 0;border-color:#dee2e6;"><h2>Payload-Analysen (' + str(len(child_analyses)) + ' Child Tasks)</h2>'
            for idx, child in enumerate(child_analyses, 1):
                c_ms = child.get('malscore', 0.0)
                c_col = '#c0392b' if c_ms >= 7 else ('#e67e22' if c_ms >= 4 else '#27ae60')
                c_fn = child.get('filename', f'Payload {idx}')
                c_id = child.get('id', child.get('task_id', '?'))
                # LLM-Text von Disk laden wenn nicht direkt im child-dict
                c_text = child.get('llm_analysis', '')
                if not c_text and c_id and c_id != '?':
                    child_llm_path = Path(f'/opt/CAPEv2/storage/analyses/{c_id}/reports/llm_analysis.json')
                    if child_llm_path.exists():
                        try:
                            child_data = json.loads(child_llm_path.read_text(encoding='utf-8'))
                            c_text = child_data.get('llm_analysis', '')
                            if not c_ms:
                                c_ms = child_data.get('malscore', 0.0)
                                c_col = '#c0392b' if c_ms >= 7 else ('#e67e22' if c_ms >= 4 else '#27ae60')
                        except Exception:
                            pass
                if not c_text:
                    c_text = '(keine Analyse verfügbar)'
                child_sections_html += f'''
<div style="border:1px solid #dee2e6;border-radius:6px;padding:1rem;margin-bottom:1.5rem;border-left:4px solid {c_col};">
<div style="display:flex;gap:1.5rem;margin-bottom:0.75rem;flex-wrap:wrap;">
  <span><strong>Payload {idx}</strong> &mdash; CAPE Task #{c_id}</span>
  <span>Datei: <strong>{c_fn}</strong></span>
  <span>Score: <strong style="color:{c_col};">{c_ms:.1f}/10</strong></span>
</div>
{md2html(c_text)}
</div>'''

        html_content = f'''<!DOCTYPE html>
<html lang="de"><head><meta charset="UTF-8">
<title>{"Konsolidierter Bericht" if is_consolidated else "Tiefenanalyse"} &mdash; {filename}</title>
<style>
  body {{ font-family: "DejaVu Sans", "Liberation Sans", Arial, sans-serif; font-size: 11pt; color: #1a1a2e; margin: 0; padding: 2rem; }}
  h1 {{ color: #1e3a5f; border-bottom: 2px solid #1e3a5f; padding-bottom: 0.5rem; }}
  h2 {{ color: #1e3a5f; margin-top: 1.5rem; border-bottom: 1px solid #dee2e6; padding-bottom: 0.3rem; }}
  h3, h4 {{ color: #374151; }}
  .meta {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 1rem; margin: 1rem 0; }}
  .meta td {{ padding: 0.3rem 0.75rem; }}
  .score {{ font-size: 2rem; font-weight: 800; color: {score_col}; }}
  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.85rem; font-weight: 700; background: {score_col}; color: white; }}
  table {{ border-collapse: collapse; width: 100%; margin: 0.5rem 0; }}
  td, th {{ border: 1px solid #dee2e6; padding: 4px 8px; }}
  th {{ background: #f1f5f9; font-weight: 600; }}
  code {{ background: #f4f4f8; padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.9em; }}
  li {{ margin: 0.2rem 0; }}
  .footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #e2e8f0; color: #6b7280; font-size: 0.8rem; text-align: center; }}
</style>
</head><body>
<h1>{"Konsolidierter Sicherheitsbericht" if is_consolidated else "Tiefenanalyse"}{consolidated_badge}</h1>
<div class="meta">
<table style="border:none;">
  <tr><td style="border:none;color:#6b7280;width:140px;">Datei</td><td style="border:none;"><strong>{filename}</strong></td></tr>
  <tr><td style="border:none;color:#6b7280;">CAPE Task</td><td style="border:none;">#{analysis_id}</td></tr>
  <tr><td style="border:none;color:#6b7280;">Malscore</td><td style="border:none;"><span class="score">{malscore:.1f}</span><span style="color:#6b7280;">/10</span></td></tr>
  {'<tr><td style="border:none;color:#6b7280;">Enthält Payloads</td><td style="border:none;"><strong>' + str(len(child_analyses)) + ' analysierte Payloads</strong></td></tr>' if child_analyses else ''}
  <tr><td style="border:none;color:#6b7280;">Generiert</td><td style="border:none;">{datetime.now().strftime("%d.%m.%Y %H:%M")}</td></tr>
</table>
</div>
{md2html(llm_text)}
{child_sections_html}
<div class="footer">IcePorge Security Platform &bull; AWS Bedrock Claude &bull; CAPE Sandbox v2</div>
</body></html>'''

        pdf_css = CSS(string='@page { margin: 1.5cm; size: A4; }')
        pdf_bytes = WP_HTML(string=html_content).write_pdf(stylesheets=[pdf_css])
        safe_name = re.sub(r'[^\w\-]', '_', filename)[:40]
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename="cape_{analysis_id}_{safe_name}.pdf"'}
        )
    except Exception as e:
        logger.error(f'CAPE PDF-Generierung fehlgeschlagen: {e}')
        return f"PDF-Generierung fehlgeschlagen: {e}", 500


@app.route('/cape')
def cape_analyses():
    """CAPE-Analysen Liste mit Suche, Filter und Paginierung."""
    days  = request.args.get('days',  30,   type=int)
    limit = request.args.get('limit', 100,  type=int)
    search = request.args.get('q', '').strip()
    min_score = request.args.get('min_score', 0, type=float)

    limit = min(max(limit, 10), 500)  # 10–500
    days  = min(max(days,   1), 365)

    # Bei reiner ID-Suche: direkt aus DB holen (umgeht Limit/Cache)
    if search and search.strip().isdigit():
        task_id = int(search.strip())
        analyses = _fetch_cape_analyses_by_id(task_id)
    else:
        analyses = get_cape_analyses(days=days, limit=limit)
        # Client-seitige Filterung (Dateiname/SHA/Malscore)
        if search or min_score > 0:
            sq = search.lower()
            analyses = [
                a for a in analyses
                if (not sq or sq in a['filename'].lower()
                           or sq in a.get('sha256_full','').lower())
                and a['malscore'] >= min_score
            ]

    return render_template('cape.html',
                           analyses=analyses,
                           cape_url=CAPE_PUBLIC_URL,
                           days=days,
                           limit=limit,
                           search=search,
                           min_score=min_score,
                           total=len(analyses))


@app.route('/cape/<int:analysis_id>')
def cape_redirect(analysis_id):
    """Redirect zu CAPE Web."""
    return redirect(f'{CAPE_PUBLIC_URL}/analysis/{analysis_id}/')




@app.route('/cape/<int:analysis_id>/llm')
def cape_llm_analysis(analysis_id):
    """LLM-Analyse — liefert gecachte Version wenn vorhanden, ?refresh=1 erzwingt Neuanalyse."""
    analysis_dir = Path(CAPE_REPORTS_DIR) / str(analysis_id)
    report_file = analysis_dir / 'reports' / 'report.json'
    llm_cache_file = analysis_dir / 'reports' / 'llm_analysis.json'

    if not report_file.exists():
        return jsonify({'error': 'Report not found'}), 404

    refresh = request.args.get('refresh', '0') == '1'

    # Gecachte Analyse zurückgeben wenn vorhanden und kein Refresh gewünscht
    consolidated_cache_file = analysis_dir / 'reports' / 'consolidated_analysis.json'
    if not refresh and llm_cache_file.exists():
        try:
            with open(llm_cache_file, 'r') as f:
                cached = json.load(f)
            cached['cached'] = True
            cached['consolidated_available'] = consolidated_cache_file.exists()
            return jsonify(cached)
        except Exception:
            pass  # Bei Lesefehler neu erzeugen

    if llm_provider is None:
        return jsonify({'error': 'LLM not initialized', 'analysis_id': analysis_id}), 503

    try:
        # Dateiname aus DB
        import sqlite3 as _sqlite3
        filename_hint = ''
        try:
            conn = _sqlite3.connect(f'file:{CAPE_DB_PATH}?mode=ro', uri=True, timeout=3)
            row = conn.execute('SELECT target FROM tasks WHERE id=?', (analysis_id,)).fetchone()
            conn.close()
            if row and row[0]:
                filename_hint = os.path.basename(row[0])
        except Exception:
            pass

        from cape_analyzer import analyze_cape_report
        result = analyze_cape_report(str(analysis_dir), llm_provider, filename_hint)
        result['analysis_id'] = analysis_id

        # Cache auf Disk speichern
        try:
            with open(llm_cache_file, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not save LLM cache for {analysis_id}: {e}")

        return jsonify(result)

    except Exception as e:
        logger.error(f"LLM analysis failed for {analysis_id}: {e}")
        return jsonify({'error': str(e)}), 500


_consolidated_jobs = {}  # analysis_id -> {'status': running|done|error, 'result': ..., 'error': ...}


@app.route('/cape/<int:analysis_id>/consolidated', methods=['GET'])
def cape_consolidated_analysis(analysis_id):
    """Konsolidierter Bericht: GET pollt Status / gibt Cache zurück, POST startet Analyse."""
    analysis_dir = Path(CAPE_REPORTS_DIR) / str(analysis_id)
    report_file = analysis_dir / 'reports' / 'report.json'
    consolidated_cache = analysis_dir / 'reports' / 'consolidated_analysis.json'

    if not report_file.exists():
        return jsonify({'error': 'Report not found'}), 404

    refresh = request.args.get('refresh', '0') == '1'

    # Wenn gerade ein Job läuft, Status zurückgeben
    job = _consolidated_jobs.get(analysis_id)
    if job and job['status'] == 'running':
        return jsonify({'status': 'running', 'message': 'Konsolidierung läuft...'})
    if job and job['status'] == 'error':
        del _consolidated_jobs[analysis_id]
        return jsonify({'error': job['error']}), 500

    # Cache zurückgeben wenn aktuell
    if not refresh and consolidated_cache.exists():
        try:
            cached = json.loads(consolidated_cache.read_text(encoding='utf-8'))
            # Prüfe ob Cache noch aktuell ist (mind. so viele Children wie beim letzten Build)
            try:
                import importlib, cape_analyzer as _ca_check
                importlib.reload(_ca_check)
                current_children = _ca_check.collect_child_analyses(str(analysis_id))
                cached_child_count = len(cached.get('child_analyses', []))
                if cached_child_count < len(current_children):
                    logger.info(f'Konsolidierung veraltet: {cached_child_count} vs {len(current_children)} — neu starten')
                    # Cache löschen und neu bauen via POST-Logik
                    consolidated_cache.unlink(missing_ok=True)
                else:
                    cached['cached'] = True
                    return jsonify(cached)
            except Exception:
                cached['cached'] = True
                return jsonify(cached)
        except Exception:
            pass

    return jsonify({'status': 'not_started', 'message': 'Noch nicht gestartet — POST zum Starten'})


@app.route('/cape/<int:analysis_id>/consolidated', methods=['POST'])
def cape_consolidated_start(analysis_id):
    """Startet Konsolidierungsanalyse im Hintergrund."""
    analysis_dir = Path(CAPE_REPORTS_DIR) / str(analysis_id)
    report_file = analysis_dir / 'reports' / 'report.json'
    consolidated_cache = analysis_dir / 'reports' / 'consolidated_analysis.json'

    if not report_file.exists():
        return jsonify({'error': 'Report not found'}), 404
    if llm_provider is None:
        return jsonify({'error': 'LLM not initialized'}), 503

    # Bereits laufend?
    job = _consolidated_jobs.get(analysis_id)
    if job and job['status'] == 'running':
        return jsonify({'status': 'running', 'message': 'Läuft bereits'})

    refresh = request.args.get('refresh', '0') == '1'
    if refresh and consolidated_cache.exists():
        consolidated_cache.unlink(missing_ok=True)

    _consolidated_jobs[analysis_id] = {'status': 'running'}

    def _run_consolidated():
        try:
            import sqlite3 as _sq, importlib, cape_analyzer as _ca
            importlib.reload(_ca)
            filename_hint = ''
            try:
                conn = _sq.connect(f'file:{CAPE_DB_PATH}?mode=ro', uri=True, timeout=3)
                row = conn.execute('SELECT target FROM tasks WHERE id=?', (analysis_id,)).fetchone()
                conn.close()
                if row and row[0]:
                    filename_hint = os.path.basename(row[0])
            except Exception:
                pass

            children = _ca.collect_child_analyses(str(analysis_id))
            if not children:
                _consolidated_jobs[analysis_id] = {'status': 'error', 'error': 'Keine Child-Analysen — zuerst Payloads analysieren'}
                return

            result = _ca.analyze_cape_report(str(analysis_dir), llm_provider, filename_hint, consolidated=True)
            result['analysis_id'] = analysis_id
            consolidated_cache.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
            _consolidated_jobs[analysis_id] = {'status': 'done', 'result': result}
        except Exception as e:
            logger.error(f'Consolidated analysis failed for {analysis_id}: {e}')
            _consolidated_jobs[analysis_id] = {'status': 'error', 'error': str(e)}

    import threading as _t
    _t.Thread(target=_run_consolidated, daemon=True).start()
    return jsonify({'status': 'running', 'message': 'Konsolidierung gestartet'})


@app.route('/cape/<int:analysis_id>/consolidated/pdf')
def cape_consolidated_pdf(analysis_id):
    """Konsolidierten Bericht als PDF — nutzt /cape/<id>/pdf?consolidated=1."""
    consolidated_cache = Path(CAPE_REPORTS_DIR) / str(analysis_id) / 'reports' / 'consolidated_analysis.json'
    if not consolidated_cache.exists():
        return "Kein konsolidierter Bericht vorhanden — bitte zuerst 'Konsolidierter Bericht erstellen' klicken", 404
    return redirect(f'/cape/{analysis_id}/pdf?consolidated=1')


@app.route('/status')
def system_status():
    """Systemstatus Seite."""
    status = get_system_status()

    # Cache leeren damit frischer Status geladen wird
    _cache.pop('system_status', None)
    status = get_system_status()

    return render_template('status.html', status=status)



@app.route('/cape/<int:analysis_id>/payloads')
def cape_payloads(analysis_id):
    """Liefert extrahierte CAPE-Payloads inkl. ILSpy/CAPE-Status aus report.json."""
    report_file = Path(CAPE_REPORTS_DIR) / str(analysis_id) / 'reports' / 'report.json'
    llm_cache = Path(CAPE_REPORTS_DIR) / str(analysis_id) / 'reports' / 'llm_analysis.json'
    if not report_file.exists():
        return jsonify({'error': 'Report nicht gefunden'}), 404
    try:
        report = json.loads(report_file.read_text(encoding='utf-8'))
        raw_payloads = (report.get('CAPE', {}).get('payloads', [])
                        or report.get('cape', {}).get('payloads', []) or [])

        # Child-Task-IDs aus Parent-Cache laden
        child_task_ids = []
        if llm_cache.exists():
            try:
                cached = json.loads(llm_cache.read_text(encoding='utf-8'))
                child_task_ids = cached.get('child_task_ids', [])
            except Exception:
                pass

        # Pro Child-Task-ID prüfen ob llm_analysis.json existiert
        child_analyzed = set()
        for cid in child_task_ids:
            cfile = Path(CAPE_REPORTS_DIR) / str(cid) / 'reports' / 'llm_analysis.json'
            if cfile.exists():
                child_analyzed.add(cid)

        payloads = []
        for i, p in enumerate(raw_payloads):
            sha256 = p.get('sha256', '')
            fpath = Path(CAPE_REPORTS_DIR) / str(analysis_id) / 'CAPE' / sha256
            ptype = p.get('type', '')
            is_dotnet = ('dll' in ptype.lower() or '.net' in ptype.lower() or
                         'mono' in ptype.lower() or 'assembly' in ptype.lower())

            # ILSpy-Ergebnis-Datei prüfen
            ilspy_result = fpath.parent / f'{sha256[:16]}_ilspy.json'
            ilspy_status = 'done' if ilspy_result.exists() else 'none'

            # Zugehöriger Child-Task
            child_task_id = child_task_ids[i] if i < len(child_task_ids) else None
            child_status = 'analyzed' if child_task_id in child_analyzed else ('pending' if child_task_id else 'none')

            payloads.append({
                'sha256': sha256,
                'name': p.get('name', sha256[:16]),
                'type': ptype,
                'size': p.get('size', 0),
                'path': str(fpath) if fpath.exists() else None,
                'is_dotnet': is_dotnet,
                'ilspy_status': ilspy_status,
                'child_task_id': child_task_id,
                'child_status': child_status,
            })

        analyzed_count = sum(1 for p in payloads if p['child_status'] == 'analyzed')
        return jsonify({
            'payloads': payloads,
            'count': len(payloads),
            'analyzed_count': analyzed_count,
            'child_task_ids': child_task_ids,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/cape/<int:analysis_id>/ilspy-payload', methods=['POST'])
def cape_ilspy_payload(analysis_id):
    """Dekompiliert einen .NET-Payload mit ILSpy und analysiert ihn per KI."""
    sha256 = request.json.get('sha256', '') if request.is_json else request.form.get('sha256', '')
    if not sha256:
        return jsonify({'error': 'Kein SHA256 angegeben'}), 400
    payload_path = Path(CAPE_REPORTS_DIR) / str(analysis_id) / 'CAPE' / sha256
    if not payload_path.exists():
        return jsonify({'error': 'Payload nicht gefunden'}), 404

    result_file = payload_path.parent / f'{sha256[:16]}_ilspy.json'
    if result_file.exists():
        return jsonify({'success': True, 'cached': True, 'sha256': sha256,
                        'result_file': str(result_file)})

    import subprocess, threading

    def _run_ilspy():
        try:
            ilspy_bin = '/root/.dotnet/tools/ilspycmd'
            env = {'PATH': '/root/.dotnet/tools:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin',
                   'HOME': '/root', 'DOTNET_ROOT': '/usr/lib/dotnet'}
            result = subprocess.run(
                [ilspy_bin, '--no-dead-code', '--no-dead-stores', str(payload_path)],
                capture_output=True, text=True, timeout=120, env=env
            )
            code = result.stdout or ''
            err = result.stderr or ''
            lines = code.splitlines()
            # Erste 1500 Zeilen nehmen (für KI-Analyse reicht das)
            snippet = '\n'.join(lines[:1500]) if len(lines) > 1500 else code

            # KI-Analyse des dekompilierten Codes
            ai_summary = ''
            if llm_provider and snippet.strip():
                try:
                    prompt = (
                        f"Analysiere diesen dekompilierten .NET-Code aus einer Malware-Sandbox-Analyse.\n"
                        f"SHA256: {sha256[:20]}...\n\n"
                        f"Antworte auf Deutsch. Untersuche:\n"
                        f"1. Hauptfunktionalität und Zweck\n"
                        f"2. Verdächtige Funktionen/Methoden (C2, Persistenz, Datendiebstahl, etc.)\n"
                        f"3. Verschleierungstechniken\n"
                        f"4. Externe Referenzen (IPs, URLs, Registry-Keys, Dateipfade)\n"
                        f"5. Bewertung: Gefährlichkeit 0-10\n\n"
                        f"```csharp\n{snippet[:8000]}\n```"
                    )
                    ai_summary = llm_provider.analyze(prompt)
                except Exception as e:
                    ai_summary = f'KI-Analyse fehlgeschlagen: {e}'

            out = {
                'sha256': sha256,
                'lines': len(lines),
                'snippet_lines': min(len(lines), 1500),
                'code': snippet,
                'ai_summary': ai_summary,
                'error': err[:500] if err and not code else '',
                'success': bool(code.strip()),
            }
            result_file.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
            logger.info(f'ILSpy abgeschlossen: {sha256[:20]} ({len(lines)} Zeilen)')
        except subprocess.TimeoutExpired:
            result_file.write_text(json.dumps({'error': 'Timeout nach 120s', 'success': False, 'sha256': sha256}),
                                    encoding='utf-8')
        except Exception as e:
            logger.error(f'ILSpy fehlgeschlagen: {e}')
            result_file.write_text(json.dumps({'error': str(e), 'success': False, 'sha256': sha256}),
                                    encoding='utf-8')

    threading.Thread(target=_run_ilspy, daemon=True).start()
    return jsonify({'success': True, 'started': True, 'sha256': sha256, 'result_file': str(result_file)})


@app.route('/cape/<int:analysis_id>/ilspy-result/<sha256_prefix>')
def cape_ilspy_result(analysis_id, sha256_prefix):
    """Liefert ILSpy-Ergebnis wenn fertig."""
    result_file = Path(CAPE_REPORTS_DIR) / str(analysis_id) / 'CAPE' / f'{sha256_prefix[:16]}_ilspy.json'
    if not result_file.exists():
        return jsonify({'ready': False})
    try:
        data = json.loads(result_file.read_text(encoding='utf-8'))
        data['ready'] = True
        return jsonify(data)
    except Exception as e:
        return jsonify({'ready': False, 'error': str(e)})


@app.route('/cape/<int:analysis_id>/auto-analyse-payloads', methods=['POST'])
def cape_auto_analyse_payloads(analysis_id):
    """Startet automatisch CAPE-Resubmit + ILSpy für alle HOCH/MITTEL-Payloads."""
    report_file = Path(CAPE_REPORTS_DIR) / str(analysis_id) / 'reports' / 'report.json'
    llm_cache = Path(CAPE_REPORTS_DIR) / str(analysis_id) / 'reports' / 'llm_analysis.json'
    if not report_file.exists():
        return jsonify({'error': 'Report nicht gefunden'}), 404

    try:
        report = json.loads(report_file.read_text(encoding='utf-8'))
        raw_payloads = (report.get('CAPE', {}).get('payloads', [])
                        or report.get('cape', {}).get('payloads', []) or [])

        child_task_ids = []
        if llm_cache.exists():
            try:
                cached = json.loads(llm_cache.read_text(encoding='utf-8'))
                child_task_ids = cached.get('child_task_ids', [])
            except Exception:
                pass

        import requests as _req, subprocess, threading

        results = []
        for i, p in enumerate(raw_payloads):
            sha256 = p.get('sha256', '')
            payload_path = Path(CAPE_REPORTS_DIR) / str(analysis_id) / 'CAPE' / sha256
            if not payload_path.exists():
                continue
            ptype = p.get('type', '')
            is_dotnet = ('dll' in ptype.lower() or '.net' in ptype.lower() or
                         'mono' in ptype.lower() or 'assembly' in ptype.lower())

            entry = {'sha256': sha256[:20], 'cape': None, 'ilspy': None}

            # CAPE Resubmit (wenn noch kein Child-Task für diesen Index)
            if i >= len(child_task_ids):
                try:
                    with open(payload_path, 'rb') as f:
                        resp = _req.post(
                            'http://localhost:8000/apiv2/tasks/create/file/',
                            files={'file': (sha256[:20] + '.bin', f, 'application/octet-stream')},
                            data={'tags': 'win11', 'comment': f'Auto-Resubmit payload from CAPE #{analysis_id}'},
                            timeout=30
                        )
                    data = resp.json()
                    task_ids = data.get('data', {}).get('task_ids', [])
                    new_id = task_ids[0] if task_ids else None
                    if new_id:
                        child_task_ids.append(new_id)
                        entry['cape'] = new_id
                except Exception as e:
                    entry['cape_error'] = str(e)
            else:
                entry['cape'] = child_task_ids[i]
                entry['cape_existing'] = True

            # ILSpy für .NET-Payloads
            if is_dotnet:
                result_file = payload_path.parent / f'{sha256[:16]}_ilspy.json'
                if result_file.exists():
                    entry['ilspy'] = 'cached'
                else:
                    entry['ilspy'] = 'started'
                    sha256_copy = sha256
                    result_file_copy = result_file
                    payload_copy = payload_path

                    def _ilspy_bg(pp=payload_copy, rf=result_file_copy, sh=sha256_copy):
                        try:
                            ilspy_bin = '/root/.dotnet/tools/ilspycmd'
                            env = {'PATH': '/root/.dotnet/tools:/usr/local/bin:/usr/bin:/bin',
                                   'HOME': '/root', 'DOTNET_ROOT': '/usr/lib/dotnet'}
                            r = subprocess.run([ilspy_bin, '--no-dead-code', str(pp)],
                                               capture_output=True, text=True, timeout=120, env=env)
                            code = r.stdout or ''
                            lines = code.splitlines()
                            snippet = '\n'.join(lines[:1500])
                            ai_summary = ''
                            if llm_provider and snippet.strip():
                                try:
                                    prompt = (
                                        f"Analysiere diesen dekompilierten .NET-Code (Malware-Sandbox).\n"
                                        f"SHA256: {sh[:20]}...\n\nAntworte auf Deutsch.\n"
                                        f"1. Hauptfunktionalität\n2. Verdächtige Funktionen\n"
                                        f"3. Externe Referenzen (IPs/URLs/Pfade)\n4. Gefährlichkeit 0-10\n\n"
                                        f"```csharp\n{snippet[:8000]}\n```"
                                    )
                                    ai_summary = llm_provider.analyze(prompt)
                                except Exception as e:
                                    ai_summary = f'KI fehlgeschlagen: {e}'
                            rf.write_text(json.dumps({'sha256': sh, 'lines': len(lines),
                                                       'code': snippet, 'ai_summary': ai_summary,
                                                       'success': bool(code.strip())},
                                                      ensure_ascii=False, indent=2), encoding='utf-8')
                        except Exception as e:
                            rf.write_text(json.dumps({'error': str(e), 'success': False, 'sha256': sh}),
                                           encoding='utf-8')

                    threading.Thread(target=_ilspy_bg, daemon=True).start()

            results.append(entry)

        # Child-IDs in llm_analysis.json speichern
        if llm_cache.exists() and child_task_ids:
            try:
                cached = json.loads(llm_cache.read_text(encoding='utf-8'))
                cached['child_task_ids'] = child_task_ids
                llm_cache.write_text(json.dumps(cached, ensure_ascii=False, indent=2), encoding='utf-8')
            except Exception:
                pass

        # LLM-Analyse für alle Child-Tasks mit CAPE-Report aber ohne llm_analysis im Hintergrund starten
        import sys as _sys2
        _sem2 = threading.Semaphore(3)

        def _analyse_one_child(cid, parent_id):
            with _sem2:
                child_dir = Path(CAPE_REPORTS_DIR) / str(cid)
                child_llm = child_dir / 'reports' / 'llm_analysis.json'
                child_report = child_dir / 'reports' / 'report.json'
                if not child_report.exists() or child_llm.exists():
                    return
                _sys2.path.insert(0, '/opt/iceporge/ai')
                try:
                    import importlib
                    import cape_analyzer as _ca2
                    importlib.reload(_ca2)
                    result = _ca2.analyze_cape_report(str(child_dir), llm_provider, '',
                                                       skip_ghidra=True)
                    result['analysis_id'] = cid
                    result['parent_id'] = parent_id
                    child_llm.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
                    logger.info(f'Child #{cid} LLM fertig, malscore={result.get("malscore",0):.1f}')
                except Exception as e:
                    logger.error(f'Child #{cid} LLM fehlgeschlagen: {e}')

        for cid in child_task_ids:
            threading.Thread(target=_analyse_one_child, args=(cid, analysis_id), daemon=True).start()

        return jsonify({'success': True, 'results': results, 'total': len(results),
                        'llm_queue': len(child_task_ids)})
    except Exception as e:
        logger.error(f'Auto-Analyse-Payloads fehlgeschlagen: {e}')
        return jsonify({'error': str(e)}), 500


@app.route('/cape/<int:analysis_id>/resubmit-payload', methods=['POST'])
def cape_resubmit_payload(analysis_id):
    """Resubmittiert einen extrahierten Payload an CAPE."""
    sha256 = request.json.get('sha256', '') if request.is_json else request.form.get('sha256', '')
    if not sha256 or len(sha256) != 64:
        return jsonify({'error': 'Ungültiger SHA256'}), 400
    payload_path = Path(CAPE_REPORTS_DIR) / str(analysis_id) / 'CAPE' / sha256
    if not payload_path.exists():
        # Auch in procdump suchen
        payload_path = Path(CAPE_REPORTS_DIR) / str(analysis_id) / 'procdump' / sha256
    if not payload_path.exists():
        return jsonify({'error': f'Payload nicht gefunden: {sha256[:16]}...'}), 404
    try:
        import requests as _req
        with open(payload_path, 'rb') as f:
            resp = _req.post(
                'http://localhost:8000/apiv2/tasks/create/file/',
                files={'file': (sha256[:20] + '.bin', f, 'application/octet-stream')},
                data={'tags': 'win11', 'comment': f'Resubmit payload from CAPE #{analysis_id}'},
                timeout=30
            )
        data = resp.json()
        if data.get('error'):
            return jsonify({'error': str(data.get('error_value', data))}), 500
        task_ids = data.get('data', {}).get('task_ids', [])
        new_id = task_ids[0] if task_ids else None

        # Child-Task-ID in Parent's llm_analysis.json registrieren
        if new_id:
            parent_cache = Path(CAPE_REPORTS_DIR) / str(analysis_id) / 'reports' / 'llm_analysis.json'
            if parent_cache.exists():
                try:
                    cached = json.loads(parent_cache.read_text(encoding='utf-8'))
                    child_ids = cached.get('child_task_ids', [])
                    if new_id not in child_ids:
                        child_ids.append(new_id)
                    cached['child_task_ids'] = child_ids
                    parent_cache.write_text(json.dumps(cached, ensure_ascii=False, indent=2),
                                            encoding='utf-8')
                except Exception as e:
                    logger.warning(f'Child-Task-Registrierung fehlgeschlagen: {e}')

        return jsonify({'success': True, 'task_id': new_id, 'sha256': sha256})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/cape/<int:analysis_id>/child-status')
def cape_child_status(analysis_id):
    """Liefert Analyse-Status aller Child-Tasks für Polling."""
    llm_cache = Path(CAPE_REPORTS_DIR) / str(analysis_id) / 'reports' / 'llm_analysis.json'
    if not llm_cache.exists():
        return jsonify({'child_task_ids': [], 'analyzed': [], 'pending': [], 'all_done': False})
    try:
        cached = json.loads(llm_cache.read_text(encoding='utf-8'))
        child_ids = cached.get('child_task_ids', [])
        analyzed = []
        pending = []
        for cid in child_ids:
            cfile = Path(CAPE_REPORTS_DIR) / str(cid) / 'reports' / 'llm_analysis.json'
            cfile_report = Path(CAPE_REPORTS_DIR) / str(cid) / 'reports' / 'report.json'
            if cfile.exists():
                try:
                    cd = json.loads(cfile.read_text(encoding='utf-8'))
                    analyzed.append({'id': cid, 'malscore': cd.get('malscore', 0),
                                     'filename': cd.get('filename', '')})
                except Exception:
                    analyzed.append({'id': cid})
            elif cfile_report.exists():
                pending.append({'id': cid, 'cape_done': True, 'llm_pending': True})
            else:
                pending.append({'id': cid, 'cape_done': False})
        return jsonify({
            'child_task_ids': child_ids,
            'analyzed': analyzed,
            'pending': pending,
            'analyzed_count': len(analyzed),
            'total': len(child_ids),
            'all_done': len(analyzed) == len(child_ids) and len(child_ids) > 0,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/cape/<int:analysis_id>/trigger-child-llm', methods=['POST'])
def cape_trigger_child_llm(analysis_id):
    """Startet LLM-Analyse für alle Child-Tasks die CAPE-Report aber keine LLM-Analyse haben."""
    llm_cache = Path(CAPE_REPORTS_DIR) / str(analysis_id) / 'reports' / 'llm_analysis.json'
    if not llm_cache.exists():
        return jsonify({'error': 'Parent LLM-Cache nicht gefunden'}), 404
    try:
        cached = json.loads(llm_cache.read_text(encoding='utf-8'))
        child_ids = cached.get('child_task_ids', [])
        queued = []
        for cid in child_ids:
            child_dir = Path(CAPE_REPORTS_DIR) / str(cid)
            child_llm = child_dir / 'reports' / 'llm_analysis.json'
            child_report = child_dir / 'reports' / 'report.json'
            if child_report.exists() and not child_llm.exists():
                queued.append(cid)

        if not queued:
            return jsonify({'success': True, 'queued': 0, 'message': 'Alle bereits analysiert'})

        import sys as _sys, threading as _threading
        # Semaphore: max 3 parallele Bedrock-Calls gleichzeitig
        _sem = _threading.Semaphore(3)

        def _analyse_one(cid, parent_id):
            with _sem:
                child_dir = Path(CAPE_REPORTS_DIR) / str(cid)
                child_llm = child_dir / 'reports' / 'llm_analysis.json'
                if child_llm.exists():
                    return
                _sys.path.insert(0, '/opt/iceporge/ai')
                try:
                    import importlib
                    import cape_analyzer as _ca_mod
                    importlib.reload(_ca_mod)
                    logger.info(f'Trigger-LLM Child #{cid} (Parent #{parent_id})')
                    res = _ca_mod.analyze_cape_report(str(child_dir), llm_provider, '',
                                                       skip_ghidra=True)
                    res['analysis_id'] = cid
                    res['parent_id'] = parent_id
                    child_llm.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding='utf-8')
                    logger.info(f'Child #{cid} fertig, malscore={res.get("malscore",0):.1f}')
                except Exception as e:
                    logger.error(f'Child #{cid} fehlgeschlagen: {e}')

        for cid in queued:
            _threading.Thread(target=_analyse_one, args=(cid, analysis_id), daemon=True).start()

        return jsonify({'success': True, 'queued': len(queued), 'ids': queued})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/cape/<int:analysis_id>/ghidra-payload', methods=['POST'])
def cape_ghidra_payload(analysis_id):
    """Startet Ghidra-Analyse für einen extrahierten Payload."""
    sha256 = request.json.get('sha256', '') if request.is_json else request.form.get('sha256', '')
    if not sha256:
        return jsonify({'error': 'Kein SHA256 angegeben'}), 400
    payload_path = Path(CAPE_REPORTS_DIR) / str(analysis_id) / 'CAPE' / sha256
    if not payload_path.exists():
        return jsonify({'error': 'Payload nicht gefunden'}), 404
    try:
        import subprocess, threading
        ghidra_script = Path('/opt/iceporge/ai/ghidra_analysis.py')
        result_file = payload_path.parent / f'{sha256[:16]}_ghidra.json'

        def _run_ghidra():
            try:
                subprocess.run(
                    ['/opt/iceporge/venv/bin/python', str(ghidra_script),
                     str(payload_path), str(result_file)],
                    timeout=600, capture_output=True
                )
            except Exception as e:
                logger.error(f'Ghidra-Payload-Analyse fehlgeschlagen: {e}')

        threading.Thread(target=_run_ghidra, daemon=True).start()
        return jsonify({'success': True, 'message': 'Ghidra-Analyse gestartet', 'sha256': sha256,
                        'result_file': str(result_file)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/cape/<int:analysis_id>/forensic-report')
def cape_forensic_report(analysis_id):
    """Generate forensic report for regulators."""
    analysis_dir = Path(CAPE_REPORTS_DIR) / str(analysis_id)
    report_file = analysis_dir / 'reports' / 'report.json'

    if not report_file.exists():
        return jsonify({'error': 'Not found'}), 404

    with open(report_file) as f:
        cape_data = json.load(f)

    target = cape_data.get('target', {}).get('file', {})
    info = cape_data.get('info', {})
    signatures = cape_data.get('signatures', [])
    network = cape_data.get('network', {})
    malscore = cape_data.get('malscore', 0)

    threat_level = "CRITICAL" if malscore >= 9 else ("HIGH" if malscore >= 7 else ("MEDIUM" if malscore >= 4 else "LOW"))
    verdict = "MALICIOUS" if malscore >= 7 else ("SUSPICIOUS" if malscore >= 4 else "LIKELY BENIGN")

    return jsonify({
        "report_metadata": {
            "report_id": f"CAPE-{analysis_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "generation_timestamp": datetime.now().isoformat(),
            "analysis_id": analysis_id,
            "classification": "CONFIDENTIAL - INTERNAL USE ONLY"
        },
        "executive_summary": {
            "threat_level": threat_level,
            "malscore": f"{malscore}/10",
            "verdict": verdict,
            "file_name": target.get('name', 'unknown'),
            "file_type": target.get('type', 'unknown'),
            "signature_hits": len(signatures),
            "ai_assessment": "LLM analysis available separately"
        },
        "evidence_chain": {
            "sample_hashes": {
                "md5": target.get('md5', 'N/A'),
                "sha1": target.get('sha1', 'N/A'),
                "sha256": target.get('sha256', 'N/A'),
                "sha512": target.get('sha512', 'N/A')
            },
            "submission_timestamp": info.get('started', 'N/A'),
            "analysis_duration_seconds": info.get('duration', 0)
        },
        "indicators_of_compromise": {
            "network_iocs": list(set([d.get('request', '') for d in network.get('dns', [])]))[:30]
        },
        "compliance_notes": {
            "data_classification": "CONFIDENTIAL",
            "retention_period": "90 days minimum (regulatory requirement)",
            "regulatory_framework": "BSI IT-Grundschutz, DSGVO Art. 32"
        }
    })
@app.route('/phishing/upload', methods=['GET', 'POST'])
def phishing_upload():
    """Upload einer .msg/.eml Datei zur Phishing-Analyse (ersetzt Mail-Eingang)."""
    if request.method == 'GET':
        return render_template('phishing_upload.html', error=request.args.get('error'))

    uploaded = request.files.get('msgfile')
    if not uploaded or not uploaded.filename:
        return render_template('phishing_upload.html', error='Keine Datei ausgewählt.')

    filename = uploaded.filename.lower()
    if not (filename.endswith('.msg') or filename.endswith('.eml')):
        return render_template('phishing_upload.html', error='Nur .msg und .eml Dateien erlaubt.')

    import tempfile, threading
    raw_bytes = uploaded.read()
    orig_name = uploaded.filename

    # In Thread auslagern damit HTTP sofort antwortet
    job_id = _time.strftime('%Y%m%d_%H%M%S') + '_' + re.sub(r'[^\w]', '_', orig_name)[:30]
    job_status = {'id': job_id, 'filename': orig_name, 'status': 'processing'}
    _phishing_jobs[job_id] = job_status
    _job_write(job_id, job_status)

    def _run():
        try:
            sys.path.insert(0, '/opt/iceporge/components/IcePorge-CAPE-Mailer')
            from cape_mailer_bedrock import CAPEMailer
            import email as _email

            mailer = CAPEMailer('/opt/iceporge/components/IcePorge-CAPE-Mailer/config.yaml')

            extra_headers = {}
            if orig_name.lower().endswith('.msg'):
                # .msg via extract-msg in RFC822 konvertieren
                import extract_msg as _emsg
                with tempfile.NamedTemporaryFile(suffix='.msg', delete=False) as tmp:
                    tmp.write(raw_bytes)
                    tmp_path = tmp.name
                try:
                    m = _emsg.openMsg(tmp_path)
                    subject = m.subject or '(kein Betreff)'
                    sender  = m.sender  or 'upload@iceporge.local'
                    body    = m.body    or ''
                    # .msg hat keine SMTP-Header — transport headers wenn vorhanden
                    if hasattr(m, 'header') and m.header:
                        hdr_obj = m.header
                        # extract-msg liefert ein email.message.Message-Objekt
                        import email.message as _emsg_mod
                        if isinstance(hdr_obj, _emsg_mod.Message):
                            for k, v in hdr_obj.items():
                                extra_headers[k] = v
                        elif isinstance(hdr_obj, str):
                            for line in hdr_obj.splitlines():
                                if ':' in line:
                                    hk, _, hv = line.partition(':')
                                    extra_headers[hk.strip()] = hv.strip()
                    # Anhänge extrahieren
                    attachments = []
                    for att in (m.attachments or []):
                        try:
                            data = att.data
                            name = att.longFilename or att.shortFilename or 'attachment'
                            ctype = 'application/octet-stream'
                            attachments.append((name, data, ctype))
                        except Exception:
                            pass
                    m.close()
                finally:
                    os.unlink(tmp_path)
            else:
                # .eml direkt als RFC822
                msg_obj = _email.message_from_bytes(raw_bytes)
                subject = mailer._decode_header(msg_obj.get('Subject', '(kein Betreff)'))
                sender  = mailer._decode_header(msg_obj.get('From', 'upload@iceporge.local'))
                attachments = mailer._extract_attachments(msg_obj)
                # Sicherheitsrelevante Header für KI-Analyse
                for hdr in ('From', 'Reply-To', 'Return-Path', 'Received', 'X-Originating-IP',
                            'Authentication-Results', 'DKIM-Signature', 'X-Spam-Status',
                            'X-Mailer', 'X-Forwarded-To', 'Message-ID'):
                    val = msg_obj.get(hdr)
                    if val:
                        extra_headers[hdr] = mailer._decode_header(val)
                # Alle Received-Header
                received = msg_obj.get_all('Received') or []
                if received:
                    extra_headers['Received'] = '\n  '.join(received[:5])
                body = ''
                if msg_obj.is_multipart():
                    for part in msg_obj.walk():
                        if part.get_content_type() == 'text/plain':
                            body = part.get_payload(decode=True).decode('utf-8', errors='replace')
                            break
                else:
                    body = msg_obj.get_payload(decode=True).decode('utf-8', errors='replace') if msg_obj.get_payload(decode=True) else ''

            job_status['subject'] = subject
            job_status['sender']  = sender
            job_status['attachments_count'] = len(attachments)
            _job_write(job_id, job_status)

            # Anhänge durch CAPE analysieren (gleiche Logik wie Mailer)
            attachment_results = []
            import tempfile as _tmp
            with _tmp.TemporaryDirectory(prefix='cape-upload-') as tmpdir:
                for att_name, att_data, att_ctype in attachments:
                    import hashlib
                    sha256 = hashlib.sha256(att_data).hexdigest()
                    result = {'filename': att_name, 'sha256': sha256,
                              'content_type': att_ctype, 'size': len(att_data)}
                    if not mailer._should_submit_to_cape(att_name, att_ctype):
                        result['skipped'] = True
                        attachment_results.append(result)
                        continue
                    logger.info(f'[Upload] Sende {att_name} an CAPE...')
                    task_id = mailer._submit_to_cape(att_name, att_data)
                    result['task_id'] = task_id
                    if not task_id:
                        result['error'] = 'CAPE submission fehlgeschlagen'
                        result['malscore'] = 0
                        attachment_results.append(result)
                        continue
                    timeout = mailer.config['cape'].get('submit_timeout', 900)
                    cape_report = mailer._wait_for_cape_result(task_id, timeout=timeout)
                    if cape_report and not cape_report.get('error'):
                        result['malscore'] = float(cape_report.get('malscore', 0))
                        rep_sha = cape_report.get('target', {}).get('file', {}).get('sha256', '')
                        if rep_sha:
                            result['sha256'] = rep_sha
                        if mailer.config['bedrock'].get('analyze_attachments', True):
                            result['ai_analysis'] = mailer._analyze_with_bedrock(cape_report, att_name, task_id)
                    else:
                        result['error'] = (cape_report or {}).get('error', 'Timeout')
                        result['malscore'] = 0
                        result['ai_analysis'] = None
                    attachment_results.append(result)

            # SMTP-Header-Analyse: für .eml msg_obj direkt, für .msg synthetisches Objekt
            if orig_name.lower().endswith('.eml'):
                smtp_headers = mailer._parse_smtp_headers(msg_obj)
            else:
                # .msg: synthetisches email.message.Message aus extra_headers bauen
                import email.message as _emsg_mod
                synthetic = _emsg_mod.Message()
                for k, v in extra_headers.items():
                    synthetic[k] = v
                smtp_headers = mailer._parse_smtp_headers(synthetic)
            smtp_headers_html = mailer._render_smtp_header_html(smtp_headers)

            mail_analysis = mailer._analyze_mail_phishing(subject, sender, body, extra_headers)
            html = mailer._build_html_report(subject, sender, attachment_results, mail_analysis,
                                              smtp_headers_html=smtp_headers_html)
            mailer._save_phishing_report(subject, sender, attachment_results, html, mail_analysis)
            _cache.pop('phishing_30_None_0', None)  # Cache invalidieren

            job_status['status'] = 'done'
            job_status['report_html'] = html
            job_status['attachment_results'] = [
                {k: v for k, v in r.items() if k != 'ai_analysis'}
                for r in attachment_results
            ]
            verdicts = [r.get('malscore', 0) for r in attachment_results if not r.get('skipped')]
            cape_malscore = max(verdicts, default=0)
            # Phishing-Score aus KI-Analyse extrahieren wenn keine CAPE-Anhänge
            ai_phishing_score = 0.0
            if mail_analysis:
                import re as _re
                m_score = _re.search(r'(\d+(?:[.,]\d+)?)\s*/\s*10', mail_analysis)
                if m_score:
                    ai_phishing_score = float(m_score.group(1).replace(',', '.'))
            job_status['malscore'] = cape_malscore if cape_malscore > 0 else ai_phishing_score
            job_status['mail_verdict'] = (mail_analysis or '')[:200]
            _job_write(job_id, job_status)

        except Exception as e:
            logger.error(f'Upload-Analyse fehlgeschlagen: {e}')
            job_status['status'] = 'error'
            job_status['error'] = str(e)
            _job_write(job_id, job_status)

    threading.Thread(target=_run, daemon=True).start()
    return redirect(url_for('phishing_upload_status', job_id=job_id))


_phishing_jobs = {}
_JOB_DIR = Path('/tmp/iceporge-jobs')
_JOB_DIR.mkdir(exist_ok=True)


def _job_write(job_id: str, data: dict) -> None:
    """Schreibt Job-Status atomar in Datei (Cross-Worker-sicher)."""
    p = _JOB_DIR / f'{job_id}.json'
    tmp = p.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, default=str), encoding='utf-8')
    tmp.replace(p)


def _job_read(job_id: str) -> dict | None:
    p = _JOB_DIR / f'{job_id}.json'
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return None


@app.route('/phishing/upload/status/<job_id>')
def phishing_upload_status(job_id):
    job = _job_read(job_id)
    if not job:
        return redirect(url_for('phishing_upload') + '?error=Job+nicht+gefunden')
    return render_template('phishing_upload_status.html', job=job)


@app.route('/api/reports')
def api_reports():
    """API: Reports als JSON."""
    days = request.args.get('days', 30, type=int)
    reports = get_phishing_reports(days=days)
    return jsonify(reports)


@app.route('/api/status')
def api_status():
    """API: Systemstatus als JSON."""
    return jsonify(get_system_status())


@app.route('/api/statistics')
def api_statistics():
    """API: Statistiken als JSON."""
    return jsonify(get_statistics())


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8085, debug=False)
