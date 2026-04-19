#!/usr/bin/env python3
"""
IcePorge Web Dashboard
Flask-basierte Web-App für Phishing-Reports und System-Monitoring
"""

import os
import re
import json
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, render_template, send_file, jsonify, request, redirect, url_for
from flask_cors import CORS

app = Flask(__name__)
CORS(app)


@app.context_processor
def inject_globals():
    """Globale Template-Variablen."""
    status = get_system_status() if 'get_system_status' in dir() else {'overall_status': 'unknown'}
    return {
        'status': status,
        'cape_url': 'http://localhost:8000',
        'mwdb_url': 'http://localhost:8081'
    }


# Konfiguration
REPORTS_DIR = '/opt/cape-mailer/reports'
CAPE_REPORTS_DIR = '/mnt/cape-data/storage/analyses'
STATUS_FILE = '/opt/iceporge/status/health.json'
CAPE_URL = 'http://localhost:8000'
MWDB_URL = 'http://localhost:8081'


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
    """Lädt alle Phishing-Reports."""
    reports = []
    cutoff = datetime.now() - timedelta(days=days)

    for report_file in Path(REPORTS_DIR).glob('phishing_*.html'):
        try:
            mtime = datetime.fromtimestamp(report_file.stat().st_mtime)
            if mtime < cutoff:
                continue

            # Report parsen
            with open(report_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Metadaten extrahieren
            report_id = report_file.stem.replace('phishing_', '')

            verdict_match = re.search(r'Verdict:\s*(\w+)', content)
            verdict = verdict_match.group(1).lower() if verdict_match else 'unknown'

            score_match = re.search(r'<span class="score"[^>]*>(\d+)/100</span>', content)
            score = int(score_match.group(1)) if score_match else 0

            sender_match = re.search(r'<td>Von</td><td>([^<]+)</td>', content)
            sender = sender_match.group(1) if sender_match else 'Unknown'

            subject_match = re.search(r'<td>Betreff</td><td>([^<]+)</td>', content)
            subject = subject_match.group(1)[:80] if subject_match else 'Unknown'

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
                'enhanced': 'Erweiterte Forensische Analyse' in content
            })

        except Exception as e:
            continue

    # Nach Datum sortieren (neueste zuerst)
    reports.sort(key=lambda x: x['timestamp'], reverse=True)
    return reports


def get_cape_analyses(days=7):
    """Lädt CAPE-Analysen."""
    analyses = []
    cutoff = datetime.now() - timedelta(days=days)

    for analysis_dir in Path(CAPE_REPORTS_DIR).iterdir():
        if not analysis_dir.is_dir() or not analysis_dir.name.isdigit():
            continue

        try:
            mtime = datetime.fromtimestamp(analysis_dir.stat().st_mtime)
            if mtime < cutoff:
                continue

            analysis_id = int(analysis_dir.name)
            report_file = analysis_dir / 'reports' / 'report.json'

            if report_file.exists():
                with open(report_file, 'r') as f:
                    data = json.load(f)

                target = data.get('target', {}).get('file', {})
                analyses.append({
                    'id': analysis_id,
                    'timestamp': mtime.isoformat(),
                    'date': mtime.strftime('%Y-%m-%d %H:%M'),
                    'filename': target.get('name', 'Unknown'),
                    'malscore': data.get('malscore', 0),
                    'sha256': target.get('sha256', '')[:16] + '...' if target.get('sha256') else '',
                    'signatures': len(data.get('signatures', []))
                })
        except:
            continue

    analyses.sort(key=lambda x: x['id'], reverse=True)
    return analyses[:50]  # Letzte 50


def get_system_status():
    """Lädt Systemstatus."""
    try:
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE, 'r') as f:
                return json.load(f)
    except:
        pass

    return {'overall_status': 'unknown', 'components': {}}


def get_statistics():
    """Berechnet Statistiken."""
    reports = get_phishing_reports(days=30)

    stats = {
        'total_reports': len(reports),
        'malicious': sum(1 for r in reports if r['verdict'] == 'malicious'),
        'suspicious': sum(1 for r in reports if r['verdict'] == 'suspicious'),
        'clean': sum(1 for r in reports if r['verdict'] in ['clean', 'likely_clean']),
        'avg_score': sum(r['score'] for r in reports) / len(reports) if reports else 0,
        'enhanced_count': sum(1 for r in reports if r['enhanced']),
        'by_day': {}
    }

    # Reports pro Tag
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
                           cape_url=CAPE_URL,
                           mwdb_url=MWDB_URL)


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
    """Detaillierte Header-Analyse eines Reports."""
    report_file = Path(REPORTS_DIR) / f'phishing_{report_id}.html'

    if not report_file.exists():
        return "Report nicht gefunden", 404

    with open(report_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # Basis-Infos
    verdict_match = re.search(r'Verdict:\s*(\w+)', content)
    verdict = verdict_match.group(1).lower() if verdict_match else 'unknown'

    score_match = re.search(r'<span class="score"[^>]*>(\d+)/100</span>', content)
    score = int(score_match.group(1)) if score_match else 0

    timestamp_match = re.search(r'<strong>Zeitstempel:</strong>\s*([^<]+)', content)
    timestamp = timestamp_match.group(1).strip() if timestamp_match else 'Unknown'

    # Header-Analyse extrahieren
    header_analysis = extract_header_analysis(content)

    return render_template('report_analysis.html',
                           report_id=report_id,
                           verdict=verdict,
                           score=score,
                           timestamp=timestamp,
                           analysis=header_analysis)


@app.route('/api/report/<report_id>/headers')
def api_report_headers(report_id):
    """API: Header-Analyse als JSON."""
    report_file = Path(REPORTS_DIR) / f'phishing_{report_id}.html'

    if not report_file.exists():
        return jsonify({'error': 'Report nicht gefunden'}), 404

    with open(report_file, 'r', encoding='utf-8') as f:
        content = f.read()

    return jsonify(extract_header_analysis(content))


@app.route('/cape')
def cape_analyses():
    """CAPE-Analysen Liste."""
    analyses = get_cape_analyses(days=30)
    return render_template('cape.html', analyses=analyses, cape_url=CAPE_URL)


@app.route('/cape/<int:analysis_id>')
def cape_redirect(analysis_id):
    """Redirect zu CAPE Web."""
    return redirect(f'{CAPE_URL}/analysis/{analysis_id}/')


@app.route('/status')
def system_status():
    """Systemstatus Seite."""
    status = get_system_status()

    # Live-Status abrufen
    try:
        result = subprocess.run(
            ['/opt/iceporge/scripts/iceporge-monitor.sh', 'check'],
            capture_output=True, text=True, timeout=30
        )
    except:
        pass

    # Status neu laden
    status = get_system_status()

    return render_template('status.html', status=status)


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
