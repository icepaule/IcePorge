#!/usr/bin/env python3
"""
IcePorge AWS MISP Sync
Synchronisiert CAPE-Analysen und Phishing-Reports nach AWS MISP

Usage:
    ./misp-aws-sync.py [--all] [--since DAYS] [--analysis ID] [--dry-run]

Konfiguration:
    /opt/iceporge/config/.env.misp.aws
"""

import os
import sys
import json
import glob
import argparse
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
from dotenv import load_dotenv

# PyMISP importieren
try:
    from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPObject
except ImportError:
    print("ERROR: pymisp nicht installiert. Bitte: pip install pymisp python-dotenv")
    sys.exit(1)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/opt/iceporge/status/misp-aws-sync.log')
    ]
)
logger = logging.getLogger(__name__)

# Konfiguration laden
ENV_FILE = '/opt/iceporge/config/.env.misp.aws'


class MISPAWSSync:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.config = self._load_config()
        self.misp = self._connect_misp()
        self.synced_file = '/opt/iceporge/status/misp-aws-synced.json'
        self.synced = self._load_synced()

    def _load_config(self) -> Dict:
        """Lädt Konfiguration aus .env Datei"""
        if not os.path.exists(ENV_FILE):
            logger.error(f"Konfigurationsdatei nicht gefunden: {ENV_FILE}")
            sys.exit(1)

        load_dotenv(ENV_FILE)

        config = {
            'url': os.getenv('MISP_AWS_URL'),
            'apikey': os.getenv('MISP_AWS_APIKEY'),
            'verifycert': os.getenv('MISP_AWS_VERIFYCERT', 'true').lower() == 'true',
            'distribution': int(os.getenv('MISP_AWS_DISTRIBUTION', '1')),
            'threat_level': int(os.getenv('MISP_AWS_THREAT_LEVEL', '2')),
            'analysis': int(os.getenv('MISP_AWS_ANALYSIS', '2')),
            'publish': os.getenv('MISP_AWS_PUBLISH', 'false').lower() == 'true',
            'tags': os.getenv('MISP_AWS_TAGS', 'cape-analysis').split(','),
            'min_malscore': float(os.getenv('MISP_AWS_MIN_MALSCORE', '3'))
        }

        # Validierung
        if not config['url'] or config['url'].startswith('https://misp.your'):
            logger.error("MISP_AWS_URL nicht konfiguriert! Bitte .env.misp.aws anpassen.")
            sys.exit(1)

        if not config['apikey'] or config['apikey'] == 'your-misp-api-key-here':
            logger.error("MISP_AWS_APIKEY nicht konfiguriert! Bitte .env.misp.aws anpassen.")
            sys.exit(1)

        return config

    def _connect_misp(self) -> Optional[PyMISP]:
        """Verbindet zu AWS MISP"""
        if self.dry_run:
            logger.info("[DRY-RUN] Würde zu MISP verbinden: %s", self.config['url'])
            return None

        try:
            misp = PyMISP(
                self.config['url'],
                self.config['apikey'],
                self.config['verifycert']
            )
            # Verbindungstest
            misp.get_sharing_groups()
            logger.info("Verbunden mit AWS MISP: %s", self.config['url'])
            return misp
        except Exception as e:
            logger.error("MISP Verbindungsfehler: %s", e)
            sys.exit(1)

    def _load_synced(self) -> Dict:
        """Lädt bereits synchronisierte IDs"""
        if os.path.exists(self.synced_file):
            try:
                with open(self.synced_file) as f:
                    return json.load(f)
            except:
                pass
        return {'cape_analyses': [], 'phishing_reports': []}

    def _save_synced(self):
        """Speichert synchronisierte IDs"""
        with open(self.synced_file, 'w') as f:
            json.dump(self.synced, f, indent=2)

    def sync_cape_analysis(self, analysis_id: int) -> bool:
        """Synchronisiert eine CAPE-Analyse nach MISP"""
        analysis_dir = f'/mnt/cape-data/storage/analyses/{analysis_id}'
        report_file = f'{analysis_dir}/reports/report.json'

        if not os.path.exists(report_file):
            logger.warning("Report nicht gefunden: %s", report_file)
            return False

        # Report laden
        try:
            with open(report_file) as f:
                report = json.load(f)
        except Exception as e:
            logger.error("Fehler beim Laden von %s: %s", report_file, e)
            return False

        malscore = report.get('malscore', 0)
        if malscore < self.config['min_malscore']:
            logger.debug("Analyse %d übersprungen (malscore %.1f < %.1f)",
                         analysis_id, malscore, self.config['min_malscore'])
            return False

        # Event erstellen
        target = report.get('target', {}).get('file', {})
        event_info = f"CAPE Analysis #{analysis_id}: {target.get('name', 'unknown')} (Score: {malscore})"

        if self.dry_run:
            logger.info("[DRY-RUN] Würde Event erstellen: %s", event_info)
            self._print_iocs(report)
            return True

        try:
            event = MISPEvent()
            event.info = event_info
            event.distribution = self.config['distribution']
            event.threat_level_id = self.config['threat_level']
            event.analysis = self.config['analysis']

            # Tags hinzufügen
            for tag in self.config['tags']:
                event.add_tag(tag.strip())

            # Sample-Attribute
            if target.get('sha256'):
                event.add_attribute('sha256', target['sha256'], comment='Analyzed sample')
            if target.get('md5'):
                event.add_attribute('md5', target['md5'])
            if target.get('sha1'):
                event.add_attribute('sha1', target['sha1'])
            if target.get('name'):
                event.add_attribute('filename', target['name'])

            # Netzwerk-IOCs
            network = report.get('network', {})

            for host in network.get('hosts', []):
                if host.get('ip'):
                    event.add_attribute('ip-dst', host['ip'], comment='Network connection')

            for domain in network.get('domains', []):
                if domain.get('domain'):
                    event.add_attribute('domain', domain['domain'])

            for dns in network.get('dns', []):
                if dns.get('request'):
                    event.add_attribute('domain', dns['request'], comment='DNS request')

            for http in network.get('http', []):
                if http.get('uri'):
                    event.add_attribute('url', http['uri'], comment='HTTP request')

            # Dropped Files
            for dropped in report.get('dropped', [])[:20]:
                if dropped.get('sha256'):
                    event.add_attribute('sha256', dropped['sha256'],
                                        comment=f"Dropped: {dropped.get('name', 'unknown')}")

            # Signaturen als Tags
            for sig in report.get('signatures', []):
                if sig.get('name'):
                    event.add_tag(f"sig:{sig['name']}")

            # Event erstellen
            result = self.misp.add_event(event)

            if 'Event' in result:
                event_id = result['Event']['id']
                logger.info("Event erstellt: %s (ID: %s)", event_info, event_id)

                if self.config['publish']:
                    self.misp.publish(event_id)
                    logger.info("Event %s publiziert", event_id)

                self.synced['cape_analyses'].append(analysis_id)
                self._save_synced()
                return True
            else:
                logger.error("Fehler beim Erstellen: %s", result)
                return False

        except Exception as e:
            logger.error("MISP Fehler für Analyse %d: %s", analysis_id, e)
            return False

    def sync_phishing_report(self, report_file: str) -> bool:
        """Synchronisiert einen Phishing-Report nach MISP"""
        report_id = Path(report_file).stem

        if report_id in self.synced['phishing_reports']:
            return False

        # HTML parsen für IOCs (vereinfacht - extrahiert JSON aus HTML)
        try:
            with open(report_file) as f:
                content = f.read()

            # IOCs aus HTML extrahieren (suche nach dem IOC JSON Block)
            import re
            ioc_match = re.search(r'<pre>\s*(\{[^}]+?"email-src"[^}]+\})\s*</pre>', content, re.DOTALL)
            if not ioc_match:
                logger.debug("Keine IOCs in %s gefunden", report_file)
                return False

            iocs = json.loads(ioc_match.group(1))

        except Exception as e:
            logger.error("Fehler beim Parsen von %s: %s", report_file, e)
            return False

        if self.dry_run:
            logger.info("[DRY-RUN] Würde Phishing-IOCs exportieren: %s", report_id)
            logger.info("  IOCs: %s", json.dumps(iocs, indent=2))
            return True

        try:
            event = MISPEvent()
            event.info = f"Phishing Report: {report_id}"
            event.distribution = self.config['distribution']
            event.threat_level_id = self.config['threat_level']
            event.analysis = self.config['analysis']
            event.add_tag('phishing')

            for tag in self.config['tags']:
                event.add_tag(tag.strip())

            # IOCs hinzufügen
            for email in iocs.get('email-src', []):
                event.add_attribute('email-src', email, comment='Phishing sender')

            for ip in iocs.get('ip-src', []):
                event.add_attribute('ip-src', ip, comment='Mail origin IP')

            for url in iocs.get('url', []):
                event.add_attribute('url', url, comment='Phishing URL')

            for domain in iocs.get('domain', []):
                event.add_attribute('domain', domain)

            result = self.misp.add_event(event)

            if 'Event' in result:
                logger.info("Phishing Event erstellt: %s", report_id)
                self.synced['phishing_reports'].append(report_id)
                self._save_synced()
                return True

        except Exception as e:
            logger.error("MISP Fehler für %s: %s", report_id, e)
            return False

        return False

    def _print_iocs(self, report: Dict):
        """Zeigt IOCs im Dry-Run Modus"""
        target = report.get('target', {}).get('file', {})
        logger.info("  SHA256: %s", target.get('sha256', '-'))
        logger.info("  Filename: %s", target.get('name', '-'))
        logger.info("  Malscore: %s", report.get('malscore', 0))

        network = report.get('network', {})
        if network.get('hosts'):
            logger.info("  IPs: %s", [h.get('ip') for h in network['hosts'][:5]])
        if network.get('domains'):
            logger.info("  Domains: %s", [d.get('domain') for d in network['domains'][:5]])

    def sync_all_cape(self, since_days: int = 7):
        """Synchronisiert alle CAPE-Analysen der letzten X Tage"""
        analyses_dir = '/mnt/cape-data/storage/analyses'
        cutoff = datetime.now() - timedelta(days=since_days)
        synced = 0
        skipped = 0

        for analysis_dir in sorted(glob.glob(f'{analyses_dir}/*/')):
            analysis_id = os.path.basename(analysis_dir.rstrip('/'))
            if not analysis_id.isdigit():
                continue

            analysis_id = int(analysis_id)

            # Bereits synchronisiert?
            if analysis_id in self.synced['cape_analyses']:
                skipped += 1
                continue

            # Zu alt?
            mtime = datetime.fromtimestamp(os.path.getmtime(analysis_dir))
            if mtime < cutoff:
                continue

            if self.sync_cape_analysis(analysis_id):
                synced += 1

        logger.info("CAPE Sync abgeschlossen: %d neu, %d übersprungen", synced, skipped)

    def sync_all_phishing(self, since_days: int = 7):
        """Synchronisiert alle Phishing-Reports der letzten X Tage"""
        reports_dir = '/opt/cape-mailer/reports'
        cutoff = datetime.now() - timedelta(days=since_days)
        synced = 0

        for report_file in glob.glob(f'{reports_dir}/phishing_*.html'):
            mtime = datetime.fromtimestamp(os.path.getmtime(report_file))
            if mtime < cutoff:
                continue

            if self.sync_phishing_report(report_file):
                synced += 1

        logger.info("Phishing Sync abgeschlossen: %d neu", synced)


def main():
    parser = argparse.ArgumentParser(description='IcePorge AWS MISP Sync')
    parser.add_argument('--all', action='store_true', help='Synchronisiere alle Analysen')
    parser.add_argument('--since', type=int, default=7, help='Nur Analysen der letzten X Tage (default: 7)')
    parser.add_argument('--analysis', type=int, help='Synchronisiere spezifische Analyse-ID')
    parser.add_argument('--phishing', action='store_true', help='Nur Phishing-Reports')
    parser.add_argument('--dry-run', action='store_true', help='Zeige was synchronisiert würde')

    args = parser.parse_args()

    sync = MISPAWSSync(dry_run=args.dry_run)

    if args.analysis:
        sync.sync_cape_analysis(args.analysis)
    elif args.phishing:
        sync.sync_all_phishing(args.since)
    elif args.all:
        sync.sync_all_cape(args.since)
        sync.sync_all_phishing(args.since)
    else:
        # Standard: nur neue Analysen
        sync.sync_all_cape(args.since)


if __name__ == '__main__':
    main()
