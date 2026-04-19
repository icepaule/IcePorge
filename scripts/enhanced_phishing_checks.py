#!/usr/bin/env python3
"""
IcePorge Enhanced Phishing Checks
Zusätzliche Prüfungen für bessere und beweissichere Phishing-Analyse

Diese Funktionen können in cape_mailer.py integriert werden.
"""

import re
import json
import socket
import subprocess
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

# Bekannte Banken und Finanzinstitute für Brand Impersonation Detection
KNOWN_BRANDS = {
    'banks_de': [
        'commerzbank', 'deutsche bank', 'sparkasse', 'volksbank', 'postbank',
        'ing', 'dkb', 'n26', 'comdirect', 'hypovereinsbank', 'targobank',
        'santander', 'lbbw', 'helaba', 'landesbank', 'raiffeisen'
    ],
    'banks_intl': [
        'paypal', 'stripe', 'wise', 'revolut', 'klarna', 'american express',
        'visa', 'mastercard', 'chase', 'wells fargo', 'bank of america'
    ],
    'tech': [
        'microsoft', 'apple', 'google', 'amazon', 'netflix', 'facebook',
        'meta', 'instagram', 'whatsapp', 'telegram', 'zoom', 'dropbox'
    ],
    'logistics': [
        'dhl', 'ups', 'fedex', 'dpd', 'hermes', 'gls', 'deutsche post'
    ],
    'government': [
        'finanzamt', 'bundesamt', 'polizei', 'zoll', 'elster', 'bafin'
    ]
}

# Verdächtige TLDs für Phishing
SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.work', '.click', '.link', '.online', '.site',
    '.info', '.biz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw'
]

# Länder mit hohem Spam/Phishing-Aufkommen (für Geo-Scoring)
HIGH_RISK_COUNTRIES = [
    'BR', 'RU', 'CN', 'NG', 'IN', 'PK', 'BD', 'VN', 'ID', 'PH',
    'UA', 'RO', 'BG', 'TR', 'EG', 'MA', 'TN', 'KE', 'ZA'
]


def check_spf_alignment(sender_ip: str, sender_domain: str) -> Dict:
    """
    Prüft ob die sendende IP im SPF-Record der Domain erlaubt ist.

    Returns:
        Dict mit spf_result, allowed_ips, is_aligned
    """
    result = {
        'spf_result': 'unknown',
        'spf_record': None,
        'allowed_ips': [],
        'sender_ip': sender_ip,
        'is_aligned': False,
        'verdict': 'unknown'
    }

    try:
        # SPF-Record abrufen
        cmd = f"dig +short {sender_domain} TXT"
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode()

        for line in output.split('\n'):
            if 'v=spf1' in line.lower():
                result['spf_record'] = line.strip('"')

                # IPs aus SPF extrahieren
                ip_matches = re.findall(r'ip4:([0-9./]+)', line)
                result['allowed_ips'] = ip_matches

                # Prüfe ob sender_ip erlaubt ist
                if sender_ip in ip_matches:
                    result['is_aligned'] = True
                    result['spf_result'] = 'pass'
                    result['verdict'] = 'pass'
                else:
                    # Prüfe CIDR-Ranges
                    from ipaddress import ip_address, ip_network
                    sender = ip_address(sender_ip)
                    for allowed in ip_matches:
                        try:
                            if '/' in allowed:
                                if sender in ip_network(allowed, strict=False):
                                    result['is_aligned'] = True
                                    result['spf_result'] = 'pass'
                                    result['verdict'] = 'pass'
                                    break
                        except:
                            pass

                    if not result['is_aligned']:
                        result['spf_result'] = 'fail'
                        result['verdict'] = 'FAIL - IP nicht im SPF-Record!'
                break

        if not result['spf_record']:
            result['spf_result'] = 'none'
            result['verdict'] = 'none - Kein SPF-Record'

    except Exception as e:
        logger.error(f"SPF check error: {e}")
        result['verdict'] = f'error: {e}'

    return result


def get_ip_geolocation(ip: str) -> Dict:
    """
    Holt Geolocation-Daten für eine IP-Adresse.
    """
    result = {
        'ip': ip,
        'country': 'Unknown',
        'country_code': 'XX',
        'city': 'Unknown',
        'isp': 'Unknown',
        'org': 'Unknown',
        'is_high_risk_country': False
    }

    try:
        import urllib.request
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org"
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read().decode())
            if data.get('status') == 'success':
                result['country'] = data.get('country', 'Unknown')
                result['country_code'] = data.get('countryCode', 'XX')
                result['city'] = data.get('city', 'Unknown')
                result['isp'] = data.get('isp', 'Unknown')
                result['org'] = data.get('org', 'Unknown')
                result['is_high_risk_country'] = result['country_code'] in HIGH_RISK_COUNTRIES
    except Exception as e:
        logger.debug(f"Geolocation error for {ip}: {e}")

    return result


def get_whois_info(domain: str) -> Dict:
    """
    Holt WHOIS-Informationen für eine Domain.
    """
    result = {
        'domain': domain,
        'registrar': 'Unknown',
        'creation_date': None,
        'expiry_date': None,
        'updated_date': None,
        'domain_age_days': None,
        'recently_updated': False,
        'recently_created': False,
        'name_servers': []
    }

    try:
        cmd = f"whois {domain}"
        output = subprocess.check_output(cmd, shell=True, timeout=15, stderr=subprocess.DEVNULL).decode()

        # Parse WHOIS output
        for line in output.split('\n'):
            line_lower = line.lower()

            if 'registrar:' in line_lower:
                result['registrar'] = line.split(':', 1)[1].strip()
            elif 'creation date:' in line_lower:
                date_str = line.split(':', 1)[1].strip()
                try:
                    result['creation_date'] = date_str[:10]
                    created = datetime.fromisoformat(date_str[:10])
                    result['domain_age_days'] = (datetime.now() - created).days
                    result['recently_created'] = result['domain_age_days'] < 30
                except:
                    pass
            elif 'updated date:' in line_lower:
                date_str = line.split(':', 1)[1].strip()
                try:
                    result['updated_date'] = date_str[:10]
                    updated = datetime.fromisoformat(date_str[:10])
                    days_since_update = (datetime.now() - updated).days
                    result['recently_updated'] = days_since_update < 7
                except:
                    pass
            elif 'expir' in line_lower and 'date' in line_lower:
                result['expiry_date'] = line.split(':', 1)[1].strip()[:10]
            elif 'name server:' in line_lower:
                ns = line.split(':', 1)[1].strip()
                if ns:
                    result['name_servers'].append(ns.lower())

    except Exception as e:
        logger.debug(f"WHOIS error for {domain}: {e}")

    return result


def detect_brand_impersonation(display_name: str, email_domain: str, body_text: str = "") -> Dict:
    """
    Erkennt Brand Impersonation (z.B. "Commerzbank" von @randomdomain.com).
    """
    result = {
        'is_brand_impersonation': False,
        'impersonated_brand': None,
        'brand_category': None,
        'confidence': 'low',
        'indicators': []
    }

    # Kombiniere Display Name und Body für Analyse
    text_to_check = f"{display_name} {body_text}".lower()

    for category, brands in KNOWN_BRANDS.items():
        for brand in brands:
            if brand in text_to_check:
                # Prüfe ob die Domain zur Brand passt
                brand_in_domain = any(b in email_domain.lower() for b in brand.split())

                if not brand_in_domain:
                    result['is_brand_impersonation'] = True
                    result['impersonated_brand'] = brand.title()
                    result['brand_category'] = category
                    result['confidence'] = 'high' if brand in display_name.lower() else 'medium'
                    result['indicators'].append(
                        f"'{brand.title()}' im {'Display Name' if brand in display_name.lower() else 'Text'}, "
                        f"aber Domain ist '{email_domain}'"
                    )

                    # Zusätzliche Prüfungen für höhere Confidence
                    if category in ['banks_de', 'banks_intl', 'government']:
                        result['confidence'] = 'critical'
                        result['indicators'].append(f"Finanzinstitut/Behörde '{brand.title()}' gefälscht")

                    return result

    return result


def check_suspicious_tld(domain: str) -> Dict:
    """
    Prüft ob die Domain eine verdächtige TLD verwendet.
    """
    result = {
        'domain': domain,
        'tld': None,
        'is_suspicious_tld': False,
        'risk_reason': None
    }

    tld = '.' + domain.split('.')[-1].lower()
    result['tld'] = tld

    if tld in SUSPICIOUS_TLDS:
        result['is_suspicious_tld'] = True
        result['risk_reason'] = f"TLD '{tld}' wird häufig für Phishing missbraucht"

    return result


def calculate_enhanced_risk_score(
    spf_check: Dict,
    geo_data: List[Dict],
    whois_data: Dict,
    brand_check: Dict,
    vt_detections: int = 0,
    vt_total: int = 94,
    existing_score: int = 0
) -> Tuple[int, List[str]]:
    """
    Berechnet einen verbesserten Risk Score mit detaillierten Begründungen.

    Returns:
        Tuple[score, list_of_reasons]
    """
    score = existing_score
    reasons = []

    # SPF Violations (+20-30 Punkte)
    if spf_check.get('spf_result') == 'fail':
        score += 30
        reasons.append(f"SPF FAIL: Sender-IP {spf_check.get('sender_ip')} nicht autorisiert")
    elif spf_check.get('spf_result') == 'none':
        score += 10
        reasons.append("Kein SPF-Record vorhanden")

    # Geolocation Risiko (+10-25 Punkte)
    for geo in geo_data:
        if geo.get('is_high_risk_country'):
            score += 15
            reasons.append(f"High-Risk Land: {geo.get('country')} ({geo.get('ip')})")

    # WHOIS Risiken (+15-30 Punkte)
    if whois_data.get('recently_created'):
        score += 25
        reasons.append(f"Domain erst {whois_data.get('domain_age_days')} Tage alt")
    elif whois_data.get('recently_updated'):
        score += 15
        reasons.append(f"Domain kürzlich aktualisiert ({whois_data.get('updated_date')})")

    # Brand Impersonation (+25-40 Punkte)
    if brand_check.get('is_brand_impersonation'):
        confidence = brand_check.get('confidence', 'low')
        if confidence == 'critical':
            score += 40
        elif confidence == 'high':
            score += 30
        else:
            score += 20
        reasons.append(f"Brand Impersonation: {brand_check.get('impersonated_brand')} ({confidence})")

    # VirusTotal Score verbessern
    if vt_detections > 0 and vt_total > 0:
        vt_percent = (vt_detections / vt_total) * 100
        if vt_percent >= 10:  # 10% oder mehr = signifikant
            score += 25
            reasons.append(f"VirusTotal: {vt_detections}/{vt_total} ({vt_percent:.1f}%) Detections")
        elif vt_percent >= 5:
            score += 15
            reasons.append(f"VirusTotal: {vt_detections}/{vt_total} ({vt_percent:.1f}%) Detections")

    # Cap score at 100
    score = min(100, score)

    return score, reasons


def generate_forensic_summary(
    spf_check: Dict,
    geo_data: List[Dict],
    whois_sender: Dict,
    whois_url: Dict,
    brand_check: Dict,
    final_score: int,
    reasons: List[str]
) -> str:
    """
    Generiert eine forensische Zusammenfassung für Beweissicherung.
    """
    summary = []
    summary.append("=" * 70)
    summary.append("FORENSISCHE ANALYSE - BEWEISSICHERUNG")
    summary.append("=" * 70)
    summary.append(f"Analyse-Zeitstempel: {datetime.now().isoformat()}")
    summary.append(f"Risiko-Score: {final_score}/100")
    summary.append("")

    # Risiko-Begründungen
    summary.append("RISIKO-INDIKATOREN:")
    for i, reason in enumerate(reasons, 1):
        summary.append(f"  {i}. {reason}")
    summary.append("")

    # SPF-Analyse
    summary.append("SPF-AUTHENTIFIZIERUNG:")
    summary.append(f"  Result: {spf_check.get('spf_result', 'unknown')}")
    summary.append(f"  Sender-IP: {spf_check.get('sender_ip', 'N/A')}")
    summary.append(f"  SPF-Record: {spf_check.get('spf_record', 'N/A')}")
    summary.append(f"  Erlaubte IPs: {', '.join(spf_check.get('allowed_ips', []))}")
    summary.append(f"  Aligned: {spf_check.get('is_aligned', False)}")
    summary.append("")

    # Geolocation
    summary.append("GEOLOCATION DER BETEILIGTEN IPs:")
    for geo in geo_data:
        summary.append(f"  {geo.get('ip')}:")
        summary.append(f"    Land: {geo.get('country')} ({geo.get('country_code')})")
        summary.append(f"    Stadt: {geo.get('city')}")
        summary.append(f"    ISP: {geo.get('isp')}")
        summary.append(f"    Organisation: {geo.get('org')}")
        if geo.get('is_high_risk_country'):
            summary.append(f"    ⚠️ HIGH-RISK COUNTRY")
    summary.append("")

    # WHOIS Sender Domain
    summary.append(f"WHOIS SENDER-DOMAIN ({whois_sender.get('domain', 'N/A')}):")
    summary.append(f"  Registrar: {whois_sender.get('registrar', 'Unknown')}")
    summary.append(f"  Erstellt: {whois_sender.get('creation_date', 'Unknown')}")
    summary.append(f"  Alter: {whois_sender.get('domain_age_days', 'Unknown')} Tage")
    summary.append(f"  Aktualisiert: {whois_sender.get('updated_date', 'Unknown')}")
    if whois_sender.get('recently_updated'):
        summary.append("  ⚠️ KÜRZLICH AKTUALISIERT")
    summary.append("")

    # WHOIS URL Domain
    if whois_url and whois_url.get('domain'):
        summary.append(f"WHOIS URL-DOMAIN ({whois_url.get('domain')}):")
        summary.append(f"  Registrar: {whois_url.get('registrar', 'Unknown')}")
        summary.append(f"  Erstellt: {whois_url.get('creation_date', 'Unknown')}")
        summary.append(f"  Aktualisiert: {whois_url.get('updated_date', 'Unknown')}")
        if whois_url.get('recently_updated'):
            summary.append("  ⚠️ KÜRZLICH AKTUALISIERT - VERDÄCHTIG!")
        summary.append("")

    # Brand Impersonation
    if brand_check.get('is_brand_impersonation'):
        summary.append("BRAND IMPERSONATION ERKANNT:")
        summary.append(f"  Gefälschte Marke: {brand_check.get('impersonated_brand')}")
        summary.append(f"  Kategorie: {brand_check.get('brand_category')}")
        summary.append(f"  Confidence: {brand_check.get('confidence')}")
        for indicator in brand_check.get('indicators', []):
            summary.append(f"  - {indicator}")
        summary.append("")

    summary.append("=" * 70)

    return "\n".join(summary)


# Integration Helper für cape_mailer.py
def run_enhanced_checks(
    sender_email: str,
    sender_ip: str,
    display_name: str,
    urls: List[str],
    all_ips: List[str],
    body_text: str = ""
) -> Dict:
    """
    Führt alle erweiterten Checks aus und gibt Ergebnisse zurück.

    Kann direkt in cape_mailer.py aufgerufen werden:

    from enhanced_phishing_checks import run_enhanced_checks
    enhanced = run_enhanced_checks(sender_email, sender_ip, display_name, urls, all_ips, body)
    """
    # Sender Domain extrahieren
    sender_domain = sender_email.split('@')[-1] if '@' in sender_email else sender_email

    # URL-Domains extrahieren
    url_domains = []
    for url in urls:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.netloc:
                url_domains.append(parsed.netloc)
        except:
            pass

    # Checks ausführen
    spf_check = check_spf_alignment(sender_ip, sender_domain)

    geo_data = []
    for ip in all_ips:
        if ip and not ip.startswith(('10.', '192.168.', '172.')):
            geo_data.append(get_ip_geolocation(ip))

    whois_sender = get_whois_info(sender_domain)
    whois_url = get_whois_info(url_domains[0]) if url_domains else {}

    brand_check = detect_brand_impersonation(display_name, sender_domain, body_text)

    # Score berechnen
    final_score, reasons = calculate_enhanced_risk_score(
        spf_check, geo_data, whois_sender, brand_check
    )

    # Forensic Summary
    forensic_summary = generate_forensic_summary(
        spf_check, geo_data, whois_sender, whois_url, brand_check, final_score, reasons
    )

    return {
        'enhanced_score': final_score,
        'risk_reasons': reasons,
        'spf_check': spf_check,
        'geolocation': geo_data,
        'whois_sender': whois_sender,
        'whois_url': whois_url,
        'brand_impersonation': brand_check,
        'forensic_summary': forensic_summary
    }


if __name__ == '__main__':
    # Test mit den Daten aus dem Commerzbank-Phishing
    print("Testing enhanced checks with Commerzbank phishing example...")

    result = run_enhanced_checks(
        sender_email="tmendez@parrilladelnato.com",
        sender_ip="200.123.232.232",
        display_name="Commerzbank Kundenbetreuung",
        urls=["https://tggpipe.com/"],
        all_ips=["200.123.232.232", "181.188.198.195"],
        body_text="Ihre Commerzbank-Daten müssen aktualisiert werden"
    )

    print(result['forensic_summary'])
    print(f"\nEnhanced Score: {result['enhanced_score']}/100")
    print(f"Risk Reasons: {result['risk_reasons']}")
