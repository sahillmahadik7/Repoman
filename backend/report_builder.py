# report_builder.py — Builds a complete, professional report structure
# Works with both JSON scan output and tagged text input

from datetime import datetime
from parser import get_summary_stats

# ===== SEVERITY CONFIG =====
SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']

SEVERITY_COLORS = {
    'CRITICAL':      '#c0392b',
    'HIGH':          '#e67e22',
    'MEDIUM':        '#f39c12',
    'LOW':           '#2980b9',
    'INFORMATIONAL': '#7f8c8d',
}

SEVERITY_WEIGHT = {
    'CRITICAL':      10,
    'HIGH':           7,
    'MEDIUM':         4,
    'LOW':            2,
    'INFORMATIONAL':  1,
}


# ===== OVERALL RISK CALCULATION =====
def calculate_overall_risk(stats):
    """
    Weighted risk score:
    - Any CRITICAL → overall is at least HIGH
    - Score drives final rating
    """
    if stats['CRITICAL'] > 0:
        return 'CRITICAL'

    score = (
        stats['HIGH']          * SEVERITY_WEIGHT['HIGH']   +
        stats['MEDIUM']        * SEVERITY_WEIGHT['MEDIUM'] +
        stats['LOW']           * SEVERITY_WEIGHT['LOW']    +
        stats['INFORMATIONAL'] * SEVERITY_WEIGHT['INFORMATIONAL']
    )

    if score >= 14: return 'HIGH'
    if score >= 7:  return 'MEDIUM'
    if score >= 2:  return 'LOW'
    if score >= 1:  return 'INFORMATIONAL'
    return 'INFORMATIONAL'


# ===== EXECUTIVE SUMMARY GENERATOR =====
def generate_executive_summary(findings, stats, overall_risk):
    """
    Writes a professional executive summary based on what was actually found.
    Handles both JSON scan data and manual text input.
    """
    total        = sum(stats.values())
    target_str   = ', '.join(findings['targets']) if findings['targets'] else 'the assessed target(s)'
    date_str     = findings['date'] or datetime.now().strftime('%B %d, %Y')
    input_format = findings.get('input_format', 'text')
    meta         = findings.get('scan_metadata', {})

    # --- Opening ---
    summary = (
        f"A cybersecurity vulnerability assessment was conducted against {target_str} "
        f"on {date_str}. "
    )

    # --- Scan context (JSON mode) ---
    if input_format == 'json' and meta:
        scans = meta.get('scans_executed', [])
        if scans:
            scan_names = ', '.join(s.replace('_', ' ') for s in scans)
            summary += (
                f"The assessment was performed using automated scanning techniques including "
                f"{scan_names}. "
            )
        if meta.get('nmap_version'):
            summary += f"Nmap version {meta['nmap_version']} was used for network enumeration. "

    # --- Findings overview ---
    open_ports = findings.get('open_ports', [])
    if open_ports:
        port_list = ', '.join(
            f"{p['port']}/{p['protocol'].upper()}" for p in open_ports
        )
        summary += (
            f"Network enumeration identified {len(open_ports)} open port(s): {port_list}. "
        )

    if total == 0:
        summary += (
            "No security findings were identified during this assessment. "
            "The target's attack surface appears minimal based on the scans performed. "
            "It is recommended to conduct a deeper assessment including authenticated scans "
            "and manual testing to validate this result."
        )
        return summary

    summary += (
        f"A total of {total} finding(s) were identified across the assessed scope. "
    )

    # --- Severity breakdown ---
    if stats['CRITICAL'] > 0:
        summary += (
            f"{stats['CRITICAL']} finding(s) were rated CRITICAL severity, "
            f"representing an immediate and significant risk to the environment. "
            f"These require urgent remediation. "
        )
    if stats['HIGH'] > 0:
        summary += (
            f"{stats['HIGH']} HIGH severity finding(s) were identified, "
            f"which pose a substantial risk and should be remediated promptly. "
        )
    if stats['MEDIUM'] > 0:
        summary += (
            f"{stats['MEDIUM']} MEDIUM severity finding(s) were noted "
            f"and should be addressed within a defined remediation window. "
        )
    if stats['LOW'] > 0:
        summary += (
            f"{stats['LOW']} LOW severity finding(s) were observed, "
            f"representing minor risks or informational observations. "
        )
    if stats['INFORMATIONAL'] > 0:
        summary += (
            f"{stats['INFORMATIONAL']} INFORMATIONAL finding(s) were recorded "
            f"for awareness and future hardening considerations. "
        )

    # --- Overall risk ---
    summary += (
        f"Based on the identified findings, the overall risk rating for this engagement "
        f"is assessed as {overall_risk}. "
    )

    # --- Closing ---
    if stats['CRITICAL'] > 0 or stats['HIGH'] > 0:
        summary += (
            "Immediate remediation of all Critical and High severity findings is strongly recommended. "
            "This report provides detailed technical descriptions, risk ratings, and actionable "
            "remediation guidance for each identified finding."
        )
    else:
        summary += (
            "This report provides detailed technical descriptions, risk ratings, and "
            "remediation recommendations for all identified findings."
        )

    return summary


# ===== RULE-BASED RECOMMENDATIONS =====
def get_recommendation(vuln):
    """
    Returns remediation recommendation.
    Prefers the one already set (from JSON parser), falls back to rule-based.
    """
    if vuln.get('recommendation'):
        return vuln['recommendation']

    desc_lower = vuln['description'].lower()

    rules = [
        (['sql injection', 'sqli'],
         'Use parameterized queries or prepared statements. Implement input validation and '
         'apply least-privilege database accounts.'),
        (['xss', 'cross-site scripting'],
         'Encode all user-supplied output using context-aware encoding. '
         'Implement a Content Security Policy (CSP) header.'),
        (['rce', 'remote code execution'],
         'Immediately patch the vulnerable component. Restrict execution permissions '
         'and isolate the affected service in a DMZ.'),
        (['weak password', 'default credential'],
         'Enforce a strong password policy (min 12 chars, complexity). '
         'Enable multi-factor authentication (MFA). Audit all default credentials.'),
        (['outdated', 'deprecated'],
         'Update the identified component to the latest stable version. '
         'Establish a regular patch management cycle.'),
        (['ssl', 'tls 1.0', 'tls 1.1'],
         'Disable deprecated TLS/SSL versions. Enforce TLS 1.2 or higher '
         'and restrict cipher suites to strong algorithms.'),
        (['csrf'],
         'Implement anti-CSRF tokens for all state-changing requests. '
         'Validate Origin and Referer headers server-side.'),
        (['open port', 'unnecessary service'],
         'Disable or firewall all unnecessary open ports. '
         'Apply the principle of least access to all network services.'),
        (['ftp'],
         'Disable FTP immediately. Migrate to SFTP or FTPS with strong authentication.'),
        (['rdp', 'remote desktop'],
         'Restrict RDP behind a VPN. Enable Network Level Authentication (NLA). '
         'Enforce strong passwords and account lockout policies.'),
        (['smb'],
         'Block SMB at the perimeter firewall. Disable SMBv1. '
         'Apply the MS17-010 security patch if not already done.'),
        (['http', 'port 80'],
         'Redirect all HTTP traffic to HTTPS. Implement HSTS (HTTP Strict Transport Security).'),
        (['ssh', 'port 22'],
         'Restrict SSH access by IP using firewall rules. Disable root login. '
         'Enforce key-based authentication and disable password login.'),
    ]

    for keywords, recommendation in rules:
        if any(kw in desc_lower for kw in keywords):
            return recommendation

    return (
        'Review and remediate this finding according to industry best practices '
        '(OWASP Top 10, NIST SP 800-115). Consult vendor advisories if a CVE is associated.'
    )


# ===== OPEN PORTS TABLE (JSON mode only) =====
def build_ports_table(findings):
    """Returns a clean list of open port dicts for the PDF port table."""
    ports = []
    for p in findings.get('open_ports', []):
        ports.append({
            'port':     p['port'],
            'protocol': p['protocol'].upper(),
            'service':  p['service'] or '—',
            'product':  p['product'] or '—',
            'version':  p['version'] or '—',
            'risk':     _port_to_risk_label(p['port']),
        })
    return ports


def _port_to_risk_label(port):
    high_risk   = {21, 23, 135, 139, 445, 2375, 4444, 6379, 9200}
    medium_risk = {22, 25, 53, 110, 143, 1433, 1521, 3306, 3389, 5432, 5900, 27017}
    low_risk    = {80, 8080, 8443, 8888, 3000}
    https_ports = {443}

    if port in high_risk:    return 'HIGH'
    if port in medium_risk:  return 'HIGH'
    if port in https_ports:  return 'INFORMATIONAL'
    if port in low_risk:     return 'LOW'
    return 'LOW'


# ===== MAIN BUILD FUNCTION =====
def build_report(findings):
    """
    Main entry point — called by app.py after parsing.
    Returns complete report dict for pdf_generator.py.
    """
    stats        = get_summary_stats(findings)
    overall_risk = calculate_overall_risk(stats)

    # Sort vulnerabilities by severity (Critical first)
    sorted_vulns = sorted(
        findings['vulnerabilities'],
        key=lambda v: SEVERITY_ORDER.index(v.get('severity', 'INFORMATIONAL'))
    )

    # Attach recommendations to each finding
    for v in sorted_vulns:
        v['recommendation'] = get_recommendation(v)

    exec_summary = generate_executive_summary(findings, stats, overall_risk)
    ports_table  = build_ports_table(findings)

    # Scan metadata summary lines
    meta = findings.get('scan_metadata', {})
    scan_summary_lines = []
    if meta.get('nmap_version'):
        scan_summary_lines.append(f"Scanner: Nmap {meta['nmap_version']}")
    if meta.get('platform'):
        scan_summary_lines.append(f"Platform: {meta['platform']}")
    if meta.get('scans_executed'):
        scan_summary_lines.append(
            "Scan Types: " + ', '.join(s.replace('_', ' ').title()
            for s in meta['scans_executed'])
        )
    if meta.get('privilege_mode'):
        scan_summary_lines.append(f"Privilege Mode: {meta['privilege_mode']}")
    if meta.get('confidence') is not None:
        scan_summary_lines.append(f"Scan Confidence: {int(meta['confidence'] * 100)}%")

    report = {
        # ---- Meta ----
        'title':          findings['title'] or 'Cybersecurity Vulnerability Assessment Report',
        'date':           findings['date']  or datetime.now().strftime('%B %d, %Y'),
        'generated_on':   datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'targets':        findings['targets'] or ['Not specified'],
        'overall_risk':   overall_risk,
        'input_format':   findings.get('input_format', 'text'),

        # ---- Summary ----
        'executive_summary': exec_summary,
        'severity_stats':    stats,
        'total_findings':    sum(stats.values()),

        # ---- Sections ----
        'vulnerabilities':    sorted_vulns,
        'scan_results':       findings['scan_results'],
        'notes':              findings['notes'],
        'proofs':             findings['proofs'],
        'os_matches':         findings.get('os_matches', []),
        'ports_table':        ports_table,
        'scan_summary_lines': scan_summary_lines,

        # ---- Style helpers ----
        'severity_colors': SEVERITY_COLORS,
        'severity_order':  SEVERITY_ORDER,
    }

    return report