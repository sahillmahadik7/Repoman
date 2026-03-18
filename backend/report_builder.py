# report_builder.py — Converts parsed findings into a structured report dict
# This dict is passed to pdf_generator.py to render the final PDF

from datetime import datetime
from parser import get_summary_stats

# ===== SEVERITY CONFIG =====
SEVERITY_ORDER    = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
SEVERITY_COLORS   = {
    'CRITICAL':      '#ff3b5c',
    'HIGH':          '#ff6b35',
    'MEDIUM':        '#ffb300',
    'LOW':           '#00c8ff',
    'INFORMATIONAL': '#7a8fa6',
}
SEVERITY_RISK_SCORE = {
    'CRITICAL': 10,
    'HIGH':      7,
    'MEDIUM':    5,
    'LOW':       2,
    'INFORMATIONAL': 1,
}


def calculate_overall_risk(stats):
    """Calculate an overall risk rating from severity counts."""
    score = (
        stats['CRITICAL'] * 10 +
        stats['HIGH']     * 7  +
        stats['MEDIUM']   * 5  +
        stats['LOW']      * 2  +
        stats['INFORMATIONAL'] * 1
    )
    if score >= 20:   return 'CRITICAL'
    if score >= 12:   return 'HIGH'
    if score >= 6:    return 'MEDIUM'
    if score >= 2:    return 'LOW'
    return 'INFORMATIONAL'


def generate_executive_summary(findings, stats, overall_risk):
    """Auto-generate an executive summary paragraph."""
    total = sum(stats.values())
    target_str = ', '.join(findings['targets']) if findings['targets'] else 'the assessed target(s)'
    date_str   = findings['date'] or datetime.now().strftime('%B %d, %Y')

    critical_high = stats['CRITICAL'] + stats['HIGH']

    summary = (
        f"A cybersecurity vulnerability assessment was conducted against {target_str} "
        f"on {date_str}. The assessment identified a total of {total} finding(s) across "
        f"multiple severity levels. "
    )

    if stats['CRITICAL'] > 0:
        summary += (
            f"{stats['CRITICAL']} critical severity vulnerability(ies) were discovered, "
            f"representing immediate risk to the environment. "
        )

    if stats['HIGH'] > 0:
        summary += (
            f"{stats['HIGH']} high severity finding(s) require prompt remediation. "
        )

    if critical_high == 0:
        summary += (
            "No critical or high severity vulnerabilities were identified. "
            "The overall security posture is considered acceptable with minor improvements recommended. "
        )

    summary += (
        f"The overall risk rating for this assessment is assessed as {overall_risk}. "
        "Immediate remediation is advised for all critical and high severity findings. "
        "This report provides detailed findings, risk ratings, and remediation recommendations."
    )

    return summary


def generate_recommendations(vulnerabilities):
    """Generate generic but contextual remediation recommendations per finding."""
    recs = []
    for v in vulnerabilities:
        desc_lower = v['description'].lower()
        rec = {
            'finding':  v['description'],
            'severity': v['severity'],
        }

        # Rule-based recommendations
        if 'sql injection' in desc_lower or 'sqli' in desc_lower:
            rec['recommendation'] = (
                "Use parameterized queries or prepared statements for all database interactions. "
                "Implement input validation and least-privilege database accounts."
            )
        elif 'xss' in desc_lower or 'cross-site scripting' in desc_lower:
            rec['recommendation'] = (
                "Encode all user-supplied output using context-aware encoding. "
                "Implement a Content Security Policy (CSP) header."
            )
        elif 'rce' in desc_lower or 'remote code execution' in desc_lower:
            rec['recommendation'] = (
                "Immediately patch the vulnerable component. "
                "Restrict execution permissions and isolate the affected service."
            )
        elif 'weak password' in desc_lower or 'default credential' in desc_lower:
            rec['recommendation'] = (
                "Enforce a strong password policy (min. 12 chars, complexity requirements). "
                "Enable multi-factor authentication (MFA) and audit all default credentials."
            )
        elif 'outdated' in desc_lower or 'deprecated' in desc_lower:
            rec['recommendation'] = (
                "Update the identified component to the latest stable version. "
                "Establish a regular patch management process."
            )
        elif 'ssl' in desc_lower or 'tls' in desc_lower:
            rec['recommendation'] = (
                "Disable deprecated TLS/SSL versions. "
                "Enforce TLS 1.2 or higher and use strong cipher suites."
            )
        elif 'csrf' in desc_lower:
            rec['recommendation'] = (
                "Implement anti-CSRF tokens for all state-changing requests. "
                "Validate the Origin and Referer headers server-side."
            )
        elif 'open port' in desc_lower or 'unnecessary service' in desc_lower:
            rec['recommendation'] = (
                "Disable or firewall unnecessary open ports and services. "
                "Apply the principle of least access to all network services."
            )
        else:
            rec['recommendation'] = (
                "Review and remediate this finding according to industry best practices "
                "(OWASP, NIST). Consult the relevant vendor advisory if a CVE is identified."
            )

        recs.append(rec)
    return recs


def build_report(findings):
    """
    Main function — builds complete report data structure.
    Returns a dict ready for pdf_generator.py
    """
    stats        = get_summary_stats(findings)
    overall_risk = calculate_overall_risk(stats)

    # Sort vulnerabilities by severity
    sorted_vulns = sorted(
        findings['vulnerabilities'],
        key=lambda v: SEVERITY_ORDER.index(v['severity'])
    )

    recommendations = generate_recommendations(sorted_vulns)
    exec_summary    = generate_executive_summary(findings, stats, overall_risk)

    report = {
        # ---- Meta ----
        'title':         findings['title'] or 'Cybersecurity Vulnerability Assessment Report',
        'date':          findings['date'] or datetime.now().strftime('%B %d, %Y'),
        'generated_on':  datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'targets':       findings['targets'] or ['Not specified'],
        'overall_risk':  overall_risk,

        # ---- Summary ----
        'executive_summary': exec_summary,
        'severity_stats':    stats,
        'total_findings':    sum(stats.values()),

        # ---- Sections ----
        'vulnerabilities':   sorted_vulns,
        'scan_results':      findings['scan_results'],
        'notes':             findings['notes'],
        'proofs':            findings['proofs'],
        'recommendations':   recommendations,

        # ---- Style helpers ----
        'severity_colors':   SEVERITY_COLORS,
        'severity_order':    SEVERITY_ORDER,
    }

    return report