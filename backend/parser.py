# parser.py — Parses raw .txt findings file into structured data
# Supports tags: [VULN], [SCAN], [NOTE], [PROOF], [TARGET], [DATE]

import re

# ===== SEVERITY KEYWORDS =====
CRITICAL_KEYWORDS = [
    'remote code execution', 'rce', 'sql injection', 'sqli',
    'command injection', 'privilege escalation', 'unauthenticated',
    'critical', 'cvss 9', 'cvss 10', '0day', 'zero-day', 'zero day',
    'authentication bypass', 'arbitrary code'
]

HIGH_KEYWORDS = [
    'xss', 'cross-site scripting', 'xxe', 'ssrf', 'deserialization',
    'path traversal', 'directory traversal', 'broken auth',
    'sensitive data exposure', 'high', 'cvss 7', 'cvss 8',
    'weak password', 'default credential', 'open redirect',
    'information disclosure'
]

MEDIUM_KEYWORDS = [
    'csrf', 'cross-site request forgery', 'clickjacking', 'outdated',
    'deprecated', 'medium', 'cvss 4', 'cvss 5', 'cvss 6',
    'misconfiguration', 'verbose error', 'missing header',
    'self-signed cert', 'ssl', 'tls 1.0', 'tls 1.1'
]

LOW_KEYWORDS = [
    'informational', 'low', 'cvss 1', 'cvss 2', 'cvss 3',
    'banner grabbing', 'version disclosure', 'cookie flag',
    'http', 'open port', 'unnecessary service'
]


def classify_severity(text):
    """Determine severity based on keywords in text."""
    text_lower = text.lower()

    for kw in CRITICAL_KEYWORDS:
        if kw in text_lower:
            return 'CRITICAL'

    for kw in HIGH_KEYWORDS:
        if kw in text_lower:
            return 'HIGH'

    for kw in MEDIUM_KEYWORDS:
        if kw in text_lower:
            return 'MEDIUM'

    for kw in LOW_KEYWORDS:
        if kw in text_lower:
            return 'LOW'

    return 'INFORMATIONAL'


def extract_cve(text):
    """Extract CVE IDs from text."""
    return re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)


def extract_cvss(text):
    """Extract CVSS score from text."""
    match = re.search(r'CVSS[:\s]+(\d+\.?\d*)', text, re.IGNORECASE)
    return match.group(1) if match else None


def parse_findings(raw_text):
    """
    Parse raw text file into structured findings dict.

    Supported line formats:
        [VULN]   - Vulnerability finding
        [SCAN]   - Scan tool output (Nmap, Nessus, etc.)
        [NOTE]   - Penetration test notes
        [PROOF]  - Screenshot descriptions / proof text
        [TARGET] - Target info (IP, domain, scope)
        [DATE]   - Assessment date
        [TITLE]  - Report title override

    Also supports plain lines (no tag) — treated as notes.
    """

    findings = {
        'vulnerabilities': [],
        'scan_results':    [],
        'notes':           [],
        'proofs':          [],
        'targets':         [],
        'date':            None,
        'title':           None,
        'raw_lines':       [],
    }

    lines = raw_text.splitlines()
    current_block = None
    current_text  = []

    def flush_block():
        """Save current accumulated multi-line block."""
        if not current_block or not current_text:
            return
        text = ' '.join(current_text).strip()
        if not text:
            return

        if current_block == 'VULN':
            findings['vulnerabilities'].append({
                'description': text,
                'severity':    classify_severity(text),
                'cve':         extract_cve(text),
                'cvss':        extract_cvss(text),
            })
        elif current_block == 'SCAN':
            findings['scan_results'].append({'detail': text})
        elif current_block == 'NOTE':
            findings['notes'].append({'detail': text})
        elif current_block == 'PROOF':
            findings['proofs'].append({'detail': text})

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            flush_block()
            current_block = None
            current_text  = []
            continue

        findings['raw_lines'].append(line)

        # Match tag at start: [TAG] content
        tag_match = re.match(r'^\[(\w+)\]\s*(.*)', line)

        if tag_match:
            flush_block()
            tag     = tag_match.group(1).upper()
            content = tag_match.group(2).strip()

            if tag == 'TARGET':
                if content:
                    findings['targets'].append(content)
                current_block = None
                current_text  = []

            elif tag == 'DATE':
                if content:
                    findings['date'] = content
                current_block = None
                current_text  = []

            elif tag == 'TITLE':
                if content:
                    findings['title'] = content
                current_block = None
                current_text  = []

            elif tag in ('VULN', 'SCAN', 'NOTE', 'PROOF'):
                current_block = tag
                current_text  = [content] if content else []

            else:
                # Unknown tag — treat as note
                current_block = 'NOTE'
                current_text  = [line]

        else:
            # Continuation of current block OR plain line → note
            if current_block:
                current_text.append(line)
            else:
                findings['notes'].append({'detail': line})

    # Flush last block
    flush_block()

    return findings


def get_summary_stats(findings):
    """Return severity count summary."""
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFORMATIONAL': 0}
    for v in findings['vulnerabilities']:
        counts[v['severity']] = counts.get(v['severity'], 0) + 1
    return counts