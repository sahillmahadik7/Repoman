# parser.py — Smart parser that handles both:
#   1. JSON format  (Nmap tool output, structured scan results)
#   2. Tagged text  (manual findings: [VULN], [SCAN], [NOTE], [PROOF], etc.)

import re
import json
from datetime import datetime

# ===== SEVERITY KEYWORD LISTS (for tagged text mode) =====
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
    'open port', 'unnecessary service'
]

# ===== PORT RISK DATABASE =====
# Maps port numbers to (severity, service_name, risk_description, recommendation)
PORT_RISK_DB = {
    21:   ('HIGH',          'FTP',           'FTP transmits credentials in plaintext. Attackers can perform credential sniffing.',
                                             'Disable FTP. Use SFTP or FTPS instead. Enforce strong authentication.'),
    22:   ('LOW',           'SSH',           'SSH port is exposed. Brute-force and credential stuffing attacks are common.',
                                             'Restrict SSH access by IP. Disable root login. Use key-based authentication only.'),
    23:   ('CRITICAL',      'Telnet',        'Telnet transmits all data including credentials in plaintext.',
                                             'Immediately disable Telnet. Replace with SSH for all remote management.'),
    25:   ('MEDIUM',        'SMTP',          'Open SMTP may allow email relay abuse or spam if misconfigured.',
                                             'Restrict SMTP relay. Enable authentication. Consider an email security gateway.'),
    53:   ('MEDIUM',        'DNS',           'Open DNS may be vulnerable to amplification attacks or zone transfer abuse.',
                                             'Restrict DNS zone transfers. Disable recursive queries for external IPs.'),
    80:   ('LOW',           'HTTP',          'Unencrypted HTTP is in use. Data in transit is not protected.',
                                             'Redirect all HTTP traffic to HTTPS. Implement HSTS.'),
    110:  ('MEDIUM',        'POP3',          'POP3 may transmit email credentials in cleartext.',
                                             'Disable plain POP3. Enforce POP3S (port 995) with TLS.'),
    135:  ('HIGH',          'MS-RPC',        'MS-RPC exposure can lead to remote exploitation and lateral movement.',
                                             'Block port 135 at the firewall. Restrict RPC access to internal networks only.'),
    139:  ('HIGH',          'NetBIOS',       'NetBIOS exposes network shares and can facilitate NTLM relay attacks.',
                                             'Disable NetBIOS over TCP/IP. Block port 139 at the perimeter firewall.'),
    143:  ('MEDIUM',        'IMAP',          'IMAP may expose email credentials if TLS is not enforced.',
                                             'Disable plain IMAP. Enforce IMAPS (port 993) with TLS.'),
    443:  ('INFORMATIONAL', 'HTTPS',         'HTTPS is in use. Verify TLS configuration and certificate validity.',
                                             'Ensure TLS 1.2+ is enforced. Disable weak cipher suites. Verify certificate expiry.'),
    445:  ('CRITICAL',      'SMB',           'SMB is exposed. Vulnerable to EternalBlue (MS17-010) and ransomware propagation.',
                                             'Block port 445 at the perimeter. Apply MS17-010 patch. Disable SMBv1 immediately.'),
    1433: ('HIGH',          'MSSQL',         'Microsoft SQL Server is exposed to the network.',
                                             'Restrict SQL Server access to application servers only. Disable sa account.'),
    1521: ('HIGH',          'Oracle DB',     'Oracle Database port is exposed to the network.',
                                             'Restrict database access to application tier only. Apply latest Oracle patches.'),
    2375: ('CRITICAL',      'Docker API',    'Unauthenticated Docker API exposure allows full host compromise.',
                                             'Immediately restrict Docker API. Enable TLS authentication. Block port 2375.'),
    3000: ('LOW',           'Dev Server',    'Development server port is exposed. May indicate a non-production service.',
                                             'Ensure development services are not exposed in production environments.'),
    3306: ('HIGH',          'MySQL',         'MySQL database port is exposed to the network.',
                                             'Restrict MySQL to localhost or application servers only. Use strong credentials.'),
    3389: ('HIGH',          'RDP',           'Remote Desktop Protocol is exposed. Common target for brute-force attacks.',
                                             'Restrict RDP behind VPN. Enable NLA. Use strong passwords and account lockout.'),
    4444: ('CRITICAL',      'Metasploit',    'Port 4444 is commonly used by Metasploit reverse shells.',
                                             'Immediately investigate and block this port. Conduct incident response.'),
    5432: ('HIGH',          'PostgreSQL',    'PostgreSQL database port is exposed to the network.',
                                             'Restrict PostgreSQL access to application servers. Disable remote superuser login.'),
    5900: ('HIGH',          'VNC',           'VNC is exposed. Often lacks strong encryption and authentication.',
                                             'Disable VNC or restrict by IP. Enforce password authentication. Use VPN for access.'),
    6379: ('CRITICAL',      'Redis',         'Redis is often unauthenticated by default. Can lead to RCE.',
                                             'Bind Redis to localhost. Enable authentication (requirepass). Block port 6379.'),
    8080: ('LOW',           'HTTP Alt',      'Alternative HTTP port is open. May expose admin interfaces or dev services.',
                                             'Review what is running on port 8080. Ensure it requires authentication.'),
    8443: ('LOW',           'HTTPS Alt',     'Alternative HTTPS port is open. Verify TLS configuration.',
                                             'Ensure TLS 1.2+ is enforced. Review what services are exposed on this port.'),
    8888: ('LOW',           'HTTP Alt',      'Alternative HTTP port is open. Often used by Jupyter or dev tools.',
                                             'Restrict access. Ensure authentication is required. Do not expose publicly.'),
    9200: ('CRITICAL',      'Elasticsearch', 'Elasticsearch is often unauthenticated. Full data exposure risk.',
                                             'Enable Elasticsearch security (X-Pack). Bind to localhost. Block port 9200.'),
    27017:('HIGH',          'MongoDB',       'MongoDB is exposed. Often has no authentication by default.',
                                             'Enable MongoDB authentication. Bind to localhost or private network. Block 27017.'),
}

# Default risk for unknown ports
DEFAULT_PORT_RISK = ('LOW', 'Unknown Service',
    'An open port was detected running an unidentified service.',
    'Investigate the service running on this port. Close if not required.')


# ===== HELPERS =====
def classify_severity(text):
    text_lower = text.lower()
    for kw in CRITICAL_KEYWORDS:
        if kw in text_lower: return 'CRITICAL'
    for kw in HIGH_KEYWORDS:
        if kw in text_lower: return 'HIGH'
    for kw in MEDIUM_KEYWORDS:
        if kw in text_lower: return 'MEDIUM'
    for kw in LOW_KEYWORDS:
        if kw in text_lower: return 'LOW'
    return 'INFORMATIONAL'


def extract_cve(text):
    return re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)


def extract_cvss(text):
    match = re.search(r'CVSS[:\s]+(\d+\.?\d*)', text, re.IGNORECASE)
    return match.group(1) if match else None


def get_port_risk(port, service='', product='', version=''):
    """Look up risk info for a given port number."""
    if port in PORT_RISK_DB:
        sev, svc, desc, rec = PORT_RISK_DB[port]
    else:
        sev, svc, desc, rec = DEFAULT_PORT_RISK
        svc = service.upper() if service else f'Port {port}'

    # Upgrade severity if product/version info reveals something risky
    combined = f'{service} {product} {version}'.lower()
    if any(k in combined for k in ['telnet', 'ftp', 'smb', 'redis', 'elasticsearch']):
        sev = 'CRITICAL'
    elif any(k in combined for k in ['mysql', 'postgres', 'mssql', 'mongodb', 'rdp']):
        sev = 'HIGH'

    return sev, svc, desc, rec


# ======================================================
# ===== JSON PARSER (for structured scan tool output) =====
# ======================================================

def parse_json_input(data):
    """
    Parse structured JSON scan output (e.g. from Nmap wrapper tools).
    Extracts: target, open ports, vulnerabilities, OS, metadata.
    """
    findings = {
        'vulnerabilities': [],
        'scan_results':    [],
        'notes':           [],
        'proofs':          [],
        'targets':         [],
        'date':            datetime.now().strftime('%B %d, %Y'),
        'title':           None,
        'raw_lines':       [],
        'input_format':    'json',
        'open_ports':      [],
        'os_matches':      [],
        'scan_metadata':   {},
    }

    # --- Extract metadata ---
    metadata = data.get('metadata', {})
    if metadata.get('target'):
        findings['targets'].append(metadata['target'])

    findings['scan_metadata'] = {
        'nmap_version':    metadata.get('nmap_version', 'Unknown'),
        'platform':        metadata.get('platform', 'Unknown'),
        'privilege_mode':  metadata.get('privilege_mode', 'Unknown'),
        'scans_executed':  metadata.get('scans_executed', []),
        'total_open_ports': metadata.get('total_open_ports', 0),
        'confidence':      data.get('confidence', None),
    }

    findings['title'] = (
        f"Vulnerability Assessment Report — {findings['targets'][0]}"
        if findings['targets'] else 'Vulnerability Assessment Report'
    )

    # --- Collect all unique open ports across all scan types ---
    seen_ports = set()
    all_ports  = []

    # Pull from raw_output first, then scan_results
    sources = []
    if 'raw_output' in data:
        sources.append(('raw_output', data['raw_output']))
    if 'scan_results' in data:
        for scan_name, scan_data in data['scan_results'].items():
            sources.append((scan_name, scan_data))

    for source_name, source_data in sources:
        if not isinstance(source_data, dict):
            continue
        for port_entry in source_data.get('open_ports', []):
            port_num = port_entry.get('port')
            if port_num and port_num not in seen_ports:
                seen_ports.add(port_num)
                all_ports.append({
                    'port':     port_num,
                    'protocol': port_entry.get('protocol', 'tcp'),
                    'service':  port_entry.get('service', ''),
                    'product':  port_entry.get('product', ''),
                    'version':  port_entry.get('version', ''),
                    'source':   source_name,
                })

    findings['open_ports'] = all_ports

    # --- Convert each open port into a vulnerability finding ---
    for p in all_ports:
        sev, svc_name, desc, rec = get_port_risk(
            p['port'], p['service'], p['product'], p['version']
        )

        product_str = f" ({p['product']})" if p['product'] else ''
        version_str = f" v{p['version']}"  if p['version'] else ''
        title       = f"Open Port {p['port']}/{p['protocol'].upper()} — {svc_name}{product_str}{version_str}"

        findings['vulnerabilities'].append({
            'description': title,
            'detail':      desc,
            'severity':    sev,
            'cve':         [],
            'cvss':        None,
            'recommendation': rec,
            'port':        p['port'],
            'service':     svc_name,
        })

    # --- Extract vulnerabilities if any exist in JSON ---
    raw_vulns = []
    if 'raw_output' in data:
        raw_vulns = data['raw_output'].get('vulnerabilities', [])
    if not raw_vulns and 'scan_results' in data:
        for scan_data in data['scan_results'].values():
            if isinstance(scan_data, dict):
                raw_vulns.extend(scan_data.get('vulnerabilities', []))

    for v in raw_vulns:
        desc = v.get('description', '') or v.get('name', '') or str(v)
        findings['vulnerabilities'].append({
            'description':    desc,
            'detail':         v.get('detail', ''),
            'severity':       v.get('severity', classify_severity(desc)).upper(),
            'cve':            extract_cve(desc) or ([v['cve']] if v.get('cve') else []),
            'cvss':           v.get('cvss', extract_cvss(desc)),
            'recommendation': v.get('recommendation', ''),
            'port':           v.get('port', None),
            'service':        v.get('service', ''),
        })

    # --- OS matches ---
    os_matches = []
    if 'raw_output' in data:
        os_matches = data['raw_output'].get('os_matches', [])
    findings['os_matches'] = os_matches

    # --- Scan result summary as notes ---
    scan_wise = metadata.get('scan_wise_counts', {})
    for scan_name, counts in scan_wise.items():
        findings['scan_results'].append({
            'detail': (
                f"{scan_name.replace('_', ' ').title()}: "
                f"{counts.get('open_ports', 0)} open port(s) found, "
                f"{counts.get('vulnerabilities', 0)} vulnerability(ies) detected."
            )
        })

    # --- Proof: raw scan evidence ---
    for p in all_ports:
        product_str = f", Product: {p['product']}" if p['product'] else ''
        version_str = f", Version: {p['version']}" if p['version'] else ''
        findings['proofs'].append({
            'detail': (
                f"Port {p['port']}/{p['protocol'].upper()} is open "
                f"[Service: {p['service'] or 'unknown'}{product_str}{version_str}] "
                f"— Detected via {p['source'].replace('_', ' ')}"
            )
        })

    return findings


# ======================================================
# ===== TAGGED TEXT PARSER (manual [VULN] [SCAN] etc.) =====
# ======================================================

def parse_tagged_text(raw_text):
    """Parse manually written findings files using [TAG] format."""
    findings = {
        'vulnerabilities': [],
        'scan_results':    [],
        'notes':           [],
        'proofs':          [],
        'targets':         [],
        'date':            None,
        'title':           None,
        'raw_lines':       [],
        'input_format':    'text',
        'open_ports':      [],
        'os_matches':      [],
        'scan_metadata':   {},
    }

    lines         = raw_text.splitlines()
    current_block = None
    current_text  = []

    def flush_block():
        if not current_block or not current_text:
            return
        text = ' '.join(current_text).strip()
        if not text:
            return
        if current_block == 'VULN':
            findings['vulnerabilities'].append({
                'description':    text,
                'detail':         '',
                'severity':       classify_severity(text),
                'cve':            extract_cve(text),
                'cvss':           extract_cvss(text),
                'recommendation': '',
                'port':           None,
                'service':        '',
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
        tag_match = re.match(r'^\[(\w+)\]\s*(.*)', line)

        if tag_match:
            flush_block()
            tag     = tag_match.group(1).upper()
            content = tag_match.group(2).strip()

            if tag == 'TARGET':
                if content: findings['targets'].append(content)
                current_block = None; current_text = []
            elif tag == 'DATE':
                if content: findings['date'] = content
                current_block = None; current_text = []
            elif tag == 'TITLE':
                if content: findings['title'] = content
                current_block = None; current_text = []
            elif tag in ('VULN', 'SCAN', 'NOTE', 'PROOF'):
                current_block = tag
                current_text  = [content] if content else []
            else:
                current_block = 'NOTE'
                current_text  = [line]
        else:
            if current_block:
                current_text.append(line)
            else:
                findings['notes'].append({'detail': line})

    flush_block()
    return findings


# ======================================================
# ===== MAIN ENTRY POINT =====
# ======================================================

def parse_findings(raw_text):
    """
    Auto-detect input format and parse accordingly.
    Returns unified findings dict for report_builder.py
    """
    stripped = raw_text.strip()

    # --- Detect JSON ---
    if stripped.startswith('{') or stripped.startswith('['):
        try:
            data = json.loads(stripped)
            return parse_json_input(data)
        except json.JSONDecodeError:
            pass  # Fall through to text parser

    # --- Default: tagged text ---
    return parse_tagged_text(raw_text)


def get_summary_stats(findings):
    """Return severity count summary dict."""
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFORMATIONAL': 0}
    for v in findings['vulnerabilities']:
        sev = v.get('severity', 'INFORMATIONAL')
        counts[sev] = counts.get(sev, 0) + 1
    return counts