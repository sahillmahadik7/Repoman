# app.py — Main Flask application
# Handles routes: upload, parse, generate PDF, preview, progress

import os
import uuid
import json
import glob
import threading
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename

from findings_parser import parse_findings      # renamed from 'parser' (built-in conflict)
from report_builder import build_report
from pdf_generator import generate_pdf

# ===== SETUP =====
app = Flask(__name__)
CORS(app)

BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER  = os.path.join(BASE_DIR, '..', 'uploads')
OUTPUT_FOLDER  = os.path.join(BASE_DIR, '..', 'outputs')
SAMPLE_FOLDER  = os.path.join(BASE_DIR, '..', 'samples')

ALLOWED_EXTENSIONS  = {'txt', 'json'}
MAX_FILE_SIZE        = 10 * 1024 * 1024   # 10 MB
MAX_FILES_PER_UPLOAD = 5
OUTPUT_MAX_AGE_HOURS = 2                  # clean up PDFs older than 2 hours

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)
os.makedirs(SAMPLE_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER']       = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH']  = MAX_FILE_SIZE * MAX_FILES_PER_UPLOAD

# In-memory job progress store  { job_id: { status, step, percent, error, pdf_path } }
jobs = {}
jobs_lock = threading.Lock()


# ===== HELPERS =====
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def cleanup_old_outputs():
    """Delete PDF files older than OUTPUT_MAX_AGE_HOURS."""
    cutoff = datetime.now() - timedelta(hours=OUTPUT_MAX_AGE_HOURS)
    for pdf in glob.glob(os.path.join(OUTPUT_FOLDER, '*.pdf')):
        try:
            mtime = datetime.fromtimestamp(os.path.getmtime(pdf))
            if mtime < cutoff:
                os.remove(pdf)
        except Exception:
            pass


def update_job(job_id, step, percent, status='running', error=None, pdf_path=None):
    with jobs_lock:
        jobs[job_id] = {
            'status':   status,
            'step':     step,
            'percent':  percent,
            'error':    error,
            'pdf_path': pdf_path,
        }


def merge_findings(findings_list):
    """Merge multiple parsed findings dicts into one unified findings dict."""
    if len(findings_list) == 1:
        return findings_list[0]

    merged = findings_list[0].copy()
    for f in findings_list[1:]:
        merged['vulnerabilities'] += f['vulnerabilities']
        merged['scan_results']    += f['scan_results']
        merged['notes']           += f['notes']
        merged['proofs']          += f['proofs']
        merged['open_ports']      += f['open_ports']
        merged['os_matches']      += f['os_matches']

        # Merge targets (deduplicate)
        for t in f['targets']:
            if t not in merged['targets']:
                merged['targets'].append(t)

        # Merge scan metadata
        for k, v in f.get('scan_metadata', {}).items():
            if k == 'scans_executed' and isinstance(v, list):
                existing = merged['scan_metadata'].get('scans_executed', [])
                merged['scan_metadata']['scans_executed'] = list(set(existing + v))
            elif k not in merged['scan_metadata']:
                merged['scan_metadata'][k] = v

        # Keep title/date from first file unless missing
        if not merged.get('title') and f.get('title'):
            merged['title'] = f['title']
        if not merged.get('date') and f.get('date'):
            merged['date'] = f['date']

    # Deduplicate open ports by port number
    seen = set()
    unique_ports = []
    for p in merged['open_ports']:
        if p['port'] not in seen:
            seen.add(p['port'])
            unique_ports.append(p)
    merged['open_ports'] = unique_ports

    return merged


def run_generation_job(job_id, filepaths, meta):
    """Background thread: parse → build → generate PDF."""
    saved_paths = filepaths  # already saved temp files

    try:
        # Step 1 — Read & parse all files
        update_job(job_id, 'Reading and parsing uploaded file(s)...', 15)
        findings_list = []

        for fpath in saved_paths:
            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    raw_text = f.read()
                if raw_text.strip():
                    parsed = parse_findings(raw_text)
                    findings_list.append(parsed)
            except Exception as e:
                update_job(job_id, '', 0, status='error',
                           error=f'Failed to read file {os.path.basename(fpath)}: {str(e)}')
                return
            finally:
                # Clean up uploaded file
                try: os.remove(fpath)
                except: pass

        if not findings_list:
            update_job(job_id, '', 0, status='error',
                       error='All uploaded files were empty or unreadable.')
            return

        # Step 2 — Merge multiple files
        update_job(job_id, 'Merging findings from all files...', 30)
        merged = merge_findings(findings_list)

        # Apply user-supplied meta overrides
        if meta.get('report_title'):
            merged['title'] = meta['report_title']
        if meta.get('assessor_name'):
            merged['assessor_name'] = meta['assessor_name']
        if meta.get('target'):
            if not merged['targets']:
                merged['targets'] = [meta['target']]

        # Validate: must have something to report
        has_data = (
            merged['vulnerabilities'] or
            merged['scan_results']    or
            merged['notes']           or
            merged['open_ports']
        )
        if not has_data:
            update_job(job_id, '', 0, status='error',
                       error=(
                           'No recognizable findings detected in any uploaded file. '
                           'For JSON files, ensure they contain open_ports or vulnerabilities. '
                           'For text files, use tags like [VULN], [SCAN], [NOTE].'
                       ))
            return

        # Step 3 — Build report structure
        update_job(job_id, 'Building report sections...', 55)
        report_data = build_report(merged)

        # Step 4 — Generate PDF
        update_job(job_id, 'Generating PDF...', 75)
        cleanup_old_outputs()

        safe_title   = secure_filename(report_data['title'].replace(' ', '_'))[:40]
        out_filename = f"CyberReport_{safe_title}_{job_id[:8]}.pdf"
        out_path     = os.path.join(OUTPUT_FOLDER, out_filename)

        generate_pdf(report_data, out_path)

        # Step 5 — Done
        update_job(job_id, 'Report ready!', 100,
                   status='done', pdf_path=out_path)

    except Exception as e:
        # Clean up any remaining temp files
        for fpath in saved_paths:
            try: os.remove(fpath)
            except: pass
        update_job(job_id, '', 0, status='error',
                   error=f'Report generation failed: {str(e)}')


# ===== ROUTES =====

@app.route('/')
def index():
    return jsonify({'status': 'CyberReport API is running', 'version': '2.0'})


@app.route('/generate', methods=['POST'])
def generate():
    """
    Accepts 1–5 files + optional metadata.
    Starts a background job and returns a job_id immediately.
    Frontend polls /progress/<job_id> for updates.
    """

    # --- Validate files ---
    if 'files' not in request.files and 'file' not in request.files:
        return jsonify({'error': 'No files uploaded.'}), 400

    # Support both 'file' (single) and 'files' (multiple) field names
    file_list = request.files.getlist('files') or request.files.getlist('file')
    file_list = [f for f in file_list if f and f.filename]

    if not file_list:
        return jsonify({'error': 'No files selected.'}), 400

    if len(file_list) > MAX_FILES_PER_UPLOAD:
        return jsonify({'error': f'Maximum {MAX_FILES_PER_UPLOAD} files per upload.'}), 400

    # --- Validate & save files ---
    saved_paths = []
    for file in file_list:
        if not allowed_file(file.filename):
            return jsonify({'error': f'Invalid file type: {file.filename}. Only .txt and .json files are accepted.'}), 400

        filename  = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
        save_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(save_path)
        saved_paths.append(save_path)

    # --- Parse optional metadata from form ---
    meta = {
        'report_title':  request.form.get('report_title', '').strip(),
        'assessor_name': request.form.get('assessor_name', '').strip(),
        'target':        request.form.get('target', '').strip(),
    }

    # --- Create job & start background thread ---
    job_id = uuid.uuid4().hex
    update_job(job_id, 'Job queued...', 5)

    thread = threading.Thread(
        target=run_generation_job,
        args=(job_id, saved_paths, meta),
        daemon=True
    )
    thread.start()

    return jsonify({'job_id': job_id}), 202


@app.route('/progress/<job_id>', methods=['GET'])
def progress(job_id):
    """Poll endpoint — returns current job status."""
    with jobs_lock:
        job = jobs.get(job_id)

    if not job:
        return jsonify({'error': 'Job not found.'}), 404

    return jsonify({
        'status':  job['status'],
        'step':    job['step'],
        'percent': job['percent'],
        'error':   job['error'],
    })


@app.route('/download/<job_id>', methods=['GET'])
def download(job_id):
    """Download the generated PDF once the job is done."""
    with jobs_lock:
        job = jobs.get(job_id)

    if not job:
        return jsonify({'error': 'Job not found.'}), 404
    if job['status'] != 'done':
        return jsonify({'error': 'Report not ready yet.'}), 400
    if not job['pdf_path'] or not os.path.exists(job['pdf_path']):
        return jsonify({'error': 'PDF file not found. It may have been cleaned up.'}), 404

    return send_file(
        job['pdf_path'],
        mimetype='application/pdf',
        as_attachment=True,
        download_name=os.path.basename(job['pdf_path'])
    )


@app.route('/preview/<job_id>', methods=['GET'])
def preview(job_id):
    """Return a JSON preview of report sections (for in-browser preview)."""
    with jobs_lock:
        job = jobs.get(job_id)

    if not job or job['status'] != 'done':
        return jsonify({'error': 'Report not ready.'}), 400

    # Re-parse report data for preview (lightweight)
    # Store report_data on job for preview use
    report_data = job.get('report_data')
    if not report_data:
        return jsonify({'error': 'Preview data not available.'}), 404

    return jsonify({
        'title':             report_data['title'],
        'targets':           report_data['targets'],
        'date':              report_data['date'],
        'overall_risk':      report_data['overall_risk'],
        'total_findings':    report_data['total_findings'],
        'severity_stats':    report_data['severity_stats'],
        'executive_summary': report_data['executive_summary'],
        'vulnerabilities': [
            {
                'description': v['description'],
                'severity':    v['severity'],
                'cve':         v.get('cve', []),
                'recommendation': v.get('recommendation', ''),
            }
            for v in report_data['vulnerabilities']
        ],
        'ports_table': report_data.get('ports_table', []),
    })


@app.route('/sample', methods=['GET'])
def get_sample():
    """Return a sample input .txt file for download."""
    sample_content = """\
# CyberReport — Sample Input File
# Lines starting with # are ignored
# Use the tags below to structure your findings

[TITLE] Web Application Security Assessment — ACME Corp

[TARGET] 192.168.1.100 — ACME Corp Internal Web Server
[TARGET] 192.168.1.101 — ACME Corp Admin Panel

[DATE] 2024-11-15

[VULN] CVE-2023-44487 — HTTP/2 Rapid Reset Attack. The web server is vulnerable to
denial of service via HTTP/2 stream cancellation. CVSS: 7.5

[VULN] SQL Injection found in /login endpoint. User-supplied input is passed directly
to database queries without sanitization. Unauthenticated remote attacker can dump
the entire database.

[VULN] Cross-Site Scripting (XSS) in /search?q= parameter. Reflected XSS allows
an attacker to execute arbitrary JavaScript in a victim's browser session.

[VULN] Default credentials found on admin panel — admin:admin123. Authentication
bypass possible. Weak password policy in effect.

[SCAN] Nmap scan results: Port 22/tcp open (OpenSSH 7.2), Port 80/tcp open (Apache 2.4.49),
Port 443/tcp open (Apache 2.4.49), Port 3306/tcp open (MySQL 5.7 outdated)

[SCAN] Nikto scan identified missing security headers: X-Frame-Options, X-XSS-Protection,
Content-Security-Policy not set on any endpoint.

[NOTE] Application runs on outdated Apache 2.4.49 which is vulnerable to path traversal
(CVE-2021-41773). Immediate patching required.

[NOTE] TLS 1.0 and TLS 1.1 are still enabled on the server. Only TLS 1.2 and 1.3
should be accepted.

[PROOF] Screenshot captured showing full database dump via SQLi on /login endpoint.
Extracted tables: users, sessions, transactions, admin_accounts.

[PROOF] Proof of concept XSS payload executed: <script>alert(document.cookie)</script>
confirmed in browser console with session token visible.
"""
    from flask import Response
    return Response(
        sample_content,
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment; filename=sample_findings.txt'}
    )


# ===== RUN =====
if __name__ == '__main__':
    print('=' * 55)
    print('  CyberReport API — v2.0')
    print('  http://127.0.0.1:5000')
    print('  Endpoints:')
    print('    POST /generate       — Upload files, start job')
    print('    GET  /progress/:id   — Poll job progress')
    print('    GET  /download/:id   — Download PDF')
    print('    GET  /sample         — Download sample input file')
    print('=' * 55)
    app.run(debug=True, host='127.0.0.1', port=5000)