# Handles routes: upload, parse, generate PDF

import os
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename

from parser import parse_findings
from report_builder import build_report
from pdf_generator import generate_pdf

# ===== SETUP =====
app = Flask(__name__)
CORS(app)  # Allow frontend to talk to backend

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'uploads')
OUTPUT_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'outputs')
ALLOWED_EXTENSIONS = {'txt'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE


# ===== HELPERS =====
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ===== ROUTES =====

@app.route('/')
def index():
    return jsonify({"status": "CyberReport API is running", "version": "1.0"})


@app.route('/generate', methods=['POST'])
def generate():
    """
    Main route:
    1. Receives uploaded .txt file
    2. Parses findings
    3. Builds report structure
    4. Generates PDF
    5. Returns PDF as download
    """

    # --- Validate file exists in request ---
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded. Please select a .txt file."}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No file selected."}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type. Only .txt files are accepted."}), 400

    # --- Save uploaded file ---
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        # --- Step 1: Parse the text file ---
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            raw_text = f.read()

        if not raw_text.strip():
            return jsonify({"error": "Uploaded file is empty."}), 400

        findings = parse_findings(raw_text)

        if not findings['vulnerabilities'] and not findings['scan_results'] and not findings['notes']:
            return jsonify({
                "error": "No recognizable findings detected. "
                         "Please use tags like [VULN], [SCAN], [NOTE], [PROOF] in your file."
            }), 400

        # --- Step 2: Build report structure ---
        report_data = build_report(findings)

        # --- Step 3: Generate PDF ---
        output_filename = f"CyberReport_{os.path.splitext(filename)[0]}.pdf"
        output_path = os.path.join(OUTPUT_FOLDER, output_filename)

        generate_pdf(report_data, output_path)

        # --- Step 4: Return PDF ---
        return send_file(
            output_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=output_filename
        )

    except Exception as e:
        return jsonify({"error": f"Report generation failed: {str(e)}"}), 500

    finally:
        # Clean up uploaded file
        if os.path.exists(filepath):
            os.remove(filepath)


# ===== RUN =====
if __name__ == '__main__':
    print("=" * 50)
    print("  CyberReport API — Phase 1")
    print("  Running at: http://127.0.0.1:5000")
    print("=" * 50)
    app.run(debug=True, host='127.0.0.1', port=5000)
