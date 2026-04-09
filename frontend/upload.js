// ===== upload.js =====
// Handles file selection, multiple uploads, real progress polling,
// report preview panel, and PDF download

const API = 'http://127.0.0.1:5000';

// ===== DOM REFS =====
const fileInput = document.getElementById('fileInput');
const fileList = document.getElementById('fileList');
const generateBtn = document.getElementById('generateBtn');
const progressWrap = document.getElementById('progressWrap');
const progressFill = document.getElementById('progressFill');
const progressLabel = document.getElementById('progressLabel');
const progressSteps = document.getElementById('progressSteps');
const errorBox = document.getElementById('errorBox');
const previewPanel = document.getElementById('previewPanel');
const metaForm = document.getElementById('metaForm');

let selectedFiles = [];
let pollInterval = null;

// ===== STEPS =====
const STEPS = [
  'Reading and parsing uploaded file(s)...',
  'Merging findings from all files...',
  'Building report sections...',
  'Generating PDF...',
  'Report ready!',
];

// ===== FILE INPUT =====
fileInput.addEventListener('change', () => {
  const newFiles = Array.from(fileInput.files);
  addFiles(newFiles);
  fileInput.value = '';
});

function addFiles(newFiles) {
  hideError();
  for (const file of newFiles) {
    if (!file.name.match(/\.(txt|json)$/i)) {
      showError(`❌ "${file.name}" is not supported. Only .txt and .json files are accepted.`);
      continue;
    }
    if (file.size > 10 * 1024 * 1024) {
      showError(`❌ "${file.name}" exceeds 10MB limit.`);
      continue;
    }
    if (selectedFiles.length >= 5) {
      showError('❌ Maximum 5 files per upload.');
      break;
    }
    if (!selectedFiles.find(f => f.name === file.name && f.size === file.size)) {
      selectedFiles.push(file);
    }
  }
  renderFileList();
}

function removeFile(index) {
  selectedFiles.splice(index, 1);
  renderFileList();
  hideError();
}

function renderFileList() {
  fileList.innerHTML = '';
  if (selectedFiles.length === 0) {
    generateBtn.disabled = true;
    return;
  }

  selectedFiles.forEach((file, i) => {
    const row = document.createElement('div');
    row.className = 'file-row';
    row.innerHTML = `
      <span class="file-icon-sm">${file.name.endsWith('.json') ? '{}' : '📄'}</span>
      <div class="file-details">
        <span class="file-name">${file.name}</span>
        <span class="file-size">${formatSize(file.size)}</span>
      </div>
      <button class="btn-clear" onclick="removeFile(${i})" title="Remove">✕</button>
    `;
    fileList.appendChild(row);
  });

  generateBtn.disabled = false;
}

// ===== GENERATE =====
async function generateReport() {
  if (selectedFiles.length === 0) return;

  hideError();
  hidePreview();
  generateBtn.disabled = true;
  showProgress();

  const formData = new FormData();

  // Append all files under 'files' key
  selectedFiles.forEach(f => formData.append('files', f));

  // Append optional metadata
  if (metaForm) {
    const title = document.getElementById('reportTitle')?.value.trim();
    const assessor = document.getElementById('assessorName')?.value.trim();
    const target = document.getElementById('targetName')?.value.trim();
    if (title) formData.append('report_title', title);
    if (assessor) formData.append('assessor_name', assessor);
    if (target) formData.append('target', target);
  }

  try {
    // POST to /generate — returns job_id immediately
    setStep('Uploading file(s) to server...', 5);

    const res = await fetch(`${API}/generate`, {
      method: 'POST',
      body: formData,
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Upload failed. Is the backend running?');
    }

    const { job_id } = await res.json();

    // Start polling
    startPolling(job_id);

  } catch (err) {
    hideProgress();
    showError('❌ ' + err.message);
    generateBtn.disabled = false;
  }
}

// ===== REAL PROGRESS POLLING =====
function startPolling(job_id) {
  clearInterval(pollInterval);

  pollInterval = setInterval(async () => {
    try {
      const res = await fetch(`${API}/progress/${job_id}`);
      const data = await res.json();

      if (data.error && data.status !== 'error') {
        // Job not found
        clearInterval(pollInterval);
        hideProgress();
        showError('❌ Job lost. Please try again.');
        generateBtn.disabled = false;
        return;
      }

      // Update progress bar
      setStep(data.step || '...', data.percent || 0);

      if (data.status === 'error') {
        clearInterval(pollInterval);
        hideProgress();
        showError('❌ ' + (data.error || 'Unknown error.'));
        generateBtn.disabled = false;

      } else if (data.status === 'done') {
        clearInterval(pollInterval);
        setStep('✅ Report ready!', 100, true);

        // Trigger download
        await sleep(600);
        triggerDownload(job_id);

        // Show preview
        await loadPreview(job_id);

        generateBtn.disabled = false;
      }

    } catch (e) {
      clearInterval(pollInterval);
      hideProgress();
      showError('❌ Lost connection to server. Is the backend still running?');
      generateBtn.disabled = false;
    }
  }, 800);
}

async function triggerDownload(job_id) {
  const a = document.createElement('a');
  a.href = `${API}/download/${job_id}`;
  a.download = `CyberReport_${Date.now()}.pdf`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

// ===== REPORT PREVIEW =====
async function loadPreview(job_id) {
  try {
    const res = await fetch(`${API}/preview/${job_id}`);
    if (!res.ok) return;
    const data = await res.json();
    renderPreview(data);
  } catch (e) {
    // Preview is optional — silently fail
  }
}

function renderPreview(data) {
  if (!previewPanel) return;

  const riskColors = {
    CRITICAL: '#c0392b', HIGH: '#e67e22', MEDIUM: '#f39c12',
    LOW: '#2980b9', INFORMATIONAL: '#7f8c8d'
  };
  const riskColor = riskColors[data.overall_risk] || '#7f8c8d';

  const stats = data.severity_stats || {};
  const statsHtml = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'].map(s => `
    <div class="prev-stat">
      <span class="prev-stat-label">${s}</span>
      <span class="prev-stat-count" style="color:${riskColors[s]}">${stats[s] || 0}</span>
    </div>
  `).join('');

  const vulnsHtml = (data.vulnerabilities || []).slice(0, 5).map(v => `
    <div class="prev-finding">
      <span class="prev-sev" style="color:${riskColors[v.severity]}">[${v.severity}]</span>
      <span class="prev-desc">${v.description}</span>
    </div>
  `).join('') || '<p class="prev-empty">No vulnerability findings.</p>';

  const moreCount = (data.vulnerabilities || []).length - 5;

  previewPanel.innerHTML = `
    <div class="preview-header">
      <div class="preview-title-row">
        <span class="preview-tag">// REPORT PREVIEW</span>
        <button class="btn-close-preview" onclick="hidePreview()">✕ Close</button>
      </div>
      <h3 class="preview-report-title">${data.title || 'Vulnerability Assessment Report'}</h3>
      <div class="preview-meta">
        <span>🎯 ${(data.targets || []).join(', ') || 'N/A'}</span>
        <span>📅 ${data.date || 'N/A'}</span>
        <span>📊 ${data.total_findings || 0} findings</span>
        <span class="preview-risk" style="color:${riskColor}">⚠ Overall: ${data.overall_risk}</span>
      </div>
    </div>

    <div class="preview-section">
      <div class="preview-section-title">Severity Breakdown</div>
      <div class="prev-stats-row">${statsHtml}</div>
    </div>

    <div class="preview-section">
      <div class="preview-section-title">Executive Summary</div>
      <p class="prev-summary">${data.executive_summary || ''}</p>
    </div>

    <div class="preview-section">
      <div class="preview-section-title">Top Findings</div>
      ${vulnsHtml}
      ${moreCount > 0 ? `<p class="prev-more">+ ${moreCount} more findings in the full PDF report</p>` : ''}
    </div>
  `;

  previewPanel.style.display = 'block';
  previewPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function hidePreview() {
  if (previewPanel) previewPanel.style.display = 'none';
}

// ===== SAMPLE FILE DOWNLOAD =====
function downloadSample() {
  const a = document.createElement('a');
  a.href = `${API}/sample`;
  a.download = 'sample_findings.txt';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

// ===== PROGRESS UI =====
function showProgress() {
  progressWrap.style.display = 'block';
  progressSteps.innerHTML = '';
  STEPS.forEach((s, i) => {
    const div = document.createElement('div');
    div.className = 'step-line';
    div.id = `step-${i}`;
    div.innerHTML = `<span class="step-wait">○</span> ${s}`;
    progressSteps.appendChild(div);
  });
}

function setStep(label, percent, done = false) {
  progressLabel.textContent = label;
  progressFill.style.width = percent + '%';

  const idx = STEPS.indexOf(label);
  if (idx >= 0) {
    for (let i = 0; i < STEPS.length; i++) {
      const el = document.getElementById(`step-${i}`);
      if (!el) continue;
      if (i < idx) el.innerHTML = `<span class="step-done">✓</span> ${STEPS[i]}`;
      else if (i === idx) el.innerHTML = `<span class="step-active">▶</span> ${STEPS[i]}`;
    }
  }
  if (done) {
    STEPS.forEach((s, i) => {
      const el = document.getElementById(`step-${i}`);
      if (el) el.innerHTML = `<span class="step-done">✓</span> ${s}`;
    });
  }
}

function hideProgress() {
  progressWrap.style.display = 'none';
}

// ===== ERROR =====
function showError(msg) {
  errorBox.textContent = msg;
  errorBox.style.display = 'block';
}
function hideError() {
  errorBox.textContent = '';
  errorBox.style.display = 'none';
}

// ===== UTILS =====
function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}
function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}