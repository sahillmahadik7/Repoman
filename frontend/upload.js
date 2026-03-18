// ===== upload.js =====
// Handles file selection, drag & drop, and sending to backend

const uploadCard   = document.getElementById('uploadCard');
const fileInput    = document.getElementById('fileInput');
const fileInfo     = document.getElementById('fileInfo');
const fileName     = document.getElementById('fileName');
const fileSize     = document.getElementById('fileSize');
const generateBtn  = document.getElementById('generateBtn');
const progressWrap = document.getElementById('progressWrap');
const progressFill = document.getElementById('progressFill');
const progressLabel= document.getElementById('progressLabel');
const progressSteps= document.getElementById('progressSteps');
const errorBox     = document.getElementById('errorBox');

let selectedFile = null;

// ===== DRAG & DROP =====
uploadCard.addEventListener('dragover', (e) => {
  e.preventDefault();
  uploadCard.classList.add('drag-over');
});

uploadCard.addEventListener('dragleave', () => {
  uploadCard.classList.remove('drag-over');
});

uploadCard.addEventListener('drop', (e) => {
  e.preventDefault();
  uploadCard.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) handleFile(file);
});

// ===== FILE INPUT CHANGE =====
fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) handleFile(fileInput.files[0]);
});

// ===== HANDLE FILE =====
function handleFile(file) {
  hideError();

  if (!file.name.endsWith('.txt')) {
    showError('❌ Only .txt files are supported. Please upload a plain text file.');
    return;
  }

  if (file.size > 5 * 1024 * 1024) {
    showError('❌ File too large. Maximum size is 5MB.');
    return;
  }

  selectedFile = file;
  fileName.textContent = file.name;
  fileSize.textContent = formatSize(file.size);
  fileInfo.style.display = 'flex';
  generateBtn.disabled = false;
}

// ===== CLEAR FILE =====
function clearFile() {
  selectedFile = null;
  fileInput.value = '';
  fileInfo.style.display = 'none';
  generateBtn.disabled = true;
  hideError();
  hideProgress();
}

// ===== GENERATE REPORT =====
async function generateReport() {
  if (!selectedFile) return;

  hideError();
  generateBtn.disabled = true;
  showProgress();

  const formData = new FormData();
  formData.append('file', selectedFile);

  try {
    // Step 1
    setStep('Parsing findings file...', 20);
    await sleep(400);

    // Step 2
    setStep('Categorizing vulnerabilities...', 45);
    await sleep(300);

    // Step 3
    setStep('Building report sections...', 65);

    const response = await fetch('http://127.0.0.1:5000/generate', {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error || 'Server error. Please try again.');
    }

    // Step 4
    setStep('Generating PDF...', 85);
    await sleep(300);

    // Step 5 — download blob
    setStep('Finalizing report...', 100);
    const blob = await response.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `CyberReport_${Date.now()}.pdf`;
    a.click();
    URL.revokeObjectURL(url);

    setStep('✅ Report downloaded successfully!', 100, true);
    generateBtn.disabled = false;

  } catch (err) {
    hideProgress();
    showError('❌ ' + err.message);
    generateBtn.disabled = false;
  }
}

// ===== PROGRESS HELPERS =====
const steps = [
  'Parsing findings file...',
  'Categorizing vulnerabilities...',
  'Building report sections...',
  'Generating PDF...',
  'Finalizing report...',
];

function showProgress() {
  progressWrap.style.display = 'block';
  progressSteps.innerHTML = '';
  steps.forEach((s, i) => {
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

  const stepIndex = steps.indexOf(label);
  if (stepIndex >= 0) {
    for (let i = 0; i < steps.length; i++) {
      const el = document.getElementById(`step-${i}`);
      if (!el) continue;
      if (i < stepIndex) {
        el.innerHTML = `<span class="step-done">✓</span> ${steps[i]}`;
      } else if (i === stepIndex) {
        el.innerHTML = `<span class="step-active">▶</span> ${steps[i]}`;
      }
    }
  }

  if (done) {
    steps.forEach((s, i) => {
      const el = document.getElementById(`step-${i}`);
      if (el) el.innerHTML = `<span class="step-done">✓</span> ${s}`;
    });
  }
}

function hideProgress() {
  progressWrap.style.display = 'none';
}

// ===== ERROR HELPERS =====
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
  return new Promise(resolve => setTimeout(resolve, ms));
}