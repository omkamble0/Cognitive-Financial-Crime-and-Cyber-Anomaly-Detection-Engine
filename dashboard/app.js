// AegisFlow AI — Enterprise Risk & Fraud Intelligence Platform
// Author: Om Kamble

let currentRawData = null;
let currentDatasetRecords = [];
let currentSensitivityThreshold = 0.50;

let chartHistogram = null;
let chartHistogramTab2 = null;
let chartSparkline = null;
let chartScatter = null;
let chartFeatureDrivers = null;
let chartDonut = null;
let activeFilter = "all";

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initCharts();
  initUploadBox();
  initSampleButtons();
  initThresholdSlider();
  initWebSocket();
  initSandboxForm();
  initCyberDefenseSuite();
  initModal();
  initAuth();

  // Header quick upload button
  const btnHeaderUpload = document.getElementById("btnHeaderUpload");
  if (btnHeaderUpload) {
    btnHeaderUpload.addEventListener("click", () => {
      document.getElementById("csvFileInput").click();
    });
  }

  // Preload default credit card sample dataset on launch
  loadSampleDataset("creditcard");
});

// ==========================================
// 1. TABS NAVIGATION & DOCK SYNC
// ==========================================
function initTabs() {
  const dockBtns = document.querySelectorAll(".dock-btn");
  const navPills = document.querySelectorAll(".nav-pill");

  function switchTab(targetId) {
    dockBtns.forEach(btn => {
      btn.classList.toggle("active", btn.getAttribute("data-tab") === targetId);
    });
    navPills.forEach(pill => {
      pill.classList.toggle("active", pill.getAttribute("data-tab") === targetId);
    });

    document.querySelectorAll(".tab-pane").forEach(pane => pane.classList.remove("active"));
    const targetPane = document.getElementById(targetId);
    if (targetPane) {
      targetPane.classList.add("active");
    }
  }

  dockBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-tab");
      if (targetId) switchTab(targetId);
    });
  });

  navPills.forEach(pill => {
    pill.addEventListener("click", () => {
      const targetId = pill.getAttribute("data-tab");
      if (targetId) switchTab(targetId);
    });
  });
}

// ==========================================
// 2. CHART.JS INITIALIZATION (LIGHT FINTECH STYLE)
// ==========================================
function initCharts() {
  const fontConfig = {
    family: "'Plus Jakarta Sans', system-ui, -apple-system, sans-serif",
    size: 11,
    weight: "600"
  };

  // Chart 1: Center Engagement / Score Distribution Bars (Emerald & Mint Tones)
  const elHist = document.getElementById("chartRiskHistogram");
  if (elHist) {
    const ctxHist = elHist.getContext("2d");
    chartHistogram = new Chart(ctxHist, {
      type: "bar",
      data: {
        labels: ["0.0-0.2", "0.2-0.4", "0.4-0.6", "0.6-0.8", "0.8-1.0"],
        datasets: [{
          label: "Scanned Transactions",
          data: [0, 0, 0, 0, 0],
          backgroundColor: [
            "rgba(16, 185, 129, 0.4)",
            "rgba(16, 185, 129, 0.55)",
            "rgba(16, 185, 129, 0.7)",
            "#059669",
            "#064e3b"
          ],
          borderRadius: 14,
          borderSkipped: false,
          barPercentage: 0.65
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "#111827",
            titleColor: "#ffffff",
            bodyColor: "#ffffff",
            cornerRadius: 10,
            padding: 10
          }
        },
        scales: {
          y: {
            display: false
          },
          x: {
            grid: { display: false },
            ticks: { color: "#64748b", font: fontConfig }
          }
        }
      }
    });
  }

  // Chart 2: Mini Sparkline Curve (Right Bento Card)
  const elSpark = document.getElementById("chartSparkline");
  if (elSpark) {
    const ctxSpark = elSpark.getContext("2d");
    chartSparkline = new Chart(ctxSpark, {
      type: "line",
      data: {
        labels: ["T-6", "T-5", "T-4", "T-3", "T-2", "T-1", "Now"],
        datasets: [{
          data: [12, 19, 15, 27, 22, 34, 28],
          borderColor: "#059669",
          backgroundColor: "rgba(16, 185, 129, 0.12)",
          fill: true,
          tension: 0.4,
          pointRadius: 0,
          borderWidth: 2.5
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        scales: {
          x: { display: false },
          y: { display: false }
        }
      }
    });
  }

  // Chart 3: Tab 2 Histogram Copy
  const elHist2 = document.getElementById("chartRiskHistogramTab2");
  if (elHist2) {
    const ctxHist2 = elHist2.getContext("2d");
    chartHistogramTab2 = new Chart(ctxHist2, {
      type: "bar",
      data: {
        labels: ["0.0 - 0.2", "0.2 - 0.4", "0.4 - 0.6", "0.6 - 0.8", "0.8 - 1.0"],
        datasets: [{
          label: "Volume",
          data: [0, 0, 0, 0, 0],
          backgroundColor: ["#10b981", "#3b82f6", "#f59e0b", "#f97316", "#ef4444"],
          borderRadius: 8
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { grid: { color: "#f1f5f9" }, ticks: { color: "#64748b", font: fontConfig } },
          x: { grid: { display: false }, ticks: { color: "#64748b", font: fontConfig } }
        }
      }
    });
  }

  // Chart 4: Scatter Plot (Amount vs Risk)
  const elScatter = document.getElementById("chartScatterCluster");
  if (elScatter) {
    const ctxScatter = elScatter.getContext("2d");
    chartScatter = new Chart(ctxScatter, {
      type: "scatter",
      data: {
        datasets: [
          { label: "Approved", data: [], backgroundColor: "rgba(16, 185, 129, 0.7)", pointRadius: 5 },
          { label: "2FA Review", data: [], backgroundColor: "rgba(245, 158, 11, 0.8)", pointRadius: 6 },
          { label: "Blocked", data: [], backgroundColor: "rgba(239, 68, 68, 0.9)", pointRadius: 7 }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "top", labels: { color: "#334155", font: fontConfig, usePointStyle: true } }
        },
        scales: {
          x: { title: { display: true, text: "Amount ($)", color: "#64748b" }, grid: { color: "#f1f5f9" } },
          y: { title: { display: true, text: "Risk Score", color: "#64748b" }, min: 0, max: 1.05, grid: { color: "#f1f5f9" } }
        }
      }
    });
  }

  // Chart 5: Feature Drivers
  const elFeat = document.getElementById("chartFeatureDrivers");
  if (elFeat) {
    const ctxFeat = elFeat.getContext("2d");
    chartFeatureDrivers = new Chart(ctxFeat, {
      type: "bar",
      data: {
        labels: ["V14", "V12", "V10", "V4", "V17", "Amount"],
        datasets: [{
          label: "Contribution %",
          data: [28, 22, 18, 14, 10, 8],
          backgroundColor: "#059669",
          borderRadius: 8
        }]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: "#f1f5f9" }, ticks: { color: "#64748b" } },
          y: { grid: { display: false }, ticks: { color: "#1e293b", font: fontConfig } }
        }
      }
    });
  }

  // Chart 6: Decision Donut
  const elDonut = document.getElementById("chartDecisionDonut");
  if (elDonut) {
    const ctxDonut = elDonut.getContext("2d");
    chartDonut = new Chart(ctxDonut, {
      type: "doughnut",
      data: {
        labels: ["Approved", "2FA Review", "Blocked Fraud"],
        datasets: [{
          data: [1, 0, 0],
          backgroundColor: ["#10b981", "#f59e0b", "#ef4444"],
          borderWidth: 0,
          hoverOffset: 8
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { color: "#334155", font: fontConfig, usePointStyle: true } }
        },
        cutout: "70%"
      }
    });
  }
}

// ==========================================
// 3. FILE UPLOAD & DROPZONE
// ==========================================
function initUploadBox() {
  const dropzoneBox = document.getElementById("dropzoneBox");
  const fileInput = document.getElementById("csvFileInput");
  const browseBtn = document.getElementById("btnBrowseFile");
  const btnUploadAnother = document.getElementById("btnUploadAnother");

  browseBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    fileInput.click();
  });

  dropzoneBox.addEventListener("click", (e) => {
    if (e.target.tagName !== "BUTTON") {
      fileInput.click();
    }
  });

  dropzoneBox.addEventListener("dragover", (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropzoneBox.classList.add("dragover");
  });

  dropzoneBox.addEventListener("dragleave", (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropzoneBox.classList.remove("dragover");
  });

  dropzoneBox.addEventListener("drop", (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropzoneBox.classList.remove("dragover");
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      uploadFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files && fileInput.files.length > 0) {
      uploadFile(fileInput.files[0]);
    }
  });

  if (btnUploadAnother) {
    btnUploadAnother.addEventListener("click", () => {
      setUploadState("idle");
    });
  }
}

function setUploadState(state, info = {}) {
  const dropzoneBox = document.getElementById("dropzoneBox");
  const uploadLoader = document.getElementById("uploadLoader");
  const successBanner = document.getElementById("uploadSuccessBanner");
  const uploadStatusTitle = document.getElementById("uploadStatusTitle");
  const uploadStatusSub = document.getElementById("uploadStatusSub");
  const successFilename = document.getElementById("successFilename");
  const successSummaryText = document.getElementById("successSummaryText");

  if (state === "idle") {
    dropzoneBox.classList.remove("hidden");
    uploadLoader.classList.add("hidden");
    successBanner.classList.add("hidden");
  } else if (state === "loading") {
    dropzoneBox.classList.add("hidden");
    uploadLoader.classList.remove("hidden");
    successBanner.classList.add("hidden");
    uploadStatusTitle.textContent = info.title || "Ingesting & Analyzing Dataset...";
    uploadStatusSub.textContent = info.sub || "Profiling schema dimensions, running isolation forests, and scoring transactions";
  } else if (state === "success") {
    dropzoneBox.classList.add("hidden");
    uploadLoader.classList.add("hidden");
    successBanner.classList.remove("hidden");
    successFilename.textContent = `${info.filename || "Dataset"} Ingestion Complete`;
    successSummaryText.textContent = `${(info.records || 0).toLocaleString()} transactions analyzed in ${(info.duration || 0)} ms • $${(info.volume || 0).toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2})} total volume`;
  }
}

async function uploadFile(file) {
  setUploadState("loading", {
    title: `Ingesting & Analyzing ${file.name}...`,
    sub: `File size: ${(file.size / (1024 * 1024)).toFixed(2)} MB • Automatic AI schema detection`
  });

  const formData = new FormData();
  formData.append("file", file);

  try {
    const res = await fetch("/api/v1/upload-dataset", {
      method: "POST",
      body: formData
    });

    if (!res.ok) {
      const err = await res.json();
      alert(`Upload Error: ${err.detail || "Unable to process dataset"}`);
      setUploadState("idle");
      return;
    }

    const data = await res.json();
    setUploadState("success", {
      filename: data.metadata.filename,
      records: data.metadata.total_records,
      duration: data.metadata.analysis_duration_ms,
      volume: data.summary_metrics.total_volume_usd
    });

    renderAnalysisView(data);
  } catch (err) {
    alert(`Network / Ingestion Error: ${err.message}`);
    setUploadState("idle");
  } finally {
    document.getElementById("csvFileInput").value = "";
  }
}

// ==========================================
// 4. SAMPLE DATASETS
// ==========================================
function initSampleButtons() {
  document.querySelectorAll("[data-sample]").forEach(btn => {
    btn.addEventListener("click", () => {
      const sampleType = btn.getAttribute("data-sample");
      loadSampleDataset(sampleType);
    });
  });
}

async function loadSampleDataset(sampleType) {
  const sampleLabels = {
    creditcard: "Credit Card Transactions (300 rows)",
    ecommerce: "E-Commerce Checkouts (500 rows)",
    wire: "P2P Wire Transfers (400 rows)"
  };

  setUploadState("loading", {
    title: `Loading sample: ${sampleLabels[sampleType] || sampleType}...`,
    sub: "Initializing automated profiling and explainable AI feature evaluation"
  });

  try {
    const res = await fetch(`/api/v1/sample-dataset/${sampleType}`);
    const data = await res.json();

    setUploadState("success", {
      filename: data.metadata.filename,
      records: data.metadata.total_records,
      duration: data.metadata.analysis_duration_ms,
      volume: data.summary_metrics.total_volume_usd
    });

    renderAnalysisView(data);
  } catch (err) {
    console.error("Failed to load sample dataset", err);
    setUploadState("idle");
  }
}

// ==========================================
// 5. DYNAMIC SENSITIVITY SLIDER
// ==========================================
function initThresholdSlider() {
  const slider = document.getElementById("inputRiskThreshold");
  if (slider) {
    slider.addEventListener("input", (e) => {
      currentSensitivityThreshold = parseFloat(e.target.value);
      const valDisplay = document.getElementById("valThresholdDisplay");
      if (valDisplay) valDisplay.textContent = currentSensitivityThreshold.toFixed(2);
      recalculateThresholdMetrics();
    });
  }
}

function recalculateThresholdMetrics() {
  if (!currentDatasetRecords || currentDatasetRecords.length === 0) return;

  let totalBlocked = 0;
  let totalChallenged = 0;
  let totalApproved = 0;
  let riskVolume = 0.0;
  let approvedVolume = 0.0;
  const challengeCutoff = currentSensitivityThreshold * 0.5;

  const scatterApproved = [];
  const scatterChallenged = [];
  const scatterBlocked = [];

  currentDatasetRecords.forEach(r => {
    const score = r.risk_score;
    let decision = "APPROVE";
    let riskLevel = "LOW";

    if (score >= currentSensitivityThreshold) {
      decision = "BLOCK";
      riskLevel = score >= 0.85 ? "CRITICAL" : "HIGH";
      totalBlocked++;
      riskVolume += parseFloat(r.amount || 0.0);
      scatterBlocked.push({ x: r.amount, y: score });
    } else if (score >= challengeCutoff || (r.reasons && r.reasons.length > 0 && r.reasons[0] !== "Baseline Transaction Parameters Nominal")) {
      decision = "CHALLENGE_2FA";
      riskLevel = "MEDIUM";
      totalChallenged++;
      scatterChallenged.push({ x: r.amount, y: score });
    } else {
      decision = "APPROVE";
      riskLevel = "LOW";
      totalApproved++;
      approvedVolume += parseFloat(r.amount || 0.0);
      scatterApproved.push({ x: r.amount, y: score });
    }

    r.dynamic_decision = decision;
    r.dynamic_risk_level = riskLevel;
  });

  const totalRows = currentDatasetRecords.length;
  const totalVol = (currentRawData && currentRawData.summary_metrics && currentRawData.summary_metrics.total_volume_usd) || 1.0;

  const elBlocked = document.getElementById("statBlockedCount");
  if (elBlocked) elBlocked.textContent = totalBlocked.toLocaleString();

  const elContam = document.getElementById("statContamRate");
  if (elContam) elContam.textContent = `${((totalBlocked / totalRows) * 100).toFixed(2)}% Contam`;

  const elChallenged = document.getElementById("statChallengedCount");
  if (elChallenged) elChallenged.textContent = totalChallenged.toLocaleString();

  const elApproved = document.getElementById("statApprovedCount");
  if (elApproved) elApproved.textContent = totalApproved.toLocaleString();

  const elApprovedVol = document.getElementById("statApprovedVolume");
  if (elApprovedVol) elApprovedVol.textContent = `$${(totalVol - riskVolume).toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2})}`;

  const elRiskVol = document.getElementById("statRiskVol");
  if (elRiskVol) elRiskVol.textContent = `$${riskVolume.toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2})}`;

  // Update Donut Chart
  if (chartDonut) {
    chartDonut.data.datasets[0].data = [totalApproved || 1, totalChallenged || 0, totalBlocked || 0];
    chartDonut.update();
  }

  // Update Scatter Chart
  if (chartScatter) {
    chartScatter.data.datasets[0].data = scatterApproved;
    chartScatter.data.datasets[1].data = scatterChallenged;
    chartScatter.data.datasets[2].data = scatterBlocked;
    chartScatter.update();
  }

  renderRecordsTable();
}

// ==========================================
// 6. RENDER ANALYSIS VIEW
// ==========================================
function renderAnalysisView(data) {
  currentRawData = data;

  // Bento Metric Values
  const metrics = data.summary_metrics;
  const elTotalVol = document.getElementById("statTotalVol");
  if (elTotalVol) elTotalVol.textContent = `$${metrics.total_volume_usd.toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2})}`;

  const elRiskVol = document.getElementById("statRiskVol");
  if (elRiskVol) elRiskVol.textContent = `$${metrics.exposed_risk_volume_usd.toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2})}`;

  const elBlocked = document.getElementById("statBlockedCount");
  if (elBlocked) elBlocked.textContent = metrics.total_blocked_fraud.toLocaleString();

  const elChallenged = document.getElementById("statChallengedCount");
  if (elChallenged) elChallenged.textContent = metrics.total_challenged.toLocaleString();

  const elApproved = document.getElementById("statApprovedCount");
  if (elApproved) elApproved.textContent = metrics.total_approved.toLocaleString();

  const elContam = document.getElementById("statContamRate");
  if (elContam) elContam.textContent = `${metrics.fraud_contamination_rate}% Contam`;

  // Update Histograms
  if (chartHistogram && data.risk_histogram) {
    chartHistogram.data.datasets[0].data = data.risk_histogram.counts;
    chartHistogram.update();
  }

  if (chartHistogramTab2 && data.risk_histogram) {
    chartHistogramTab2.data.datasets[0].data = data.risk_histogram.counts;
    chartHistogramTab2.update();
  }

  // Feature Drivers
  if (chartFeatureDrivers && data.feature_importances && data.feature_importances.length > 0) {
    chartFeatureDrivers.data.labels = data.feature_importances.map(f => f.feature);
    chartFeatureDrivers.data.datasets[0].data = data.feature_importances.map(f => f.importance);
    chartFeatureDrivers.update();
  }

  currentDatasetRecords = data.scored_records || [];
  recalculateThresholdMetrics();

  // Populate Schema EDA Table
  renderSchemaTable(data.column_profiles || []);

  initTableFilters();
}

function renderSchemaTable(profiles) {
  const tbody = document.getElementById("schemaTableBody");
  if (!tbody) return;

  if (!profiles || profiles.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="9">No column profiles available.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  profiles.forEach(col => {
    const tr = document.createElement("tr");
    const isNum = col.dtype === "Numeric";
    const badgeClass = isNum ? "chip-approved" : "chip-warning";

    tr.innerHTML = `
      <td style="font-weight: 700; color: #059669;">${col.name}</td>
      <td><span class="status-chip ${badgeClass}">${col.dtype}</span></td>
      <td>${col.null_count}</td>
      <td style="color: ${col.null_pct > 5 ? '#e11d48' : '#475569'}; font-weight: 600;">${col.null_pct}%</td>
      <td>${col.unique_count.toLocaleString()}</td>
      <td style="font-family: var(--font-mono); font-size: 11px;">${col.min !== undefined ? col.min : '—'}</td>
      <td style="font-family: var(--font-mono); font-size: 11px;">${col.max !== undefined ? col.max : '—'}</td>
      <td style="font-family: var(--font-mono); font-size: 11px;">${col.mean !== undefined ? col.mean : '—'}</td>
      <td style="font-family: var(--font-mono); font-size: 11px;">${col.std !== undefined ? col.std : '—'}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderRecordsTable() {
  const tbody = document.getElementById("datasetTableBody");
  if (!tbody) return;
  tbody.innerHTML = "";

  const filtered = currentDatasetRecords.filter(r => {
    const dec = r.dynamic_decision || r.decision;
    if (activeFilter === "all") return true;
    if (activeFilter === "BLOCK") return dec === "BLOCK";
    if (activeFilter === "CHALLENGE") return dec === "CHALLENGE_2FA" || dec === "MANUAL_REVIEW";
    if (activeFilter === "APPROVE") return dec === "APPROVE";
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="8">No records match the selected filter.</td></tr>`;
    return;
  }

  // Sample Merchant / Category Logos for human-friendly SaaS feel
  const icons = ["🛍️", "💳", "⚡", "📱", "✈️", "🍔", "☕", "💻"];

  filtered.forEach((r, idx) => {
    const tr = document.createElement("tr");
    const dec = r.dynamic_decision || r.decision;

    let chipClass = "chip-approved";
    let chipLabel = "• Approved";
    if (dec === "BLOCK") {
      chipClass = "chip-danger";
      chipLabel = "• Flagged Fraud";
    } else if (dec === "CHALLENGE_2FA" || dec === "MANUAL_REVIEW") {
      chipClass = "chip-warning";
      chipLabel = "• 2FA Review";
    }

    const icon = icons[idx % icons.length];
    const reasonSnippet = r.reasons && r.reasons.length > 0 ? r.reasons[0] : "Nominal Parameters";
    const isCritical = r.risk_score >= currentSensitivityThreshold;

    tr.innerHTML = `
      <td>${r.row_index}</td>
      <td>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="font-size: 16px;">${icon}</span>
          <strong style="color: #0f172a; font-family: var(--font-mono); font-size: 12px;">${r.transaction_id}</strong>
        </div>
      </td>
      <td>${r.user_id}</td>
      <td style="font-weight: 800; color: #0f172a;">$${parseFloat(r.amount).toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2})}</td>
      <td style="color: ${isCritical ? '#e11d48' : '#059669'}; font-weight: 800; font-family: var(--font-mono);">${r.risk_score}</td>
      <td><span class="status-chip ${chipClass}">${chipLabel}</span></td>
      <td style="font-size: 12px; color: #64748b; max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${reasonSnippet}</td>
      <td><button type="button" class="btn-inspect btn-inspect-row">Audit</button></td>
    `;

    tbody.appendChild(tr);

    tr.querySelector(".btn-inspect-row").addEventListener("click", () => {
      openAuditModal(r);
    });
  });
}

function initTableFilters() {
  document.querySelectorAll(".filter-pill").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".filter-pill").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      activeFilter = btn.getAttribute("data-filter");
      renderRecordsTable();
    });
  });
}

// ==========================================
// 7. DRILL-DOWN AUDIT MODAL
// ==========================================
function initModal() {
  const modal = document.getElementById("drilldownModal");
  const btnClose = document.getElementById("btnCloseModal");

  if (btnClose) {
    btnClose.addEventListener("click", () => {
      modal.classList.add("hidden");
    });
  }

  if (modal) {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) modal.classList.add("hidden");
    });
  }
}

function openAuditModal(record) {
  const modal = document.getElementById("drilldownModal");
  const dec = record.dynamic_decision || record.decision;
  document.getElementById("modalTxnTitle").textContent = `Audit Inspection: ${record.transaction_id}`;

  const body = document.getElementById("modalBodyContent");

  let chipClass = "chip-approved";
  let chipLabel = "• Approved";
  if (dec === "BLOCK") {
    chipClass = "chip-danger";
    chipLabel = "• Flagged Fraud";
  } else if (dec === "CHALLENGE_2FA" || dec === "MANUAL_REVIEW") {
    chipClass = "chip-warning";
    chipLabel = "• 2FA Review";
  }

  let reasonsHtml = "";
  if (record.reasons && record.reasons.length > 0) {
    reasonsHtml = `<ul style="padding-left: 20px; margin-top: 8px; font-size: 13px; color: #334155;">` +
      record.reasons.map(reason => `<li style="margin-bottom: 4px;">${reason}</li>`).join("") + `</ul>`;
  } else {
    reasonsHtml = `<p style="font-size: 13px; color: #64748b;">No high-risk anomaly signals triggered.</p>`;
  }

  let rawFieldsHtml = "";
  if (record.raw_preview) {
    rawFieldsHtml = `<div style="background: #f8fafc; padding: 14px; border-radius: 12px; font-family: var(--font-mono); font-size: 12px; max-height: 150px; overflow-y: auto; border: 1px solid #e2e8f0;">` +
      Object.entries(record.raw_preview).map(([k, v]) => `<div style="margin-bottom: 3px;"><span style="color: #059669; font-weight: 700;">${k}:</span> ${v}</div>`).join("") + `</div>`;
  }

  body.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid #e2e8f0;">
      <div>
        <span class="status-chip ${chipClass}" style="font-size: 13px;">${chipLabel}</span>
        <span style="font-size: 13px; color: #64748b; margin-left: 10px;">Risk Tier: <strong>${record.dynamic_risk_level || record.risk_level}</strong></span>
      </div>
      <div style="font-family: var(--font-mono); font-size: 16px;">
        Risk Score: <strong style="color: ${record.risk_score >= currentSensitivityThreshold ? '#e11d48' : '#059669'};">${record.risk_score}</strong>
      </div>
    </div>
    <div style="margin-bottom: 16px;">
      <h4 style="font-size: 12px; color: #64748b; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.04em;">Audit Reason Codes & Signals:</h4>
      ${reasonsHtml}
    </div>
    <div style="margin-bottom: 20px;">
      <h4 style="font-size: 12px; color: #64748b; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.04em;">Raw Dimensions Preview:</h4>
      ${rawFieldsHtml}
    </div>
    <div style="display: flex; gap: 10px; border-top: 1px solid #e2e8f0; padding-top: 16px;">
      <button type="button" class="btn btn-outline-sm" onclick="alert('Transaction ${record.transaction_id} added to Safe Whitelist.')">✓ Mark False Positive</button>
      <button type="button" class="btn btn-emerald-sm" style="background: #e11d48;" onclick="alert('Transaction ${record.transaction_id} confirmed as Fraud. Payment instrument locked.')">🚨 Confirm Fraud Block</button>
    </div>
  `;

  modal.classList.remove("hidden");
}

// ==========================================
// 8. TAB 4: WEBSOCKET LIVE STREAM FEED
// ==========================================
function initWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/stream`;
  const statusElem = document.getElementById("systemStatusText");

  try {
    const ws = new WebSocket(wsUrl);
    ws.onopen = () => { if (statusElem) statusElem.textContent = "AI Stream Active"; };
    ws.onmessage = (e) => {
      const tx = JSON.parse(e.data);
      appendLiveRadarRow(tx);
    };
    ws.onclose = () => {
      if (statusElem) statusElem.textContent = "Reconnecting...";
      setTimeout(initWebSocket, 3000);
    };
  } catch (err) {
    if (statusElem) statusElem.textContent = "Standby";
  }

  const btnBurst = document.getElementById("btnBurst10");
  if (btnBurst) {
    btnBurst.addEventListener("click", async () => {
      btnBurst.disabled = true;
      btnBurst.textContent = "Injecting...";
      try {
        await fetch("/api/v1/simulate?count=10&fraud_ratio=0.3", { method: "POST" });
      } finally {
        btnBurst.disabled = false;
        btnBurst.textContent = "⚡ Inject 10 Synthetic Txns";
      }
    });
  }
}

function appendLiveRadarRow(tx) {
  const tbody = document.getElementById("liveStreamTableBody");
  if (!tbody) return;

  const empty = tbody.querySelector(".empty-row");
  if (empty) empty.remove();

  const tr = document.createElement("tr");
  let chipClass = "chip-approved";
  let chipLabel = "• Approved";
  if (tx.decision === "BLOCK") {
    chipClass = "chip-danger";
    chipLabel = "• Blocked";
  } else if (tx.decision === "CHALLENGE_2FA" || tx.decision === "MANUAL_REVIEW") {
    chipClass = "chip-warning";
    chipLabel = "• 2FA Review";
  }

  tr.innerHTML = `
    <td style="font-family: var(--font-mono); font-size: 11px;">${tx.timestamp.split(" ")[1] || "Just now"}</td>
    <td style="color: #059669; font-family: var(--font-mono); font-weight: 700;">${tx.transaction_id}</td>
    <td>${tx.user_id}</td>
    <td style="font-weight: 800; color: #0f172a;">$${parseFloat(tx.amount).toFixed(2)}</td>
    <td style="color: ${tx.fraud_score >= 0.5 ? '#e11d48' : '#059669'}; font-weight: 800; font-family: var(--font-mono);">${tx.fraud_score}</td>
    <td><span class="status-chip ${chipClass}">${chipLabel}</span></td>
    <td style="color: #64748b; font-family: var(--font-mono); font-size: 11px;">${tx.latency_ms} ms</td>
  `;

  tbody.insertBefore(tr, tbody.firstChild);
  if (tbody.children.length > 30) tbody.removeChild(tbody.lastChild);

  // Also update Cyber Defense feeds if active
  if (tx.audit_ledger || tx.cyber_intel) {
    appendCyberAuditRow(tx);
  }
}

// ==========================================
// 9. TAB 5: XAI RISK SANDBOX
// ==========================================
function initSandboxForm() {
  const btnLegit = document.getElementById("btnSandboxLegit");
  if (btnLegit) {
    btnLegit.addEventListener("click", async () => {
      const res = await fetch("/api/v1/sample/legit");
      const data = await res.json();
      populateSandboxForm(data);
    });
  }

  const btnFraud = document.getElementById("btnSandboxFraud");
  if (btnFraud) {
    btnFraud.addEventListener("click", async () => {
      const res = await fetch("/api/v1/sample/fraud");
      const data = await res.json();
      populateSandboxForm(data);
    });
  }

  const form = document.getElementById("inspectorForm");
  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const payload = {
        user_id: document.getElementById("simUser").value,
        Amount: parseFloat(document.getElementById("simAmount").value),
        V14: parseFloat(document.getElementById("simV14").value),
        V12: parseFloat(document.getElementById("simV12").value),
        V4: parseFloat(document.getElementById("simV4").value),
        device_trust_score: parseFloat(document.getElementById("simTrust").value),
        Time: 0.0
      };

      const res = await fetch("/api/v1/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      const data = await res.json();
      renderSandboxAudit(data);
    });
  }
}

function populateSandboxForm(sample) {
  document.getElementById("simAmount").value = sample.Amount || 149.62;
  document.getElementById("simUser").value = sample.user_id || "usr_sample";
  document.getElementById("simV14").value = sample.V14 || 0.0;
  document.getElementById("simV12").value = sample.V12 || 0.0;
  document.getElementById("simV4").value = sample.V4 || 0.0;
  document.getElementById("simTrust").value = sample.device_trust_score || 1.0;
}

function renderSandboxAudit(data) {
  const card = document.getElementById("sandboxAuditCard");
  if (!card) return;
  card.classList.remove("hidden");

  const badge = document.getElementById("simBadge");
  badge.className = "status-chip " + (data.decision === "BLOCK" ? "chip-danger" : data.decision === "CHALLENGE_2FA" ? "chip-warning" : "chip-approved");
  badge.textContent = data.decision === "BLOCK" ? "• Flagged Fraud" : data.decision === "CHALLENGE_2FA" ? "• 2FA Review" : "• Approved";

  document.getElementById("simRiskScore").textContent = data.risk_score;
  document.getElementById("simRecommendation").textContent = data.recommendation;

  const rulesBox = document.getElementById("simRulesBox");
  const rulesList = document.getElementById("simRulesList");
  rulesList.innerHTML = "";
  if (data.triggered_rules && data.triggered_rules.length > 0) {
    rulesBox.classList.remove("hidden");
    data.triggered_rules.forEach(r => {
      const li = document.createElement("li");
      li.textContent = r;
      rulesList.appendChild(li);
    });
  } else {
    rulesBox.classList.add("hidden");
  }

  const xaiList = document.getElementById("simXaiList");
  xaiList.innerHTML = "";
  if (data.explainability && data.explainability.length > 0) {
    data.explainability.forEach(item => {
      const div = document.createElement("div");
      div.className = "xai-row";
      div.innerHTML = `
        <div>
          <strong style="color: #059669;">${item.feature}</strong>: ${item.title}
          <div style="font-size: 11px; color: #64748b;">Value: ${item.value} (${item.signal})</div>
        </div>
        <span style="font-weight: 800; color: #b45309;">${item.contribution_percentage}%</span>
      `;
      xaiList.appendChild(div);
    });
  } else {
    xaiList.innerHTML = `<div style="font-size: 12px; color: #64748b;">All latent subspace parameters are within nominal bounds.</div>`;
  }
}

// ==========================================
// 10. CLOUD DATABASE AUTHENTICATION & SESSIONS
// ==========================================
let currentUser = null;

function initAuth() {
  const profileBtn = document.getElementById("userProfileBtn");
  const authModal = document.getElementById("authModal");
  const btnCloseAuth = document.getElementById("btnCloseAuthModal");

  if (profileBtn) {
    profileBtn.addEventListener("click", () => {
      authModal.classList.remove("hidden");
    });
  }

  if (btnCloseAuth) {
    btnCloseAuth.addEventListener("click", () => {
      authModal.classList.add("hidden");
    });
  }

  if (authModal) {
    authModal.addEventListener("click", (e) => {
      if (e.target === authModal) authModal.classList.add("hidden");
    });
  }

  // Auth Tabs navigation
  const authTabBtns = document.querySelectorAll(".auth-tab-btn");
  authTabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      authTabBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const targetTab = btn.getAttribute("data-authtab");
      document.querySelectorAll(".authtab-content").forEach(c => c.classList.remove("active"));
      const content = document.getElementById(targetTab);
      if (content) content.classList.add("active");
    });
  });

  // Fetch Cloud Database Status
  fetchDatabaseStatus();

  // Login Form
  const loginForm = document.getElementById("loginForm");
  const loginErrorMsg = document.getElementById("loginErrorMsg");
  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      loginErrorMsg.classList.add("hidden");
      const identifier = document.getElementById("loginIdentifier").value;
      const password = document.getElementById("loginPassword").value;

      try {
        const res = await fetch("/api/v1/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username_or_email: identifier, password: password })
        });

        if (!res.ok) {
          const err = await res.json();
          loginErrorMsg.textContent = err.detail || "Invalid login credentials.";
          loginErrorMsg.classList.remove("hidden");
          return;
        }

        const user = await res.json();
        setCurrentUser(user);
        authModal.classList.add("hidden");
        loginForm.reset();
      } catch (err) {
        loginErrorMsg.textContent = "Unable to connect to Cloud Database.";
        loginErrorMsg.classList.remove("hidden");
      }
    });
  }

  // Register Form
  const registerForm = document.getElementById("registerForm");
  const registerErrorMsg = document.getElementById("registerErrorMsg");
  if (registerForm) {
    registerForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      registerErrorMsg.classList.add("hidden");
      const payload = {
        full_name: document.getElementById("regFullName").value,
        email: document.getElementById("regEmail").value,
        username: document.getElementById("regUsername").value,
        role: document.getElementById("regRole").value,
        password: document.getElementById("regPassword").value
      };

      try {
        const res = await fetch("/api/v1/auth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });

        if (!res.ok) {
          const err = await res.json();
          registerErrorMsg.textContent = err.detail || "Registration error.";
          registerErrorMsg.classList.remove("hidden");
          return;
        }

        const user = await res.json();
        setCurrentUser(user);
        authModal.classList.add("hidden");
        registerForm.reset();
        alert(`Account created in Cloud Database! Welcome to AegisFlow, ${user.full_name}.`);
      } catch (err) {
        registerErrorMsg.textContent = "Server error while registering.";
        registerErrorMsg.classList.remove("hidden");
      }
    });
  }

  // Sign out button
  const btnSignOut = document.getElementById("btnSignOutSession");
  if (btnSignOut) {
    btnSignOut.addEventListener("click", () => {
      localStorage.removeItem("aegisflow_user");
      setGuestState();
      authModal.classList.remove("hidden");
      document.querySelector('[data-authtab="authtab-login"]').click();
    });
  }

  // Restore saved session from localStorage if exists
  const saved = localStorage.getItem("aegisflow_user");
  if (saved) {
    try {
      setCurrentUser(JSON.parse(saved));
    } catch (e) {
      setGuestState();
    }
  } else {
    setGuestState();
  }
}

async function fetchDatabaseStatus() {
  try {
    const res = await fetch("/api/v1/auth/db-status");
    if (res.ok) {
      const data = await res.json();
      const badge = document.getElementById("dbStatusBadge");
      if (badge) {
        badge.textContent = data.type;
        badge.className = "status-chip " + (data.is_cloud ? "chip-approved" : "chip-warning");
      }
    }
  } catch (err) {
    console.warn("DB status check failed", err);
  }
}

function setGuestState() {
  currentUser = null;

  const elTitle = document.getElementById("welcomeTitle");
  if (elTitle) elTitle.textContent = "Welcome to AegisFlow Risk Studio";

  const elSub = document.getElementById("welcomeSubtitle");
  if (elSub) elSub.textContent = "Autonomous financial fraud detection, explainable AI, and multi-format transaction analytics. Sign in or create an account to personalize your workspace.";

  const elNavName = document.getElementById("navUserName");
  if (elNavName) elNavName.textContent = "Sign In / Register";

  const elNavRole = document.getElementById("navUserRole");
  if (elNavRole) elNavRole.textContent = "Guest Access";

  const elNavAvatar = document.getElementById("navUserAvatar");
  if (elNavAvatar) {
    elNavAvatar.textContent = "👤";
    elNavAvatar.style.background = "#64748b";
  }

  const elModalActive = document.getElementById("modalActiveUserLabel");
  if (elModalActive) elModalActive.textContent = "Guest (Not Signed In)";

  const btnSignOut = document.getElementById("btnSignOutSession");
  if (btnSignOut) btnSignOut.classList.add("hidden");
}

function setCurrentUser(user) {
  currentUser = user;
  localStorage.setItem("aegisflow_user", JSON.stringify(user));

  const elTitle = document.getElementById("welcomeTitle");
  if (elTitle) elTitle.innerHTML = `Welcome Back, <span style="color: #059669;">${user.full_name}</span>`;

  const elSub = document.getElementById("welcomeSubtitle");
  if (elSub) elSub.innerHTML = `Logged in as <strong>${user.role}</strong> • Real-time transaction scoring and explainable AI active.`;

  const elNavName = document.getElementById("navUserName");
  if (elNavName) elNavName.textContent = user.full_name;

  const elNavRole = document.getElementById("navUserRole");
  if (elNavRole) elNavRole.textContent = user.role;

  const elNavAvatar = document.getElementById("navUserAvatar");
  if (elNavAvatar) {
    elNavAvatar.textContent = user.avatar_initials || "U";
    elNavAvatar.style.background = "#059669";
  }

  const elModalActive = document.getElementById("modalActiveUserLabel");
  if (elModalActive) elModalActive.textContent = `${user.full_name} (${user.username} • ${user.role})`;

  const btnSignOut = document.getElementById("btnSignOutSession");
  if (btnSignOut) btnSignOut.classList.remove("hidden");
}

// ==========================================
// 11. TAB 5: CYBER DEFENSE & AUDIT LEDGER SUITE
// ==========================================
function initCyberDefenseSuite() {
  fetchAuditLedger();
  fetchBotSentinelStats();

  // 1. Verify Full Audit Ledger
  const btnVerify = document.getElementById("btnVerifyAuditLedger");
  if (btnVerify) {
    btnVerify.addEventListener("click", async () => {
      btnVerify.disabled = true;
      btnVerify.textContent = "Verifying...";
      try {
        const res = await fetch("/api/v1/security/audit-ledger/verify", { method: "POST" });
        const data = await res.json();
        updateAuditVerificationBanner(data);
      } catch (err) {
        console.error("Audit verification failed:", err);
      } finally {
        btnVerify.disabled = false;
        btnVerify.textContent = "🔍 Verify Chain";
      }
    });
  }

  // 2. Simulate Tampering (Demo Feature)
  const btnTamper = document.getElementById("btnTamperAuditLedger");
  if (btnTamper) {
    btnTamper.addEventListener("click", async () => {
      btnTamper.disabled = true;
      try {
        const res = await fetch("/api/v1/security/audit-ledger/simulate-tamper", { method: "POST" });
        const tamperData = await res.json();
        alert(`🚨 SIMULATION: ${tamperData.message}\nBlock #${tamperData.tampered_block_index} altered to '${tamperData.tampered_decision}'. Running cryptographic verification now...`);
        
        // Immediately run verification to demonstrate instant detection
        const verifyRes = await fetch("/api/v1/security/audit-ledger/verify", { method: "POST" });
        const verifyData = await verifyRes.json();
        updateAuditVerificationBanner(verifyData);
      } catch (err) {
        console.error("Tamper simulation error:", err);
      } finally {
        btnTamper.disabled = false;
      }
    });
  }

  // 3. Restore & Re-Seal Ledger
  const btnRestore = document.getElementById("btnRestoreAuditLedger");
  if (btnRestore) {
    btnRestore.addEventListener("click", async () => {
      btnRestore.disabled = true;
      btnRestore.textContent = "Re-Sealing...";
      try {
        const res = await fetch("/api/v1/security/audit-ledger/restore", { method: "POST" });
        const data = await res.json();
        alert(`✅ ${data.message} All SHA-256 links restored.`);
        fetchAuditLedger();
      } catch (err) {
        console.error("Ledger restore error:", err);
      } finally {
        btnRestore.disabled = false;
        btnRestore.textContent = "🔄 Re-Seal";
      }
    });
  }

  // 4. Simulate Botnet Carding Attack
  const btnSimAttack = document.getElementById("btnSimCardingAttack");
  if (btnSimAttack) {
    btnSimAttack.addEventListener("click", async () => {
      btnSimAttack.disabled = true;
      btnSimAttack.textContent = "⚡ Attacking...";
      try {
        const res = await fetch("/api/v1/security/bot-sentinel/simulate-carding-attack?botnet_size=6", { method: "POST" });
        const data = await res.json();
        
        // Trigger alert banner
        const banner = document.getElementById("cyberAttackBanner");
        const statusText = document.getElementById("cyberSentinelStatusText");
        const threatPill = document.getElementById("cyberThreatPill");

        if (banner) {
          banner.style.background = "rgba(244, 63, 94, 0.12)";
          banner.style.borderColor = "rgba(244, 63, 94, 0.4)";
        }
        if (statusText) {
          statusText.innerHTML = `<strong style="color: #f43f5e;">🚨 BOTNET CARDING BURST INTERCEPTED:</strong> ${data.cards_tested} unique cards tested in <400ms from IP <strong>${data.attacker_ip}</strong>. IP automatically quarantined!`;
        }
        if (threatPill) {
          threatPill.textContent = "ATTACK MITIGATED";
          threatPill.className = "badge badge-rose";
        }

        // Populate carding threat table with simulated attacker records
        data.results.forEach(r => appendCardingThreatRow(r));
        fetchBotSentinelStats();
      } catch (err) {
        console.error("Botnet simulation failed:", err);
      } finally {
        btnSimAttack.disabled = false;
        btnSimAttack.textContent = "⚡ Simulate Botnet Attack";
      }
    });
  }
}

async function fetchAuditLedger() {
  try {
    const res = await fetch("/api/v1/security/audit-ledger?limit=15");
    if (!res.ok) return;
    const data = await res.json();
    
    updateAuditVerificationBanner(data.summary);
    renderAuditBlocksTable(data.recent_blocks || []);
    
    const rootEl = document.getElementById("cyberRootDigest");
    if (rootEl && data.summary.root_merkle_digest) {
      rootEl.textContent = data.summary.root_merkle_digest.slice(0, 20) + "...";
      rootEl.title = data.summary.root_merkle_digest;
    }
  } catch (err) {
    console.warn("Failed to fetch audit ledger:", err);
  }
}

async function fetchBotSentinelStats() {
  try {
    const res = await fetch("/api/v1/security/bot-sentinel/stats");
    if (!res.ok) return;
    const data = await res.json();

    const qEl = document.getElementById("cyberQuarantinedIps");
    if (qEl) qEl.textContent = data.quarantined_ips_count || 0;

    const cEl = document.getElementById("cyberCardingAttacks");
    if (cEl) cEl.textContent = data.carding_attacks_mitigated_60s || 0;
  } catch (err) {
    console.warn("Failed to fetch bot sentinel stats:", err);
  }
}

function updateAuditVerificationBanner(summary) {
  const banner = document.getElementById("auditVerificationBanner");
  const statusText = document.getElementById("auditBannerStatusText");
  const subtext = document.getElementById("auditBannerSubtext");
  const countBadge = document.getElementById("auditVerifiedCountBadge");
  const statusBadge = document.getElementById("auditStatusBadge");

  if (!banner || !summary) return;

  if (summary.is_valid) {
    banner.style.background = "rgba(0, 230, 118, 0.08)";
    banner.style.borderColor = "rgba(0, 230, 118, 0.3)";
    if (statusText) {
      statusText.innerHTML = `STATUS: 100% CRYPTOGRAPHICALLY VERIFIED`;
      statusText.style.color = "var(--accent-emerald)";
    }
    if (subtext) {
      subtext.textContent = `All ${summary.blocks_verified} blocks signed & unbroken. Verified in ${summary.verification_latency_ms || 0.2}ms (PCI-DSS 10.x Compliant).`;
    }
    if (countBadge) {
      countBadge.textContent = `${summary.blocks_verified} Blocks Valid`;
      countBadge.className = "badge badge-emerald";
    }
    if (statusBadge) {
      statusBadge.textContent = "VERIFIED SECURE";
      statusBadge.className = "kpi-value emerald-text";
    }
  } else {
    banner.style.background = "rgba(244, 63, 94, 0.15)";
    banner.style.borderColor = "rgba(244, 63, 94, 0.5)";
    if (statusText) {
      statusText.innerHTML = `🚨 STATUS: COMPROMISED — TAMPERING DETECTED AT BLOCK #${summary.error_at_index || '?'}`;
      statusText.style.color = "#f43f5e";
    }
    if (subtext) {
      subtext.innerHTML = `<strong>Violation Reason:</strong> ${summary.reason || 'Cryptographic signature mismatch'}. Zero-trust non-repudiation barrier triggered.`;
    }
    if (countBadge) {
      countBadge.textContent = `FAILED (Block #${summary.error_at_index})`;
      countBadge.className = "badge badge-rose";
    }
    if (statusBadge) {
      statusBadge.textContent = "COMPROMISED";
      statusBadge.className = "kpi-value rose-text";
    }
  }
}

function renderAuditBlocksTable(blocks) {
  const tbody = document.getElementById("auditBlocksTableBody");
  if (!tbody) return;

  if (!blocks || blocks.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="5">No audit blocks logged yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  blocks.forEach(b => {
    const tr = document.createElement("tr");
    let decChip = "chip-approved";
    if (b.decision === "BLOCK") decChip = "chip-danger";
    else if (b.decision === "CHALLENGE_2FA" || b.decision === "MANUAL_REVIEW") decChip = "chip-warning";

    tr.innerHTML = `
      <td style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-cyan);">#${b.index}</td>
      <td style="font-family: var(--font-mono); font-size: 12px; font-weight: 600;">${b.txn_id}</td>
      <td><span class="status-chip ${decChip}">${b.decision}</span></td>
      <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${b.prev_hash ? b.prev_hash.slice(0, 10) + '...' : '0000000000...'}</td>
      <td style="font-family: var(--font-mono); font-size: 11px; color: var(--accent-emerald); font-weight: 600;">${b.block_hash ? b.block_hash.slice(0, 14) + '...' : 'N/A'}</td>
    `;
    tbody.appendChild(tr);
  });
}

function appendCardingThreatRow(tx) {
  const tbody = document.getElementById("cardingThreatTableBody");
  if (!tbody) return;

  const empty = tbody.querySelector(".empty-row");
  if (empty) empty.remove();

  const tr = document.createElement("tr");
  const ip = tx.cyber_intel ? tx.cyber_intel.ip_address : (tx.ip_address || "185.220.101.44");
  const cardId = tx.cyber_intel ? tx.cyber_intel.card_identifier : (tx.card_identifier || "4532_8890_XXXX");
  const threatScore = tx.cyber_intel ? tx.cyber_intel.threat_score : 0.95;
  const reason = tx.triggered_rules && tx.triggered_rules.length > 0 ? tx.triggered_rules[0] : "BOTNET_CARDING_BURST";

  tr.innerHTML = `
    <td style="font-family: var(--font-mono); font-size: 12px; font-weight: 700; color: #f43f5e;">${ip}</td>
    <td style="font-family: var(--font-mono); font-size: 12px;">${cardId}</td>
    <td style="font-weight: 700;">$${parseFloat(tx.amount).toFixed(2)}</td>
    <td style="font-family: var(--font-mono); font-weight: 800; color: #f43f5e;">${threatScore}</td>
    <td><span class="status-chip chip-danger">🚨 BLOCKED: ${reason.split(":")[0]}</span></td>
  `;

  tbody.insertBefore(tr, tbody.firstChild);
  if (tbody.children.length > 20) tbody.removeChild(tbody.lastChild);
}

function appendCyberAuditRow(tx) {
  // Update Bot Threat Table if carding attack
  if (tx.cyber_intel && (tx.cyber_intel.is_bot_attack || tx.cyber_intel.threat_level === "ATTACK_IN_PROGRESS")) {
    appendCardingThreatRow(tx);
    fetchBotSentinelStats();
  }

  // Prepend to audit blocks table if audit block exists
  if (tx.audit_ledger) {
    const tbody = document.getElementById("auditBlocksTableBody");
    if (tbody) {
      const empty = tbody.querySelector(".empty-row");
      if (empty) empty.remove();

      const tr = document.createElement("tr");
      let decChip = "chip-approved";
      if (tx.decision === "BLOCK") decChip = "chip-danger";
      else if (tx.decision === "CHALLENGE_2FA" || tx.decision === "MANUAL_REVIEW") decChip = "chip-warning";

      tr.innerHTML = `
        <td style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-cyan);">#${tx.audit_ledger.block_index}</td>
        <td style="font-family: var(--font-mono); font-size: 12px; font-weight: 600;">${tx.transaction_id}</td>
        <td><span class="status-chip ${decChip}">${tx.decision}</span></td>
        <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${tx.audit_ledger.prev_hash ? tx.audit_ledger.prev_hash.slice(0, 10) + '...' : '0000000000...'}</td>
        <td style="font-family: var(--font-mono); font-size: 11px; color: var(--accent-emerald); font-weight: 600;">${tx.audit_ledger.block_hash ? tx.audit_ledger.block_hash.slice(0, 14) + '...' : 'N/A'}</td>
      `;

      tbody.insertBefore(tr, tbody.firstChild);
      if (tbody.children.length > 20) tbody.removeChild(tbody.lastChild);

      const countBadge = document.getElementById("auditVerifiedCountBadge");
      if (countBadge) countBadge.textContent = `${tx.audit_ledger.block_index + 1} Blocks Valid`;
    }
  }
}

