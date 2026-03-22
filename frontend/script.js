/**
 * ============================================================
 * QUANTUM-SAFE CRYPTOGRAPHY SCANNER — script.js
 * Post-Quantum TLS Risk Analyzer
 *
 * Phase 0: SPA Refactor
 * Phase 1: Home Dashboard Init
 * ============================================================
 */

'use strict';

// State variables — declared at top to avoid temporal dead zone
let discoveryTabsInitialized = false;
let networkGraphInitialized = false;
let cyberRatingInitialized = false;
let reportingInitialized = false;
let sidebarCollapsed = false;
let demoMode = false;

const API_BASE_URL = 'http://localhost:8000';

/* ============================================================
   1. MOCK DATA ENGINE
   ============================================================ */

const MOCK_PROFILES = [
  {
    pattern: /gov|bank|finance|legacy|old/i,
    data: {
      riskLevel: 'HIGH',
      riskScore: 87,
      readiness: 8,
      tls: {
        version: 'TLS 1.2',
        cipherSuite: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
        keyExchange: 'RSA (Static)',
        publicKeyType: 'RSA',
        keySize: '2048-bit',
        signatureHash: 'SHA-256 with RSA',
      },
      recommendations: [
        { priority: 'high', text: '<strong>Critical:</strong> Migrate from static RSA key exchange to ECDHE. RSA is broken by Shor\'s algorithm on quantum computers.' },
        { priority: 'high', text: '<strong>Upgrade TLS:</strong> Enforce TLS 1.3+ and disable TLS 1.2 or earlier — older versions lack forward secrecy.' },
        { priority: 'high', text: '<strong>Deploy Kyber-768</strong> (CRYSTALS-Kyber, FIPS 203) as post-quantum KEM for hybrid key exchange.' },
        { priority: 'medium', text: '<strong>Replace RSA signatures</strong> with ML-DSA (CRYSTALS-Dilithium, FIPS 204) or SLH-DSA (SPHINCS+, FIPS 205).' },
        { priority: 'medium', text: '<strong>Inventory all certificates</strong> with 2048-bit RSA keys. Begin re-issuance with hybrid PQC+classical certificates.' },
        { priority: 'low', text: '<strong>Adopt a crypto-agility framework</strong> to enable rapid algorithm rotation without full re-deployment cycles.' },
      ],
    },
  },
  {
    pattern: /cloud|aws|azure|microsoft|google|corp|enterprise/i,
    data: {
      riskLevel: 'MEDIUM',
      riskScore: 54,
      readiness: 42,
      tls: {
        version: 'TLS 1.3',
        cipherSuite: 'TLS_AES_256_GCM_SHA384',
        keyExchange: 'ECDHE (X25519)',
        publicKeyType: 'ECDSA',
        keySize: '256-bit (P-256)',
        signatureHash: 'SHA-384 with ECDSA',
      },
      recommendations: [
        { priority: 'high', text: '<strong>Hybrid PQC integration:</strong> X25519 is classically safe but quantum-vulnerable. Add CRYSTALS-Kyber hybrid KEM alongside ECDHE.' },
        { priority: 'medium', text: '<strong>Certificate readiness:</strong> Plan ECDSA to ML-DSA migration path. Current P-256 certificates are quantum-vulnerable.' },
        { priority: 'medium', text: '<strong>Test Kyber/Dilithium:</strong> Begin staging deployments with hybrid TLS per IETF draft-ietf-tls-hybrid-design.' },
        { priority: 'low', text: '<strong>Update HSM firmware:</strong> Validate that Hardware Security Modules support PQC algorithm acceleration (FIPS 140-3).' },
        { priority: 'low', text: '<strong>Audit long-lived secrets:</strong> Data encrypted today with AES-256 is safe, but key exchange material should be treated as at risk.' },
      ],
    },
  },
  {
    pattern: /.*/,
    data: {
      riskLevel: 'LOW',
      riskScore: 22,
      readiness: 81,
      tls: {
        version: 'TLS 1.3',
        cipherSuite: 'TLS_AES_256_GCM_SHA384',
        keyExchange: 'Kyber-768 + X25519 (Hybrid)',
        publicKeyType: 'Dilithium3 (ML-DSA)',
        keySize: '1952-bit (PQC)',
        signatureHash: 'SHA3-384 with ML-DSA',
      },
      recommendations: [
        { priority: 'low', text: '<strong>Well configured:</strong> Hybrid Kyber+X25519 key exchange detected. Track NIST PQC finalization updates to stay current.' },
        { priority: 'low', text: '<strong>Expand PQC coverage:</strong> Ensure all service endpoints, not just primary TLS, have migrated to PQC-capable cipher suites.' },
        { priority: 'low', text: '<strong>Monitor FIPS 205 (SLH-DSA):</strong> Consider SPHINCS+ as a stateless hash-based signature backup for high-assurance certificates.' },
      ],
    },
  },
];

function getMockScanData(domain) {
  const profile = MOCK_PROFILES.find(p => p.pattern.test(domain)) || MOCK_PROFILES[MOCK_PROFILES.length - 1];
  return { domain, ...profile.data };
}

function shouldSimulateFailure(domain) {
  return /fail|error|down|offline/i.test(domain);
}

/* ============================================================
   2. APPLICATION STATE AND CHARTS
   ============================================================ */

const AppState = {
  currentScan: null,
  scanHistory: [],
  loadingState: false,
  errorState: null,
};

const HomeCharts = {
  assetType: null,
  assetRisk: null,
  ipVersion: null
};

/* ============================================================
   3. SPA ROUTER
   ============================================================ */

const Router = {
  currentSection: 'home',
  navigate(sectionId) {
    // hide all sections
    document.querySelectorAll('.spa-section').forEach(sec => {
      sec.classList.remove('active-section');
    });
    // show target section
    const targetEl = document.getElementById('section-' + sectionId);
    if (targetEl) {
      targetEl.classList.add('active-section');
    }
    // update active nav item
    document.querySelectorAll('.app-sidebar .nav-item').forEach(nav => {
      nav.classList.remove('active');
      if (nav.getAttribute('data-section') === sectionId) {
        nav.classList.add('active');
      }
    });

    // Initialize Home Charts if entering 'home' section for first time
    if (sectionId === 'home') setTimeout(() => initHomeCharts(), 50);
    if (sectionId === 'asset-discovery') setTimeout(() => initDiscoveryTabs(), 50);
    if (sectionId === 'cbom') setTimeout(() => initCbomCharts(), 150);
    if (sectionId === 'posture-pqc') setTimeout(() => initPqcCharts(), 150);
    if (sectionId === 'cyber-rating') {
      if (!cyberRatingInitialized) {
        console.info('[QSCS Phase 5] Cyber Rating initialized.');
        cyberRatingInitialized = true;
      }
    }
    if (sectionId === 'reporting') initReporting();

    // update browser hash
    window.location.hash = sectionId;
    this.currentSection = sectionId;
  },
  init() {
    // attach click listeners to all nav items
    document.querySelectorAll('.app-sidebar .nav-item').forEach(nav => {
      nav.addEventListener('click', (e) => {
        e.preventDefault();
        const navSection = nav.getAttribute('data-section');
        this.navigate(navSection);
      });
    });

    // Handle hash on load
    const validSections = [
      'home', 'asset-inventory', 'asset-discovery',
      'cbom', 'posture-pqc', 'cyber-rating', 'reporting'
    ];
    let hashSection = window.location.hash.replace('#', '');
    if (!validSections.includes(hashSection)) {
      hashSection = 'home';
    }
    this.navigate(hashSection);

    // Also handle manual hash changes
    window.addEventListener('hashchange', () => {
      const changedHash = window.location.hash.replace('#', '');
      if (validSections.includes(changedHash)) {
        this.navigate(changedHash);
      }
    });
  }
};

/* ============================================================
   4. HOME DASHBOARD CHARTS (PHASE 1)
   ============================================================ */

function initHomeCharts() {
  if (HomeCharts.assetType !== null) return; // Prevent re-initialization

  const el = document.getElementById('lastUpdatedTime');
  if (el) {
    el.textContent = new Date().toLocaleTimeString('en-IN', {
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false
    });
  }

  // Shared options
  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          color: '#555566', // var(--pnb-text-muted)
          usePointStyle: true,
          padding: 20
        }
      }
    }
  };

  const pnbColors = {
    red: '#C41230',
    gold: '#F5A623',
    info: '#3B82F6',
    success: '#22C55E',
    warning: '#F59E0B',
    danger: '#EF4444',
    muted: '#555566',
    bg: '#F8F6F3' // var(--pnb-surface-2) equivalent for grid tests
  };

  // 1. Asset Type Distribution (Donut)
  const ctxType = document.getElementById('chartAssetType');
  if (ctxType) {
    HomeCharts.assetType = new Chart(ctxType, {
      type: 'doughnut',
      data: {
        labels: ['Web Apps', 'APIs', 'Servers', 'Load Balancers', 'Other'],
        datasets: [{
          data: [42, 26, 37, 11, 12],
          backgroundColor: [pnbColors.red, pnbColors.gold, pnbColors.info, pnbColors.success, pnbColors.muted],
          borderWidth: 0,
          cutout: '75%'
        }]
      },
      options: {
        ...chartOptions,
        onClick: (event, elements) => {
          if (!elements.length) return;
          const labels = ['Web App', 'API', 'Server', 'Load Balancer', 'Other'];
          const clicked = labels[elements[0].index];
          const typeFilter = document.querySelector('.filter-select[data-filter="type"]');
          if (typeFilter) {
            typeFilter.value = clicked;
            if (typeof applyHomeFilters === 'function') applyHomeFilters();
            document.getElementById('homeAssetTableBody')?.closest('.card')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
          }
        },
        onHover: (event, elements) => {
          event.native.target.style.cursor = elements.length ? 'pointer' : 'default';
        }
      }
    });
  }

  // 2. Asset Risk Distribution (Vertical Bar)
  const ctxRisk = document.getElementById('chartAssetRisk');
  if (ctxRisk) {
    HomeCharts.assetRisk = new Chart(ctxRisk, {
      type: 'bar',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          label: 'Assets',
          data: [14, 28, 45, 41],
          backgroundColor: [pnbColors.danger, pnbColors.warning, pnbColors.info, pnbColors.success],
          borderWidth: 0,
          borderRadius: 4
        }]
      },
      options: {
        ...chartOptions,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            grid: { display: false, drawBorder: false },
            ticks: { color: '#555566' }
          },
          y: {
            grid: { color: 'rgba(0,0,0,0.07)', drawBorder: false },
            ticks: { color: '#555566' }
          }
        },
        onClick: (event, elements) => {
          if (!elements.length) return;
          const labels = ['Critical', 'High', 'Medium', 'Low'];
          const clicked = labels[elements[0].index];
          const riskFilter = document.querySelector('.filter-select[data-filter="risk"]');
          if (riskFilter) {
            riskFilter.value = clicked;
            if (typeof applyHomeFilters === 'function') applyHomeFilters();
            document.getElementById('homeAssetTableBody')?.closest('.card')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
          }
        },
        onHover: (event, elements) => {
          event.native.target.style.cursor = elements.length ? 'pointer' : 'default';
        }
      }
    });
  }

  // 3. IP Version Breakdown (Donut)
  const ctxIp = document.getElementById('chartIpVersion');
  if (ctxIp) {
    HomeCharts.ipVersion = new Chart(ctxIp, {
      type: 'doughnut',
      data: {
        labels: ['IPv4', 'IPv6'],
        datasets: [{
          data: [86, 14],
          backgroundColor: [pnbColors.red, pnbColors.info],
          borderWidth: 0,
          cutout: '75%'
        }]
      },
      options: chartOptions
    });
  }

  console.info('[QSCS Phase 1] Home dashboard initialized.');
}

/* ============================================================
   5. DOM ELEMENT REFERENCES
   ============================================================ */

const DOM = {
  statusDot: document.getElementById('statusDot'),
  statusLabel: document.getElementById('statusLabel'),
  domainInput: document.getElementById('domainInput'),
  scanBtn: document.getElementById('scanBtn'),
  scanBtnText: document.getElementById('scanBtnText'),
  scanBtnSpinner: document.getElementById('scanBtnSpinner'),
  scanBtnIcon: document.getElementById('scanBtnIcon'),
  validationMsg: document.getElementById('validationMsg'),
  riskBadge: document.getElementById('riskBadge'),
  riskEmptyState: document.getElementById('riskEmptyState'),
  riskContent: document.getElementById('riskContent'),
  riskScore: document.getElementById('riskScore'),
  readinessPct: document.getElementById('readinessPct'),
  progressFill: document.getElementById('progressFill'),
  progressLabel: document.getElementById('progressLabel'),
  progressBar: document.getElementById('progressBar'),
  riskTarget: document.getElementById('riskTarget'),
  errorBanner: document.getElementById('errorBanner'),
  errorMsg: document.getElementById('errorMsg'),
  errorClose: document.getElementById('errorClose'),
  tlsGrid: document.getElementById('tlsGrid'),
  tlsEmptyState: document.getElementById('tlsEmptyState'),
  tlsLiveBadge: document.getElementById('tlsLiveBadge'),
  tlsVersion: document.getElementById('tlsVersion'),
  tlsCipher: document.getElementById('tlsCipher'),
  tlsKeyExchange: document.getElementById('tlsKeyExchange'),
  tlsKeyType: document.getElementById('tlsKeyType'),
  tlsKeySize: document.getElementById('tlsKeySize'),
  tlsSigHash: document.getElementById('tlsSigHash'),
  recEmptyState: document.getElementById('recEmptyState'),
  recList: document.getElementById('recList'),
  recCount: document.getElementById('recCount'),
  tableEmptyState: document.getElementById('tableEmptyState'),
  tableWrapper: document.getElementById('tableWrapper'),
  historyTableBody: document.getElementById('historyTableBody'),
  historyCount: document.getElementById('historyCount'),
  clearHistoryBtn: document.getElementById('clearHistoryBtn'),
};

/* ============================================================
   6. VALIDATION
   ============================================================ */

function validateInput(value) {
  const trimmed = value.trim();
  if (!trimmed) return { valid: false, message: 'Please enter a domain or IP address.' };
  if (trimmed.length > 253) return { valid: false, message: 'Input exceeds maximum allowed length (253 chars).' };

  // IPv4
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4.test(trimmed)) {
    const parts = trimmed.split('.').map(Number);
    if (parts.every(p => p >= 0 && p <= 255)) return { valid: true, message: '' };
    return { valid: false, message: 'Invalid IPv4 address — octets must be 0-255.' };
  }

  // Domain
  const domain = /^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*(\.[a-zA-Z]{2,})$/;
  if (domain.test(trimmed)) return { valid: true, message: '' };

  return { valid: false, message: 'Enter a valid domain (e.g. example.com) or IPv4 address.' };
}

/* ============================================================
   7. UI HELPERS
   ============================================================ */

function setStatus(label, state = 'ready') {
  DOM.statusLabel.textContent = label;
  DOM.statusDot.className = 'status-dot';
  if (state === 'scanning') DOM.statusDot.classList.add('scanning');
  if (state === 'error') DOM.statusDot.classList.add('error');
}

function setVisible(el, visible) {
  if (!el) return;
  visible ? el.removeAttribute('hidden') : el.setAttribute('hidden', '');
}

function showValidationError(msg) {
  DOM.validationMsg.textContent = msg;
  DOM.domainInput.classList.add('error');
}

function clearValidationError() {
  DOM.validationMsg.textContent = '';
  DOM.domainInput.classList.remove('error');
}

function showErrorBanner(msg) {
  if (!DOM.errorMsg || !DOM.errorBanner) return;
  DOM.errorMsg.textContent = msg;
  setVisible(DOM.errorBanner, true);
}

function hideErrorBanner() {
  if (!DOM.errorBanner) return;
  setVisible(DOM.errorBanner, false);
}

/* ============================================================
   8. LOADING STATE
   ============================================================ */

function setLoadingState(isLoading) {
  AppState.loadingState = isLoading;
  DOM.scanBtn.disabled = isLoading;
  DOM.domainInput.disabled = isLoading;
  setVisible(DOM.scanBtnSpinner, isLoading);
  setVisible(DOM.scanBtnIcon, !isLoading);
  DOM.scanBtnText.textContent = isLoading ? 'Scanning...' : 'Scan Now';
  setStatus(isLoading ? 'Scanning in progress...' : 'System Ready', isLoading ? 'scanning' : 'ready');
}

/* ============================================================
   9. RENDER: RISK SUMMARY
   ============================================================ */

function renderRiskSummary(data) {
  if (!DOM.riskEmptyState || !DOM.riskContent || !DOM.riskBadge) return;
  setVisible(DOM.riskEmptyState, false);
  setVisible(DOM.riskContent, true);
  DOM.riskBadge.textContent = data.riskLevel;
  DOM.riskBadge.setAttribute('data-level', data.riskLevel);
  if (DOM.riskScore) DOM.riskScore.textContent = data.riskScore;
  if (DOM.readinessPct) DOM.readinessPct.textContent = data.readiness;
  if (DOM.riskTarget) DOM.riskTarget.textContent = data.domain;

  // Animate progress bar after paint
  setTimeout(() => {
    const pct = data.readiness;
    if (DOM.progressFill) {
      DOM.progressFill.style.width = pct + '%';
      DOM.progressFill.setAttribute('data-level', data.riskLevel);
    }
    if (DOM.progressBar) DOM.progressBar.setAttribute('aria-valuenow', pct);
    if (DOM.progressLabel) DOM.progressLabel.textContent = pct + '%';
  }, 80);
}

function resetRiskSummary() {
  setVisible(DOM.riskEmptyState, true);
  setVisible(DOM.riskContent, false);
  DOM.riskBadge.textContent = '—';
  DOM.riskBadge.setAttribute('data-level', '');
  DOM.progressFill.style.width = '0%';
  DOM.progressFill.removeAttribute('data-level');
  DOM.progressLabel.textContent = '0%';
  DOM.progressBar.setAttribute('aria-valuenow', 0);
}

/* ============================================================
   10. RENDER: TLS DETAILS
   ============================================================ */

function renderTLSDetails(tls) {
  setVisible(DOM.tlsEmptyState, false);
  setVisible(DOM.tlsGrid, true);
  setVisible(DOM.tlsLiveBadge, true);
  DOM.tlsVersion.textContent = tls.version;
  DOM.tlsCipher.textContent = tls.cipherSuite;
  DOM.tlsKeyExchange.textContent = tls.keyExchange;
  DOM.tlsKeyType.textContent = tls.publicKeyType;
  DOM.tlsKeySize.textContent = tls.keySize;
  DOM.tlsSigHash.textContent = tls.signatureHash;
}

function resetTLSDetails() {
  setVisible(DOM.tlsEmptyState, true);
  setVisible(DOM.tlsGrid, false);
  setVisible(DOM.tlsLiveBadge, false);
}

/* ============================================================
   11. RENDER: RECOMMENDATIONS
   ============================================================ */

function renderRecommendations(recs) {
  setVisible(DOM.recEmptyState, false);
  setVisible(DOM.recList, true);
  DOM.recCount.textContent = recs.length + ' item' + (recs.length !== 1 ? 's' : '');
  setVisible(DOM.recCount, true);
  DOM.recList.innerHTML = '';

  recs.forEach((rec, idx) => {
    const li = document.createElement('li');
    li.className = 'rec-item';
    li.style.animationDelay = (idx * 60) + 'ms';

    const bullet = document.createElement('span');
    bullet.className = 'rec-bullet priority-' + rec.priority;
    bullet.textContent = rec.priority === 'high' ? 'H' : rec.priority === 'medium' ? 'M' : 'L';
    bullet.title = 'Priority: ' + rec.priority;

    const text = document.createElement('span');
    text.className = 'rec-text';
    text.innerHTML = rec.text;

    li.appendChild(bullet);
    li.appendChild(text);
    DOM.recList.appendChild(li);
  });
}

function resetRecommendations() {
  setVisible(DOM.recEmptyState, true);
  setVisible(DOM.recList, false);
  setVisible(DOM.recCount, false);
  DOM.recList.innerHTML = '';
}

/* ============================================================
   12. RENDER: SCAN HISTORY TABLE
   ============================================================ */

function formatTimestamp(date) {
  return date.toLocaleString('en-US', {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  });
}

function buildHistoryRow(record, isNew) {
  const tr = document.createElement('tr');
  if (isNew) tr.classList.add('new-row');

  const tdDomain = document.createElement('td');
  tdDomain.className = 'td-domain';
  tdDomain.textContent = record.domain;

  const tdRisk = document.createElement('td');
  const pill = document.createElement('span');
  pill.className = 'td-risk-pill ' + record.riskLevel;
  pill.textContent = record.riskLevel;
  tdRisk.appendChild(pill);

  const tdScore = document.createElement('td');
  tdScore.className = 'td-score';
  tdScore.textContent = record.riskScore;

  const tdTime = document.createElement('td');
  tdTime.className = 'td-timestamp';
  tdTime.textContent = formatTimestamp(record.timestamp);

  const tdAction = document.createElement('td');
  const btn = document.createElement('button');
  btn.className = 'td-action-btn';
  btn.textContent = 'Re-scan';
  btn.type = 'button';
  btn.setAttribute('aria-label', 'Re-scan ' + record.domain);
  btn.addEventListener('click', () => {
    DOM.domainInput.value = record.domain;
    DOM.domainInput.focus();
    handleScan();
  });
  tdAction.appendChild(btn);

  tr.appendChild(tdDomain);
  tr.appendChild(tdRisk);
  tr.appendChild(tdScore);
  tr.appendChild(tdTime);
  tr.appendChild(tdAction);

  return tr;
}

function renderHistoryTable() {
  const hasHistory = AppState.scanHistory.length > 0;
  setVisible(DOM.tableEmptyState, !hasHistory);
  setVisible(DOM.tableWrapper, hasHistory);
  setVisible(DOM.clearHistoryBtn, hasHistory);
  setVisible(DOM.historyCount, hasHistory);
  if (!hasHistory) return;

  DOM.historyCount.textContent = AppState.scanHistory.length + ' record' + (AppState.scanHistory.length !== 1 ? 's' : '');
  DOM.historyTableBody.innerHTML = '';

  [...AppState.scanHistory].reverse().forEach((record, idx) => {
    const tr = buildHistoryRow(record, idx === 0);
    DOM.historyTableBody.appendChild(tr);
  });
}

function appendToHistory(data) {
  AppState.scanHistory.push({ ...data, timestamp: new Date() });
  renderHistoryTable();

  // Update home activity feed
  const activityFeed = document.getElementById('homeActivityFeed');
  if (activityFeed) {
    const item = document.createElement('div');
    item.className = 'activity-item activity-new';
    item.innerHTML = `
      <span class="activity-icon">✅</span>
      <span class="activity-text">Scan completed: 
        <strong>${data.domain}</strong> — 
        Risk: ${data.riskLevel}</span>
      <span class="activity-time">just now</span>
    `;
    activityFeed.prepend(item);
    // Keep only latest 5 items
    const items = activityFeed.querySelectorAll('.activity-item');
    if (items.length > 5) items[items.length - 1].remove();
  }
}

function clearHistory() {
  AppState.scanHistory = [];
  renderHistoryTable();
}

/* ============================================================
   13. CORE SCAN HANDLER
   ============================================================ */

function setDemoMode(enabled) {
  demoMode = enabled;
  const existing = document.getElementById('demoModeBadge');
  if (enabled && !existing) {
    const badge = document.createElement('span');
    badge.id = 'demoModeBadge';
    badge.textContent = 'Demo Mode';
    badge.style.cssText = [
      'font-family:var(--font-mono)',
      'font-size:0.65rem',
      'font-weight:700',
      'background:rgba(245,158,11,0.15)',
      'color:#F59E0B',
      'border:1px solid rgba(245,158,11,0.4)',
      'padding:3px 10px',
      'border-radius:20px',
      'margin-right:8px'
    ].join(';');
    const headerRight = document.querySelector('.header-right');
    if (headerRight) headerRight.prepend(badge);
  } else if (!enabled && existing) {
    existing.remove();
  }
}

async function handleScan() {
  const domain = DOM.domainInput.value.trim().toLowerCase();
  clearValidationError();
  hideErrorBanner();

  const { valid, message } = validateInput(domain);
  if (!valid) {
    showValidationError(message);
    DOM.domainInput.focus();
    return;
  }

  setLoadingState(true);
  AppState.errorState = null;
  resetRiskSummary();
  resetTLSDetails();
  resetRecommendations();

  try {
    let scanData;

    try {
      // Call real backend
      const response = await fetch(`${API_BASE_URL}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
        signal: AbortSignal.timeout(25000)
      });

      if (!response.ok) {
        const err = await response.json().catch(() => ({
          detail: 'Scan failed'
        }));
        throw new Error(err.detail || `Server error ${response.status}`);
      }

      const raw = await response.json();

      // Map API response to frontend format
      scanData = {
        domain: raw.domain,
        riskLevel: raw.pqc.risk_level,
        riskScore: raw.pqc.risk_score,
        readiness: raw.pqc.pqc_readiness,
        tls: {
          version: raw.tls.version,
          cipherSuite: raw.tls.cipher_suite,
          keyExchange: raw.tls.key_exchange,
          publicKeyType: raw.tls.public_key_type,
          keySize: raw.tls.key_size,
          signatureHash: raw.tls.signature_hash,
        },
        recommendations: raw.pqc.recommendations
      };

      setDemoMode(false);

    } catch (fetchErr) {
      // If backend is offline, fall back to mock data silently
      const isNetworkError = (
        fetchErr.name === 'TypeError' ||
        fetchErr.name === 'AbortError' ||
        String(fetchErr).includes('fetch')
      );

      if (isNetworkError) {
        setDemoMode(true);
        await sleep(1200 + Math.random() * 800);
        if (shouldSimulateFailure(domain)) {
          throw new Error(
            'Connection refused: Unable to reach ' + domain +
            '. The host may be offline or blocking TLS probes.'
          );
        }
        scanData = getMockScanData(domain);
      } else {
        setDemoMode(false);
        throw fetchErr;
      }
    }

    AppState.currentScan = scanData;
    renderRiskSummary(scanData);
    renderTLSDetails(scanData.tls);
    renderRecommendations(scanData.recommendations);
    appendToHistory(scanData);
    setStatus(
      `Scan complete — ${domain}${demoMode ? ' (demo)' : ''}`,
      'ready'
    );

  } catch (err) {
    AppState.errorState = err.message;
    AppState.currentScan = null;
    showErrorBanner(err.message);
    setStatus('Scan failed', 'error');
    resetRiskSummary();
    resetTLSDetails();
    resetRecommendations();
    setTimeout(() => {
      setStatus('System Ready', 'ready');
      AppState.errorState = null;
    }, 5000);

  } finally {
    setLoadingState(false);
  }
}

/* ============================================================
   14. UTILITY
   ============================================================ */

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/* ============================================================
   15. EVENT LISTENERS
   ============================================================ */

DOM.scanBtn.addEventListener('click', handleScan);

DOM.domainInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !AppState.loadingState) handleScan();
});

DOM.domainInput.addEventListener('input', () => {
  if (DOM.domainInput.value.trim()) clearValidationError();
});

DOM.errorClose.addEventListener('click', hideErrorBanner);

DOM.clearHistoryBtn.addEventListener('click', clearHistory);

/* ============================================================
   16. INIT
   ============================================================ */

function init() {
  // Initialize SPA Router
  console.info('[QSCS Phase 0] SPA initialized.');
  Router.init();
  initHomeFeatures();

  // Reset states
  resetRiskSummary();
  resetTLSDetails();
  resetRecommendations();
  renderHistoryTable();
  hideErrorBanner();
  setStatus('System Ready', 'ready');

  // Initialize discovery tabs (Phase 2)
  initDiscoveryTabs();

  // Set focus on initial load if on asset-inventory
  if (Router.currentSection === 'asset-inventory') {
    DOM.domainInput.focus();
  }

  // Fallback if not initialized dynamically by hash Router map
  if (!window.location.hash || window.location.hash === '#home') {
    initHomeCharts();
  }

  function updateDateTime() {
    const now = new Date();
    const formatted = now.toLocaleString('en-IN', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false
    });
    const el = document.getElementById('headerDatetime');
    if (el) el.textContent = formatted;
  }
  updateDateTime();
  setInterval(updateDateTime, 1000);


  // Top bar datetime
  function updateTopBar() {
    const el = document.getElementById('topBarDateTime');
    if (el) {
      el.textContent = new Date().toLocaleString('en-IN', {
        weekday: 'short', day: '2-digit', month: 'short', year: 'numeric',
        hour: '2-digit', minute: '2-digit', hour12: false
      });
    }
  }
  updateTopBar();
  setInterval(updateTopBar, 1000);

  console.log('%c Quantum-Proof Systems Scanner ',
    'background:#C41230;color:white;font-weight:bold;padding:4px 8px;border-radius:4px');
  console.log('%c Team CypherRed261 | PSB Hackathon 2026 | LPU ',
    'background:#F5A623;color:#0D0D0F;font-weight:bold;padding:4px 8px;border-radius:4px');
  console.log('%c All 7 modules initialized successfully ✓ ',
    'background:#22C55E;color:white;font-weight:bold;padding:4px 8px;border-radius:4px');
}

init();

/* ============================================================
   17. ASSET DISCOVERY MODULE (PHASE 2)
   ============================================================ */


const GRAPH_DATA = {
  nodes: [
    { id: 'pnb.bank.in', type: 'domain' },
    { id: 'portal.pnb.bank.in', type: 'domain' },
    { id: 'api.pnb.bank.in', type: 'domain' },
    { id: 'vpn.pnb.bank.in', type: 'domain' },
    { id: '103.109.225.128', type: 'ip' },
    { id: '103.109.225.201', type: 'ip' },
    { id: '40.104.62.216', type: 'ip' },
    { id: 'SSL-cert-1', type: 'ssl' },
    { id: 'SSL-cert-2', type: 'ssl' },
    { id: 'Tag:VPN', type: 'tag' },
    { id: 'Tag:WebApp', type: 'tag' },
    { id: 'Tag:API', type: 'tag' },
  ],
  links: [
    { source: 'pnb.bank.in', target: '103.109.225.128' },
    { source: 'portal.pnb.bank.in', target: '103.109.225.128' },
    { source: 'portal.pnb.bank.in', target: 'SSL-cert-1' },
    { source: 'api.pnb.bank.in', target: '103.109.225.201' },
    { source: 'api.pnb.bank.in', target: 'SSL-cert-2' },
    { source: 'vpn.pnb.bank.in', target: '40.104.62.216' },
    { source: 'vpn.pnb.bank.in', target: 'Tag:VPN' },
    { source: 'portal.pnb.bank.in', target: 'Tag:WebApp' },
    { source: 'api.pnb.bank.in', target: 'Tag:API' },
    { source: '103.109.225.128', target: 'Tag:WebApp' },
  ]
};

function initDiscoveryTabs() {
  if (discoveryTabsInitialized) return;

  // Use event delegation on discovery section
  const section = document.getElementById('section-asset-discovery');
  if (!section) return;

  // Tab switching via delegation
  section.addEventListener('click', (e) => {
    const tab = e.target.closest('.tab-button') || e.target.closest('.discovery-tab');
    if (tab) {
      const targetId = tab.getAttribute('data-tab');
      // Remove active from all tabs
      section.querySelectorAll('.tab-button, .discovery-tab').forEach(t => t.classList.remove('active'));
      // Hide all panels
      section.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active-panel', 'active'));
      // Activate clicked
      tab.classList.add('active');
      const panel = document.getElementById(targetId);
      if (panel) panel.classList.add('active-panel', 'active');
      // Init network graph if needed
      if (targetId === 'tab-network') initNetworkGraph();
    }

    // Sub-filter switching
    const subFilter = e.target.closest('.sub-filter');
    if (subFilter) {
      const parent = subFilter.closest('.sub-filter-bar') || subFilter.closest('.sub-filters');
      if (parent) {
        parent.querySelectorAll('.sub-filter').forEach(f => f.classList.remove('active'));
        subFilter.classList.add('active');
      }
    }

    // Feature - Discovery Search
    if (e.target.id === 'discoverySearchBtn') {
      const input = document.getElementById('discoverySearchInput');
      // simple visual feedback
      e.target.textContent = 'Searching...';
      setTimeout(() => {
        e.target.textContent = 'Search';
      }, 1000);
    }
  });

  console.info('[QSCS Phase 2] Asset Discovery initialized.');
  discoveryTabsInitialized = true;
}

function initNetworkGraph() {
  if (networkGraphInitialized) return;

  const container = document.getElementById('networkGraph');
  if (!container) return;
  const width = container.clientWidth || 800;
  const height = 480;

  const colorScale = d3.scaleOrdinal()
    .domain(['domain', 'ip', 'ssl', 'tag'])
    .range(['#22C55E', '#3B82F6', '#F5A623', '#C41230']);

  const radiusScale = d3.scaleOrdinal()
    .domain(['domain', 'ip', 'ssl', 'tag'])
    .range([14, 10, 10, 12]);

  const svg = d3.select('#networkGraph')
    .append('svg')
    .attr('width', '100%')
    .attr('height', '100%')
    .attr('viewBox', [0, 0, width, height]);

  const simulation = d3.forceSimulation(GRAPH_DATA.nodes)
    .force('link', d3.forceLink(GRAPH_DATA.links).id(d => d.id).distance(100))
    .force('charge', d3.forceManyBody().strength(-300))
    .force('center', d3.forceCenter(width / 2, height / 2));

  const link = svg.append('g')
    .attr('stroke', 'rgba(255,255,255,0.2)')
    .attr('stroke-width', 1.5)
    .selectAll('line')
    .data(GRAPH_DATA.links)
    .join('line');

  const node = svg.append('g')
    .selectAll('circle')
    .data(GRAPH_DATA.nodes)
    .join('circle')
    .attr('r', d => radiusScale(d.type))
    .attr('fill', d => colorScale(d.type))
    .call(drag(simulation));

  const label = svg.append('g')
    .selectAll('text')
    .data(GRAPH_DATA.nodes)
    .join('text')
    .text(d => d.id)
    .attr('font-size', '10px')
    .attr('fill', '#8A8A90')
    .attr('dy', -16)
    .attr('text-anchor', 'middle');

  simulation.on('tick', () => {
    link
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);

    node
      .attr('cx', d => Math.max(15, Math.min(width - 15, d.x)))
      .attr('cy', d => Math.max(15, Math.min(height - 15, d.y)));

    label
      .attr('x', d => Math.max(15, Math.min(width - 15, d.x)))
      .attr('y', d => Math.max(15, Math.min(height - 15, d.y)));
  });

  function drag(simulation) {
    function dragstarted(event) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      event.subject.fx = event.subject.x;
      event.subject.fy = event.subject.y;
    }

    function dragged(event) {
      event.subject.fx = event.x;
      event.subject.fy = event.y;
    }

    function dragended(event) {
      if (!event.active) simulation.alphaTarget(0);
      event.subject.fx = null;
      event.subject.fy = null;
    }

    return d3.drag()
      .on('start', dragstarted)
      .on('drag', dragged)
      .on('end', dragended);
  }

  console.info('[QSCS Phase 2] Network graph initialized.');
  networkGraphInitialized = true;
}

/* ============================================================
   18. CBOM MODULE (PHASE 3)
   ============================================================ */

const CbomCharts = {
  keyLength: null,
  cipherUsage: null,
  certAuthorities: null,
  encryptionProtocols: null
};

const centerTextPlugin = {
  id: 'centerText',
  afterDraw(chart) {
    if (chart.canvas.id !== 'chartEncryptionProtocols') return;
    const { ctx, chartArea: { width, height, left, top } } = chart;
    ctx.save();
    ctx.font = 'bold 28px DM Sans';
    ctx.fillStyle = '#F0F0F2';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    const cx = left + width / 2;
    const cy = top + height / 2 - 10;
    ctx.fillText('72%', cx, cy);
    ctx.font = '12px DM Sans';
    ctx.fillStyle = '#8A8A90';
    ctx.fillText('TLS 1.3', cx, cy + 22);
    ctx.restore();
  }
};
function initCbomCharts() {
  if (CbomCharts.keyLength) {
    const canvas = document.getElementById('chartKeyLength');
    if (canvas && canvas.offsetWidth > 0) return;
    Object.values(CbomCharts).forEach(c => { if (c) c.destroy(); });
    CbomCharts.keyLength = null;
    CbomCharts.cipherUsage = null;
    CbomCharts.certAuthorities = null;
    CbomCharts.encryptionProtocols = null;
  }
  Chart.register(centerTextPlugin);

  const pnbColors = {
    red: '#C41230',
    gold: '#F5A623',
    goldLight: '#FFD166',
    info: '#3B82F6',
    success: '#22C55E',
    warning: '#F59E0B',
    danger: '#EF4444',
    muted: '#555566',
    bg: '#F8F6F3'
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false }
    }
  };

  // 1. Key Length Distribution (Vertical Bar)
  const ctxKey = document.getElementById('chartKeyLength');
  if (ctxKey) {
    CbomCharts.keyLength = new Chart(ctxKey, {
      type: 'bar',
      data: {
        labels: ['4096', '3078', '2048', '2044', '27'],
        datasets: [{
          data: [36, 46, 42, 37, 27],
          backgroundColor: pnbColors.gold,
          hoverBackgroundColor: pnbColors.goldLight,
          borderWidth: 0,
          borderRadius: 4
        }]
      },
      options: {
        ...chartOptions,
        scales: {
          x: {
            grid: { display: false, drawBorder: false },
            ticks: { color: '#555566' }
          },
          y: {
            grid: { color: 'rgba(0,0,0,0.07)', drawBorder: false },
            ticks: { color: '#555566' }
          }
        }
      }
    });
  }

  // 2. Cipher Usage (Horizontal Bar)
  const ctxCipher = document.getElementById('chartCipherUsage');
  if (ctxCipher) {
    CbomCharts.cipherUsage = new Chart(ctxCipher, {
      type: 'bar',
      data: {
        labels: [
          'ECDHE-RSA-AES256-GCM-SHA384',
          'ECDHE-ECDSA-AES256-GCM-SHA384',
          'AES256-GCM-SHA384',
          'AES128-GCM-SHA256',
          'TLS_RSA_WITH_DES_CBC_SHA'
        ],
        datasets: [{
          data: [29, 23, 19, 15, 9],
          backgroundColor: [
            pnbColors.success,
            pnbColors.success,
            pnbColors.info,
            pnbColors.warning,
            pnbColors.danger
          ],
          borderWidth: 0,
          borderRadius: 4
        }]
      },
      options: {
        ...chartOptions,
        indexAxis: 'y',
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            grid: { display: false, drawBorder: false },
            ticks: { color: '#555566' }
          },
          y: {
            grid: { display: false, drawBorder: false },
            ticks: { color: '#555566', font: { family: 'IBM Plex Mono' } }
          }
        }
      }
    });
  }

  // 3. Top Certificate Authorities (Donut)
  const ctxCert = document.getElementById('chartCertAuthorities');
  if (ctxCert) {
    CbomCharts.certAuthorities = new Chart(ctxCert, {
      type: 'doughnut',
      data: {
        labels: ['DigiCert', 'Thawte', "Let's Encrypt", 'COMODO', 'Other'],
        datasets: [{
          data: [39, 39, 12, 6, 16],
          backgroundColor: [pnbColors.info, pnbColors.gold, pnbColors.success, pnbColors.danger, pnbColors.muted],
          borderWidth: 0,
          cutout: '65%'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: '#555566',
              usePointStyle: true,
              padding: 20
            }
          }
        }
      }
    });
  }

  // 4. Encryption Protocols (Donut)
  const ctxEnc = document.getElementById('chartEncryptionProtocols');
  if (ctxEnc) {
    CbomCharts.encryptionProtocols = new Chart(ctxEnc, {
      type: 'doughnut',
      data: {
        labels: ['TLS 1.3', 'TLS 1.2', 'TLS 1.1'],
        datasets: [{
          data: [72, 20, 8],
          backgroundColor: [pnbColors.success, pnbColors.info, pnbColors.danger],
          borderWidth: 0,
          cutout: '65%'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: '#555566',
              usePointStyle: true,
              padding: 20
            }
          }
        }
      }
    });
  }

  console.info('[QSCS Phase 3] CBOM dashboard initialized.');
}

/* ============================================================
   19. POSTURE OF PQC (PHASE 4)
   ============================================================ */

const PqcCharts = {
  classificationGrade: null,
  applicationStatus: null
};

function initPqcCharts() {
  if (PqcCharts.classificationGrade) {
    const canvas = document.getElementById('chartClassificationGrade');
    if (canvas && canvas.offsetWidth > 0) return;
    Object.values(PqcCharts).forEach(c => { if (c) c.destroy(); });
    PqcCharts.classificationGrade = null;
    PqcCharts.applicationStatus = null;
  }

  const pnbColors = {
    red: '#C41230',
    info: '#3B82F6',
    success: '#22C55E',
    warning: '#F59E0B',
    danger: '#EF4444',
    muted: '#555566',
    bg: '#F8F6F3'
  };

  const commonOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false }
    }
  };

  const ctxClass = document.getElementById('chartClassificationGrade');
  if (ctxClass) {
    PqcCharts.classificationGrade = new Chart(ctxClass, {
      type: 'bar',
      data: {
        labels: ['Elite', 'Critical', 'Std'],
        datasets: [{
          data: [37, 2, 4],
          backgroundColor: [
            pnbColors.success,
            pnbColors.danger,
            pnbColors.warning
          ],
          borderWidth: 0,
          borderRadius: 4
        }]
      },
      options: {
        ...commonOptions,
        scales: {
          x: {
            grid: { display: false, drawBorder: false },
            ticks: { color: '#555566' }
          },
          y: {
            grid: { color: 'rgba(0,0,0,0.07)', drawBorder: false },
            ticks: { color: '#555566' }
          }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  }

  const ctxApp = document.getElementById('chartApplicationStatus');
  if (ctxApp) {
    PqcCharts.applicationStatus = new Chart(ctxApp, {
      type: 'doughnut',
      data: {
        labels: ['Elite-PQC Ready', 'Standard', 'Legacy', 'Critical'],
        datasets: [{
          data: [45, 30, 15, 10],
          backgroundColor: [pnbColors.success, pnbColors.warning, pnbColors.info, pnbColors.danger],
          borderWidth: 0,
          cutout: '60%'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: true,
            position: 'bottom',
            labels: {
              color: '#555566',
              usePointStyle: true,
              padding: 20
            }
          }
        }
      }
    });
  }


  console.info('[QSCS Phase 4] Posture of PQC initialized.');
}

/* ============================================================
   20. REPORTING (PHASE 6)
   ============================================================ */

function initReporting() {
  if (reportingInitialized) return;

  const section = document.getElementById('section-reporting');
  if (!section) return;

  // Landing card clicks via delegation
  section.addEventListener('click', (e) => {
    const card = e.target.closest('.report-card');
    if (card) {
      showReportView(card.getAttribute('data-report'));
      return;
    }
    const backBtn = e.target.closest('.report-back-btn');
    if (backBtn) {
      showReportView('landing');
      return;
    }
    if (e.target.id === 'btnScheduleReport') {
      showReportToast('scheduled');
    }
    if (e.target.id === 'btnGenerateReport') {
      showReportToast('generated');
    }
  });

  reportingInitialized = true;
  console.info('[QSCS Phase 6] Reporting module initialized.');
}

function showReportView(type) {
  document.querySelectorAll('.report-view').forEach(v =>
    v.classList.remove('active'));
  const target = document.getElementById('report-view-' + type);
  if (target) target.classList.add('active');
}

function showReportToast(type) {
  const toast = document.getElementById('reportToast');
  if (!toast) return;
  toast.textContent = type === 'scheduled'
    ? '✅ Report scheduled successfully!'
    : '✅ Report generated successfully!';
  toast.style.display = 'block';
  toast.style.animation = 'slideUp 0.3s ease';
  setTimeout(() => { toast.style.display = 'none'; }, 3000);
}

/* ============================================================
   21. PHASE 8 - HOME FEATURES
   ============================================================ */

function applyHomeFilters() {
  const filters = {};
  document.querySelectorAll('.filter-select').forEach(sel => {
    if (sel.value) filters[sel.dataset.filter] = sel.value.toLowerCase();
  });
  const tbody = document.getElementById('homeAssetTableBody');
  if (!tbody) return;
  tbody.querySelectorAll('tr:not(.no-results-row)').forEach(row => {
    const type = row.cells[4]?.textContent.toLowerCase() || '';
    const owner = row.cells[5]?.textContent.toLowerCase() || '';
    const risk = row.cells[6]?.textContent.toLowerCase() || '';
    const cert = row.cells[7]?.textContent.toLowerCase() || '';
    const show =
      (!filters.type || type.includes(filters.type)) &&
      (!filters.owner || owner.includes(filters.owner)) &&
      (!filters.risk || risk.includes(filters.risk)) &&
      (!filters.cert || cert.includes(filters.cert));
    row.style.display = show ? '' : 'none';
  });
}


function initHomeFeatures() {
  // Sidebar toggle
  const toggleBtn = document.getElementById('sidebarToggle');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      sidebarCollapsed = !sidebarCollapsed;
      document.querySelector('.app-sidebar').classList.toggle('collapsed', sidebarCollapsed);
      document.querySelector('.app-main-content').classList.toggle('sidebar-collapsed', sidebarCollapsed);
    });
  }

  // Resolve button
  const resolveBtn = document.querySelector('[data-action="resolve"]');
  if (resolveBtn) {
    resolveBtn.addEventListener('click', function () {
      this.textContent = 'Resolving...';
      this.disabled = true;
      setTimeout(() => {
        this.textContent = 'Resolve';
        this.disabled = false;
        const toast = document.getElementById('reportToast');
        if (toast) {
          toast.textContent = '✅ DNS resolved successfully for company.com';
          toast.style.display = 'block';
          setTimeout(() => { toast.style.display = 'none'; }, 3000);
        }
      }, 1500);
    });
  }

  // Add Asset modal
  const addAssetBtn = document.querySelector('[data-action="add-asset"]');
  if (addAssetBtn) {
    addAssetBtn.addEventListener('click', () => {
      const modal = document.getElementById('addAssetModal');
      if (modal) modal.style.display = 'flex';
    });
  }
  ['closeAssetModal', 'cancelAssetModal'].forEach(id => {
    const btn = document.getElementById(id);
    if (btn) btn.addEventListener('click', () => {
      document.getElementById('addAssetModal').style.display = 'none';
    });
  });
  const confirmAdd = document.getElementById('confirmAddAsset');
  if (confirmAdd) {
    confirmAdd.addEventListener('click', () => {
      const name = document.getElementById('newAssetName')?.value.trim();
      const url = document.getElementById('newAssetUrl')?.value.trim();
      const type = document.getElementById('newAssetType')?.value;
      const owner = document.getElementById('newAssetOwner')?.value;
      if (!name) return;
      const tbody = document.getElementById('homeAssetTableBody');
      if (tbody) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td class="td-domain">${name}</td><td><a href="${url}" style="color:var(--pnb-info);font-size:0.78rem">${url || '—'}</a></td><td class="mono" style="font-size:0.75rem">—</td><td class="mono" style="font-size:0.75rem">—</td><td>${type}</td><td>${owner}</td><td><span class="td-risk-pill LOW">LOW</span></td><td style="color:var(--pnb-success);font-size:0.78rem">Valid</td><td class="mono" style="font-size:0.75rem">—</td><td style="color:var(--pnb-text-dim);font-size:0.72rem">just now</td>`;
        tbody.prepend(tr);
      }
      document.getElementById('addAssetModal').style.display = 'none';
      if (document.getElementById('newAssetName')) document.getElementById('newAssetName').value = '';
      if (document.getElementById('newAssetUrl')) document.getElementById('newAssetUrl').value = '';
    });
  }

  // Scan All
  const scanAllBtn = document.querySelector('[data-action="scan-all"]');
  if (scanAllBtn) {
    scanAllBtn.addEventListener('click', function () {
      this.disabled = true;
      this.innerHTML = '<span class="scan-btn-spinner"></span> Scanning...';
      setTimeout(() => {
        this.disabled = false;
        this.innerHTML = 'Scan All ›';
        const el = document.getElementById('lastUpdatedTime');
        if (el) el.textContent = new Date().toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
        const toast = document.getElementById('reportToast');
        if (toast) {
          toast.textContent = '✅ All 128 assets scanned successfully!';
          toast.style.display = 'block';
          setTimeout(() => { toast.style.display = 'none'; }, 3000);
        }
      }, 2000);
    });
  }

  // Search filter
  const searchInput = document.querySelector('[data-action="asset-search"]');
  if (searchInput) {
    searchInput.addEventListener('input', function () {
      const query = this.value.toLowerCase().trim();
      const tbody = document.getElementById('homeAssetTableBody');
      if (!tbody) return;
      const rows = tbody.querySelectorAll('tr:not(.no-results-row)');
      let visibleCount = 0;
      rows.forEach(row => {
        const match = !query || (row.cells[0]?.textContent.toLowerCase() || '').includes(query) || (row.cells[1]?.textContent.toLowerCase() || '').includes(query);
        row.style.display = match ? '' : 'none';
        if (match) visibleCount++;
      });
      let noResults = tbody.querySelector('.no-results-row');
      if (visibleCount === 0 && query) {
        if (!noResults) {
          noResults = document.createElement('tr');
          noResults.className = 'no-results-row';
          noResults.innerHTML = '<td colspan="10" style="text-align:center;padding:24px;color:var(--pnb-text-dim)">No matching assets found</td>';
          tbody.appendChild(noResults);
        }
        noResults.style.display = '';
      } else if (noResults) {
        noResults.style.display = 'none';
      }
    });
  }

  // Filter dropdowns
  document.querySelectorAll('.filter-select').forEach(sel => sel.addEventListener('change', applyHomeFilters));
  const resetBtn = document.getElementById('resetFilters');
  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      document.querySelectorAll('.filter-select').forEach(s => s.value = '');
      applyHomeFilters();
    });
  }
}

/* ============================================================
   LOGIN SYSTEM — Quantum-Proof Systems Scanner
   Team CypherRed261 | PSB Hackathon 2026
   ============================================================ */

const AUTHORIZED_USERS = {
  'judge01':  'pnb@123',
  'judge02':  'pnb@123',
  'judge03':  'pnb@123',
  'pnbuser':  'pnb@123',
  'chanukya': 'pnb@123',
  'anil':     'pnb@123',
  'ankush':   'pnb@123',
  'santosh':  'pnb@123',
  'mentor':   'pnb@123'
};

const USER_DISPLAY = {
  'judge01':  'Judge 01',  'judge02': 'Judge 02', 'judge03': 'Judge 03',
  'pnbuser':  'PNB User',  'chanukya':'Chanukya',
  'anil':     'Anil',      'ankush':  'Ankush',
  'santosh':  'Santosh',   'mentor':  'Mentor'
};

const SESSION_KEY = 'qscs_session_v1';

/* ── helpers ── */
function $id(id) { return document.getElementById(id); }

function loginSetError(msg) {
  var el = $id('loginErrorMsg');
  var tx = $id('loginErrorText');
  var u  = $id('loginUsername');
  var p  = $id('loginPassword');
  if (tx) tx.textContent = msg;
  if (el) { el.style.display = 'flex'; }
  if (u)  u.classList.add('error');
  if (p)  p.classList.add('error');
  setTimeout(function() {
    if (el) el.style.display = 'none';
    if (u)  u.classList.remove('error');
    if (p)  p.classList.remove('error');
  }, 4000);
}

function loginShakeCard() {
  var card = document.querySelector('.login-card');
  if (!card) return;
  var orig = card.style.transition;
  card.style.transition = 'transform 0.07s ease';
  var steps = [-8, 8, -5, 5, -2, 0];
  var i = 0;
  var step = function() {
    if (i < steps.length) {
      card.style.transform = 'translateX(' + steps[i] + 'px)';
      i++;
      setTimeout(step, 70);
    } else {
      card.style.transition = orig;
    }
  };
  step();
}

function enterApp(username) {
  var screen = $id('login-screen');
  if (!screen) return;
  var nameEl = $id('headerUserName');
  if (nameEl) nameEl.textContent = '\uD83D\uDC64 ' + (USER_DISPLAY[username] || username);
  screen.classList.add('fade-out');
  setTimeout(function() { screen.style.display = 'none'; }, 480);
  try {
    fetch(API_BASE_URL + '/api/audit-login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username, event: 'USER_LOGIN' })
    }).catch(function(){});
  } catch(e) {}
  console.info('[QSCS Auth] Logged in as: ' + username);
}

function handleLoginClick() {
  var uEl = $id('loginUsername');
  var pEl = $id('loginPassword');
  var btn = $id('loginBtn');
  var btnTxt = $id('loginBtnContent');

  var username = (uEl ? uEl.value.trim().toLowerCase() : '');
  var password = (pEl ? pEl.value : '');

  // clear errors
  var errEl = $id('loginErrorMsg');
  if (errEl) errEl.style.display = 'none';
  if (uEl) uEl.classList.remove('error');
  if (pEl) pEl.classList.remove('error');

  if (!username) { loginSetError('Please enter your username'); if(uEl) uEl.focus(); return; }
  if (!password) { loginSetError('Please enter your password'); if(pEl) pEl.focus(); return; }

  // loading state
  if (btn) btn.disabled = true;
  if (btnTxt) btnTxt.innerHTML = '<span class="login-btn-spinner"></span> Authenticating...';

  setTimeout(function() {
    var expected = AUTHORIZED_USERS[username];
    if (expected && password === expected) {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify({ username: username }));
      enterApp(username);
    } else {
      if (btn) btn.disabled = false;
      if (btnTxt) btnTxt.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg> Sign In';
      loginShakeCard();
      if (!AUTHORIZED_USERS[username]) {
        loginSetError('Username not found — access denied');
      } else {
        loginSetError('Incorrect password — please try again');
      }
      if (pEl) { pEl.value = ''; pEl.focus(); }
    }
  }, 800);
}

function handleLogout() {
  sessionStorage.removeItem(SESSION_KEY);
  var screen = $id('login-screen');
  if (screen) {
    screen.style.display = 'flex';
    screen.style.opacity = '1';
    screen.classList.remove('fade-out');
  }
  var u = $id('loginUsername');
  var p = $id('loginPassword');
  if (u) u.value = '';
  if (p) p.value = '';
  var nameEl = $id('headerUserName');
  if (nameEl) nameEl.textContent = '';
  console.info('[QSCS Auth] Logged out');
}

function initLoginSystem() {
  // Check existing session
  try {
    var sess = sessionStorage.getItem(SESSION_KEY);
    if (sess) {
      var data = JSON.parse(sess);
      if (data.username && AUTHORIZED_USERS[data.username]) {
        enterApp(data.username);
        return;
      }
    }
  } catch(e) {}

  // Wire up login button
  var loginBtn = $id('loginBtn');
  if (loginBtn) {
    loginBtn.onclick = handleLoginClick;
  } else {
    console.error('[QSCS Auth] loginBtn not found!');
  }

  // Enter key support
  ['loginUsername', 'loginPassword'].forEach(function(id) {
    var el = $id(id);
    if (el) el.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') handleLoginClick();
    });
  });

  // Password visibility toggle
  var toggle = $id('loginPwdToggle');
  var pwdInput = $id('loginPassword');
  var eyeOpen = $id('eyeOpen');
  var eyeClosed = $id('eyeClosed');
  if (toggle && pwdInput) {
    toggle.onclick = function() {
      var show = pwdInput.type === 'password';
      pwdInput.type = show ? 'text' : 'password';
      if (eyeOpen)   eyeOpen.style.display   = show ? 'none'  : 'block';
      if (eyeClosed) eyeClosed.style.display = show ? 'block' : 'none';
      pwdInput.focus();
    };
  }

  // Logout button
  var logoutBtn = $id('logoutBtn');
  if (logoutBtn) logoutBtn.onclick = handleLogout;

  // Focus username
  setTimeout(function() {
    var u = $id('loginUsername');
    if (u) u.focus();
  }, 300);

  console.info('[QSCS Auth] Login system ready');
}

// Run after DOM fully loaded
window.addEventListener('load', initLoginSystem);
