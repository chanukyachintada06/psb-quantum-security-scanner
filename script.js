/**
 * ============================================================
 * QUANTUM-SAFE CRYPTOGRAPHY SCANNER — script.js
 * Post-Quantum TLS Risk Analyzer
 *
 * Phase B: Dynamic rendering & mock scan logic
 * Phase C: UX handling & state management
 * ============================================================
 */

'use strict';

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
   2. APPLICATION STATE
   ============================================================ */

const AppState = {
  currentScan: null,
  scanHistory: [],
  loadingState: false,
  errorState: null,
};

/* ============================================================
   3. DOM ELEMENT REFERENCES
   ============================================================ */

const DOM = {
  statusDot:        document.getElementById('statusDot'),
  statusLabel:      document.getElementById('statusLabel'),
  domainInput:      document.getElementById('domainInput'),
  scanBtn:          document.getElementById('scanBtn'),
  scanBtnText:      document.getElementById('scanBtnText'),
  scanBtnSpinner:   document.getElementById('scanBtnSpinner'),
  scanBtnIcon:      document.getElementById('scanBtnIcon'),
  validationMsg:    document.getElementById('validationMsg'),
  riskBadge:        document.getElementById('riskBadge'),
  riskEmptyState:   document.getElementById('riskEmptyState'),
  riskContent:      document.getElementById('riskContent'),
  riskScore:        document.getElementById('riskScore'),
  readinessPct:     document.getElementById('readinessPct'),
  progressFill:     document.getElementById('progressFill'),
  progressLabel:    document.getElementById('progressLabel'),
  progressBar:      document.getElementById('progressBar'),
  riskTarget:       document.getElementById('riskTarget'),
  errorBanner:      document.getElementById('errorBanner'),
  errorMsg:         document.getElementById('errorMsg'),
  errorClose:       document.getElementById('errorClose'),
  tlsGrid:          document.getElementById('tlsGrid'),
  tlsEmptyState:    document.getElementById('tlsEmptyState'),
  tlsLiveBadge:     document.getElementById('tlsLiveBadge'),
  tlsVersion:       document.getElementById('tlsVersion'),
  tlsCipher:        document.getElementById('tlsCipher'),
  tlsKeyExchange:   document.getElementById('tlsKeyExchange'),
  tlsKeyType:       document.getElementById('tlsKeyType'),
  tlsKeySize:       document.getElementById('tlsKeySize'),
  tlsSigHash:       document.getElementById('tlsSigHash'),
  recEmptyState:    document.getElementById('recEmptyState'),
  recList:          document.getElementById('recList'),
  recCount:         document.getElementById('recCount'),
  tableEmptyState:  document.getElementById('tableEmptyState'),
  tableWrapper:     document.getElementById('tableWrapper'),
  historyTableBody: document.getElementById('historyTableBody'),
  historyCount:     document.getElementById('historyCount'),
  clearHistoryBtn:  document.getElementById('clearHistoryBtn'),
};

/* ============================================================
   4. VALIDATION
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
   5. UI HELPERS
   ============================================================ */

function setStatus(label, state = 'ready') {
  DOM.statusLabel.textContent = label;
  DOM.statusDot.className = 'status-dot';
  if (state === 'scanning') DOM.statusDot.classList.add('scanning');
  if (state === 'error')    DOM.statusDot.classList.add('error');
}

function setVisible(el, visible) {
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
  DOM.errorMsg.textContent = msg;
  setVisible(DOM.errorBanner, true);
}

function hideErrorBanner() {
  setVisible(DOM.errorBanner, false);
}

/* ============================================================
   6. LOADING STATE
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
   7. RENDER: RISK SUMMARY
   ============================================================ */

function renderRiskSummary(data) {
  setVisible(DOM.riskEmptyState, false);
  setVisible(DOM.riskContent, true);
  DOM.riskBadge.textContent = data.riskLevel;
  DOM.riskBadge.setAttribute('data-level', data.riskLevel);
  DOM.riskScore.textContent = data.riskScore;
  DOM.readinessPct.textContent = data.readiness;
  DOM.riskTarget.textContent = data.domain;

  // Animate progress bar after paint
  setTimeout(() => {
    const pct = data.readiness;
    DOM.progressFill.style.width = pct + '%';
    DOM.progressFill.setAttribute('data-level', data.riskLevel);
    DOM.progressBar.setAttribute('aria-valuenow', pct);
    DOM.progressLabel.textContent = pct + '%';
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
   8. RENDER: TLS DETAILS
   ============================================================ */

function renderTLSDetails(tls) {
  setVisible(DOM.tlsEmptyState, false);
  setVisible(DOM.tlsGrid, true);
  setVisible(DOM.tlsLiveBadge, true);
  DOM.tlsVersion.textContent     = tls.version;
  DOM.tlsCipher.textContent      = tls.cipherSuite;
  DOM.tlsKeyExchange.textContent = tls.keyExchange;
  DOM.tlsKeyType.textContent     = tls.publicKeyType;
  DOM.tlsKeySize.textContent     = tls.keySize;
  DOM.tlsSigHash.textContent     = tls.signatureHash;
}

function resetTLSDetails() {
  setVisible(DOM.tlsEmptyState, true);
  setVisible(DOM.tlsGrid, false);
  setVisible(DOM.tlsLiveBadge, false);
}

/* ============================================================
   9. RENDER: RECOMMENDATIONS
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
   10. RENDER: SCAN HISTORY TABLE
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
}

function clearHistory() {
  AppState.scanHistory = [];
  renderHistoryTable();
}

/* ============================================================
   11. CORE SCAN HANDLER
   ============================================================ */

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

  const willFail = shouldSimulateFailure(domain);
  setLoadingState(true);
  AppState.errorState = null;
  resetRiskSummary();
  resetTLSDetails();
  resetRecommendations();

  try {
    // Simulate network latency
    await sleep(1500 + Math.random() * 1000);

    if (willFail) {
      throw new Error('Connection refused: Unable to reach ' + domain + '. The host may be offline or blocking TLS probes.');
    }

    const scanData = getMockScanData(domain);
    AppState.currentScan = scanData;

    renderRiskSummary(scanData);
    renderTLSDetails(scanData.tls);
    renderRecommendations(scanData.recommendations);
    appendToHistory(scanData);
    setStatus('Scan complete — ' + domain, 'ready');

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
   12. UTILITY
   ============================================================ */

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/* ============================================================
   13. EVENT LISTENERS
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
   14. INIT
   ============================================================ */

function init() {
  resetRiskSummary();
  resetTLSDetails();
  resetRecommendations();
  renderHistoryTable();
  hideErrorBanner();
  setStatus('System Ready', 'ready');
  DOM.domainInput.focus();
  console.info('[QSCS] Dashboard initialized. v2.4.1');
}

init();
