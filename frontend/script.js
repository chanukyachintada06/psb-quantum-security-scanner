/**
 * ============================================================
 * QUANTUM-SAFE CRYPTOGRAPHY SCANNER â€” script.js
 * Post-Quantum TLS Risk Analyzer
 *
 * Phase 0: SPA Refactor
 * Phase 1: Home Dashboard Init
 * ============================================================
 */

'use strict';

// State variables â€” declared at top to avoid temporal dead zone
let discoveryTabsInitialized = false;
let networkGraphInitialized = false;
let cyberRatingInitialized = false;
let reportingInitialized = false;
let sidebarCollapsed = false;
let demoMode = false;

const API_BASE_URL = window.location.origin.includes('localhost') || window.location.origin.includes('127.0.0.1') 
  ? 'http://localhost:8000' 
  : window.location.origin;


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
        { priority: 'high', text: '<strong>Upgrade TLS:</strong> Enforce TLS 1.3+ and disable TLS 1.2 or earlier â€” older versions lack forward secrecy.' },
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
  assetsInventory: [],
  nameservers: [],
  loadingState: false,
  errorState: null,
  user: null,
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
        labels: ['Web App', 'API', 'Server', 'Load Balancer', 'Other'],
        datasets: [{
          data: [0, 0, 0, 0, 0], // Start at zero for real-time fetch
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
            document.getElementById('section-asset-inventory')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
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
          data: [0, 0, 0, 0],
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
          const labels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
          const clicked = labels[elements[0].index];
          const riskFilter = document.querySelector('.filter-select[data-filter="risk"]');
          if (riskFilter) {
            riskFilter.value = clicked;
            if (typeof applyHomeFilters === 'function') applyHomeFilters();
            document.getElementById('section-asset-inventory')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
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
          data: [0, 0],
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
  errorBanner: document.getElementById('errorBanner'),
  errorMsg: document.getElementById('errorMsg'),
  errorClose: document.getElementById('errorClose'),
  
  // New Engine UI components
  engineResultsContainer: document.getElementById('engineResultsContainer'),
  engineHndlBadge: document.getElementById('engineHndlBadge'),
  engineSummaryCard: document.getElementById('engineSummaryCard'),
  engineDomainName: document.getElementById('engineDomainName'),
  enginePqcScore: document.getElementById('enginePqcScore'),
  engineAgilityScore: document.getElementById('engineAgilityScore'),
  engineRiskLevel: document.getElementById('engineRiskLevel'),
  engineTopRiskNode: document.getElementById('engineTopRiskNode'),
  engineNodeTableBody: document.getElementById('engineNodeTableBody'),
  engineFindingsGrid: document.getElementById('engineFindingsGrid'),

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
    return { valid: false, message: 'Invalid IPv4 address â€” octets must be 0-255.' };
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

/* ============================================================
   9. DATA ADAPTER (TRANSFORM ENGINE)
   ============================================================ */

function transformScanData(raw) {
    if (!raw) return null;
    
    // Safety normalizations
    const summary = raw.risk_profile || {};
    const nodes = Array.isArray(raw.ip_details) ? raw.ip_details : [];
    const findings = Array.isArray(raw.findings) ? raw.findings : [];
    
    // Backward compat for old payloads
    if (nodes.length === 0 && raw.tls) {
       nodes.push({
          ip_address: raw.domain || 'unknown',
          tls: raw.tls,
          certificate: raw.certificate || {},
          is_successful: true
       });
    }
    
    // Backward compat for findings
    if (findings.length === 0 && raw.pqc?.recommendations) {
        raw.pqc.recommendations.forEach(r => {
            findings.push({
                title: 'Legacy Recommendation',
                description: r.text,
                severity: r.priority === 'high' ? 'HIGH' : 'MEDIUM'
            });
        });
    }

    return {
       domain: raw.domain || 'unknown',
       summary: {
           pqc_score: summary.pqc_score !== undefined ? summary.pqc_score : (raw.pqc?.risk_score || 0),
           crypto_agility_score: summary.crypto_agility_score || 0,
           risk_level: summary.risk_level || raw.pqc?.risk_level || 'UNKNOWN',
           hndl_risk: summary.hndl_risk === true
       },
       nodes: nodes,
       findings: findings,
       raw: raw
    };
}

/* ============================================================
   10. RENDER: ENGINE UI (PHASED)
   ============================================================ */

function renderEngineSummary(data) {
   DOM.engineDomainName.textContent = data.domain;
   DOM.enginePqcScore.textContent = data.summary.pqc_score;
   DOM.engineAgilityScore.textContent = data.summary.crypto_agility_score;
   
   DOM.engineRiskLevel.textContent = data.summary.risk_level;
   DOM.engineRiskLevel.style.color = 'var(--pnb-text)';
   if(data.summary.risk_level === 'CRITICAL' || data.summary.risk_level === 'HIGH') DOM.engineRiskLevel.style.color = 'var(--pnb-red)';
   
   // HNDL Risk Badge
   if (data.summary.hndl_risk) {
       DOM.engineHndlBadge.style.display = 'flex';
   } else {
       DOM.engineHndlBadge.style.display = 'none';
   }
   
   // Top Risk Node Calculation
   let topRiskNode = null;
   if (data.nodes && data.nodes.length > 0) {
       const failed = data.nodes.find(n => !n.is_successful);
       topRiskNode = failed ? failed : data.nodes[0];
   }
   
   if (topRiskNode && topRiskNode.ip_address) {
       DOM.engineTopRiskNode.textContent = `Highest Risk Node: ${topRiskNode.ip_address} `;
       if (!topRiskNode.is_successful) {
           DOM.engineTopRiskNode.textContent += '(ERROR)';
           DOM.engineTopRiskNode.style.color = 'var(--pnb-red)';
       } else {
           DOM.engineTopRiskNode.textContent += `(ANALYZED)`;
           DOM.engineTopRiskNode.style.color = 'var(--pnb-text-muted)';
       }
   } else {
       DOM.engineTopRiskNode.textContent = '';
   }
}

function renderEngineNodes(data) {
   DOM.engineNodeTableBody.innerHTML = '';
   if (!data.nodes || data.nodes.length === 0) {
      DOM.engineNodeTableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 24px; color:var(--pnb-text-muted);">No endpoints discovered.</td></tr>`;
      return;
   }
   
   data.nodes.forEach(node => {
      const isFailed = node.is_successful === false;
      const tls = node.tls || {};
      const cert = node.certificate || {};
      
      const trMain = document.createElement('tr');
      trMain.className = 'node-row';
      trMain.innerHTML = `
         <td class="mono" style="font-weight:600;">${node.ip_address || 'unknown'}</td>
         <td class="mono" style="color:var(--pnb-text-muted);">${tls.version || '—'}</td>
         <td class="mono" style="color:var(--pnb-text-muted);">${tls.public_key_type || '—'}</td>
         <td style="font-weight:600; color:var(--pnb-${isFailed ? 'danger' : 'text'})">${isFailed ? 'FAILED' : 'RESOLVED'}</td>
         <td>
             <span class="finding-badge ${isFailed ? 'badge-critical' : 'badge-low'}">
                 ${isFailed ? 'ERROR' : 'SUCCESS'}
             </span>
         </td>
      `;
      
      const trDetails = document.createElement('tr');
      trDetails.className = 'node-details-row';
      trDetails.innerHTML = `
         <td colspan="5" style="padding:0;">
             <div class="node-details-container">
                 <div class="node-detail-group">
                     <span class="node-detail-label">Cipher Suite</span>
                     <span class="node-detail-value">${tls.cipher_suite || '—'}</span>
                 </div>
                 <div class="node-detail-group">
                     <span class="node-detail-label">Key Exchange</span>
                     <span class="node-detail-value">${tls.key_exchange || '—'}</span>
                 </div>
                 <div class="node-detail-group">
                     <span class="node-detail-label">Cert Status</span>
                     <span class="node-detail-value" style="color:var(--pnb-${cert.chain_status === 'VALID' ? 'success' : 'danger'})">
                         ${cert.chain_status || 'UNKNOWN'}
                     </span>
                 </div>
             </div>
         </td>
      `;
      
      trMain.addEventListener('click', () => {
          trDetails.classList.toggle('expanded');
      });
      
      DOM.engineNodeTableBody.appendChild(trMain);
      DOM.engineNodeTableBody.appendChild(trDetails);
   });
}

function renderEngineFindings(data) {
   DOM.engineFindingsGrid.innerHTML = '';
   if (!data.findings || data.findings.length === 0) {
      DOM.engineFindingsGrid.innerHTML = `<div style="color:var(--pnb-text-muted); font-size:0.9rem; padding:16px;">No misconfigurations or recommendations flagged.</div>`;
      return;
   }
   
   data.findings.forEach(f => {
      const card = document.createElement('div');
      card.className = 'finding-card';
      const sev = f.severity ? f.severity.toUpperCase() : 'LOW';
      card.setAttribute('data-severity', sev);
      
      let badgeClass = 'badge-low';
      if(sev === 'CRITICAL') badgeClass = 'badge-critical';
      if(sev === 'HIGH') badgeClass = 'badge-high';
      if(sev === 'MEDIUM') badgeClass = 'badge-medium';
      
      card.innerHTML = `
          <div class="finding-header">
              <span class="finding-title">${f.title || 'Security Notice'}</span>
              <span class="finding-badge ${badgeClass}">${sev}</span>
          </div>
          <div class="finding-desc">${f.description || ''}</div>
      `;
      DOM.engineFindingsGrid.appendChild(card);
   });
}

function clearEngineUI() {
    DOM.engineResultsContainer.style.display = 'none';
    DOM.engineSummaryCard.style.opacity = '0';
    DOM.engineNodeTableBody.innerHTML = '';
    DOM.engineFindingsGrid.innerHTML = '';
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
      <span class="activity-icon">âœ…</span>
      <span class="activity-text">Scan completed: 
        <strong>${data.domain}</strong> â€” 
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
   12B. ASSETS & NAMESERVERS ENGINE
   ============================================================ */

async function fetchAssetsFromSupabase() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/assets`, {
      headers: typeof authHeaders === 'function' ? authHeaders() : {}
    });
    if (!response.ok) return;
    const data = await response.json();
    AppState.assetsInventory = data.assets || [];
    renderAssetsTable();
    // Also update asset discovery if on that page
    if (Router.currentSection === 'asset-discovery') renderAssetDiscovery();
  } catch (err) {
    console.warn('Failed to fetch assets:', err);
  }
}

function renderAssetDiscovery() {
  const assets = AppState.assetsInventory;
  
  // 1. Domains Tab
  const domainsTbody = document.querySelector('#tab-domains tbody');
  if (domainsTbody) {
    const domains = assets.filter(a => ['Web App', 'API', 'Gateway'].includes(a.asset_type));
    domainsTbody.innerHTML = domains.map(a => `
      <tr>
        <td class="td-dim">${new Date(a.created_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}</td>
        <td class="td-strong">${a.name}</td>
        <td class="td-dim">${a.registration_date || '—'}</td>
        <td>${a.registrar || '—'}</td>
        <td>${a.owner_department || 'PNB'}</td>
      </tr>
    `).join('') || '<tr><td colspan="5" style="text-align:center; padding: 20px;">No domains found.</td></tr>';
    
    // Update badge count
    const domainBadge = document.querySelector('.tab-button[data-tab="tab-domains"] .tab-badge');
    if (domainBadge) domainBadge.textContent = domains.length;
  }

  // 2. SSL Tab
  const sslTbody = document.querySelector('#tab-ssl tbody');
  if (sslTbody) {
    const sslAssets = assets.filter(a => a.cert_status);
    sslTbody.innerHTML = sslAssets.map(a => `
      <tr>
        <td class="td-dim">${new Date(a.updated_at || a.created_at).toLocaleDateString('en-GB')}</td>
        <td><span class="mono sha-fingerprint" title="${a.ssl_fingerprint || 'N/A'}">${(a.ssl_fingerprint || 'N/A').substring(0, 16)}...</span></td>
        <td class="td-dim">${a.cert_valid_from || '—'}</td>
        <td class="td-strong">${a.name}</td>
        <td>${a.owner_department || 'PNB'}</td>
        <td>${a.ca_name || 'DigiCert'}</td>
      </tr>
    `).join('') || '<tr><td colspan="6" style="text-align:center; padding: 20px;">No SSL data found.</td></tr>';
    
    const sslBadge = document.querySelector('.tab-button[data-tab="tab-ssl"] .tab-badge');
    if (sslBadge) sslBadge.textContent = sslAssets.length;
  }

  // 3. IPs Tab
  const ipsTbody = document.querySelector('#tab-ips tbody');
  if (ipsTbody) {
    const ipAssets = assets.filter(a => a.ipv4 || a.ipv6);
    ipsTbody.innerHTML = ipAssets.map(a => `
      <tr>
        <td class="td-dim">${new Date(a.created_at).toLocaleDateString('en-GB')}</td>
        <td class="td-strong">${a.ipv4 || a.ipv6}</td>
        <td>${a.ipv4 ? 'IPv4' : 'IPv6'}</td>
        <td><span class="td-risk-pill ${a.risk_level}">${a.risk_level}</span></td>
        <td>${a.owner_department || 'Infra'}</td>
      </tr>
    `).join('') || '<tr><td colspan="5" style="text-align:center; padding: 20px;">No IP assets found.</td></tr>';
    
    const ipBadge = document.querySelector('.tab-button[data-tab="tab-ips"] .tab-badge');
    if (ipBadge) ipBadge.textContent = ipAssets.length;
  }
}

let currentEditingAssetId = null;

function renderAssetsTable() {
  const tbody = document.getElementById('homeAssetTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (AppState.assetsInventory.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; padding: 40px; color: var(--pnb-text-muted);">No assets found in inventory.</td></tr>';
    return;
  }
  AppState.assetsInventory.forEach(asset => {
    const tr = document.createElement('tr');
    const createdDate = asset.created_at ? new Date(asset.created_at).toLocaleDateString() : '—';
    const scanDate = asset.last_scan_at ? new Date(asset.last_scan_at).toLocaleDateString() : 'Never';
    
    tr.innerHTML = `
      <td class="td-strong">${asset.name}</td>
      <td><a href="${asset.url}" class="td-link" target="_blank">${asset.url}</a></td>
      <td>${asset.asset_type || '—'}</td>
      <td>${asset.owner_department || '—'}</td>
      <td><span class="td-risk-pill ${asset.risk_level || 'LOW'}">${asset.risk_level || 'LOW'}</span></td>
      <td><span class="td-status-text ${asset.cert_status === 'Valid' ? 'color-success' : 'color-danger'}">${asset.cert_status || 'Valid'}</span></td>
      <td class="td-dim" style="font-size:0.751rem; line-height: 1.2">${createdDate}<br/><span style="opacity:0.7">by ${asset.created_by || 'system'}</span></td>
      <td class="td-dim" style="font-size:0.751rem; line-height: 1.2">${scanDate}<br/><span style="opacity:0.7">${asset.last_scan_by ? 'by ' + asset.last_scan_by : ''}</span></td>
      <td style="text-align: center">
        <div style="display:flex; gap: 8px; justify-content: center">
          <button class="action-btn-icon" onclick="editAsset('${asset.id}')" title="Edit">✏️</button>
          <button class="action-btn-icon delete" onclick="deleteAsset('${asset.id}', '${asset.name}')" title="Delete">🗑️</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

window.deleteAsset = async function(id, name) {
  if (!confirm(`Are you sure you want to delete asset "${name}"?`)) return;
  try {
    const response = await fetch(`${API_BASE_URL}/api/assets/${id}`, {
      method: "DELETE",
      headers: typeof authHeaders === "function" ? authHeaders() : {}
    });
    if (response.ok) {
       fetchAssetsFromSupabase();
       if (typeof fetchAuditLogs === "function") fetchAuditLogs();
    } else {
       alert("Failed to delete asset.");
    }
  } catch(e) { console.error(e); }
};

window.editAsset = function(id) {
  const asset = AppState.assetsInventory.find(a => a.id === id);
  if (!asset) return;
  
  currentEditingAssetId = id;
  const modal = document.getElementById('addAssetModal');
  if (!modal) return;
  
  modal.querySelector('h3').textContent = 'Edit Asset';
  document.getElementById('confirmAddAsset').textContent = 'Update Asset';
  
  if (document.getElementById('newAssetName')) document.getElementById('newAssetName').value = asset.name || '';
  if (document.getElementById('newAssetUrl')) document.getElementById('newAssetUrl').value = asset.url || '';
  if (document.getElementById('newAssetType')) document.getElementById('newAssetType').value = asset.asset_type || 'Web App';
  if (document.getElementById('newAssetOwner')) document.getElementById('newAssetOwner').value = asset.owner_department || 'IT';
  
  modal.style.display = 'flex';
};

async function fetchNameservers(domain = null) {
  try {
    const url = domain ? `${API_BASE_URL}/api/nameservers?domain=${domain}` : `${API_BASE_URL}/api/nameservers`;
    const response = await fetch(url, {
      headers: typeof authHeaders === 'function' ? authHeaders() : {}
    });
    if (!response.ok) return;
    const data = await response.json();
    AppState.nameservers = data.nameservers || [];
    renderNameserverTable();
  } catch (err) {
    console.warn('Nameserver fetch error:', err);
  }
}

function renderNameserverTable() {
  const tbody = document.getElementById('nameserverTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (AppState.nameservers.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 20px; color: var(--pnb-text-muted);">No records found.</td></tr>';
    return;
  }
  AppState.nameservers.forEach(ns => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="td-strong">${ns.hostname}</td>
      <td>${ns.record_type}</td>
      <td class="mono">${ns.ipv4 || '—'}</td>
      <td class="mono">${ns.ipv6 || '—'}</td>
      <td class="mono">${ns.ttl || '—'}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function fetchAuditLogs() {
  const feed = document.getElementById('homeActivityFeed');
  if (!feed) return;
  
  try {
    const response = await fetch(`${API_BASE_URL}/api/audit`, {
      headers: typeof authHeaders === "function" ? authHeaders() : {}
    });
    if (!response.ok) return;
    const data = await response.json();
    renderActivityFeed(data.audit_logs || []);
  } catch (err) {
    console.warn("Failed to fetch audit logs:", err);
  }
}

function renderActivityFeed(logs) {
  const feed = document.getElementById("homeActivityFeed");
  if (!feed) return;
  feed.innerHTML = "";
  if (logs.length === 0) {
    feed.innerHTML = '<div class="activity-item" style="justify-content: center; opacity: 0.6; padding: 10px;">No recent activity.</div>';
    return;
  }
  
  const iconMap = {
    "SCAN_COMPLETED": "✅",
    "SCAN_FAILED":    "❌",
    "SCAN_INITIATED": "🔍",
    "USER_LOGIN":     "👤",
    "SYSTEM_STARTUP": "⚙️",
  };

  logs.slice(0, 10).forEach(log => {
    const item = document.createElement("div");
    item.className = "activity-item";
    const timeStr = formatRelativeTime(new Date(log.created_at));
    const icon = iconMap[log.action] || "📝";
    let text = log.action.replace(/_/g, " ");
    if (log.domain) text += `: ${log.domain}`;
    
    item.innerHTML = `
      <span class="activity-icon">${icon}</span>
      <span class="activity-text" style="font-size:0.82rem; flex:1">${text}</span>
      <span class="activity-time td-dim" style="font-size:0.75rem">${timeStr}</span>
    `;
    feed.appendChild(item);
  });
}

function formatRelativeTime(date) {
  const now = new Date();
  const diffInSecs = Math.floor((now - date) / 1000);
  if (diffInSecs < 60) return "just now";
  const diffInMins = Math.floor(diffInSecs / 60);
  if (diffInMins < 60) return `${diffInMins}m ago`;
  const diffInHours = Math.floor(diffInMins / 60);
  if (diffInHours < 24) return `${diffInHours}h ago`;
  return date.toLocaleDateString();
}

/* ============================================================
   12C. DASHBOARD ANALYTICS ENGINE
   ============================================================ */

async function fetchDashboardStats() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/stats`, {
      headers: typeof authHeaders === 'function' ? authHeaders() : {}
    });
    if (!response.ok) return;
    const data = await response.json();
    updateDashboardStatsUI(data);
  } catch (err) {
    console.warn('[Dashboard] Stats fetch error:', err);
  }
}

function updateDashboardStatsUI(data) {
  if (!data) return;

  const setVal = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val !== undefined ? val : 0;
  };

  // Update Stat Cards (with safe fallbacks)
  setVal('stat-total-assets', data.total_assets);
  setVal('stat-web-apps', data.count_by_asset_type?.['Web App']);
  setVal('stat-apis', data.count_by_asset_type?.['API']);
  setVal('stat-high-risk', data.high_risk_assets_count);
  setVal('stat-ipv4', data.ipv4_count);
  setVal('stat-ipv6', data.ipv6_count);

  // Update "Last Updated" timestamp
  const timeEl = document.getElementById('lastUpdatedTime');
  if (timeEl) {
    timeEl.textContent = new Date().toLocaleTimeString('en-IN', {
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
    });
  }

  // Handle Charts Update
  if (HomeCharts.assetType && data.count_by_asset_type) {
    HomeCharts.assetType.data.datasets[0].data = [
      data.count_by_asset_type['Web App'] || 0,
      data.count_by_asset_type['API'] || 0,
      data.count_by_asset_type['Server'] || 0,
      data.count_by_asset_type['Load Balancer'] || 0,
      data.count_by_asset_type['Other'] || 0
    ];
    HomeCharts.assetType.update();
  }

  if (HomeCharts.assetRisk && data.count_by_risk_level) {
    HomeCharts.assetRisk.data.datasets[0].data = [
      data.count_by_risk_level['CRITICAL'] || 0,
      data.count_by_risk_level['HIGH'] || 0,
      data.count_by_risk_level['MEDIUM'] || 0,
      data.count_by_risk_level['LOW'] || 0
    ];
    HomeCharts.assetRisk.update();
  }

  if (HomeCharts.ipVersion) {
    HomeCharts.ipVersion.data.datasets[0].data = [
      data.ipv4_count || 0,
      data.ipv6_count || 0
    ];
    HomeCharts.ipVersion.update();
  }

  // Handle Empty State UX
  const chartGrids = document.querySelectorAll('.chart-grid');
  if (data.total_assets === 0) {
    chartGrids.forEach(grid => grid.style.opacity = '0.35');
  } else {
    chartGrids.forEach(grid => grid.style.opacity = '1');
  }
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
  clearEngineUI();

  try {
    let rawApiResponse;

    try {
      // Call real backend
      const response = await fetch(`${API_BASE_URL}/api/scan`, {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/json' }, typeof authHeaders === 'function' ? authHeaders() : {}),
        body: JSON.stringify({ domain }),
        signal: AbortSignal.timeout(25000)
      });

      if (!response.ok) {
        const err = await response.json().catch(() => ({ detail: 'Scan failed' }));
        throw new Error(err.detail || `Server error ${response.status}`);
      }

      rawApiResponse = await response.json();
      setDemoMode(false);

    } catch (fetchErr) {
      // If backend is offline, fall back to mock data
      const isNetworkError = (fetchErr.name === 'TypeError' || fetchErr.name === 'AbortError' || String(fetchErr).includes('fetch'));
      if (isNetworkError) {
        setDemoMode(true);
        await sleep(1200 + Math.random() * 800);
        if (shouldSimulateFailure(domain)) {
          throw new Error('Connection refused: Unable to reach ' + domain);
        }
        rawApiResponse = getMockScanData(domain);
      } else {
        setDemoMode(false);
        throw fetchErr;
      }
    }

    // 1. Adapter: Transform Data
    const engineData = transformScanData(rawApiResponse);
    AppState.currentScan = engineData;
    
    // Capture scan_id from real API response (not available in demo mode)
    const scanId = rawApiResponse && rawApiResponse.scan_id ? rawApiResponse.scan_id : null;
    
    // 2. Phased Rendering
    DOM.engineResultsContainer.style.display = 'flex';
    
    // Phase A: Summary displays immediately
    renderEngineSummary(engineData);
    DOM.engineSummaryCard.style.opacity = '1';
    
    // Phase B & C: Nodes and Findings flow sequentially
    setTimeout(() => {
        renderEngineNodes(engineData);
        renderEngineFindings(engineData);
        // Phase D: Export buttons (only when we have a real DB scan_id)
        renderExportButtons(scanId, engineData.domain);
    }, 150);

    // Legacy Fallback mapping for history appending
    const legacyHistoryObj = {
        domain: engineData.domain,
        riskLevel: engineData.summary.risk_level,
        riskScore: engineData.summary.pqc_score,
        timestamp: new Date()
    };
    appendToHistory(legacyHistoryObj);
    
    setStatus(`Engine Sequence Complete — ${domain}${demoMode ? ' (demo)' : ''}`, 'ready');

  } catch (err) {
    AppState.errorState = err.message;
    AppState.currentScan = null;
    showErrorBanner(err.message);
    setStatus('Scan failed', 'error');
    clearEngineUI();
    setTimeout(() => {
      setStatus('System Ready', 'ready');
      AppState.errorState = null;
    }, 5000);

  } finally {
    setLoadingState(false);
    if (typeof refreshDashboardData === 'function') {
      setTimeout(refreshDashboardData, 1500);
    }
  }
}

/* ============================================================
   13B. EXPORT BUTTONS RENDERER
   ============================================================ */

/**
 * Render PDF + Excel export buttons inside the engine results container.
 * Buttons only appear when a real scan_id is available (non-demo mode).
 *
 * @param {string|null} scanId  - UUID from the backend API response
 * @param {string}      domain  - Scanned domain name
 */
function renderExportButtons(scanId, domain) {
  // Remove any previous export container
  const existingContainer = document.getElementById('exportActionsContainer');
  if (existingContainer) existingContainer.remove();

  // No export in demo mode or without a real scan_id
  if (!scanId || demoMode) return;

  const container = document.createElement('div');
  container.id = 'exportActionsContainer';
  container.className = 'export-actions';

  container.innerHTML = `
    <div class="export-actions-label">
      <span class="export-icon">📄</span>
      <span>Export Report</span>
    </div>
    <div class="export-buttons-row">
      <button
        id="btnExportPdf"
        class="btn-export btn-export-pdf"
        title="Download Executive PDF Report"
        aria-label="Export PDF Report for ${domain}"
      >
        <span class="btn-export-icon">📋</span>
        <span class="btn-export-label">Export PDF</span>
      </button>
      <button
        id="btnExportExcel"
        class="btn-export btn-export-excel"
        title="Download Multi-Sheet Excel Workbook"
        aria-label="Export Excel Report for ${domain}"
      >
        <span class="btn-export-icon">📊</span>
        <span class="btn-export-label">Export Excel</span>
      </button>
    </div>
    <div class="export-hint">
      Scan ID: <code>${scanId.substring(0, 8)}…</code>
    </div>
  `;

  // PDF handler
  container.querySelector('#btnExportPdf').addEventListener('click', async () => {
    const btn = container.querySelector('#btnExportPdf');
    btn.disabled = true;
    btn.innerHTML = `<span class="btn-export-spinner"></span><span class="btn-export-label">Generating…</span>`;
    try {
      const url = `${API_BASE_URL}/api/report/pdf/${scanId}`;
      const a = document.createElement('a');
      a.href = url;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } catch (e) {
      console.error('PDF export failed:', e);
    } finally {
      setTimeout(() => {
        btn.disabled = false;
        btn.innerHTML = `<span class="btn-export-icon">📋</span><span class="btn-export-label">Export PDF</span>`;
      }, 2000);
    }
  });

  // Excel handler
  container.querySelector('#btnExportExcel').addEventListener('click', async () => {
    const btn = container.querySelector('#btnExportExcel');
    btn.disabled = true;
    btn.innerHTML = `<span class="btn-export-spinner"></span><span class="btn-export-label">Generating…</span>`;
    try {
      const url = `${API_BASE_URL}/api/report/excel/${scanId}`;
      const a = document.createElement('a');
      a.href = url;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } catch (e) {
      console.error('Excel export failed:', e);
    } finally {
      setTimeout(() => {
        btn.disabled = false;
        btn.innerHTML = `<span class="btn-export-icon">📊</span><span class="btn-export-label">Export Excel</span>`;
      }, 2000);
    }
  });

  // Insert at top of results container
  DOM.engineResultsContainer.insertBefore(container, DOM.engineResultsContainer.firstChild);
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
  clearEngineUI();
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
  console.log('%c All 7 modules initialized successfully âœ“ ',
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
async function fetchCBOMData() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/cbom`, {
      headers: typeof authHeaders === 'function' ? authHeaders() : {}
    });
    if (!response.ok) return;
    const data = await response.json();
    const records = data.cbom_records || [];
    
    // 1. Update stats cards
    const totalApps = new Set(records.map(r => r.scan_results?.domain)).size;
    const activeCerts = records.filter(r => r.nist_standard).length;
    const weakCrypto = records.filter(r => r.pqc_status === 'VULNERABLE').length;

    updateStat('.cbom-stats-row .stat-card:nth-child(1) .stat-value', totalApps || 0);
    updateStat('.cbom-stats-row .stat-card:nth-child(3) .stat-value', activeCerts || 0);
    updateStat('.cbom-stats-row .stat-card:nth-child(4) .stat-value', weakCrypto || 0);

    // 2. Update Table
    const tbody = document.querySelector('.cbom-cipher-table tbody');
    if (tbody) {
      tbody.innerHTML = records.slice(0, 10).map(r => `
        <tr class="${r.pqc_status === 'VULNERABLE' ? 'cipher-row-danger' : ''}">
          <td class="td-strong">${r.scan_results?.domain || '—'}</td>
          <td class="cipher-col-mono">${r.key_length || '—'}</td>
          <td class="cipher-col-mono" ${r.pqc_status === 'VULNERABLE' ? 'style="color: #EF4444;"' : ''}>${r.cipher_suite || '—'}</td>
          <td>${r.nist_standard || 'N/A'}</td>
        </tr>
      `).join('') || '<tr><td colspan="4" style="text-align:center; padding: 20px;">No CBOM records found.</td></tr>';
    }

    // 3. Update Charts
    updateCBOMCharts(records);
    
  } catch (err) {
    console.warn('Failed to fetch CBOM data:', err);
  }
}

function updateStat(selector, value) {
  const el = document.querySelector(selector);
  if (el) el.textContent = value;
}

function updateCBOMCharts(records) {
  if (!CbomCharts.keyLength) return;

  // Key Length Aggregation
  const keyLengths = records.reduce((acc, r) => {
    const kl = r.key_length || 'Unknown';
    acc[kl] = (acc[kl] || 0) + 1;
    return acc;
  }, {});
  CbomCharts.keyLength.data.labels = Object.keys(keyLengths);
  CbomCharts.keyLength.data.datasets[0].data = Object.values(keyLengths);
  CbomCharts.keyLength.update();

  // Cipher Usage Aggregation
  const ciphers = records.reduce((acc, r) => {
    const c = r.cipher_suite || 'Unknown';
    acc[c] = (acc[c] || 0) + 1;
    return acc;
  }, {});
  const sortedCiphers = Object.entries(ciphers).sort((a,b) => b[1] - a[1]).slice(0, 5);
  CbomCharts.cipherUsage.data.labels = sortedCiphers.map(e => e[0]);
  CbomCharts.cipherUsage.data.datasets[0].data = sortedCiphers.map(e => e[1]);
  CbomCharts.cipherUsage.update();
  
  // Protocols Aggregation (simulated if missing from CBOM record directly, using cipher names)
  const protocols = records.reduce((acc, r) => {
     // rudimentary check
     const p = r.cipher_suite?.includes('TLS13') || r.cipher_suite?.includes('AES_GCM') ? 'TLS 1.3' : 'TLS 1.2';
     acc[p] = (acc[p] || 0) + 1;
     return acc;
  }, {});
  CbomCharts.encryptionProtocols.data.datasets[0].data = [protocols['TLS 1.3'] || 0, protocols['TLS 1.2'] || 0, 0];
  CbomCharts.encryptionProtocols.update();
}

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
  
  // Fetch real data after creating chart skeletons
  setTimeout(() => fetchCBOMData(), 200);

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
    ? 'âœ… Report scheduled successfully!'
    : 'âœ… Report generated successfully!';
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
          toast.textContent = 'âœ… DNS resolved successfully for company.com';
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
      if (modal) {
        currentEditingAssetId = null; 
        modal.querySelector('h3').textContent = 'Add New Asset';
        document.getElementById('confirmAddAsset').textContent = 'Add Asset';
        // Clear fields
        if (document.getElementById('newAssetName')) document.getElementById('newAssetName').value = '';
        if (document.getElementById('newAssetUrl')) document.getElementById('newAssetUrl').value = '';
        modal.style.display = 'flex';
      }
    });
  }
  ['closeAssetModal', 'cancelAssetModal'].forEach(id => {
    const btn = document.getElementById(id);
    if (btn) btn.addEventListener('click', () => {
      document.getElementById('addAssetModal').style.display = 'none';
      currentEditingAssetId = null;
    });
  });
  const confirmAdd = document.getElementById('confirmAddAsset');
  if (confirmAdd) {
    confirmAdd.addEventListener('click', async () => {
      const name = document.getElementById('newAssetName')?.value.trim();
      const url = document.getElementById('newAssetUrl')?.value.trim();
      const type = document.getElementById('newAssetType')?.value;
      const owner = document.getElementById('newAssetOwner')?.value;
      if (!name || !url) {
        alert('Asset Name and URL are required');
        return;
      }

      confirmAdd.disabled = true;
      confirmAdd.textContent = currentEditingAssetId ? 'Updating...' : 'Adding...';

      const method = currentEditingAssetId ? 'PUT' : 'POST';
      const endpoint = currentEditingAssetId ? `${API_BASE_URL}/api/assets/${currentEditingAssetId}` : `${API_BASE_URL}/api/assets`;

      try {
        const response = await fetch(endpoint, {
          method,
          headers: Object.assign({ 'Content-Type': 'application/json' }, typeof authHeaders === 'function' ? authHeaders() : {}),
          body: JSON.stringify({ 
             name, 
             url, 
             asset_type: type, 
             owner_department: owner 
          })
        });

        if (response.ok) {
           document.getElementById('addAssetModal').style.display = 'none';
           // Reset form
           document.getElementById('newAssetName').value = '';
           document.getElementById('newAssetUrl').value = '';
           currentEditingAssetId = null;
           fetchAssetsFromSupabase();
           if (typeof fetchAuditLogs === "function") fetchAuditLogs();
        } else {
           const err = await response.json();
           alert('Operation failed: ' + (err.detail || 'Unknown error'));
        }
      } catch (err) {
        console.error('Error:', err);
      } finally {
        confirmAdd.disabled = false;
        confirmAdd.textContent = currentEditingAssetId ? 'Update Asset' : 'Add Asset';
      }
    });
  }

  // Scan All
  const scanAllBtn = document.querySelector('[data-action="scan-all"]');
  if (scanAllBtn) {
    scanAllBtn.addEventListener('click', async function () {
      if (AppState.assetsInventory.length === 0) {
        alert('No assets found in inventory to scan.');
        return;
      }
      
      this.disabled = true;
      this.innerHTML = '<span class="scan-btn-spinner"></span> Scanning All...';
      
      let completed = 0;
      const total = AppState.assetsInventory.length;
      
      // Sequential scan for progress stability
      for (const asset of AppState.assetsInventory) {
        try {
          let domain = asset.url;
          if (domain.includes("://")) {
            domain = new URL(domain).hostname;
          }
          
          this.innerHTML = `<span class="scan-btn-spinner"></span> Scanning (${completed + 1}/${total})...`;
          
          await fetch(`${API_BASE_URL}/api/scan/${domain}`, {
            headers: typeof authHeaders === "function" ? authHeaders() : {}
          });
          
          completed++;
        } catch (err) {
          console.warn("Scan all error:", asset.url, err);
        }
      }
      
      this.innerHTML = '✅ Scan Completed!';
      
      refreshDashboardData();
      
      const toast = document.getElementById('reportToast');
      if (toast) {
        toast.textContent = `Successfully scanned ${completed} assets!`;
        toast.style.display = 'block';
        setTimeout(() => { toast.style.display = 'none'; }, 3000);
      }

      // Return to original state after 5 seconds
      setTimeout(() => {
        this.disabled = false;
        this.innerHTML = 'Scan All';
      }, 5000);
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
   SUPABASE AUTH SYSTEM â€” Quantum-Proof Systems Scanner
   Team CypherRed261 | PSB Hackathon 2026
   ============================================================ */

// â”€â”€ Supabase client (anon key â€” safe for browser) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const SUPABASE_URL      = 'https://uiulgfwvswdoguzksaya.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVpdWxnZnd2c3dkb2d1emtzYXlhIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzU0Nzk1NjEsImV4cCI6MjA5MTA1NTU2MX0.PsyN6X0lbyP4q8Q6blaRM97B83idgItVQ5zxhEJ6yVA';
let sbClient = null;
if (window.supabase) {
  sbClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
} else {
  console.error('[QSCS] Supabase CDN failed to load!');
}

// Active session â€” updated on login / session restore
let _session = null;

/** Return the JWT access token for API Authorization headers. */
function getJWT() {
  return _session?.access_token ?? null;
}

/** Build Authorization headers; falls back to Content-Type only if unauthenticated. */
function authHeaders() {
  const token = getJWT();
  return token
    ? { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }
    : { 'Content-Type': 'application/json' };
}

/* â”€â”€ DOM helper â”€â”€ */
function $id(id) { return document.getElementById(id); }

// â”€â”€ Error display â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
  }, 5000);
}

// â”€â”€ Card shake animation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function loginShakeCard() {
  var card = document.querySelector('.login-card');
  if (!card) return;
  var orig = card.style.transition;
  card.style.transition = 'transform 0.07s ease';
  var steps = [-8, 8, -5, 5, -2, 0];
  var i = 0;
  (function step() {
    if (i < steps.length) {
      card.style.transform = 'translateX(' + steps[i++] + 'px)';
      setTimeout(step, 70);
    } else {
      card.style.transition = orig;
    }
  })();
}

// â”€â”€ Show the main app after authentication â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function enterApp(user) {
  var screen = $id('login-screen');
  if (!screen) return;

  var nameEl = $id('headerUserName');
  if (nameEl) nameEl.textContent = '\uD83D\uDC64 ' + (user.email || 'User');

  screen.classList.add('fade-out');
  setTimeout(function() { screen.style.display = 'none'; }, 480);

  // Log login event to backend with real JWT
  try {
    fetch(API_BASE_URL + '/api/audit-login', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ event: 'USER_LOGIN' })
    }).catch(function(){});
  } catch(e) {}

  // Load all live dashboard data from Supabase
  refreshDashboardData();
  console.info('[QSCS Auth] Logged in as:', user.email);
}

// â”€â”€ Fetch scan history from Supabase (RLS-filtered by user) â”€â”€â”€
async function fetchHistoryFromSupabase() {
  try {
    const { data, error } = await sbClient
      .from('scan_results')
      .select('id, domain, pqc_score, risk_level, created_at')
      .order('created_at', { ascending: false })
      .limit(50);

    if (error) throw error;
    if (!data || data.length === 0) return;

    AppState.scanHistory = data.map(row => ({
      domain:    row.domain,
      riskLevel: row.risk_level   || 'UNKNOWN',
      riskScore: row.pqc_score || 0,
      readiness: 0, // Computed or omitted if not in schema
      timestamp: new Date(row.created_at),
      id:        row.id,
    }));

    renderHistoryTable();
    console.info('[QSCS Supabase] Loaded', data.length, 'scan records');
  } catch (err) {
    console.warn('[QSCS Supabase] Could not load history:', err.message);
  }
}

function refreshDashboardData() {
  if (typeof fetchHistoryFromSupabase === 'function') fetchHistoryFromSupabase();
  if (typeof fetchAssetsFromSupabase === 'function') fetchAssetsFromSupabase();
  if (typeof fetchNameservers === 'function') fetchNameservers();
  if (typeof fetchAuditLogs === 'function') fetchAuditLogs();
  if (typeof fetchDashboardStats === 'function') fetchDashboardStats();
}

// â”€â”€ Login click handler â€” Supabase Auth â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function handleLoginClick() {
  var uEl    = $id('loginUsername');
  var pEl    = $id('loginPassword');
  var btn    = $id('loginBtn');
  var btnTxt = $id('loginBtnContent');

  var email    = (uEl ? uEl.value.trim() : '');
  var password = (pEl ? pEl.value : '');

  var errEl = $id('loginErrorMsg');
  if (errEl) errEl.style.display = 'none';
  if (uEl) uEl.classList.remove('error');
  if (pEl) pEl.classList.remove('error');

  if (!email)    { loginSetError('Please enter your email address'); if (uEl) uEl.focus(); return; }
  if (!password) { loginSetError('Please enter your password');       if (pEl) pEl.focus(); return; }

  if (btn)    btn.disabled = true;
  if (btnTxt) btnTxt.innerHTML = '<span class="login-btn-spinner"></span> Authenticating...';

  try {
    const { data, error } = await sbClient.auth.signInWithPassword({ email, password });
    if (error) throw error;
    _session = data.session;
    enterApp(data.user);
  } catch (err) {
    if (btn)    btn.disabled = false;
    if (btnTxt) btnTxt.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg> Sign In';
    loginShakeCard();
    const msg = err.message || '';
    if (msg.includes('Invalid login')) {
      loginSetError('Incorrect email or password \u2014 please try again');
    } else if (msg.includes('Email not confirmed')) {
      loginSetError('Please confirm your email address first');
    } else {
      loginSetError(msg || 'Authentication failed \u2014 please try again');
    }
    console.warn('[QSCS Auth] Login failed:', err.message);
  }
}

// â”€â”€ Logout â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function handleLogout() {
  await sbClient.auth.signOut();
  _session = null;

  var screen = $id('login-screen');
  if (screen) {
    screen.style.display = 'flex';
    screen.style.opacity = '1';
    screen.classList.remove('fade-out');
  }
  if ($id('loginUsername')) $id('loginUsername').value = '';
  if ($id('loginPassword')) $id('loginPassword').value = '';
  if ($id('headerUserName')) $id('headerUserName').textContent = '';

  AppState.scanHistory = [];
  renderHistoryTable();
  console.info('[QSCS Auth] Logged out');
}

// â”€â”€ Init login system â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function initLoginSystem() {

  // 1. Patch handleScan: inject JWT into backend fetch calls
  const _origHandleScan = window.handleScan || handleScan;
  window.handleScan = async function() {
    const _origFetch = window.fetch;
    window.fetch = function(url, opts) {
      opts = opts || {};
      if (typeof url === "string" && url.includes(API_BASE_URL)) {
        opts.headers = Object.assign({}, opts.headers || {}, authHeaders());
      }
      return _origFetch.call(this, url, opts);
    };
    try {
      await _origHandleScan();
    } finally {
      window.fetch = _origFetch;
      setTimeout(refreshDashboardData, 1500);
    }
  };

  // 2. Wire up login button SYNCHRONOUSLY first
  var loginBtn = $id('loginBtn');
  if (loginBtn) loginBtn.onclick = handleLoginClick;

  ['loginUsername', 'loginPassword'].forEach(function(id) {
    var el = $id(id);
    if (el) el.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') handleLoginClick();
    });
  });

  var toggle = $id('loginPwdToggle');
  var pwdInput = $id('loginPassword');
  var eyeOpen = $id('eyeOpen');
  var eyeClosed = $id('eyeClosed');
  if (toggle && pwdInput) {
    toggle.onclick = function() {
      var show = pwdInput.type === 'password';
      pwdInput.type = show ? 'text' : 'password';
      if (eyeOpen) eyeOpen.style.display = show ? 'none' : 'block';
      if (eyeClosed) eyeClosed.style.display = show ? 'block' : 'none';
      pwdInput.focus();
    };
  }

  var logoutBtn = $id('logoutBtn');
  if (logoutBtn) logoutBtn.onclick = handleLogout;

  var label = document.querySelector('label[for="loginUsername"]');
  if (label) label.textContent = 'Email';
  var uInput = $id('loginUsername');
  if (uInput) {
    uInput.type = 'email';
    uInput.placeholder = 'Enter your email address';
    uInput.autocomplete = 'email';
  }

  setTimeout(function() {
    var u = $id('loginUsername');
    if (u && !_session) u.focus();
  }, 200);

  if (!sbClient) return;

  try {
    const { data: { session } } = await sbClient.auth.getSession();
    if (session) {
      _session = session;
      enterApp(session.user);
    }
  } catch(e) {}

  sbClient.auth.onAuthStateChange(function(_event, newSession) {
    _session = newSession;
  });
}

// Run after DOM fully loaded
window.addEventListener('load', initLoginSystem);

