/* ============================================================
   UPDATED handleScan() — Replace in script.js
   Calls the real FastAPI backend. Falls back to mock if backend
   is not running (Demo Mode).
   ============================================================ */

// Backend API URL — change this if deploying to a server
const API_BASE_URL = 'http://localhost:8000';

// Track whether we're in demo mode (backend not available)
let demoMode = false;

function setDemoMode(enabled) {
  demoMode = enabled;
  const existing = document.getElementById('demoModeBadge');
  if (enabled && !existing) {
    const badge = document.createElement('span');
    badge.id = 'demoModeBadge';
    badge.textContent = 'Demo Mode';
    badge.style.cssText = `
      font-family: var(--font-mono);
      font-size: 0.65rem;
      font-weight: 700;
      background: rgba(245,158,11,0.15);
      color: #F59E0B;
      border: 1px solid rgba(245,158,11,0.4);
      padding: 3px 10px;
      border-radius: 20px;
      margin-right: 8px;
    `;
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

    // ── TRY REAL BACKEND FIRST ──────────────────────────────
    try {
      const response = await fetch(`${API_BASE_URL}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
        signal: AbortSignal.timeout(22000) // 22s timeout
      });

      if (!response.ok) {
        const err = await response.json().catch(() => ({ detail: 'Scan failed' }));
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
        recommendations: raw.pqc.recommendations,
        // Extra data from real scan (bonus fields for display)
        _certInfo: raw.certificate,
        _cbom: raw.cbom,
        _scanDurationMs: raw.scan_duration_ms
      };

      // Real scan succeeded — remove demo mode badge
      setDemoMode(false);

    } catch (fetchErr) {
      // ── FALLBACK TO MOCK DATA ─────────────────────────────
      // Backend not running or network error — use mock silently
      const isNetworkError = (
        fetchErr.name === 'TypeError' ||       // fetch failed (backend offline)
        fetchErr.name === 'AbortError' ||      // timeout
        fetchErr.message.includes('fetch')
      );

      if (isNetworkError) {
        // Backend offline — fall back to mock data
        setDemoMode(true);
        await sleep(1200 + Math.random() * 800); // simulate scan delay

        if (shouldSimulateFailure(domain)) {
          throw new Error(
            'Connection refused: Unable to reach ' + domain +
            '. The host may be offline or blocking TLS probes.'
          );
        }

        scanData = getMockScanData(domain);
      } else {
        // Real error from backend (invalid domain, scan failed, etc.)
        setDemoMode(false);
        throw fetchErr;
      }
    }

    // ── RENDER RESULTS ──────────────────────────────────────
    AppState.currentScan = scanData;
    renderRiskSummary(scanData);
    renderTLSDetails(scanData.tls);
    renderRecommendations(scanData.recommendations);
    appendToHistory(scanData);

    const suffix = demoMode ? ' (demo)' : '';
    setStatus(`Scan complete — ${domain}${suffix}`, 'ready');

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
