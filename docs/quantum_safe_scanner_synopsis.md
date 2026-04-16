# Project Synopsis: Quantum-Safe Cryptography Scanner for Banking Systems
**Team CypherRed261 | PSB Hackathon 2026**

---

## 1. Project Objective and Problem Statement
### Objective
To develop a high-performance assessment tool that evaluates the quantum-readiness of banking infrastructure by identifying vulnerable cryptographic algorithms and providing a roadmap for migration to Post-Quantum Cryptography (PQC).

### Problem Statement
Current banking security relies on classical cryptographic standards (RSA, ECC, Diffie-Hellman). The advent of cryptographically relevant quantum computers (CRQC) and Shor's Algorithm poses an existential threat, as these classical methods can be broken in seconds. Banking institutions face the "Harvest Now, Decrypt Later" (HNDL) threat, where encrypted data captured today can be decrypted once quantum computers mature.

---

## 2. Importance of Quantum-Safe Cryptography in Banking
Banking systems handle high-value, long-term sensitive data including transaction records, identity credentials, and trade secrets. 
- **Regulatory Compliance:** Adherence to upcoming NIST PQC standards (FIPS 203/204/205) and national mandates (RBI CSF, CERT-IN Annexure-A).
- **Data Longevity:** Ensuring that data encrypted today remains secure for decades.
- **Service Continuity:** Transitioning to PQC prevents future systemic failures caused by cryptographic obsolescence.

---

## 3. Features Implemented So Far
- **Real-Time TLS Scanning:** Direct handshake analysis using `sslyze` to extract real-world cryptographic parameters (not mock data).
- **PQC Risk Scoring Engine:** Algorithmic logic to calculate a "Quantum Readiness Score" (0–100) based on NIST standards.
- **CBOM Generation:** Automatic creation of a Cryptographic Bill of Materials (CBOM) detailing key lengths, algorithms, and usage.
- **7-Module Dashboard:** Comprehensive UI covering Posture, Asset Inventory, Asset Discovery (D3.js), CBOM, Cyber Rating, and Reporting.
- **MySQL Persistence:** Full history of scans, audit logs, and PQC labels stored for institutional auditing.
- **Demo Mode Fallback:** Smart UI that functions seamlessly with mock data if the backend scanning engine is offline.

---

## 4. System Architecture
- **Frontend Layer:** Single Page Application (SPA) providing a low-latency, responsive user experience.
- **Backend Layer:** FastAPI-based Python server coordinating scanner execution, database transactions, and risk assessment logic.
- **Scanner Engine:** A hybrid engine combining `sslyze` for network-level TLS extraction and a custom `Quantum Validator` for algorithm classification (NIST FIPS compliance check).
- **Database Layer:** MySQL 8.0 relational database for structured storage of scan results, audit trails, and user credentials.

---

## 5. Technologies Used
- **Backend:** Python 3.12, FastAPI, Uvicorn, SSLyze API.
- **Frontend:** HTML5, CSS3 (Custom PNB-inspired premium dark theme), Vanilla JavaScript.
- **Visualization:** Chart.js (Scoring/Statistics), D3.js (Asset Relationship Mapping).
- **Database:** MySQL 8.0 (mysql-connector-python).
- **Standards:** NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA), CERT-IN Annexure-A.

---

## 6. System Workflow (Data Flow)
1. **Initiation:** User submits a banking domain (e.g., `pnbindia.in`) via the Asset Inventory module.
2. **Analysis:** The backend initiates a multi-layered TLS scan to identify supported cipher suites, key exchange methods, and certificate signatures.
3. **Classification:** The Quantum Validation Engine maps identified algorithms against NIST/CERT-IN vulnerability databases.
4. **Quantification:** The system generates a risk score and identifies "Quantum-Safe" vs "Quantum-Vulnerable" components.
5. **Archival:** Results are normalized and stored in the MySQL `scan_results` and `cbom_records` tables.
6. **Reporting:** The dashboard renders visual metrics and prioritized migration recommendations (e.g., migrating from RSA-2048 to Kyber-768).

---

## 7. Current Progress Status
- **Phase 1 (Core Engine):** 100% Complete. Real TLS scanning and risk scoring logic are fully operational.
- **Phase 2 (Database & Persistence):** 100% Complete. MySQL integration supports history and audit logging.
- **Phase 3 (Dashboard UI):** 95% Complete. All 7 modules are interactive and linked to the backend API.
- **Phase 4 (Validation):** Ongoing testing against live banking endpoints and PQC compliance checklists.

---

## 8. Innovations and Additional Features
- **Network Asset Graph:** Interactive D3.js visualization to map subdomains and their interconnected security posture.
- **CERT-IN Compliant CBOM:** Export-ready data formats specifically designed to meet Indian regulatory reporting requirements.
- **Hybrid Recommendations:** Suggests "Transitionary Hybrid Algorithms" (combining Classical + PQC) to maintain compatibility during the migration phase.
- **Audit Traceability:** Every scan is logged with user ID, timestamp, and client IP for strict enterprise accountability.

---

## 9. Next Steps / Future Improvements
- **Cloud Deployment:** Migration to AWS/Azure using Docker containers for enterprise scale.
- **PDF Report Export:** Integration of a reporting engine for automated Executive Summary generation.
- **CI/CD Integration:** Plugins for DevSecOps pipelines to scan banking applications during build time.
- **AI-Driven Forecasts:** Predicting the "Year of Vulnerability" ($Y2Q$) for specific assets based on computing trends.

---
**Team CypherRed261 | Lovely Professional University | PSB Hackathon 2026**
