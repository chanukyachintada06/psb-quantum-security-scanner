# 🛡️ Quantum-Proof Systems Scanner
 
### Post-Quantum Cryptography Compliance Scanner for Banking Infrastructure
**Team CypherRed261 | PSB Hackathon 2026 | Lovely Professional University**
 
---
 
## 📌 Project Overview
 
The **Quantum-Proof Systems Scanner** is a full-stack web application that performs real TLS cryptographic vulnerability assessment on public-facing banking endpoints and evaluates their readiness against Post-Quantum Cryptography (PQC) standards.
 
With the advent of cryptographically relevant quantum computers, classical algorithms such as RSA and ECC become breakable using Shor's algorithm. This tool helps banking institutions like Punjab National Bank identify vulnerable assets, generate a Cryptographic Bill of Materials (CBOM), and receive prioritized migration recommendations aligned to NIST PQC standards.
 
---
## 🔐 Live Demo Access

Try the live deployment here:
**🔗 https://psb-hackathon2026.vercel.app/**

| Username | Password | Role |
|---|---|---|
| `pnbuser` | `pnb@123` | PNB User |
| `judge01` | `pnb@123` | Judge |
| `judge02` | `pnb@123` | Judge |
| `judge03` | `pnb@123` | Judge |

> **Note:** The live deployment runs in Demo Mode (mock data).
> For real TLS scanning, clone the repo and run the backend locally.
 
## 🎯 Objectives
 
- Scan public-facing banking endpoints for TLS cryptographic configuration
- Detect quantum-vulnerable algorithms (RSA, ECC, DH, DSA)
- Assign a PQC risk score (0–100) and readiness percentage
- Generate structured CBOM aligned with CERT-IN Annexure-A
- Recommend Post-Quantum alternatives (Kyber-768, Dilithium, SPHINCS+, Hybrid TLS)
- Store scan history, audit logs, and classification labels in Supabase (PostgreSQL)
- Display results on a real-time interactive dashboard
 
---
 
## ⚙️ System Workflow
 
1. User logs in with authorized credentials
2. User inputs a domain or IP address in Asset Inventory
3. Backend connects to domain:443 and performs TLS handshake analysis via sslyze
4. Cryptographic parameters extracted (cipher suites, key types, certificate metadata)
5. Quantum Validation Engine classifies vulnerability using NIST FIPS 203/204/205
6. Risk score, PQC readiness, and recommendations generated
7. Results stored in Supabase (scan_results, cbom_records, audit_logs, classification_labels)
8. Dashboard displays real-time output across 7 modules
 
---
 
## 🧱 Tech Stack
 
| Layer | Technology |
|---|---|
| **Frontend** | HTML5, CSS3, Vanilla JavaScript (SPA) |
| **Backend** | Python 3.12, FastAPI, Uvicorn |
| **TLS Scanner** | sslyze 6.x, cryptography library |
| **PQC Engine** | Custom classifier — NIST FIPS 203/204/205 |
| **Database** | Supabase (PostgreSQL) |
| **Version Control** | Git, GitHub |
| **IDE** | VS Code, Antigravity IDE |
 
---
 
## 📂 Repository Structure
 
```
quantum-proof-scanner/
│
├── frontend/
│   ├── index.html          ← Single Page Application (7 modules)
│   ├── styles.css          ← PNB red/gold dark theme
│   └── script.js           ← SPA router, charts, login, scan logic
│
├── backend/
│   ├── main.py             ← FastAPI app + all API endpoints
│   ├── scanner.py          ← TLS scanning engine (sslyze)
│   ├── quantum_validator.py← PQC algorithm classifier
│   ├── database.py         ← Supabase connection + all queries
│   ├── models.py           ← Pydantic response models
│   ├── requirements.txt    ← Python dependencies
│   ├── run.bat             ← Windows one-click startup
│   └── .env.example        ← Environment variable template
│
└── README.md
```
 
---
 
## 🖥️ Frontend Modules
 
| Module | Description |
|---|---|
| **Home** | Dashboard with 6 stat cards, 4 charts, asset table, activity feed |
| **Asset Inventory** | Real TLS scan with risk summary, TLS details, recommendations |
| **Asset Discovery** | Domain, SSL, IP, Software tabs + D3.js network graph |
| **CBOM** | Cryptographic Bill of Materials — key lengths, cipher usage charts |
| **Posture of PQC** | Risk heatmap, classification grades, PQC support status |
| **Cyber Rating** | Enterprise score (0–1000), gauge, per-asset scores |
| **Reporting** | Executive, Scheduled, On-Demand report generation |
 
---
 
## 🔌 API Endpoints
 
| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | API info and status |
| GET | `/health` | Health check + DB status |
| POST | `/api/scan` | Scan a domain (JSON body) |
| GET | `/api/scan/{domain}` | Scan a domain (URL param) |
| GET | `/api/history` | Recent scan history from Supabase |
| GET | `/api/cbom` | CBOM records from Supabase |
| GET | `/api/audit` | Audit logs from Supabase |
| GET | `/api/stats` | Aggregated dashboard statistics |
| GET | `/docs` | Swagger UI documentation |
 
---
 
## 🗄️ Database Schema (Supabase/PostgreSQL)
 
```
quantum_scanner_db
├── scan_results          ← TLS scan data per domain
├── cbom_records          ← Cryptographic Bill of Materials
├── audit_logs            ← System event tracking (SRS 5.4)
└── classification_labels ← PQC labels issued (FR-17, FR-18)
```
 
Tables are created automatically on first backend startup — no manual SQL needed.
 
---
 
## 🚀 Setup & Running
 
### Prerequisites
- Python 3.10+
- Supabase Account (Free Tier OK)
- Google Chrome
 
### Step 1 — Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/quantum-proof-scanner.git
cd quantum-proof-scanner
```
 
### Step 2 — Configure Supabase Backend

The platform uses Supabase for PostgreSQL persistence and JWT authentication.

1. **Environment Configuration**: Update your `.env` file with your project credentials:
   ```env
   SUPABASE_URL=https://your-project.supabase.co
   SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
   SUPABASE_JWT_SECRET=your_jwt_secret
   ```
 
### Step 3 — Initialize Environment
```bash
cd backend
cp .env.example .env
# Edit .env and ensure Supabase keys are correct
```
 

 
### Step 4 — Install Python Dependencies
```bash
pip install -r requirements.txt
```
 
### Step 5 — Start the Backend
```bash
# Windows
python -m uvicorn main:app --reload
 
# Linux/Mac
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
 
You should see:
```
✅ Supabase connected successfully!
✅ Database schema verified.
INFO: Application startup complete.
```
 
### Step 6 — Open the Frontend
Open `frontend/index.html` directly in Chrome.
 
API docs available at: `http://localhost:8000/docs`
 
### Step 7 — Test with Real Domains
Try scanning:
- `google.com` → TLS 1.3, MEDIUM risk (RSA key)
- `sbi.co.in` → Real Indian bank TLS config
- `github.com` → ECDSA, lower risk
 
> **Demo Mode:** If the backend is offline, the frontend automatically falls back to mock data with a yellow "Demo Mode" badge — the UI works either way.
 
---
 
## 🛡️ PQC Compliance Standards
 
| Standard | Description |
|---|---|
| NIST FIPS 203 | ML-KEM (CRYSTALS-Kyber) — Key Encapsulation |
| NIST FIPS 204 | ML-DSA (CRYSTALS-Dilithium) — Digital Signatures |
| NIST FIPS 205 | SLH-DSA (SPHINCS+) — Hash-based Signatures |
| CERT-IN | Annexure-A Cryptographic Requirements |
| RBI CSF | RBI Cybersecurity Framework TLS Requirements |
 
---
 
## 🔐 Key Features
 
- ✅ Real TLS scanning via sslyze (not mock data)
- ✅ PQC risk scoring aligned to NIST FIPS 203/204/205
- ✅ CBOM generation per CERT-IN Annexure-A
- ✅ Supabase persistence — scan history survives restarts
- ✅ Full audit trail — every scan logged with timestamp and IP
- ✅ User authentication — role-based login system
- ✅ Demo mode fallback — works offline with mock data
- ✅ Interactive D3.js network graph of asset relationships
- ✅ Chart.js dashboards across all modules
- ✅ Responsive SPA — no page reloads
 
---
 
## 👥 Team

| Member | Role |
|---|---|
| [Chanukya Venkata Sai](https://github.com/chanukyachintada06) | Team Lead — Risk Engine, Frontend, Integration | 
| [G.L. Santhosh Reddy](https://github.com/santhoshreddy28) | Backend Developer — Scanner Engine & API |
| [ANKUSH TANWAR](https://github.com/ANKUSHTANWAR55) | Database Engineer — Supabase/PostgreSQL Design & Data Integrity |
| [Anil Kumar Reddy](https://github.com/Anil6373)  | QA Engineer — Testing & Validation |

---
---
 
## 🚀 Future Scope
 
- Cloud deployment on AWS/Azure with Docker
- Hybrid PQC + classical certificate issuance
- PDF/JSON compliance report export
- Multi-tenant support for enterprise banking groups
- CI/CD pipeline integration for automated scanning
- RBAC expansion — Admin, Auditor, Checker roles
 
---
 
## 📜 License
 
This project is developed for the **PSB Cybersecurity Hackathon 2026** in collaboration with **IIT Kanpur**.
 
---
 
*Team CypherRed261 | Lovely Professional University | PSB Hackathon 2026*
