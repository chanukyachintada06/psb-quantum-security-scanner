# 🛡 Quantum-Safe Cryptography Scanner for Banking Systems

## 📌 Project Overview

The Quantum-Safe Cryptography Scanner is designed to analyze banking
systems and identify cryptographic algorithms that are vulnerable to
future quantum computer attacks.

With advancements in quantum computing, classical algorithms such as RSA
and ECC may become insecure. This tool helps banking institutions assess
their quantum readiness and migrate toward Post-Quantum Cryptography
(PQC).

------------------------------------------------------------------------

## 🎯 Objectives

-   Detect cryptographic algorithms used in banking endpoints
-   Identify quantum-vulnerable algorithms
-   Assign a quantum risk score
-   Recommend Post-Quantum alternatives (Kyber, Dilithium, Hybrid TLS)
-   Store scan history and generate analytics dashboard

------------------------------------------------------------------------

## ⚙️ System Workflow

1.  User inputs domain/IP
2.  Scanner analyzes TLS configuration
3.  Extracts cipher suites & key exchange algorithms
4.  Risk engine evaluates quantum vulnerability
5.  Generates recommendation
6.  Stores results in MongoDB
7.  Displays output on dashboard

------------------------------------------------------------------------

## 🧱 Tech Stack

Frontend: HTML, CSS, JavaScript\
Backend: Node.js / Python (Scanner + Risk Engine)\
Database: MongoDB\
Version Control: GitHub\
Project Management: Notion

------------------------------------------------------------------------

## 📂 Repository Structure

    quantum-safe-banking-scanner/
    │
    ├── frontend/
    │   ├── index.html
    │   ├── css/
    │   ├── js/
    │   └── assets/
    │
    ├── backend/
    │   ├── scanner/           # TLS detection & crypto extraction
    │   ├── risk_engine/       # Quantum risk scoring logic
    │   ├── routes/            # API endpoints
    │   ├── controllers/       # Business logic handlers
    │   └── config/            # Environment configuration
    │
    ├── database/
    │   ├── models/            # MongoDB models
    │   └── schema_design.md   # Collection & indexing plan
    │
    ├── docs/
    │   ├── architecture.md
    │   ├── threat_model.md
    │   ├── api_documentation.md
    │   └── presentation_material/
    │
    ├── tests/
    │   ├── test_cases.md
    │   └── test_reports/
    │
    ├── .env.example
    ├── README.md
    └── package.json / requirements.txt

------------------------------------------------------------------------

## 👥 Team Members

-   Chanukya -- Team Lead, Risk Engine, Frontend, Integration Testing\
-   Santosh -- Scanner Engine & Backend APIs\
-   Ankush -- MongoDB Design & Data Integrity\
-   Anil -- Testing & QA

------------------------------------------------------------------------

## 🔐 Key Features

-   Quantum vulnerability detection
-   Risk scoring model
-   Post-Quantum migration recommendations
-   Scan history tracking
-   Modular and scalable architecture

------------------------------------------------------------------------

## 🚀 Future Scope

-   Integration with CI/CD pipelines
-   Automated compliance reporting
-   Hybrid classical + PQC detection
-   Cloud deployment & scaling

------------------------------------------------------------------------

## 📜 License

This project is developed for the PSB Cybersecurity Hackathon.
