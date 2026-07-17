# Obsidian XDR

<div align="center">

# Obsidian XDR
### AI-Powered Extended Detection & Response (XDR) Platform

**Empowering financial institutions with real-time cyber risk visibility, AI-assisted incident response, insider threat detection, and post-quantum security readiness.**

### Live Demo

**Frontend UI Demo:** https://obsidian-iota-three.vercel.app/

> **Note:** This deployment showcases the frontend user interface only. Backend-powered features—including live telemetry, AI Copilot, WebSocket streaming, and security simulations—require the FastAPI backend.

</div>

---

# Overview

Cyber threats targeting financial institutions continue to evolve, placing banks, fintech organizations, insurance providers, and enterprises under constant pressure to detect attacks earlier, respond faster, and maintain regulatory compliance.

**Obsidian XDR** is an AI-powered Security Operations Center (SOC) platform that consolidates security telemetry, insider threat monitoring, privileged access visibility, AI-assisted investigations, and post-quantum security workflows into a single operational dashboard.

Designed as a modern XDR platform, Obsidian XDR enables security teams and executives to gain actionable insights through intuitive visualizations, automated response simulations, and intelligent risk prioritization.

---

# Why Obsidian XDR?

Traditional security tools overwhelm analysts with thousands of alerts while providing little business context.

Obsidian XDR demonstrates how Artificial Intelligence can transform Security Operations by:

- Prioritizing security alerts using AI
- Delivering executive-level cyber risk visibility
- Simulating rapid incident response workflows
- Detecting insider threats and risky user behavior
- Monitoring privileged identities and critical sessions
- Demonstrating post-quantum cryptographic readiness
- Reducing response time through intelligent automation

---

# Key Features

## Security Operations

- Real-time incident monitoring
- Insider threat detection
- Identity and user risk scoring
- Executive security posture dashboard
- Privileged session monitoring
- Security analytics
- Live attack visualization
- Automated mitigation workflows

---

## AI Security Copilot

- Gemini-powered AI assistant
- Natural language security investigations
- AI-assisted incident analysis
- Intelligent security recommendations
- Local rules-based fallback when API keys are unavailable

---

## Post-Quantum Security

Preparing organizations for the next generation of cybersecurity.

Features include:

- ML-KEM workflow simulation
- ML-DSA security demonstrations
- Secure key rotation
- Token rotation workflows
- Quantum readiness visualization

---

## Live Infrastructure

- Live telemetry generation
- WebSocket event streaming
- Persistent event storage
- Real-time dashboard updates
- Interactive security simulations

---

# Dashboard Modules

Obsidian XDR provides multiple operational views for security teams.

- Executive Dashboard
- Security Analytics
- Incident Triage
- User Risk Profiles
- Live Attack Map
- Privileged Sessions
- Quantum Security Center
- AI Copilot Chat

---

# Business Impact

Obsidian XDR is designed around the operational requirements of highly regulated industries.

## Target Industries

- Banking
- Financial Services
- FinTech
- Insurance
- Enterprise Security Operations
- Government Organizations

## Value Delivered

Faster incident detection

Reduced analyst fatigue

Executive cyber risk visibility

Improved privileged access governance

AI-assisted investigations

Enhanced operational resilience

Future-ready post-quantum security awareness

---

# Architecture

```
                +---------------------------------------+
                |          React Frontend               |
                |     Vite + TypeScript + Motion        |
                +------------------+--------------------+
                                   |
                           REST API / WebSocket
                                   |
                +------------------v--------------------+
                |           FastAPI Backend             |
                |                                       |
                | • Security Telemetry Engine           |
                | • Incident Response Simulator         |
                | • AI Security Copilot                 |
                | • Risk Analytics                      |
                | • WebSocket Event Streaming           |
                +------------------+--------------------+
                                   |
                             SQLite Database
```

---

# Project Structure

```
obsidian/
│
├── backend/
│   ├── main.py
│   ├── requirements.txt
│   ├── .env
│   └── ...
│
├── frontend/
│   ├── src/
│   ├── package.json
│   ├── metadata.json
│   └── ...
│
├── render.yaml
└── README.md
```

---

# Technology Stack

## Frontend

- React 19
- TypeScript
- Vite
- Motion
- Lucide React

## Backend

- FastAPI
- Python 3.10+
- Uvicorn
- SQLite
- python-dotenv

---

# Getting Started

## Prerequisites

- Node.js 18+
- Python 3.10+
- npm
- pip

Optional:

- Google Gemini API Key

---

## Clone the Repository

```bash
git clone https://github.com/<your-username>/obsidian-xdr.git

cd obsidian-xdr
```

---

# Backend Setup

```bash
cd backend

python -m venv .venv
```

### Activate Environment

macOS / Linux

```bash
source .venv/bin/activate
```

Windows

```powershell
.venv\Scripts\activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

Create a `.env` file

```env
GEMINI_API_KEY=your_api_key_here
```

Run the backend

```bash
python main.py
```

Backend URL

```
http://localhost:8000
```

---

# Frontend Setup

Open another terminal.

```bash
cd frontend

npm install

npm run dev
```

Frontend URL

```
http://localhost:3000
```

---

# API Overview

| Method | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/v1/system/status` | System health |
| POST | `/api/v1/telemetry` | Submit telemetry |
| POST | `/api/v1/copilot/chat` | AI Security Copilot |
| POST | `/api/v1/mitigate/force-rotate` | Execute mitigation workflow |
| POST | `/api/v1/simulator/control` | Control simulation engine |

### WebSocket

```
ws://localhost:8000/ws/logs
```

Streams live security telemetry to the dashboard.

---

# Deployment

The project includes a **Render** deployment configuration.

Recommended deployment architecture:

- Frontend → Vercel / Render Static Site
- Backend → Render / Railway / Azure App Service
- Database → SQLite (Demo) or PostgreSQL (Production)

---

# Vision

The future of cybersecurity requires more than monitoring—it requires intelligent decision support.

Obsidian XDR demonstrates how Artificial Intelligence can transform Security Operations Centers into proactive cyber defense platforms capable of helping analysts detect threats earlier, prioritize incidents intelligently, and respond with greater confidence.

By combining live telemetry, AI-assisted investigations, insider threat analytics, executive dashboards, privileged access monitoring, and post-quantum security workflows, Obsidian XDR showcases a modern vision for protecting critical financial infrastructure against evolving cyber threats.

---

# Future Roadmap

- Multi-cloud security monitoring
- SOAR integrations
- SIEM interoperability
- MITRE ATT&CK mapping
- Threat Intelligence feeds
- Compliance reporting
- Predictive AI risk scoring
- Multi-tenant enterprise deployment
- Real-time anomaly detection using Machine Learning

---

# License

This repository currently does not include an open-source license.

For public distribution, the MIT License is recommended.

---

<div align="center">

### Built for the future of AI-driven Cyber Defense.

**Secure • Detect • Respond • Recover**

</div>
