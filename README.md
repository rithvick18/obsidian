# Obsidian XDR

Obsidian XDR is a simulated security operations platform for monitoring insider threats, triaging incidents, tracking privileged sessions, and exploring post-quantum cryptography workflows in a single dashboard.

This project combines:
- a FastAPI backend that generates telemetry, exposes control endpoints, and streams live security events over WebSockets
- a Vite + React + TypeScript frontend that renders a real-time SOC/XDR dashboard

---

## Overview

Obsidian XDR is designed as a high-fidelity demo/security dashboard for:
- executive security posture monitoring
- live attack simulation and telemetry
- identity risk scoring
- AI-assisted cyber response
- privileged session visibility
- post-quantum key and token rotation workflows

The app presents multiple operational views such as:
- Executive Dashboard
- Quantum Center
- Incident Triage
- Security Analytics
- User Risk Profiles
- AI Copilot Chat
- Live Attack Map
- Privileged Sessions

---

## Architecture

The repository is organized into two main parts:

- `backend/` — FastAPI service with live telemetry simulation, SQLite persistence, WebSocket streaming, and control endpoints
- `frontend/` — React dashboard UI built with Vite, TypeScript, Tailwind-style styling, and reusable dashboard components

Key implementation files:
- `backend/main.py` — main backend service
- `frontend/src/App.tsx` — root dashboard layout and navigation
- `frontend/package.json` — frontend scripts and dependencies

---

## Features

### Security Operations
- Real-time incident stream simulation
- Risk scoring for user activity and anomaly detection
- Privileged session monitoring
- Automated response and mitigation workflow simulation

### AI Copilot
- Optional Gemini-powered chat support
- Rules-based fallback system for environments without an API key

### Post-Quantum Security Simulation
- ML-KEM / ML-DSA style security workflow simulation
- Token rotation and mitigation actions

---

## Tech Stack

### Backend
- Python 3.10+
- FastAPI
- Uvicorn
- SQLite
- python-dotenv

### Frontend
- React 19
- TypeScript
- Vite
- Lucide React
- Motion

---

## Prerequisites

Before running the project locally, make sure you have:

- Node.js 18+ recommended
- Python 3.10+
- A Gemini API key if you want to enable full AI Copilot capabilities

---

## Local Setup

### 1. Start the backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
