# Obsidian XDR (Extended Detection & Response)

Welcome to **Obsidian XDR** (Obsidian Security Engine), a unified corporate banking security dashboard built to detect insider threats, monitor privileged sessions, and simulate quantum-resistant security operations.

Obsidian XDR combines real-time streaming telemetry, identity risk analytics, post-quantum cryptographic (PQC) keys rotation, and a generative AI Security Copilot powered by Google Gemini.

---

## Key Features

Obsidian XDR offers eight specialized tabs for complete security operations:

1. **Executive Dashboard**: High-level telemetry cards (monitored sessions, anomalies deflected, PQC vault status), security posture health charts, and interactive incident queues.
2. **Quantum Center**: Live NIST-standard post-quantum cryptography management. Simulates key encapsulation (`ML-KEM-1024`) and digital signatures (`ML-DSA-85`) with interactive key generation and audit signing.
3. **Incident Triage**: Live incident responder dashboard allowing operators to analyze critical threat incidents (e.g. `INC-8429`), review interactive attack chains, inspect chronological timelines, and execute sandboxing mitigations.
4. **Security Analytics**: Real-time traffic indicators, compliance ratings, and security scanning automation.
5. **User Risk Profiles**: Identity-centric risk profiling. Tracks trust scores and provides playbooks to mitigate compromised or high-risk human behavior (e.g., impossible travel alerts).
6. **AI Copilot Chat**: An interactive chat terminal assisting SOC operators with intelligent triage and playbook suggestions. Directly leverages Google Gemini or falls back to rules-based models.
7. **Live Attack Map**: A real-time geospatial visualization of security alerts and anomalies.
8. **Privileged Sessions**: Live monitoring of shell sessions (`ssh`, `tty`). Inspects command history, calculates typing cadences, and offers session termination or flagging capabilities.

---

## Architecture

Obsidian XDR is built as a split client-server architecture:
- **Backend ([backend/main.py](../backend/main.py))**: A single-file FastAPI server that exposes REST API control endpoints and broadcasts continuous system event streams via WebSockets (`ws://localhost:8000/ws/logs`).
- **Frontend ([frontend/src](./src))**: A React client written in TypeScript, using Vite, TailwindCSS, and Lucide React. It communicates with the backend REST endpoints and listens to the live WebSocket feed for instantaneous dashboard updates.

---

## Getting Started (Run Locally)

To run the full Obsidian XDR application locally, you will need to start both the Python backend service and the Vite React frontend.

### Prerequisites
- **Node.js** (v18 or newer recommended)
- **Python 3.10+**
- **Google Gemini API Key** (optional, for Copilot Chat integration)

---

### Step 1: Start the Backend Server

The backend serves the live event simulation, WebSocket stream, and handles the Copilot Chat queries.

1. Navigate to the `backend` directory:
   ```bash
   cd backend
   ```

2. (Optional) Create and activate a Python virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On macOS/Linux
   # or venv\Scripts\activate on Windows
   ```

3. Install required Python packages:
   ```bash
   pip3 install -r requirements.txt
   ```

4. Configure your Gemini API key (optional but recommended for full Copilot features):
   Open `backend/.env` (and optionally `frontend/.env`) and add your API key:
   ```env
   GEMINI_API_KEY="your-gemini-api-key-here"
   ```
   The backend server automatically loads this key from the `.env` file using `python-dotenv`.

5. Run the FastAPI server:
   ```bash
   python main.py
   ```
   The backend will start and run on `http://localhost:8000`.

---

### Step 2: Start the Frontend Application

The frontend renders the React dashboard and connects to the backend server.

1. Navigate to the `frontend` directory:
   ```bash
   cd frontend
   ```

2. Install the frontend dependencies:
   ```bash
   npm install
   ```

3. Start the Vite React development server:
   ```bash
   npm run dev
   ```

4. Open your browser and navigate to `http://localhost:3000` (or the port outputted in the terminal).

---

## ⚙️ Configuration Details

- **Gemini API Integration**: The AI Copilot Chat loads environment variables (including `GEMINI_API_KEY` defined in `.env`). If this key is not set, the backend automatically falls back to a rules-based fallback system simulating context responses for `INC-8429`, Quantum Cryptography, and Arjun Vardhan.
- **REST Endpoints**:
  - `GET /api/v1/system/status`: Retrieves real-time metrics of the Security Engine.
  - `POST /api/v1/mitigate/force-rotate`: Revokes user credentials and replaces them with fresh post-quantum cryptographic keys.
  - `POST /api/v1/copilot/chat`: Communicates with Gemini or the rule fallback framework.
- **WebSockets**:
  - `/ws/logs`: Streams continuous event simulations, including simulated security logs and manual threat mitigations.

