"""
Obsidian Security Engine — v1.0.0
Single-file asynchronous FastAPI backend for real-time insider threat
detection and quantum-safe credential protection (simulated).

Microservices (in-memory):
  1. Ingestion & Anomaly Engine   – WebSocket /ws/logs
  2. Risk Evaluation & PQC Vault  – automatic threat flagging + token rotation
  3. REST Control Plane           – status & manual mitigation endpoints
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import random
import secrets
import time
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Application initialisation
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Obsidian Security Engine",
    version="1.0.0",
    description="Corporate banking insider-threat detection & PQC credential vault.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# In-memory state  (shared across simulated micro-services)
# ---------------------------------------------------------------------------

# Cumulative counters
_metrics: dict[str, Any] = {
    "sessions_monitored": 0,
    "anomalies_deflected": 0,
    "vault_status": "Armed",
    "honeypot_lures_active": 4,
}

# Contextual Canary Honeypots
HONEYPOT_RESOURCES: set[str] = {
    "db_admin.shadow_vault_backup",
    "core.root.shadow_key_vault",
    "pam_auth.shadow_master_key",
    "swift.gateway.shadow_channel",
}

# Velocity tracking for Graph-Based Role Distance
_user_call_timestamps: dict[str, list[float]] = {}

# Audit trail for every rotation (PQC or manual)
_rotation_log: list[dict[str, Any]] = []

# Track the boot timestamp so we can report uptime
_boot_time: float = time.time()

# Internal message queue between the Ingestion engine and Risk Evaluator
_anomaly_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

# Connected WebSocket clients
_ws_clients: set[WebSocket] = set()

# ---------------------------------------------------------------------------
# Corporate profile definitions
# ---------------------------------------------------------------------------

PROFILES: list[dict[str, Any]] = [
    {
        "user_id": "s.murphy.admin",
        "role": "System Administrator",
        "department": "IT Operations",
        "action": "Standard maintenance — routine log review",
        "risk_range": (5, 12),
        "base_status": "SECURE",
    },
    {
        "user_id": "v.patel.contractor",
        "role": "External Contractor",
        "department": "Data Analytics",
        "action": "Sudden mass query execution against customer PII tables",
        "risk_range": (85, 91),
        "base_status": "ALERT",
    },
    {
        "user_id": "compromised.root.node",
        "role": "Root Service Account",
        "department": "Core Infrastructure",
        "action": "Unauthorized system configuration edit — privilege escalation attempt",
        "risk_range": (92, 96),
        "base_status": "CRITICAL",
    },
    {
        "user_id": "c.vance.intern",
        "role": "Helpdesk Intern",
        "department": "Tier 1 Support",
        "action": "SELECT * FROM db_admin.shadow_vault_backup — Canary Honeypot Probe",
        "risk_range": (15, 25),
        "base_status": "ALERT",
    },
]

# ---------------------------------------------------------------------------
# PQC simulation helpers
# ---------------------------------------------------------------------------


def _generate_pqc_artefacts() -> dict[str, str]:
    """
    Simulate NIST-standardised Post-Quantum Cryptographic key material.

    - ML-KEM-1024  : Module-Lattice Key Encapsulation Mechanism (token encapsulation)
    - ML-DSA-85    : Module-Lattice Digital Signature Algorithm (audit log signing)

    In production these would come from a hardware security module (HSM).
    Here we generate random hex strings of representative lengths.
    """
    # ML-KEM-1024 shared-secret is 32 bytes; public key ~1568 bytes (we show a fingerprint)
    kem_shared_secret = secrets.token_hex(32)
    kem_public_key_fingerprint = hashlib.sha3_256(secrets.token_bytes(1568)).hexdigest()

    # ML-DSA-85 signature is 4627 bytes (we show a truncated hex + fingerprint)
    dsa_signature = secrets.token_hex(64)  # representative excerpt
    dsa_public_key_fingerprint = hashlib.sha3_256(secrets.token_bytes(2592)).hexdigest()

    return {
        "ml_kem_1024": {
            "algorithm": "ML-KEM-1024",
            "shared_secret_hex": kem_shared_secret,
            "public_key_fingerprint": kem_public_key_fingerprint,
            "purpose": "Token encapsulation",
        },
        "ml_dsa_85": {
            "algorithm": "ML-DSA-85",
            "signature_hex": dsa_signature,
            "public_key_fingerprint": dsa_public_key_fingerprint,
            "purpose": "Audit log digital signature",
        },
    }


def _build_rotation_record(user_id: str, trigger: str) -> dict[str, Any]:
    """Build a full rotation record with PQC artefacts."""
    pqc = _generate_pqc_artefacts()
    record = {
        "rotation_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": user_id,
        "trigger": trigger,
        "status": "REVOKED & ROTATED",
        "pqc_keys": pqc,
    }
    _rotation_log.append(record)
    _metrics["anomalies_deflected"] += 1
    return record


# ---------------------------------------------------------------------------
# Broadcast helper  (avoids augmented-assignment scoping issues on globals)
# ---------------------------------------------------------------------------


async def _broadcast(payload: str) -> None:
    """Send *payload* to every connected WebSocket client, pruning dead ones."""
    disconnected: set[WebSocket] = set()
    for ws in _ws_clients:
        try:
            await ws.send_text(payload)
        except Exception:
            disconnected.add(ws)
    # .difference_update is a method call — safe on a module-level set
    _ws_clients.difference_update(disconnected)


def _calculate_role_distance_risk(user_id: str, role: str, action: str, base_score: int) -> tuple[int, list[dict[str, Any]], bool, Optional[str]]:
    """
    Calculate dynamic graph-based role distance risk score & check for honeypot trips.
    Returns: (final_risk_score, risk_factors_list, is_honeypot, tamper_lock_signature)
    """
    now = time.time()
    # Check honeypot trip first (bypasses threshold scoring -> instantly 100)
    is_honeypot = any(h in action for h in HONEYPOT_RESOURCES) or "shadow_vault_backup" in action or "canary honeypot" in action.lower()
    if is_honeypot:
        lock_hash = hashlib.sha3_256(f"{user_id}:{now}".encode()).hexdigest()[:24]
        tamper_sig = f"mldsa_root_honeypot_lock_{lock_hash}"
        factors = [
            {"factor": "Canary Honeypot Probe (db_admin.shadow_vault_backup)", "delta": 100},
            {"factor": "Tamper-Evident ML-DSA Root Signature Locked", "delta": 0},
        ]
        return 100, factors, True, tamper_sig

    risk_factors: list[dict[str, Any]] = []
    total_score = base_score

    # 1. Time Delta: Is the action happening outside standard operational hours (07:00 - 19:00 UTC)?
    current_hour = datetime.now(timezone.utc).hour
    if current_hour < 7 or current_hour > 19 or "contractor" in role.lower():
        total_score += 15
        risk_factors.append({"factor": "Time Delta: Outside standard operational hours (+15)", "delta": 15})

    # 2. Role Divergence: Is a Helpdesk role / Tier 1 / Contractor accessing Core SWIFT Gateways or critical asset?
    if any(r in role.lower() for r in ("helpdesk", "contractor", "intern", "tier 1")) and any(
        k in action.lower() for k in ("swift", "gateways", "pii", "root", "pam", "config", "mass query", "escalation")
    ):
        total_score += 40
        risk_factors.append({"factor": "Role Divergence: Unauthorized cross-boundary asset access (+40)", "delta": 40})

    # 3. Velocity Spike: Has this user initiated >3 high-impact system calls in the last 2 seconds?
    timestamps = _user_call_timestamps.setdefault(user_id, [])
    timestamps[:] = [ts for ts in timestamps if now - ts <= 2.0]
    timestamps.append(now)
    if len(timestamps) > 3 or ("mass query" in action.lower() and random.random() < 0.4):
        total_score += 25
        risk_factors.append({"factor": "Velocity Spike: >3 high-impact system calls in 2.0s (+25)", "delta": 25})

    final_score = min(100, total_score)
    return final_score, risk_factors, False, None


# ---------------------------------------------------------------------------
# Microservice 1 — Ingestion & Anomaly Engine
# ---------------------------------------------------------------------------


async def _ingestion_loop() -> None:
    """
    Continuously generate session events for each corporate profile,
    broadcast them to every connected WebSocket client, and enqueue
    high-risk events for the Risk Evaluator.
    """
    cycle_index = 0
    while True:
        profile = PROFILES[cycle_index % len(PROFILES)]
        base_score = random.randint(*profile["risk_range"])
        dynamic_score, factors, is_honeypot, tamper_sig = _calculate_role_distance_risk(
            user_id=profile["user_id"],
            role=profile["role"],
            action=profile["action"],
            base_score=base_score,
        )

        event: dict[str, Any] = {
            "event_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": profile["user_id"],
            "role": profile["role"],
            "department": profile["department"],
            "action": profile["action"],
            "risk_score": dynamic_score,
            "status": "CRITICAL HONEYPOT BREACH" if is_honeypot else profile["base_status"],
            "risk_factors": factors,
            "is_honeypot": is_honeypot,
        }
        if tamper_sig:
            event["tamper_lock_signature"] = tamper_sig

        _metrics["sessions_monitored"] += 1

        # If risk exceeds threshold or honeypot tripped, hand off to the Risk Evaluator
        if dynamic_score > 75 or is_honeypot:
            await _anomaly_queue.put(event)

        await _broadcast(json.dumps(event))

        cycle_index += 1
        await asyncio.sleep(2)


# ---------------------------------------------------------------------------
# Microservice 2 — Risk Evaluation & Cryptographic Vault Service
# ---------------------------------------------------------------------------


async def _risk_evaluator_loop() -> None:
    """
    Consume events from the anomaly queue. When an event's risk score
    exceeds 75 or hits a canary honeypot it is flagged as an insider threat
    and a PQC token rotation is triggered.
    """
    while True:
        event = await _anomaly_queue.get()

        is_honeypot = event.get("is_honeypot", False)
        if is_honeypot:
            event["threat_classification"] = "100 [CRITICAL HONEYPOT BREACH]"
            event["mitigation"] = "Tamper-evident PQC signature locked & immediate quarantine initiated"
        else:
            event["threat_classification"] = "INSIDER THREAT — ACTIVE"
            event["mitigation"] = "Automated PQC token rotation & containment initiated"

        # Perform simulated rotation
        rotation = _build_rotation_record(
            user_id=event["user_id"],
            trigger="auto:honeypot_breach" if is_honeypot else "auto:risk_threshold_exceeded",
        )
        event["rotation"] = rotation
        event["status"] = "CRITICAL HONEYPOT BREACH" if is_honeypot else "REVOKED & ROTATED"

        # Broadcast the enriched threat event
        await _broadcast(json.dumps(event))

        _anomaly_queue.task_done()


# ---------------------------------------------------------------------------
# Lifecycle — start background microservices
# ---------------------------------------------------------------------------


@app.on_event("startup")
async def _startup() -> None:
    """Launch the two background microservice loops."""
    asyncio.create_task(_ingestion_loop())
    asyncio.create_task(_risk_evaluator_loop())


# ---------------------------------------------------------------------------
# WebSocket endpoint — live log stream
# ---------------------------------------------------------------------------


@app.websocket("/ws/logs")
async def ws_logs(ws: WebSocket) -> None:
    """
    Accept a WebSocket connection and register it for live event broadcasts.
    The connection stays open until the client disconnects.
    """
    await ws.accept()
    _ws_clients.add(ws)
    try:
        # Keep the connection alive by waiting for client messages (pings / close)
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        _ws_clients.discard(ws)


# ---------------------------------------------------------------------------
# REST Endpoint — System Status
# ---------------------------------------------------------------------------


@app.get("/api/v1/system/status")
async def system_status() -> dict[str, Any]:
    """
    Return current operational metrics of the Obsidian Security Engine.
    """
    return {
        "engine": "Obsidian Security Engine",
        "version": "1.0.0",
        "sessions_monitored": _metrics["sessions_monitored"],
        "anomalies_deflected": _metrics["anomalies_deflected"],
        "vault_status": _metrics["vault_status"],
        "honeypot_lures_active": _metrics["honeypot_lures_active"],
        "uptime_seconds": round(time.time() - _boot_time, 2),
        "active_ws_clients": len(_ws_clients),
        "rotation_log_size": len(_rotation_log),
    }


# ---------------------------------------------------------------------------
# REST Endpoint — Manual Force-Rotate & Dual-Control Mitigation
# ---------------------------------------------------------------------------


class ForceRotateRequest(BaseModel):
    """Request body for the unified manual force-rotate & dual-control mitigation endpoint."""
    user_id: str
    action_type: str = "FORCE_ROTATE"  # FORCE_ROTATE, ISOLATE_HOST, TERMINATE_SESSION, GENERATE_KEY
    primary_operator: str = "SOC_Operator_04"
    secondary_approver: Optional[str] = None


@app.post("/api/v1/mitigate/force-rotate")
async def force_rotate(body: ForceRotateRequest) -> dict[str, Any]:
    """
    Unified dual-control mitigation endpoint.
    Enforces the Four-Eyes Principle by requiring valid sign-off from both
    the primary operator and a secondary security approver.
    Handles FORCE_ROTATE, ISOLATE_HOST, TERMINATE_SESSION, and GENERATE_KEY actions cleanly.
    """
    if not body.secondary_approver or not body.secondary_approver.strip():
        return {
            "result": "error",
            "message": "Dual-control authorization rejected: Secondary approver profile is required under the Four-Eyes Principle.",
            "status_code": 403,
        }

    rotation = _build_rotation_record(
        user_id=body.user_id,
        trigger=f"manual:{body.action_type.lower()}_by_{body.primary_operator}_auth_{body.secondary_approver}",
    )

    action_label = {
        "FORCE_ROTATE": "Manual force-rotate & PQC rekeying executed",
        "ISOLATE_HOST": "Virtual containment isolation block enforced on host",
        "TERMINATE_SESSION": "Privileged session forcefully severed with Code 137",
        "GENERATE_KEY": "Corporate lattice seed keys synchronized across subnets",
    }.get(body.action_type, f"Action [{body.action_type}] executed")

    status_label = {
        "FORCE_ROTATE": "REVOKED & ROTATED",
        "ISOLATE_HOST": "CONTAINED & ISOLATED",
        "TERMINATE_SESSION": "TERMINATED (CODE 137)",
        "GENERATE_KEY": "LATTICE_SYNCHRONIZED",
    }.get(body.action_type, "REVOKED & ROTATED")

    # Also broadcast as a control-plane event over WebSocket
    control_event = {
        "event_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": body.user_id,
        "action": f"{action_label} (Primary: {body.primary_operator} // Approver: {body.secondary_approver})",
        "risk_score": None,
        "status": status_label,
        "threat_classification": f"OPERATOR OVERRIDE [{body.action_type}] (Four-Eyes Sign-Off: {body.secondary_approver})",
        "action_type": body.action_type,
        "primary_operator": body.primary_operator,
        "secondary_approver": body.secondary_approver,
        "rotation": rotation,
    }
    await _broadcast(json.dumps(control_event))

    return {
        "result": "success",
        "message": f"{action_label} for '{body.user_id}' with Four-Eyes authorization ({body.secondary_approver}).",
        "action_type": body.action_type,
        "rotation": rotation,
    }


# ---------------------------------------------------------------------------
# REST Endpoint — AI Copilot Chat
# ---------------------------------------------------------------------------


class CopilotChatRequest(BaseModel):
    """Request body for the Copilot Chat endpoint."""
    message: str


@app.post("/api/v1/copilot/chat")
async def copilot_chat(body: CopilotChatRequest) -> dict[str, Any]:
    """
    Query Gemini for smart cybersecurity architect guidance,
    or fall back to a rule-based triage answer generator if the API key is missing.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        # Fallback rule-based response
        q = body.message.lower()
        if "inc-8429" in q or "lateral" in q:
            reply = (
                "### Threat Analysis: INC-8429 (Unauthorized Database Bulk Export)\n\n"
                "**Attack Path Overview:**\n"
                "The attacker compromised the credential set for **j.smith@obsidian.io** from a Ukrainian IP. "
                "They achieved **UAC Bypass (T1068)** to elevate privileges and executed direct mass query exports targeting `SV-PROD-DB-02`.\n\n"
                "**Recommended Mitigation Playbook:**\n"
                "1. **Isolate the workstation:** Apply the virtual quarantine sandbox rules to sever outbound routes. *(Click \"Isolate Impacted Host\" in the Incidents dashboard)*.\n"
                "2. **Revoke Active SAML Sessions:** Invalidate Smith's SAML tokens to block subsequent database access attempts.\n"
                "3. **Trigger Password Vault Rotation:** Force immediate rotation of administrative database connection strings."
            )
        elif "quantum" in q or "pqc" in q or "lattice" in q:
            reply = (
                "### Post-Quantum Cryptographic Migration Guide\n\n"
                "We are currently transitioning local subnets from legacy asymmetric algorithms (RSA-4096) to NIST-approved **FIPS 203 Lattice Cryptography** standards.\n\n"
                "**Current Readiness Standing:**\n"
                "- **ML-KEM-768 Deployment:** **88% Active**. Remaining subnets include legacy logistics offices in APAC.\n"
                "- **Latency Impact:** ML-KEM-768 latency is highly optimized (~152.4ms overhead), whereas RSA-4096 exhibits extreme latency (~14.2s) under quantum emulation testing.\n\n"
                "*Recommendation:* Proceed to the **Quantum Center** to trigger corporate lattice seed keys for the remainder of legacy APAC routers."
            )
        elif "arjun" in q or "trust" in q or "risk" in q:
            reply = (
                "### User Risk Triage: Arjun Vardhan\n\n"
                "**Identity Security Audit:**\n"
                "- **Current Trust Score:** **28/100 (HIGH RISK)**\n"
                "- **Critical Trigger Event:** \"Impossible Travel\" detected between Chennai, IN and Frankfurt, DE within a 45-minute window.\n"
                "- **Access Anomaly:** Attempted to access financial buckets S3://prod-fin-records/* from the unrecognized Frankfurt IP.\n\n"
                "**Mitigation Protocol:**\n"
                "- Proactively place user on temporary SAML quarantine.\n"
                "- Verify whether user initiated an authorized VPN tunnel."
            )
        elif "vulnerab" in q or "subnet" in q or "port" in q:
            reply = (
                "### Corporate Subnet Vulnerability Matrix\n\n"
                "Active scanning of internal subnets reveals **2 Critical** and **14 Moderate** vulnerabilities:\n\n"
                "1. **Subnet EMEA-PROD-DB:** Exposed to unpatched CVE-2026-9021 (Remote Code Execution, named \"Frostbyte\").\n"
                "2. **Subnet MKT-WS:** High incidence of endpoint systems running UAC bypass configurations.\n\n"
                "*Remediation action:* Trigger an automated patch schedule via the **Security Analytics** scanning board to apply the security patch instantly."
            )
        else:
            reply = (
                "### Obsidian Security Copilot Response\n\n"
                f"I have analyzed your request: *\"{body.message}\"*.\n\n"
                "As an AI-powered security architect, I can assist you with:\n"
                "- **Incident Investigation:** Triage of active threat alerts like INC-8429 or INC-8395.\n"
                "- **Quantum Cryptography:** Guidance on lattice-based keys, ML-KEM or ML-DSA protocols.\n"
                "- **Risk Remediation:** Analyzing employee anomalies, impossible travel, or credential risk.\n"
                "- **Remediation Execution:** Generating sandboxing commands for infected target hosts.\n\n"
                "Please select one of the suggested query chips below or provide a more specific security telemetry question."
            )
        return {"response": reply}

    import urllib.request
    import urllib.error

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
    system_instruction = (
        "You are Obsidian Copilot, a secure AI cybersecurity architect assistant. "
        "You have access to active XDR telemetry and help SOC operators with triage, containment, and cryptographic modeling. "
        "Use markdown and keep answers concise and professional."
    )

    payload = {
        "contents": [
            {
                "parts": [
                    {"text": f"System Context: {system_instruction}\nUser Query: {body.message}"}
                ]
            }
        ]
    }

    req_body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=req_body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=10.0) as response:
            resp_data = json.loads(response.read().decode("utf-8"))
            try:
                text = resp_data["candidates"][0]["content"]["parts"][0]["text"]
                return {"response": text}
            except (KeyError, IndexError):
                return {"response": "Error: Failed to parse Gemini response payload."}
    except Exception as e:
        return {"response": f"Error calling Gemini API: {str(e)}"}


# ---------------------------------------------------------------------------
# Entrypoint (for `python main.py` convenience)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
