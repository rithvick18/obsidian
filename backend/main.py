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
from datetime import datetime, timezone
from typing import Any
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
    allow_origins=["http://localhost:5173"],
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
}

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
        risk_score = random.randint(*profile["risk_range"])

        event: dict[str, Any] = {
            "event_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": profile["user_id"],
            "role": profile["role"],
            "department": profile["department"],
            "action": profile["action"],
            "risk_score": risk_score,
            "status": profile["base_status"],
        }

        _metrics["sessions_monitored"] += 1

        # If risk exceeds threshold, hand off to the Risk Evaluator
        if risk_score > 75:
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
    exceeds 75 it is flagged as an insider threat and a PQC token rotation
    is triggered.  The enriched event is then re-broadcast to all WS clients.
    """
    while True:
        event = await _anomaly_queue.get()

        # Flag as insider threat
        event["threat_classification"] = "INSIDER THREAT — ACTIVE"
        event["mitigation"] = "Automated PQC token rotation initiated"

        # Perform simulated rotation
        rotation = _build_rotation_record(
            user_id=event["user_id"],
            trigger="auto:risk_threshold_exceeded",
        )
        event["rotation"] = rotation
        event["status"] = "REVOKED & ROTATED"

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
        "uptime_seconds": round(time.time() - _boot_time, 2),
        "active_ws_clients": len(_ws_clients),
        "rotation_log_size": len(_rotation_log),
    }


# ---------------------------------------------------------------------------
# REST Endpoint — Manual Force-Rotate
# ---------------------------------------------------------------------------


class ForceRotateRequest(BaseModel):
    """Request body for the manual force-rotate endpoint."""
    user_id: str


@app.post("/api/v1/mitigate/force-rotate")
async def force_rotate(body: ForceRotateRequest) -> dict[str, Any]:
    """
    Manually trigger a PQC token rotation for a specific user.
    This simulates an operator-initiated credential revocation and
    quantum-safe re-keying.
    """
    rotation = _build_rotation_record(
        user_id=body.user_id,
        trigger="manual:force_rotate",
    )

    # Also broadcast as a control-plane event over WebSocket
    control_event = {
        "event_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": body.user_id,
        "action": "Manual force-rotate executed by operator",
        "risk_score": None,
        "status": "REVOKED & ROTATED",
        "threat_classification": "OPERATOR OVERRIDE",
        "rotation": rotation,
    }
    await _broadcast(json.dumps(control_event))

    return {
        "result": "success",
        "message": f"Credentials for '{body.user_id}' revoked and rotated with PQC keys.",
        "rotation": rotation,
    }


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
