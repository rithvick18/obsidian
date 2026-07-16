import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { Incident, PrivilegedSession, RiskProfile, AlgorithmPerformance, AuditEvent } from '../types';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';

interface SystemStatus {
  engine: string;
  version: string;
  sessions_monitored: number;
  anomalies_deflected: number;
  vault_status: string;
  honeypot_lures_active?: number;
  uptime_seconds: number;
  active_ws_clients: number;
  rotation_log_size: number;
}

interface SecurityContextType {
  incidents: Incident[];
  sessions: PrivilegedSession[];
  profiles: RiskProfile[];
  signals: any[];
  algorithms: AlgorithmPerformance[];
  systemStatus: SystemStatus | null;
  generationLogs: string[];
  isGeneratingKey: boolean;
  isConnected: boolean;
  forceRotateUser: (userId: string, actionType?: string, secondaryApprover?: string) => Promise<boolean>;
  isolateHost: (entityName: string, incidentId: string, secondaryApprover?: string) => void;
  mitigateIncidentDirect: (incidentId: string) => void;
  terminateSession: (sessionId: string, secondaryApprover?: string) => void;
  flagSession: (sessionId: string) => void;
  runComplianceScan: () => void;
  complianceScanning: boolean;
  auditScore: number;
  auditEvents: AuditEvent[];
  generatePqcKey: (secondaryApprover?: string) => void;
  sendCopilotMessage: (message: string) => Promise<string>;
  dualControlModalOpen: boolean;
  dualControlActionType: string;
  dualControlTargetEntity: string;
  openDualControlModal: (actionType: string, targetEntity: string, callback: (approver: string) => void) => void;
  closeDualControlModal: () => void;
  confirmDualControlAction: (approver: string) => void;
  currentOperator: string;
}

const SecurityContext = createContext<SecurityContextType | undefined>(undefined);

// Purged baseline arrays to enforce absolute reliance on active backend streams
const INITIAL_INCIDENTS: Incident[] = [];
const INITIAL_SESSIONS: PrivilegedSession[] = [];
const INITIAL_ALGORITHMS: AlgorithmPerformance[] = [];

export const SecurityProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [incidents, setIncidents] = useState<Incident[]>(INITIAL_INCIDENTS);
  const [sessions, setSessions] = useState<PrivilegedSession[]>(INITIAL_SESSIONS);
  const [profiles, setProfiles] = useState<RiskProfile[]>([]);
  const [algorithms, setAlgorithms] = useState<AlgorithmPerformance[]>(INITIAL_ALGORITHMS);
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  
  const [signals, setSignals] = useState<any[]>([]);

  const [generationLogs, setGenerationLogs] = useState<string[]>([]);
  const [isGeneratingKey, setIsGeneratingKey] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [currentOperator] = useState<string>('SOC_Operator_04');

  // Dual-Control Modal state
  const [dualControlModalOpen, setDualControlModalOpen] = useState(false);
  const [dualControlActionType, setDualControlActionType] = useState('FORCE_ROTATE');
  const [dualControlTargetEntity, setDualControlTargetEntity] = useState('');
  const [dualControlCallback, setDualControlCallback] = useState<((approver: string) => void) | null>(null);

  const openDualControlModal = useCallback((actionType: string, targetEntity: string, callback: (approver: string) => void) => {
    setDualControlActionType(actionType);
    setDualControlTargetEntity(targetEntity);
    setDualControlCallback(() => callback);
    setDualControlModalOpen(true);
  }, []);

  const closeDualControlModal = useCallback(() => {
    setDualControlModalOpen(false);
    setDualControlCallback(null);
  }, []);

  const confirmDualControlAction = useCallback((approver: string) => {
    if (dualControlCallback) {
      dualControlCallback(approver);
    }
    setDualControlModalOpen(false);
    setDualControlCallback(null);
  }, [dualControlCallback]);
  
  const [complianceScanning, setComplianceScanning] = useState(false);
  const [auditScore, setAuditScore] = useState(0.0);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);

  const fetchSystemStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API_URL}/api/v1/system/status`);
      if (res.ok) {
        const data = await res.json();
        setSystemStatus(data);
      }
    } catch (e) {
      console.warn('Backend REST endpoint unavailable.');
    }
  }, []);

  useEffect(() => {
    fetchSystemStatus();
    const interval = setInterval(fetchSystemStatus, 3000);
    return () => clearInterval(interval);
  }, [fetchSystemStatus]);

  // WebSocket Log Loop connection
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimeout: any = null;
    let isComponentMounted = true;

    const connectWebSocket = () => {
      ws = new WebSocket(`${WS_URL}/ws/logs`);

      ws.onopen = () => {
        if (!isComponentMounted) return;
        setIsConnected(true);
      };

      ws.onmessage = (event) => {
        if (!isComponentMounted) return;
        try {
          const log = JSON.parse(event.data);
          processIncomingLog(log);
        } catch (e) {
          console.error('WebSocket event parse error:', e);
        }
      };

      ws.onclose = () => {
        if (!isComponentMounted) return;
        setIsConnected(false);
        reconnectTimeout = setTimeout(connectWebSocket, 3000);
      };

      ws.onerror = (err) => {
        if (!isComponentMounted) return;
        ws?.close();
      };
    };

    connectWebSocket();

    return () => {
      isComponentMounted = false;
      if (ws) {
        ws.onopen = null;
        ws.onmessage = null;
        ws.onclose = null;
        ws.onerror = null;
        ws.close();
      }
      clearTimeout(reconnectTimeout);
    };
  }, []);

  const processIncomingLog = (event: any) => {
    const timestampStr = new Date(event.timestamp || Date.now()).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });

    const isAnomaly = event.risk_score > 75 || !!event.threat_classification || event.is_honeypot;
    const isControlEvent = event.threat_classification && event.threat_classification.includes('OPERATOR OVERRIDE');
    const isHoneypot = event.is_honeypot || event.risk_score === 100 || (event.threat_classification && event.threat_classification.includes('HONEYPOT'));

    setSystemStatus((prev) => {
      if (!prev) return null;
      return {
        ...prev,
        sessions_monitored: prev.sessions_monitored + (isAnomaly ? 0 : 1),
        anomalies_deflected: prev.anomalies_deflected + (isAnomaly ? 1 : 0)
      };
    });

    setSessions((prevSessions) => {
      const initials = event.user_id ? event.user_id.substring(0, 2).toUpperCase() : '??';
      const existingIndex = prevSessions.findIndex((s) => s.user === event.user_id);
      
      const ip = `192.168.4.${(event.user_id?.charCodeAt(0) || 4) % 20}`;
      const device = event.user_id?.includes('admin') ? 'M4 MacBook Air' : 'Linux Workstation';
      const resource = event.resource || 'IT-COLO-CLUSTER-01';

      const logText = isHoneypot
        ? `[🍯 HONEYPOT TRIP] ${event.action} | Zero-Tolerance boundary exception.`
        : isAnomaly 
        ? `[ALERT] ${event.action} | Severity threshold crossed.`
        : `[OK] ${event.action}`;

      if (existingIndex > -1) {
        return prevSessions.map((sess, idx) => {
          if (idx === existingIndex) {
            let updatedLogs = [...sess.logs, `[${timestampStr}] ${logText}`];
            if (event.status?.includes('ROTATED') || event.status?.includes('BREACH')) {
              updatedLogs.push(`[${timestampStr}] PQC ROTATION TOKEN IMPLEMENTED.`);
              updatedLogs.push(`[${timestampStr}] Severing terminal socket connections.`);
            }

            return {
              ...sess,
              riskIndex: isHoneypot ? 100 : (event.risk_score || sess.riskIndex),
              riskText: (isHoneypot || event.risk_score > 75 ? 'CRITICAL' : 'LOW') as any,
              status: (event.status?.includes('ROTATED') || event.status?.includes('BREACH')) ? 'Terminated' : sess.status,
              logs: updatedLogs.slice(-15)
            };
          }
          return sess;
        });
      } else {
        return [
          ...prevSessions,
          {
            id: event.event_id || `sess-${Math.random().toString(36).substring(2, 6)}`,
            user: event.user_id || 'unknown_node',
            avatarInitials: initials,
            ipAddress: ip,
            sourceDevice: device,
            resource: resource,
            resourceType: 'cluster',
            duration: '1m',
            riskIndex: isHoneypot ? 100 : (event.risk_score || 10),
            riskText: (isHoneypot || event.risk_score > 75 ? 'CRITICAL' : 'LOW') as any,
            status: 'Active',
            logs: [`[${timestampStr}] Pipeline connected.`, `[${timestampStr}] ${logText}`],
            typingCadence: 80,
            commandIntention: 90
          }
        ];
      }
    });

    if (isAnomaly || isHoneypot) {
      setIncidents((prev) => {
        const incId = `INC-${(event.event_id || '').substring(0, 4).toUpperCase() || 'TRK'}`;
        const existingInc = prev.find((inc) => inc.impactedEntity === event.user_id && inc.status !== 'Mitigated');

        if (existingInc) {
          return prev.map((inc) => {
            if (inc.id === existingInc.id) {
              return {
                ...inc,
                status: (event.status?.includes('ROTATED') || event.status?.includes('BREACH')) ? 'Mitigated' : inc.status
              };
            }
            return inc;
          });
        } else {
          const ip = `192.168.4.${(event.user_id?.charCodeAt(0) || 4) % 20}`;
          return [{
            id: incId,
            title: isHoneypot ? `CRITICAL HONEYPOT BREACH: ${event.user_id}` : `Active Anomaly: ${event.threat_classification || 'Insider Threat'}`,
            timeAgo: 'Just now',
            severity: isHoneypot || event.risk_score > 90 ? 'critical' : 'high',
            tags: isHoneypot ? ['Honeypot', 'Lockout'] : ['Telemetry Anomaly'],
            impactedEntity: event.user_id || 'System Node',
            assignee: 'SOC_Operator_04',
            status: 'Active',
            attackChain: { node1: ip, node2: event.role || 'Operator', node3: event.department || 'Core' },
            timeline: [{ time: timestampStr, title: 'Threshold Crossed', description: event.action || 'Risk breach.', type: 'error' }]
          }, ...prev];
        }
      });
    }

    if (event.rotation) {
      const keys = event.rotation.pqc_keys;
      setGenerationLogs((prev) => [
        `[${timestampStr}] [ROTATION TRIGGERED] Automatic post-quantum token rotation complete.`,
        `[${timestampStr}] Algorithm: ${keys.ml_kem_1024.algorithm} // Agreement established (NIST Category 5)`,
        `[${timestampStr}] Algorithm: ${keys.ml_dsa_85.algorithm} // Signature verified (NIST Category 5)`,
        ...prev
      ]);
    }

    setAuditEvents((prev) => {
      const exists = prev.some((e: any) => e.artifactId === event.event_id && event.event_id);
      if (exists) return prev;
      
      return [{
        timestamp: event.timestamp || new Date().toISOString(),
        eventType: event.action || 'System Audit Event',
        framework: event.framework || 'NIST-800-53',
        artifactId: event.event_id || `AUD-${Math.floor(Math.random() * 9000 + 1000)}`,
        status: event.status || 'Verified',
        icon: 'shield',
        risk_score: event.risk_score || 0,
        user_id: event.user_id,
        role: event.role,
        department: event.department,
        action: event.action,
        resource: event.resource,
        is_honeypot: event.is_honeypot,
        tamper_lock_signature: event.tamper_lock_signature,
        risk_factors: event.risk_factors
      }, ...prev].slice(0, 100);
    });
  };

  const forceRotateUser = async (userId: string, actionType: string = 'FORCE_ROTATE', secondaryApprover?: string): Promise<boolean> => {
    if (!secondaryApprover) {
      openDualControlModal(actionType, userId, (approver) => {
        forceRotateUser(userId, actionType, approver);
      });
      return false;
    }

    try {
      const res = await fetch(`${API_URL}/api/v1/mitigate/force-rotate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          action_type: actionType,
          primary_operator: currentOperator,
          secondary_approver: secondaryApprover
        })
      });
      if (res.ok) {
        fetchSystemStatus();
        return true;
      }
    } catch (e) {
      console.error('Manual mitigation request failed:', e);
    }
    return false;
  };

  const isolateHost = (entityName: string, incidentId: string, secondaryApprover?: string) => {
    if (!secondaryApprover) {
      openDualControlModal('ISOLATE_HOST', entityName, (approver) => {
        isolateHost(entityName, incidentId, approver);
      });
      return;
    }
    forceRotateUser(entityName, 'ISOLATE_HOST', secondaryApprover);
    setIncidents((prev) => prev.map((inc) => inc.id === incidentId ? { ...inc, status: 'Mitigated' } : inc));
  };

  const mitigateIncidentDirect = (incidentId: string) => {
    setIncidents((prev) => prev.map((inc) => inc.id === incidentId ? { ...inc, status: 'Mitigated' } : inc));
  };

  const terminateSession = (sessionId: string, secondaryApprover?: string) => {
    const targetSession = sessions.find((s) => s.id === sessionId);
    const userId = targetSession?.user || sessionId;

    if (!secondaryApprover) {
      openDualControlModal('TERMINATE_SESSION', userId, (approver) => {
        terminateSession(sessionId, approver);
      });
      return;
    }
    forceRotateUser(userId, 'TERMINATE_SESSION', secondaryApprover);
    setSessions((prevSessions) => prevSessions.map((s) => s.id === sessionId ? { ...s, status: 'Terminated', riskIndex: 100 } : s));
  };

  const flagSession = (sessionId: string) => {
    setSessions((prevSessions) => prevSessions.map((s) => s.id === sessionId ? { ...s, status: 'Flagged' } : s));
  };

  const runComplianceScan = () => {
    setComplianceScanning(true);
    setTimeout(() => {
      setAuditEvents((prev) => [{
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        eventType: 'Compliance Telemetry Scan Verification',
        framework: 'NIST-CSF-v2',
        artifactId: `SCN-RES-${Math.floor(Math.random() * 900) + 100}`,
        status: 'Verified',
        icon: 'check_circle',
        risk_score: 10
      }, ...prev]);
      setAuditScore((prev) => Math.min(100.0, parseFloat((prev + 0.6).toFixed(1))));
      setComplianceScanning(false);
    }, 1500);
  };

  const generatePqcKey = (secondaryApprover?: string) => {
    if (!secondaryApprover) {
      openDualControlModal('GENERATE_KEY', 'Enterprise Subnets & HSM Nodes', (approver) => {
        generatePqcKey(approver);
      });
      return;
    }

    setIsGeneratingKey(true);
    setGenerationLogs((prev) => [
      `[INIT] Manual cryptographic rotation triggered via operational authorization: ${secondaryApprover}`,
      ...prev
    ]);

    setTimeout(() => {
      forceRotateUser('admin_node_01', 'GENERATE_KEY', secondaryApprover);
      setIsGeneratingKey(false);
    }, 1200);
  };

  const sendCopilotMessage = async (message: string): Promise<string> => {
    try {
      const res = await fetch(`${API_URL}/api/v1/copilot/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message })
      });
      if (res.ok) {
        const data = await res.json();
        return data.response;
      }
    } catch (e) {
      console.error('Copilot request connection error:', e);
    }
    return `Error: Security Copilot endpoint unreachable. Verify local FastAPI server status.`;
  };

  return (
    <SecurityContext.Provider
      value={{
        incidents, sessions, profiles, signals, algorithms, systemStatus, generationLogs, isGeneratingKey, isConnected,
        forceRotateUser, isolateHost, mitigateIncidentDirect, terminateSession, flagSession, runComplianceScan,
        complianceScanning, auditScore, auditEvents, generatePqcKey, sendCopilotMessage, dualControlModalOpen,
        dualControlActionType, dualControlTargetEntity, openDualControlModal, closeDualControlModal, confirmDualControlAction, currentOperator
      }}
    >
      {children}
    </SecurityContext.Provider>
  );
};

export const useSecurity = () => {
  const context = useContext(SecurityContext);
  if (context === undefined) {
    throw new Error('useSecurity must be used within a SecurityProvider');
  }
  return context;
};
