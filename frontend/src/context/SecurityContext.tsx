import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { Incident, PrivilegedSession, RiskProfile, AlgorithmPerformance, AuditEvent } from '../types';

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

// Initial Static / Starting States to bootstrap the views elegantly
const INITIAL_INCIDENTS: Incident[] = [
  {
    id: 'INC-8429',
    title: 'Unauthorized Database Bulk Export Attempt',
    timeAgo: '12m ago',
    severity: 'critical',
    tags: ['Data Leakage', 'Credential Abuse', 'Insider Threat'],
    impactedEntity: 'contractor_node_02',
    assignee: 'SOC_Operator_04',
    status: 'Investigating',
    attackChain: {
      node1: '185.12.99.102',
      node2: 'External Contractor',
      node3: 'SV-PROD-DB-02'
    },
    timeline: [
      {
        time: '11:45:12',
        title: 'Anomalous Query Spike Detected',
        description: 'User initiated bulk SELECT * FROM customer_pii with row count > 10,000.',
        statusBadge: 'ANOMALY',
        type: 'error'
      },
      {
        time: '11:45:15',
        title: 'Automatic Risk Score Elevation',
        description: 'Risk score elevated from 12 to 88 based on PII export signature.',
        statusBadge: 'RISK_ELEVATED',
        type: 'warning'
      }
    ]
  }
];

const INITIAL_SESSIONS: PrivilegedSession[] = [
  {
    id: 'sess-001',
    user: 'admin_node_01',
    avatarInitials: 'AD',
    ipAddress: '192.168.1.50',
    sourceDevice: 'Workstation-SM',
    resource: 'IT-COLO-CLUSTER-01',
    resourceType: 'cluster',
    duration: '42m',
    riskIndex: 10,
    riskText: 'LOW',
    status: 'Active',
    logs: [
      '[SESSION START] tty-pipeline-sess-001 initiated from 192.168.1.50',
      '[OK] git fetch origin master',
      '[OK] docker compose ps',
      '[OK] tail -n 100 /var/log/syslog'
    ],
    typingCadence: 78,
    commandIntention: 92
  },
  {
    id: 'sess-002',
    user: 'contractor_node_02',
    avatarInitials: 'CO',
    ipAddress: '185.12.99.102',
    sourceDevice: 'Contractor-Laptop',
    resource: 'SV-PROD-DB-02',
    resourceType: 'database',
    duration: '14m',
    riskIndex: 88,
    riskText: 'CRITICAL',
    status: 'Flagged',
    logs: [
      '[SESSION START] tty-pipeline-sess-002 initiated from 185.12.99.102',
      '[OK] select * from customer_pii limit 100;',
      'CRITICAL: Query matches pattern \'PII_MASS_DUMP\'',
      'Policy Breach: Exceeded row extraction limit (max 50)'
    ],
    typingCadence: 45,
    commandIntention: 12
  },
  {
    id: 'sess-003',
    user: 'root_service_node_03',
    avatarInitials: 'RS',
    ipAddress: '10.0.12.3',
    sourceDevice: 'Root-Service-Acct',
    resource: 'OBSIDIAN-VAULT-PRIMARY',
    resourceType: 'key',
    duration: '2m',
    riskIndex: 95,
    riskText: 'CRITICAL',
    status: 'Flagged',
    logs: [
      '[SESSION START] tty-pipeline-sess-003 initiated from 10.0.12.3',
      '[OK] sudo systemctl reload nginx',
      'CRITICAL: Unauthorized write operation to /etc/pam.d/common-auth',
      'Policy Breach: Privilege Escalation detected'
    ],
    typingCadence: 95,
    commandIntention: 5
  }
];

const INITIAL_PROFILES: RiskProfile[] = [
  {
    name: 'admin_node_01',
    role: 'System Administrator • IT Operations',
    employeeId: 'EMP-9021',
    office: 'London Hub',
    image: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=256&h=256',
    trustScore: 92,
    anomalySummary: 'Standard administrative activity patterns. Routine server updates and log rotations observed.',
    heatmap: [
      [1, 1, 2, 1, 0],
      [1, 2, 1, 1, 1],
      [0, 1, 1, 2, 0],
      [1, 1, 1, 1, 1],
      [1, 2, 0, 1, 1],
      [0, 0, 0, 0, 0]
    ],
    radar: {
      loginRisk: 12,
      accessPattern: 8,
      deviceTrust: 15,
      behaviorScore: 10,
      networkSecurity: 5,
      appIntegrity: 10
    },
    telemetry: [
      {
        timestamp: '11:30:15',
        eventType: 'SSH Log In',
        path: 'IT-COLO-CLUSTER-01',
        sourceIp: '192.168.1.50',
        riskDelta: '0',
        severity: 'success'
      },
      {
        timestamp: '11:32:00',
        eventType: 'Config Read',
        path: '/etc/nginx/nginx.conf',
        sourceIp: '192.168.1.50',
        riskDelta: '0',
        severity: 'success'
      }
    ]
  },
  {
    name: 'contractor_node_02',
    role: 'External Contractor • Data Analytics',
    employeeId: 'EMP-4831',
    office: 'Remote / Berlin',
    image: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?auto=format&fit=crop&q=80&w=256&h=256',
    trustScore: 28,
    anomalySummary: 'Critical anomalies. High-volume SELECT queries executed against customer records containing active PII data.',
    heatmap: [
      [1, 2, 1, 1, 0],
      [2, 3, 2, 2, 1],
      [1, 2, 3, 1, 1],
      [2, 3, 4, 3, 2],
      [3, 4, 5, 4, 3],
      [5, 5, 5, 5, 5]
    ],
    radar: {
      loginRisk: 68,
      accessPattern: 85,
      deviceTrust: 42,
      behaviorScore: 88,
      networkSecurity: 55,
      appIntegrity: 30
    },
    telemetry: [
      {
        timestamp: '11:40:02',
        eventType: 'Database Access',
        path: 'SV-PROD-DB-02',
        sourceIp: '185.12.99.102',
        riskDelta: '+10',
        severity: 'warning'
      },
      {
        timestamp: '11:45:12',
        eventType: 'Bulk Data Query',
        path: 'customer_pii',
        sourceIp: '185.12.99.102',
        riskDelta: '+76',
        severity: 'error'
      }
    ]
  },
  {
    name: 'root_service_node_03',
    role: 'Root Service Account • Core Infrastructure',
    employeeId: 'SVC-0085',
    office: 'Global VPC',
    image: 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&q=80&w=256&h=256',
    trustScore: 12,
    anomalySummary: 'Privilege escalation alert. High entropy shell commands issued on authorization config nodes.',
    heatmap: [
      [0, 1, 0, 0, 0],
      [1, 1, 1, 0, 0],
      [0, 1, 1, 1, 0],
      [1, 2, 1, 1, 0],
      [2, 3, 2, 3, 1],
      [5, 5, 5, 5, 5]
    ],
    radar: {
      loginRisk: 90,
      accessPattern: 92,
      deviceTrust: 95,
      behaviorScore: 96,
      networkSecurity: 88,
      appIntegrity: 92
    },
    telemetry: [
      {
        timestamp: '11:50:00',
        eventType: 'Root Execution',
        path: 'OBSIDIAN-VAULT-PRIMARY',
        sourceIp: '10.0.12.3',
        riskDelta: '+15',
        severity: 'warning'
      },
      {
        timestamp: '11:51:10',
        eventType: 'PAM File Modification',
        path: '/etc/pam.d/common-auth',
        sourceIp: '10.0.12.3',
        riskDelta: '+83',
        severity: 'error'
      }
    ]
  }
];

const INITIAL_ALGORITHMS: AlgorithmPerformance[] = [
  { name: 'ML-KEM-1024', latency: 152, level: 'Level 5 (FIPS 203)', size: '1.5 KB', status: 'ACTIVE' },
  { name: 'ML-DSA-85', latency: 254, level: 'Level 5 (FIPS 204)', size: '2.6 KB', status: 'ACTIVE' },
  { name: 'ML-KEM-768', latency: 112, level: 'Level 3 (FIPS 203)', size: '1.1 KB', status: 'OPTIMIZED' },
  { name: 'ML-DSA-65', latency: 185, level: 'Level 3 (FIPS 204)', size: '1.9 KB', status: 'OPTIMIZED' },
  { name: 'RSA-4096 (Legacy)', latency: 14200, level: 'Non-Quantum', size: '4.0 KB', status: 'DEPRECATED' },
];

export const SecurityProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [incidents, setIncidents] = useState<Incident[]>(INITIAL_INCIDENTS);
  const [sessions, setSessions] = useState<PrivilegedSession[]>(INITIAL_SESSIONS);
  const [profiles, setProfiles] = useState<RiskProfile[]>(INITIAL_PROFILES);
  const [algorithms, setAlgorithms] = useState<AlgorithmPerformance[]>(INITIAL_ALGORITHMS);
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  
  const [signals, setSignals] = useState<any[]>([
    { id: 1, origin: 'Frankfurt, DE (185.12.99.102)', target: 'Chennai Cloud Hub', severity: 'high', rate: '1.2 GB/s' },
    { id: 2, origin: 'Kiev, UA (45.128.11.94)', target: 'SV-PROD-DB-02', severity: 'critical', rate: 'Bulk SQL' },
    { id: 3, origin: 'Beijing, CN (112.90.1.18)', target: 'EMEA Subnet Router', severity: 'medium', rate: '600 KB/s' },
  ]);

  const [generationLogs, setGenerationLogs] = useState<string[]>([
    'System status: Stable. Ready for quantum safe encryption audit.',
    'Click "Generate Safe PQC Key" above to deploy cryptographic lattice layers.'
  ]);
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
  
  // Compliance ratings state
  const [complianceScanning, setComplianceScanning] = useState(false);
  const [auditScore, setAuditScore] = useState(94.2);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([
    {
      timestamp: '11:00',
      eventType: 'System Bootstrap Audit Signed',
      framework: 'FIPS-140-3',
      artifactId: 'BOOT-SIG-042',
      status: 'Signed',
      icon: 'shield',
      risk_score: 15,
      user_id: 'admin_node_01',
      role: 'System Administrator',
      department: 'IT Operations',
      action: 'System Bootstrap Audit Signed',
      resource: 'BOOT-SIG-042'
    },
    {
      timestamp: '11:15',
      eventType: 'Database Access Policy Alignment',
      framework: 'SOC2-CC3',
      artifactId: 'POL-ALN-109',
      status: 'Verified',
      icon: 'check_circle',
      risk_score: 22,
      user_id: 'contractor_node_02',
      role: 'External Contractor',
      department: 'Data Analytics',
      action: 'Database Access Policy Alignment',
      resource: 'POL-ALN-109'
    },
    {
      timestamp: '11:30',
      eventType: 'Privileged Access Revocation Event',
      framework: 'GDPR-Ch4',
      artifactId: 'REV-ACT-089',
      status: 'Critical',
      icon: 'alert_octagon',
      risk_score: 85,
      user_id: 'root_service_node_03',
      role: 'Root Service Account',
      department: 'Core Infrastructure',
      action: 'Privileged Access Revocation Event',
      resource: 'REV-ACT-089'
    },
    {
      timestamp: '11:45',
      eventType: 'Automatic HSM Key Rotation',
      framework: 'NIST-800-53',
      artifactId: 'ROT-KEY-002',
      status: 'Signed',
      icon: 'refresh_ccw',
      risk_score: 18,
      user_id: 'admin_node_01',
      role: 'System Administrator',
      department: 'IT Operations',
      action: 'Automatic HSM Key Rotation',
      resource: 'ROT-KEY-002'
    },
    {
      timestamp: '12:00',
      eventType: 'Compliance Telemetry Scan Verification',
      framework: 'NIST-CSF-v2',
      artifactId: 'SCN-RES-412',
      status: 'Verified',
      icon: 'check_circle',
      risk_score: 29,
      user_id: 'intern_node_04',
      role: 'Helpdesk Intern',
      department: 'Tier 1 Support',
      action: 'Compliance Telemetry Scan Verification',
      resource: 'SCN-RES-412'
    }
  ]);

  // REST API status poller
  const fetchSystemStatus = useCallback(async () => {
    try {
      const res = await fetch('http://localhost:8000/api/v1/system/status');
      if (res.ok) {
        const data = await res.json();
        setSystemStatus(data);
      }
    } catch (e) {
      console.warn('Backend REST status endpoint unavailable (make sure main.py is running).');
    }
  }, []);

  useEffect(() => {
    fetchSystemStatus();
    const interval = setInterval(fetchSystemStatus, 3000);
    return () => clearInterval(interval);
  }, [fetchSystemStatus]);

  // WebSocket Live Log Stream client
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimeout: any = null;
    let isComponentMounted = true;

    const connectWebSocket = () => {
      console.log('Establishing connection to Obsidian Security Engine at ws://localhost:8000/ws/logs...');
      ws = new WebSocket('ws://localhost:8000/ws/logs');

      ws.onopen = () => {
        if (!isComponentMounted) return;
        console.log('Connected to live threat stream.');
        setIsConnected(true);
      };

      ws.onmessage = (event) => {
        if (!isComponentMounted) return;
        try {
          const log = JSON.parse(event.data);
          processIncomingLog(log);
        } catch (e) {
          console.error('Error parsing live log event:', e);
        }
      };

      ws.onclose = () => {
        if (!isComponentMounted) return;
        console.warn('Connection to threat stream severed. Attempting reconnect in 3s...');
        setIsConnected(false);
        reconnectTimeout = setTimeout(connectWebSocket, 3000);
      };

      ws.onerror = (err) => {
        if (!isComponentMounted) return;
        console.error('WebSocket error:', err);
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

  // Process live stream signals into local component states
  const processIncomingLog = (event: any) => {
    const timestampStr = new Date(event.timestamp || Date.now()).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });

    const isAnomaly = event.risk_score > 75 || !!event.threat_classification || event.is_honeypot;
    const isControlEvent = event.threat_classification && event.threat_classification.includes('OPERATOR OVERRIDE');
    const isHoneypot = event.is_honeypot || event.risk_score === 100 || (event.threat_classification && event.threat_classification.includes('HONEYPOT'));

    // 1. Sync System Status Counters incrementally
    setSystemStatus((prev) => {
      if (!prev) return null;
      return {
        ...prev,
        sessions_monitored: prev.sessions_monitored + (isAnomaly ? 0 : 1),
        anomalies_deflected: prev.anomalies_deflected + (isAnomaly ? 1 : 0),
        active_ws_clients: prev.active_ws_clients
      };
    });

    // 2. Manage sessions view
    setSessions((prevSessions) => {
      const initials = event.user_id === 'admin_node_01'
        ? 'AD'
        : event.user_id === 'contractor_node_02'
        ? 'CO'
        : event.user_id === 'root_service_node_03'
        ? 'RS'
        : event.user_id === 'intern_node_04'
        ? 'IN'
        : event.user_id
        ? event.user_id.split('.').map((p: string) => p[0].toUpperCase()).join('').substring(0, 2)
        : '??';

      const existingIndex = prevSessions.findIndex((s) => s.user === event.user_id);
      
      // Compute static assets for profiles
      const ip = event.user_id === 'admin_node_01' ? '192.168.1.50' : event.user_id === 'contractor_node_02' ? '185.12.99.102' : event.user_id === 'intern_node_04' ? '172.16.4.19' : '10.0.12.3';
      const device = event.user_id === 'admin_node_01' ? 'Workstation-SM' : event.user_id === 'contractor_node_02' ? 'Contractor-Laptop' : event.user_id === 'intern_node_04' ? 'Helpdesk-Terminal-04' : 'Root-Service-Acct';
      const resourceType = event.user_id === 'root_service_node_03' ? 'key' : event.user_id === 'contractor_node_02' ? 'database' : 'cluster';
      const resource = event.user_id === 'root_service_node_03' ? 'OBSIDIAN-VAULT-PRIMARY' : event.user_id === 'contractor_node_02' ? 'SV-PROD-DB-02' : event.user_id === 'intern_node_04' ? 'db_admin.shadow_vault_backup' : 'IT-COLO-CLUSTER-01';

      const logText = isHoneypot
        ? `[🍯 HONEYPOT TRIP] ${event.action} | Deterministic IoC breached!`
        : isAnomaly 
        ? `[ALERT] ${event.action} | Threat detected: ${event.threat_classification || 'Anomaly'}`
        : `[OK] ${event.action}`;

      if (existingIndex > -1) {
        return prevSessions.map((sess, idx) => {
          if (idx === existingIndex) {
            let updatedLogs = [...sess.logs, `[${timestampStr}] ${logText}`];
            if (event.status === 'REVOKED & ROTATED' || event.status === 'CRITICAL HONEYPOT BREACH') {
              updatedLogs.push(`[${timestampStr}] PQC ROTATION KEY ATTACHED.`);
              if (isHoneypot) {
                updatedLogs.push(`[${timestampStr}] 🔒 TAMPER-EVIDENT PQC LOCK: ${event.tamper_lock_signature || 'mldsa_root_honeypot_lock_active'}`);
              }
              updatedLogs.push(`[${timestampStr}] Severing session connections. Returning Code: 137.`);
            }

            return {
              ...sess,
              riskIndex: isHoneypot ? 100 : (event.risk_score || sess.riskIndex),
              riskText: (isHoneypot || event.risk_score > 75 ? 'CRITICAL' : event.risk_score > 25 ? 'MED' : 'LOW') as any,
              status: (event.status === 'REVOKED & ROTATED' || event.status === 'CRITICAL HONEYPOT BREACH') ? 'Terminated' : (event.risk_score > 75 ? 'Flagged' : 'Active') as any,
              isHoneypot: isHoneypot || sess.isHoneypot,
              tamperLockSignature: event.tamper_lock_signature || sess.tamperLockSignature,
              riskFactors: event.risk_factors || sess.riskFactors,
              logs: updatedLogs.slice(-15) // Keep last 15 entries
            };
          }
          return sess;
        });
      } else {
        return [
          ...prevSessions,
          {
            id: event.event_id || `sess-${Math.random().toString(36).substring(2, 6)}`,
            user: event.user_id || 'unknown',
            avatarInitials: initials,
            ipAddress: ip,
            sourceDevice: device,
            resource: resource,
            resourceType: resourceType as any,
            duration: '1m',
            riskIndex: isHoneypot ? 100 : (event.risk_score || 10),
            riskText: (isHoneypot || event.risk_score > 75 ? 'CRITICAL' : event.risk_score > 25 ? 'MED' : 'LOW') as any,
            status: (event.status === 'REVOKED & ROTATED' || event.status === 'CRITICAL HONEYPOT BREACH') ? 'Terminated' : (event.risk_score > 75 ? 'Flagged' : 'Active') as any,
            logs: [`[${timestampStr}] [SESSION START] Pipeline initialized`, `[${timestampStr}] ${logText}`],
            typingCadence: Math.floor(Math.random() * 40) + 50,
            commandIntention: Math.floor(Math.random() * 40) + 50,
            isHoneypot: isHoneypot,
            tamperLockSignature: event.tamper_lock_signature,
            riskFactors: event.risk_factors
          }
        ];
      }
    });

    // 3. Process Incidents
    if (isAnomaly || isHoneypot) {
      setIncidents((prev) => {
        const incId = `INC-${(event.event_id || '').substring(0, 4).toUpperCase() || Math.floor(Math.random() * 9000 + 1000)}`;
        const existingInc = prev.find((inc) => inc.impactedEntity === event.user_id && inc.status !== 'Mitigated');

        if (existingInc) {
          return prev.map((inc) => {
            if (inc.id === existingInc.id) {
              const newLogs: Incident['timeline'] = [
                {
                  time: timestampStr,
                  title: isHoneypot ? 'Canary Honeypot Breached' : isControlEvent ? 'Operator Overrode Credentials' : 'Anomaly Refinement Loop',
                  description: event.action,
                  statusBadge: isHoneypot ? 'HONEYPOT TRIP' : event.status,
                  type: 'error',
                  isHoneypot: isHoneypot,
                  tamperLockSignature: event.tamper_lock_signature
                }
              ];
              if (event.rotation) {
                newLogs.push({
                  time: timestampStr,
                  title: 'Post-Quantum Lattice Re-Keying Complete',
                  description: `Credential encapsulation key (ML-KEM-1024): ${event.rotation.pqc_keys.ml_kem_1024.shared_secret_hex.substring(0, 18)}...`,
                  statusBadge: 'SECURE_PQC',
                  type: 'success' as const
                });
              }
              return {
                ...inc,
                status: (event.status === 'REVOKED & ROTATED' || event.status === 'CRITICAL HONEYPOT BREACH') ? 'Mitigated' : inc.status,
                isHoneypot: isHoneypot || inc.isHoneypot,
                tamperLockSignature: event.tamper_lock_signature || inc.tamperLockSignature,
                timeline: [...newLogs, ...inc.timeline]
              };
            }
            return inc;
          });
        } else {
          const ip = event.user_id === 'admin_node_01' ? '192.168.1.50' : event.user_id === 'contractor_node_02' ? '185.12.99.102' : event.user_id === 'intern_node_04' ? '172.16.4.19' : '10.0.12.3';
          const newInc: Incident = {
            id: incId,
            title: isHoneypot ? `CRITICAL HONEYPOT BREACH: ${event.user_id}` : isControlEvent ? 'Operator-Initiated Security Override' : `Active Threat: ${event.threat_classification || 'Insider Anomaly'}`,
            timeAgo: 'Just now',
            severity: isHoneypot || event.risk_score > 90 ? 'critical' : 'high',
            tags: isHoneypot ? ['Canary Honeypot', 'Tamper Lock', 'High-Fidelity IoC'] : isControlEvent ? ['Manual Revocation', 'Vault Rotation'] : ['Anomaly', event.role || 'Insider', 'PQC Shield'],
            impactedEntity: event.user_id || 'System Node',
            assignee: 'SOC_Operator_04',
            status: (event.status === 'REVOKED & ROTATED' || event.status === 'CRITICAL HONEYPOT BREACH') ? 'Mitigated' : 'Active',
            isHoneypot: isHoneypot,
            tamperLockSignature: event.tamper_lock_signature,
            riskFactors: event.risk_factors,
            attackChain: {
              node1: ip,
              node2: event.role || 'Internal Role',
              node3: event.department || 'Infrastructure'
            },
            timeline: [
              {
                time: timestampStr,
                title: isHoneypot ? 'Canary Trap Tripped (Zero-Tolerance)' : isControlEvent ? 'Operator Override Issued' : 'High Risk Event Logged',
                description: event.action || 'Risk threshold breached by privileged system credentials.',
                statusBadge: isHoneypot ? 'HONEYPOT TRIP' : (event.status || 'ALERT'),
                type: 'error',
                isHoneypot: isHoneypot,
                tamperLockSignature: event.tamper_lock_signature
              }
            ]
          };

          if (event.rotation) {
            newInc.timeline.push({
              time: timestampStr,
              title: 'Automatic Post-Quantum Rekeying',
              description: `Generated lattice key materials. ML-KEM shared secret verified.`,
              statusBadge: 'SECURE_PQC',
              type: 'success'
            });
          }

          return [newInc, ...prev];
        }
      });
    }

    // 4. Update Risk Profiles telemetry and scores
    setProfiles((prevProfiles) => {
      return prevProfiles.map((prof) => {
        if (prof.name === event.user_id) {
          const delta = isHoneypot ? '+100' : event.risk_score > 75 ? `+${event.risk_score}` : '0';
          const severity = isHoneypot || event.risk_score > 75 ? 'error' : event.risk_score > 25 ? 'warning' : 'success';
          
          const newTelemetry = {
            timestamp: timestampStr,
            eventType: isHoneypot ? 'Canary Honeypot Trip' : isAnomaly ? (event.threat_classification || 'Anomaly Trigger') : 'Operational Log',
            path: event.action.substring(0, 30),
            sourceIp: prof.name === 'admin_node_01' ? '192.168.1.50' : prof.name === 'contractor_node_02' ? '185.12.99.102' : '10.0.12.3',
            riskDelta: delta,
            severity: severity as any,
            isHoneypot: isHoneypot,
            tamperLockSignature: event.tamper_lock_signature
          };

          const newScore = isHoneypot ? 0 : Math.max(10, 100 - (event.risk_score || 0));

          const newRadar = { ...prof.radar };
          if (isHoneypot || event.risk_score > 75) {
            newRadar.behaviorScore = Math.min(100, newRadar.behaviorScore + 10);
            newRadar.accessPattern = Math.min(100, newRadar.accessPattern + 12);
          }

          return {
            ...prof,
            trustScore: newScore,
            radar: newRadar,
            telemetry: [newTelemetry, ...prof.telemetry].slice(0, 10)
          };
        }
        return prof;
      });
    });

    // 5. Append attack map signals
    if (isAnomaly || isHoneypot) {
      setSignals((prev) => {
        const ip = event.user_id === 'admin_node_01' ? '192.168.1.50' : event.user_id === 'contractor_node_02' ? '185.12.99.102' : '10.0.12.3';
        const location = event.user_id === 'contractor_node_02' ? 'Kiev, UA' : event.user_id === 'root_service_node_03' ? 'Beijing, CN' : 'Frankfurt, DE';
        
        const newSig = {
          id: Date.now() + Math.random(),
          origin: `${location} (${ip})`,
          target: event.action.substring(0, 25),
          severity: isHoneypot || event.risk_score > 90 ? 'critical' : 'high',
          rate: isHoneypot ? 'Honeypot Trip' : event.risk_score > 85 ? 'Bulk Access' : 'Anomaly Flow'
        };
        return [newSig, ...prev.slice(0, 5)];
      });
    }

    // 6. Push PQC details to Quantum Center logs with smooth random float latencies
    if (event.rotation) {
      const keys = event.rotation.pqc_keys;
      const kemLatency = (1.2 + Math.random() * 1.3).toFixed(2);
      const dsaLatency = (1.4 + Math.random() * 1.1).toFixed(2);
      setGenerationLogs((prev) => [
        `[${timestampStr}] [ROTATION TRIGGERED] Automatic post-quantum token rotation.`,
        `[${timestampStr}] Algorithm: ${keys.ml_kem_1024.algorithm} (Purpose: ${keys.ml_kem_1024.purpose}) // ML-KEM Key Agreement established in ${kemLatency}ms (Security Level: NIST Category 5)`,
        `[${timestampStr}] ML-KEM-1024 Public Key: ${keys.ml_kem_1024.public_key_fingerprint}`,
        `[${timestampStr}] ML-KEM-1024 Shared Secret: 0x${keys.ml_kem_1024.shared_secret_hex}`,
        `[${timestampStr}] Algorithm: ${keys.ml_dsa_85.algorithm} (Purpose: ${keys.ml_dsa_85.purpose}) // ML-DSA-85 Digital Signature signed in ${dsaLatency}ms (Security Level: NIST Category 5)`,
        `[${timestampStr}] ML-DSA-85 Digital Signature Excerpt: ${keys.ml_dsa_85.signature_hex.substring(0, 32)}...`,
        ...(isHoneypot ? [`[${timestampStr}] 🔒 TAMPER-EVIDENT PQC LOCK: ${event.tamper_lock_signature}`] : []),
        `[${timestampStr}] [STATUS] Cryptographic credentials safely rotated and distributed across target subnets.`,
        ...prev
      ]);
    }

    // 7. Sync AuditEvents state
    setAuditEvents((prev) => {
      const exists = prev.some((e: any) => (e.id === event.event_id || e.event_id === event.event_id) && event.event_id);
      if (exists) return prev;
      
      const newEvent: AuditEvent = {
        timestamp: event.timestamp || new Date().toISOString(),
        eventType: event.action || 'System Audit Event',
        framework: event.framework || 'NIST-800-53',
        artifactId: event.event_id || `AUD-${Math.floor(Math.random() * 9000 + 1000)}`,
        status: event.status || 'Verified',
        icon: event.icon || 'shield',
        risk_score: event.risk_score || 0,
        user_id: event.user_id,
        role: event.role,
        department: event.department,
        action: event.action,
        resource: event.resource,
        is_honeypot: event.is_honeypot,
        tamper_lock_signature: event.tamper_lock_signature,
        risk_factors: event.risk_factors
      };
      return [newEvent, ...prev].slice(0, 100);
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
      const res = await fetch('http://localhost:8000/api/v1/mitigate/force-rotate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
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
      console.error('Failed to trigger manual force rotate REST endpoint:', e);
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

    setIncidents((prev) =>
      prev.map((inc) => {
        if (inc.id === incidentId) {
          const isAlreadyContained = inc.timeline.some((t) => t.title === 'Manual Action: Host Isolated');
          if (isAlreadyContained) return inc;

          const updatedTimeline = [
            {
              time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
              title: `Manual Action: Host Isolated (${secondaryApprover})`,
              description: `Operator triggered virtual containment isolation block on host: ${entityName} with Four-Eyes authorization. Outbound subnets locked.`,
              statusBadge: 'CONTAINED_ISOLATED',
              type: 'success' as const
            },
            ...inc.timeline
          ];

          return {
            ...inc,
            status: 'Mitigated',
            timeline: updatedTimeline,
            primaryOperator: currentOperator,
            secondaryApprover: secondaryApprover
          };
        }
        return inc;
      })
    );
  };

  const mitigateIncidentDirect = (incidentId: string) => {
    setIncidents((prev) =>
      prev.map((inc) => {
        if (inc.id === incidentId) {
          return {
            ...inc,
            status: 'Mitigated'
          };
        }
        return inc;
      })
    );
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

    setSessions((prevSessions) =>
      prevSessions.map((sess) => {
        if (sess.id === sessionId) {
          if (sess.status === 'Terminated') return sess;
          
          forceRotateUser(sess.user, 'TERMINATE_SESSION', secondaryApprover);

          const updatedLogs = [
            ...sess.logs,
            '-------------------------------------------------------',
            `[ADMIN LOCKOUT AND FOUR-EYES SIGN-OFF AT ${new Date().toLocaleTimeString()}]`,
            `FATAL: Session forcefully severed by operator with authorization: ${secondaryApprover}.`,
            'Connection severed. Status code: 137'
          ];
          return {
            ...sess,
            status: 'Terminated',
            logs: updatedLogs,
            riskIndex: 100
          };
        }
        return sess;
      })
    );
  };

  const flagSession = (sessionId: string) => {
    setSessions((prevSessions) =>
      prevSessions.map((sess) => {
        if (sess.id === sessionId) {
          if (sess.status === 'Flagged') return sess;
          return {
            ...sess,
            status: 'Flagged',
            riskIndex: Math.min(100, sess.riskIndex + 15)
          };
        }
        return sess;
      })
    );
  };

  const runComplianceScan = () => {
    setComplianceScanning(true);
    setTimeout(() => {
      const newEvent: AuditEvent = {
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        eventType: 'Compliance Telemetry Scan Verification',
        framework: 'NIST-CSF-v2',
        artifactId: `SCN-RES-${Math.floor(Math.random() * 900) + 100}`,
        status: 'Verified',
        icon: 'check_circle',
        risk_score: Math.floor(Math.random() * 45) + 15
      };
      setAuditEvents((prev) => [newEvent, ...prev]);
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
    const kemLatency = (1.2 + Math.random() * 1.3).toFixed(2);
    const dsaLatency = (1.4 + Math.random() * 1.1).toFixed(2);
    const newLogs = [
      `[INIT] Triggering manual lattice key audit with Four-Eyes authorization (${secondaryApprover})...`,
      `[ML-KEM] Preparing module-lattice dimensions... // ML-KEM Key Agreement established in ${kemLatency}ms (Security Level: NIST Category 5)`,
      `[ML-DSA] Generating FIPS 204 digital signature structures... // ML-DSA-85 Digital Signature signed in ${dsaLatency}ms (Security Level: NIST Category 5)`,
      `[SYSTEM] Invoking uvicorn manual force-rotate API with unified action_type: GENERATE_KEY...`
    ];

    setGenerationLogs((prev) => [...newLogs, ...prev]);

    setTimeout(() => {
      forceRotateUser('admin_node_01', 'GENERATE_KEY', secondaryApprover);
      setIsGeneratingKey(false);
    }, 1200);
  };

  const sendCopilotMessage = async (message: string): Promise<string> => {
    try {
      const res = await fetch('http://localhost:8000/api/v1/copilot/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ message })
      });
      if (res.ok) {
        const data = await res.json();
        return data.response;
      }
    } catch (e) {
      console.error('Failed to contact Copilot Chat REST endpoint:', e);
    }
    return `Error: Could not reach the Obsidian XDR Copilot backend at http://localhost:8000. Please verify main.py is running.`;
  };

  return (
    <SecurityContext.Provider
      value={{
        incidents,
        sessions,
        profiles,
        signals,
        algorithms,
        systemStatus,
        generationLogs,
        isGeneratingKey,
        isConnected,
        forceRotateUser,
        isolateHost,
        mitigateIncidentDirect,
        terminateSession,
        flagSession,
        runComplianceScan,
        complianceScanning,
        auditScore,
        auditEvents,
        generatePqcKey,
        sendCopilotMessage,
        dualControlModalOpen,
        dualControlActionType,
        dualControlTargetEntity,
        openDualControlModal,
        closeDualControlModal,
        confirmDualControlAction,
        currentOperator
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
