import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { Incident, PrivilegedSession, RiskProfile, AlgorithmPerformance, AuditEvent } from '../types';

interface SystemStatus {
  engine: string;
  version: string;
  sessions_monitored: number;
  anomalies_deflected: number;
  vault_status: string;
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
  forceRotateUser: (userId: string) => Promise<boolean>;
  isolateHost: (entityName: string, incidentId: string) => void;
  mitigateIncidentDirect: (incidentId: string) => void;
  terminateSession: (sessionId: string) => void;
  flagSession: (sessionId: string) => void;
  runComplianceScan: () => void;
  complianceScanning: boolean;
  auditScore: number;
  auditEvents: AuditEvent[];
  generatePqcKey: () => void;
  sendCopilotMessage: (message: string) => Promise<string>;
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
    impactedEntity: 'v.patel.contractor',
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
    user: 's.murphy.admin',
    avatarInitials: 'SM',
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
    user: 'v.patel.contractor',
    avatarInitials: 'VP',
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
    user: 'compromised.root.node',
    avatarInitials: 'CR',
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
    name: 's.murphy.admin',
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
    name: 'v.patel.contractor',
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
    name: 'compromised.root.node',
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
      icon: 'shield'
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

    const connectWebSocket = () => {
      console.log('Establishing connection to Obsidian Security Engine at ws://localhost:8000/ws/logs...');
      ws = new WebSocket('ws://localhost:8000/ws/logs');

      ws.onopen = () => {
        console.log('Connected to live threat stream.');
        setIsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const log = JSON.parse(event.data);
          processIncomingLog(log);
        } catch (e) {
          console.error('Error parsing live log event:', e);
        }
      };

      ws.onclose = () => {
        console.warn('Connection to threat stream severed. Attempting reconnect in 3s...');
        setIsConnected(false);
        reconnectTimeout = setTimeout(connectWebSocket, 3000);
      };

      ws.onerror = (err) => {
        console.error('WebSocket error:', err);
        ws?.close();
      };
    };

    connectWebSocket();

    return () => {
      if (ws) ws.close();
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

    const isAnomaly = event.risk_score > 75 || !!event.threat_classification;
    const isControlEvent = event.threat_classification === 'OPERATOR OVERRIDE';

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
      const initials = event.user_id
        ? event.user_id.split('.').map((p: string) => p[0].toUpperCase()).join('').substring(0, 2)
        : '??';

      const existingIndex = prevSessions.findIndex((s) => s.user === event.user_id);
      
      // Compute static assets for profiles
      const ip = event.user_id === 's.murphy.admin' ? '192.168.1.50' : event.user_id === 'v.patel.contractor' ? '185.12.99.102' : '10.0.12.3';
      const device = event.user_id === 's.murphy.admin' ? 'Workstation-SM' : event.user_id === 'v.patel.contractor' ? 'Contractor-Laptop' : 'Root-Service-Acct';
      const resourceType = event.user_id === 'compromised.root.node' ? 'key' : event.user_id === 'v.patel.contractor' ? 'database' : 'cluster';
      const resource = event.user_id === 'compromised.root.node' ? 'OBSIDIAN-VAULT-PRIMARY' : event.user_id === 'v.patel.contractor' ? 'SV-PROD-DB-02' : 'IT-COLO-CLUSTER-01';

      const logText = isAnomaly 
        ? `[ALERT] ${event.action} | Threat detected: ${event.threat_classification || 'Anomaly'}`
        : `[OK] ${event.action}`;

      if (existingIndex > -1) {
        return prevSessions.map((sess, idx) => {
          if (idx === existingIndex) {
            let updatedLogs = [...sess.logs, `[${timestampStr}] ${logText}`];
            if (event.status === 'REVOKED & ROTATED') {
              updatedLogs.push(`[${timestampStr}] PQC ROTATION KEY ATTACHED.`);
              updatedLogs.push(`[${timestampStr}] Severing session connections. Returning Code: 137.`);
            }

            return {
              ...sess,
              riskIndex: event.risk_score || sess.riskIndex,
              riskText: (event.risk_score > 75 ? 'CRITICAL' : event.risk_score > 25 ? 'MED' : 'LOW') as any,
              status: event.status === 'REVOKED & ROTATED' ? 'Terminated' : (event.risk_score > 75 ? 'Flagged' : 'Active') as any,
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
            riskIndex: event.risk_score || 10,
            riskText: (event.risk_score > 75 ? 'CRITICAL' : event.risk_score > 25 ? 'MED' : 'LOW') as any,
            status: event.status === 'REVOKED & ROTATED' ? 'Terminated' : (event.risk_score > 75 ? 'Flagged' : 'Active') as any,
            logs: [`[${timestampStr}] [SESSION START] Pipeline initialized`, `[${timestampStr}] ${logText}`],
            typingCadence: Math.floor(Math.random() * 40) + 50,
            commandIntention: Math.floor(Math.random() * 40) + 50
          }
        ];
      }
    });

    // 3. Process Incidents
    if (isAnomaly) {
      setIncidents((prev) => {
        const incId = `INC-${(event.event_id || '').substring(0, 4).toUpperCase() || Math.floor(Math.random() * 9000 + 1000)}`;
        const existingInc = prev.find((inc) => inc.impactedEntity === event.user_id && inc.status !== 'Mitigated');

        if (existingInc) {
          return prev.map((inc) => {
            if (inc.id === existingInc.id) {
              const newLogs = [
                {
                  time: timestampStr,
                  title: isControlEvent ? 'Operator Overrode Credentials' : 'Anomaly Refinement Loop',
                  description: event.action,
                  statusBadge: event.status,
                  type: 'error' as const
                }
              ];
              if (event.rotation) {
                newLogs.push({
                  time: timestampStr,
                  title: 'Post-Quantum Lattice Re-Keying Complete',
                  description: `Credential encapsulation key (ML-KEM-1024): ${event.rotation.pqc_keys.ml_kem_1024.shared_secret_hex.substring(0, 18)}...`,
                  statusBadge: 'PQC_ROTATED',
                  type: 'success' as const
                });
              }
              return {
                ...inc,
                status: event.status === 'REVOKED & ROTATED' ? 'Mitigated' : inc.status,
                timeline: [...newLogs, ...inc.timeline]
              };
            }
            return inc;
          });
        } else {
          const ip = event.user_id === 's.murphy.admin' ? '192.168.1.50' : event.user_id === 'v.patel.contractor' ? '185.12.99.102' : '10.0.12.3';
          const newInc: Incident = {
            id: incId,
            title: isControlEvent ? 'Operator-Initiated Security Override' : `Active Threat: ${event.threat_classification || 'Insider Anomaly'}`,
            timeAgo: 'Just now',
            severity: event.risk_score > 90 ? 'critical' : 'high',
            tags: isControlEvent ? ['Manual Revocation', 'Vault Rotation'] : ['Anomaly', event.role || 'Insider', 'PQC Shield'],
            impactedEntity: event.user_id || 'System Node',
            assignee: 'SOC_Operator_04',
            status: event.status === 'REVOKED & ROTATED' ? 'Mitigated' : 'Active',
            attackChain: {
              node1: ip,
              node2: event.role || 'Internal Role',
              node3: event.department || 'Infrastructure'
            },
            timeline: [
              {
                time: timestampStr,
                title: isControlEvent ? 'Operator Override Issued' : 'High Risk Event Logged',
                description: event.action || 'Risk threshold breached by privileged system credentials.',
                statusBadge: event.status || 'ALERT',
                type: 'error'
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
          const delta = event.risk_score > 75 ? `+${event.risk_score}` : '0';
          const severity = event.risk_score > 75 ? 'error' : event.risk_score > 25 ? 'warning' : 'success';
          
          const newTelemetry = {
            timestamp: timestampStr,
            eventType: isAnomaly ? (event.threat_classification || 'Anomaly Trigger') : 'Operational Log',
            path: event.action.substring(0, 30),
            sourceIp: prof.name === 's.murphy.admin' ? '192.168.1.50' : prof.name === 'v.patel.contractor' ? '185.12.99.102' : '10.0.12.3',
            riskDelta: delta,
            severity: severity as any
          };

          const newScore = Math.max(10, 100 - (event.risk_score || 0));

          const newRadar = { ...prof.radar };
          if (event.risk_score > 75) {
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
    if (isAnomaly) {
      setSignals((prev) => {
        const ip = event.user_id === 's.murphy.admin' ? '192.168.1.50' : event.user_id === 'v.patel.contractor' ? '185.12.99.102' : '10.0.12.3';
        const location = event.user_id === 'v.patel.contractor' ? 'Kiev, UA' : event.user_id === 'compromised.root.node' ? 'Beijing, CN' : 'Frankfurt, DE';
        
        const newSig = {
          id: Date.now() + Math.random(),
          origin: `${location} (${ip})`,
          target: event.action.substring(0, 25),
          severity: event.risk_score > 90 ? 'critical' : 'high',
          rate: event.risk_score > 85 ? 'Bulk Access' : 'Anomaly Flow'
        };
        return [newSig, ...prev.slice(0, 5)];
      });
    }

    // 6. Push PQC details to Quantum Center logs
    if (event.rotation) {
      const keys = event.rotation.pqc_keys;
      setGenerationLogs((prev) => [
        `[${timestampStr}] [ROTATION TRIGGERED] Automatic post-quantum token rotation.`,
        `[${timestampStr}] Algorithm: ${keys.ml_kem_1024.algorithm} (Purpose: ${keys.ml_kem_1024.purpose})`,
        `[${timestampStr}] ML-KEM-1024 Public Key: ${keys.ml_kem_1024.public_key_fingerprint}`,
        `[${timestampStr}] ML-KEM-1024 Shared Secret: 0x${keys.ml_kem_1024.shared_secret_hex}`,
        `[${timestampStr}] Algorithm: ${keys.ml_dsa_85.algorithm} (Purpose: ${keys.ml_dsa_85.purpose})`,
        `[${timestampStr}] ML-DSA-85 Digital Signature Excerpt: ${keys.ml_dsa_85.signature_hex.substring(0, 32)}...`,
        `[${timestampStr}] [STATUS] Cryptographic credentials safely rotated and distributed across target subnets.`,
        ...prev
      ]);
    }
  };

  const forceRotateUser = async (userId: string): Promise<boolean> => {
    try {
      const res = await fetch('http://localhost:8000/api/v1/mitigate/force-rotate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ user_id: userId })
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

  const isolateHost = (entityName: string, incidentId: string) => {
    forceRotateUser(entityName);

    setIncidents((prev) =>
      prev.map((inc) => {
        if (inc.id === incidentId) {
          const isAlreadyContained = inc.timeline.some((t) => t.title === 'Manual Action: Host Isolated');
          if (isAlreadyContained) return inc;

          const updatedTimeline = [
            {
              time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
              title: 'Manual Action: Host Isolated',
              description: `Operator triggered virtual containment isolation block on host: ${entityName}. Outbound subnets locked.`,
              statusBadge: 'MANUAL ISO',
              type: 'success' as const
            },
            ...inc.timeline
          ];

          return {
            ...inc,
            status: 'Mitigated',
            timeline: updatedTimeline
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

  const terminateSession = (sessionId: string) => {
    setSessions((prevSessions) =>
      prevSessions.map((sess) => {
        if (sess.id === sessionId) {
          if (sess.status === 'Terminated') return sess;
          
          forceRotateUser(sess.user);

          const updatedLogs = [
            ...sess.logs,
            '-------------------------------------------------------',
            `[ADMIN LOCKOUT TRIGGERED AT ${new Date().toLocaleTimeString()}]`,
            'FATAL: Session forcefully severed by operator commands.',
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
        icon: 'check_circle'
      };
      setAuditEvents((prev) => [newEvent, ...prev]);
      setAuditScore((prev) => Math.min(100.0, parseFloat((prev + 0.6).toFixed(1))));
      setComplianceScanning(false);
    }, 1500);
  };

  const generatePqcKey = () => {
    setIsGeneratingKey(true);
    const newLogs = [
      `[INIT] Triggering manual lattice key audit...`,
      `[ML-KEM] Preparing module-lattice dimensions...`,
      `[SYSTEM] Invoking uvicorn manual force-rotate API...`
    ];

    setGenerationLogs((prev) => [...newLogs, ...prev]);

    setTimeout(() => {
      forceRotateUser('s.murphy.admin');
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
        sendCopilotMessage
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
