export type ActiveTab =
  | 'executive'
  | 'quantum'
  | 'incidents'
  | 'analytics'
  | 'risk'
  | 'copilot'
  | 'map'
  | 'sessions';

export interface Incident {
  id: string;
  title: string;
  timeAgo: string;
  severity: 'critical' | 'high' | 'medium';
  tags: string[];
  impactedEntity: string;
  assignee: string;
  status: 'Active' | 'Mitigated' | 'Investigating';
  attackChain: {
    node1: string;
    node2: string;
    node3: string;
  };
  timeline: {
    time: string;
    title: string;
    description: string;
    statusBadge?: string;
    type?: 'info' | 'warning' | 'error' | 'success';
  }[];
}

export interface PrivilegedSession {
  id: string;
  user: string;
  avatarInitials: string;
  ipAddress: string;
  sourceDevice: string;
  resource: string;
  resourceType: 'database' | 'key' | 'cluster';
  duration: string;
  riskIndex: number;
  riskText: 'LOW' | 'MED' | 'CRITICAL';
  status: 'Active' | 'Flagged' | 'Terminated';
  logs: string[];
  typingCadence: number;
  commandIntention: number;
}

export interface AuditEvent {
  timestamp: string;
  eventType: string;
  framework: string;
  artifactId: string;
  status: 'Verified' | 'Critical' | 'Pending' | 'Signed';
  icon: string;
}

export interface RiskFactor {
  name: string;
  value: number;
}

export interface RiskProfile {
  name: string;
  role: string;
  employeeId: string;
  office: string;
  image: string;
  trustScore: number;
  anomalySummary: string;
  heatmap: number[][];
  radar: {
    loginRisk: number;
    accessPattern: number;
    deviceTrust: number;
    behaviorScore: number;
    networkSecurity: number;
    appIntegrity: number;
  };
  telemetry: {
    timestamp: string;
    eventType: string;
    path: string;
    sourceIp: string;
    riskDelta: string;
    severity: 'error' | 'warning' | 'success';
  }[];
}

export interface AlgorithmPerformance {
  name: string;
  latency: number;
  level: string;
  size: string;
  status: string;
}
