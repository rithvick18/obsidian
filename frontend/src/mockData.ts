import { Incident, PrivilegedSession, AuditEvent } from './types';

export const INITIAL_INCIDENTS: Incident[] = [
  {
    id: 'INC-8429',
    title: 'Unauthorized Database Bulk Export',
    timeAgo: '2m ago',
    severity: 'critical',
    tags: ['Data Exfiltration', 'Privilege Escalation'],
    impactedEntity: 'SV-PROD-DB-02',
    assignee: 'SOC_Lead_01',
    status: 'Active',
    attackChain: {
      node1: 'Initial Access',
      node2: 'Escalation',
      node3: 'Action on Objectives',
    },
    timeline: [
      {
        time: '08:42:11',
        title: 'External Login Identified',
        description: 'User j.smith@obsidian.io logged in from unrecognized IP: 45.128.11.94 (Kiev, UA).',
        type: 'info',
      },
      {
        time: '08:44:05',
        title: 'Privilege Escalation Detected',
        description: 'Successful attempt to bypass UAC using mock-up folder technique on WS-MKT-081.',
        statusBadge: 'T1068',
        type: 'warning',
      },
      {
        time: '08:45:30',
        title: 'Direct Database Access (SQL Injection)',
        description: 'System detected malformed SQL query against Customer_PII table. Source: j.smith session.',
        type: 'error',
      },
      {
        time: '08:46:12',
        title: 'Automated Response: Session Isolated',
        description: 'Risk engine triggered lockout. Network session for j.smith terminated and workstation isolated.',
        statusBadge: 'POLICY APPLIED',
        type: 'success',
      },
      {
        time: '08:48:00',
        title: 'Incident Notification Dispatched',
        description: 'Executive alert sent to CISO and SOC Level 3 escalation group.',
        type: 'info',
      },
    ],
  },
  {
    id: 'INC-8421',
    title: 'Multiple Failed Login Attempts (Brute Force)',
    timeAgo: '14m ago',
    severity: 'critical',
    tags: ['Identity', 'Brute Force'],
    impactedEntity: 'AD-CONTROLLER-01',
    assignee: 'Sec_Analyst_04',
    status: 'Investigating',
    attackChain: {
      node1: 'Reconnaissance',
      node2: 'Credential Access',
      node3: 'Active Lockout',
    },
    timeline: [
      {
        time: '08:28:10',
        title: 'Targeted Scanning Detected',
        description: 'Continuous port scanning activities originating from node outside secure whitelist.',
        type: 'info',
      },
      {
        time: '08:30:15',
        title: 'SSH Bruteforce Ingress',
        description: 'Over 14,000 login failures observed targeting local root accounts within 3 minutes.',
        statusBadge: 'T1110',
        type: 'error',
      },
      {
        time: '08:32:00',
        title: 'Security Policy Lockout',
        description: 'Directory Controller automatically disabled temporary authentication routes for high-risk IPs.',
        statusBadge: 'AUTO LOCK',
        type: 'success',
      },
    ],
  },
  {
    id: 'INC-8395',
    title: 'PowerShell Execution of Obfuscated Script',
    timeAgo: '1h ago',
    severity: 'high',
    tags: ['Endpoint', 'Execution'],
    impactedEntity: 'WS-FIN-092',
    assignee: 'SOC_Lead_01',
    status: 'Mitigated',
    attackChain: {
      node1: 'User Execution',
      node2: 'Command Shell',
      node3: 'Registry Mutation',
    },
    timeline: [
      {
        time: '07:15:22',
        title: 'Phishing Attachment Clicked',
        description: 'User in accounting opened invoice_scan_902.zip leading to local payload extraction.',
        type: 'warning',
      },
      {
        time: '07:16:04',
        title: 'Obfuscated PowerShell Execution',
        description: 'Encoded system query running bypass protocols detected in workspace registry.',
        statusBadge: 'T1059.001',
        type: 'error',
      },
      {
        time: '07:18:11',
        title: 'Antivirus Host Quarantine',
        description: 'Obsidian Agent successfully blocked active process and moved host to virtual sandbox.',
        statusBadge: 'CONTAINED',
        type: 'success',
      },
    ],
  },
];

export const INITIAL_SESSIONS: PrivilegedSession[] = [
  {
    id: '8829-QX',
    user: 'j_doe_admin',
    avatarInitials: 'JD',
    ipAddress: '192.168.1.104',
    sourceDevice: 'Workstation-D01',
    resource: 'SQL-PROD-01',
    resourceType: 'database',
    duration: '02:14:55',
    riskIndex: 12,
    riskText: 'LOW',
    status: 'Active',
    logs: [
      '[SESSION START: 2026-07-15 14:12:05 UTC]',
      'root@SQL-PROD-01:~# whoami',
      'root',
      'root@SQL-PROD-01:~# systemctl status postgresql',
      '● postgresql.service - PostgreSQL RDBMS',
      '   Loaded: loaded (/lib/systemd/system/postgresql.service; enabled; vendor preset: enabled)',
      '   Active: active (running) since Mon 2026-07-15 04:12:01 UTC; 10h ago',
      'root@SQL-PROD-01:~# tail -n 20 /var/log/postgresql/postgresql-14-main.log',
      '[Output Suppressed for Clarity]',
      'root@SQL-PROD-01:~# pg_dump -U postgres db_prod_core > /tmp/backup_core.sql',
      '[OK] File /tmp/backup_core.sql written successfully (1.1 MB)',
      'root@SQL-PROD-01:~# exit',
    ],
    typingCadence: 98.2,
    commandIntention: 94.6,
  },
  {
    id: '1102-PT',
    user: 'srv_acc_core',
    avatarInitials: 'SA',
    ipAddress: '45.2.118.99',
    sourceDevice: 'Unknown Origin',
    resource: 'ROOT_VALUT',
    resourceType: 'key',
    duration: '00:04:12',
    riskIndex: 89,
    riskText: 'CRITICAL',
    status: 'Flagged',
    logs: [
      '[SESSION START: 2026-07-15 16:10:12 UTC]',
      'srv_acc_core@ROOT_VALUT:~# whoami',
      'srv_acc_core',
      'srv_acc_core@ROOT_VALUT:~# cd /var/lib/postgresql/data/base/',
      'srv_acc_core@ROOT_VALUT:/var/lib/postgresql/data/base/# rm -rf *',
      'CRITICAL: UNRECOVERABLE DESTRUCTIVE COMMAND DETECTED',
      '-------------------------------------------------------',
      'Policy Breach: SQL-DATA-PROT-44',
      'Execution halted by Obsidian Guard Engine.',
      'Operator privileges temporarily suspended pending audit.',
    ],
    typingCadence: 32.4,
    commandIntention: 42.1,
  },
  {
    id: '9001-BZ',
    user: 'm_lee_sec',
    avatarInitials: 'ML',
    ipAddress: '10.0.4.52',
    sourceDevice: 'SOC-NODE-A4',
    resource: 'K8S-CLUSTER',
    resourceType: 'cluster',
    duration: '01:44:10',
    riskIndex: 34,
    riskText: 'MED',
    status: 'Active',
    logs: [
      '[SESSION START: 2026-07-15 14:30:22 UTC]',
      'm_lee_sec@k8s-node-04:~# kubectl get pods -A',
      'NAMESPACE     NAME                               READY   STATUS    RESTARTS   AGE',
      'kube-system   coredns-78fcd69978-vwscb           1/1     Running   0          42d',
      'kube-system   kube-proxy-7h9k2                   1/1     Running   0          42d',
      'default       obsidian-api-68ffdb9777-62kpx      2/2     Running   0          5d',
      'default       obsidian-database-0                1/1     Running   0          5d',
      'm_lee_sec@k8s-node-04:~# kubectl logs obsidian-database-0 -n default --tail=10',
      '2026-07-15 14:32:01 [INFO] Database connection pool synchronized.',
      '2026-07-15 14:34:42 [INFO] Vacuum process finished.',
    ],
    typingCadence: 92.5,
    commandIntention: 88.7,
  },
];

export const COMPLIANCE_EVENTS: AuditEvent[] = [
  {
    timestamp: '2026-07-15 14:22',
    eventType: 'Evidence Collected',
    framework: 'SOC2',
    artifactId: 'IAM-LOG-0042',
    status: 'Verified',
    icon: 'file_download',
  },
  {
    timestamp: '2026-07-15 11:05',
    eventType: 'Violation Detected',
    framework: 'PCI-DSS',
    artifactId: 'SQL-ENC-8812',
    status: 'Critical',
    icon: 'error',
  },
  {
    timestamp: '2026-07-15 03:59',
    eventType: 'Scan Scheduled',
    framework: 'NIST',
    artifactId: 'SCN-SYS-001',
    status: 'Pending',
    icon: 'timer',
  },
  {
    timestamp: '2026-07-14 18:40',
    eventType: 'Review Completed',
    framework: 'ISO 27001',
    artifactId: 'REV-USR-990',
    status: 'Verified',
    icon: 'file_download',
  },
  {
    timestamp: '2026-07-14 09:12',
    eventType: 'Policy Update',
    framework: 'General',
    artifactId: 'POL-SEC-V2.1',
    status: 'Signed',
    icon: 'description',
  },
];

export const ALGORITHM_PERFORMANCE = [
  { name: 'ML-KEM-768', latency: 152.4, level: 'NIST Level 3', size: '1,184 Bytes', status: 'ACTIVE' },
  { name: 'ML-DSA-65', latency: 284.1, level: 'NIST Level 3', size: '1,952 Bytes', status: 'ACTIVE' },
  { name: 'AES-256-GCM', latency: 12.2, level: 'Quantum Safe', size: '32 Bytes', status: 'OPTIMIZED' },
  { name: 'RSA-4096 (Legacy)', latency: 14200.0, level: 'Q-Vulnerable', size: '512 Bytes', status: 'DEPRECATING' },
];

export interface RiskProfile {
  name: string;
  role: string;
  employeeId: string;
  office: string;
  image: string;
  trustScore: number;
  anomalySummary: string;
  heatmap: number[][]; // weekly grid values
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

export const RISK_PROFILES: RiskProfile[] = [
  {
    name: 'Arjun Vardhan',
    role: 'Senior Systems Architect • Cloud Infrastructure',
    employeeId: '#OX-99281-B',
    office: 'Chennai Hub',
    image: 'https://lh3.googleusercontent.com/aida-public/AB6AXuDSWrDGkvlUYzQXOMk_42iXoCg3eJtKDGGmDCOwLB9TA4OSHmYpKyzWSKYaYP1kl6SyN9S-2pCk5F3lGC1m6inoQbIxeb0MI_4kDuOvTZhrMT3Bg12QFkg2SHI75woWlFWOEroPLPNJHwDQ3NV2c6DTleREUeIPqSOA1W3N6gE1KBJz7kqxiY1Ex5L2yQAtdKkSMihWQwNukongRvtqPW4-9azb-5u4INjjyorZ2r7UCdkGy_D5x8ch6kSJysAeE6Bj-FyK5IdKA8o',
    trustScore: 28,
    anomalySummary: 'Arjun normally logs in from Chennai (IN) between 09:00 - 18:00 IST using a MacBook Pro. Today, a session originated from Frankfurt (DE) at 03:22 IST on a Linux machine with an unknown kernel. This aligns with known "Impossible Travel" patterns.',
    heatmap: [
      [2, 0, 3, 0, 1], // Mon
      [0, 2, 4, 0, 0], // Tue
      [5, 3, 0, 2, 1], // Wed
      [0, 2, 0, 0, 1], // Thu
      [0, 0, 0, 0, 0], // Fri
      [5, 4, 3, 0, 0], // anomalous period focus
    ],
    radar: {
      loginRisk: 90,
      accessPattern: 85,
      deviceTrust: 75,
      behaviorScore: 80,
      networkSecurity: 65,
      appIntegrity: 50,
    },
    telemetry: [
      {
        timestamp: '2026-07-15 03:22:11',
        eventType: 'Geo-Anomalous Login',
        path: '/auth/saml/callback',
        sourceIp: '185.12.99.102 (Frankfurt, DE)',
        riskDelta: '+42.0',
        severity: 'error',
      },
      {
        timestamp: '2026-07-15 03:25:44',
        eventType: 'Mass File Access',
        path: 'S3://prod-fin-records/*',
        sourceIp: '185.12.99.102 (Frankfurt, DE)',
        riskDelta: '+18.5',
        severity: 'warning',
      },
      {
        timestamp: '2026-07-15 02:45:00',
        eventType: 'Routine Sync',
        path: '/api/v1/heartbeat',
        sourceIp: '122.164.21.18 (Chennai, IN)',
        riskDelta: '-0.2',
        severity: 'success',
      },
      {
        timestamp: '2026-07-14 18:12:09',
        eventType: 'Privilege Escalation Attempt',
        path: '/iam/role-update',
        sourceIp: '185.12.99.102 (Frankfurt, DE)',
        riskDelta: '+35.0',
        severity: 'warning',
      },
    ],
  },
  {
    name: 'Sarah Jenkins',
    role: 'Lead Financial Operator',
    employeeId: '#OX-88371-A',
    office: 'London Office',
    image: 'https://lh3.googleusercontent.com/aida-public/AB6AXuAErF9pVnO997gSbH60S4wuSJf3QxjbISG2GWqBiZBzMLulBnZG-helqvUE7NBr4ejrYNezwmBZSW1sjnxMzkY84QiEXfyt9xuFO407xQQD6OIwZQdP-QPn1gYoQGDbcfsYauH6XfqLb3tP4ZqPjRDs7h2VRRYNEAKBiP84qxXnbLjHZZY6JmSgtblfsYNHUELBTn8btc9ha09KlWX4CGs5HsZHQ_8EEitx0xWrDNJp4AaBcyD7rIBXVuttoe9NZQG0hHQ4NXLrhs8',
    trustScore: 94,
    anomalySummary: 'Sarah exhibits consistent financial transaction workflows originating from London, UK. Security audit shows pristine logging compliance with zero critical alerts in the last 180 days.',
    heatmap: [
      [1, 1, 1, 0, 1], // Mon
      [1, 2, 2, 1, 1], // Tue
      [2, 1, 1, 1, 2], // Wed
      [1, 1, 1, 1, 1], // Thu
      [1, 1, 2, 0, 1], // Fri
      [1, 1, 1, 0, 1],
    ],
    radar: {
      loginRisk: 10,
      accessPattern: 15,
      deviceTrust: 10,
      behaviorScore: 12,
      networkSecurity: 8,
      appIntegrity: 5,
    },
    telemetry: [
      {
        timestamp: '2026-07-15 11:32:00',
        eventType: 'Standard Policy Authorization',
        path: '/vault/payout-verify',
        sourceIp: '194.22.41.90 (London, UK)',
        riskDelta: '-0.5',
        severity: 'success',
      },
      {
        timestamp: '2026-07-15 09:15:22',
        eventType: 'Successful MFA Challenge',
        path: '/auth/saml/mfa',
        sourceIp: '194.22.41.90 (London, UK)',
        riskDelta: '-1.2',
        severity: 'success',
      },
    ],
  },
];
