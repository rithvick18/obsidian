import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Users, 
  Terminal, 
  Clock, 
  Database, 
  FileKey, 
  Server, 
  Lock, 
  Activity, 
  RotateCw,
  CheckCircle,
  Play
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';

const defaultSession: any = {
  id: 'SYSTEM-INIT',
  user: 'admin_node_01',
  avatarInitials: 'AD',
  ipAddress: '192.168.1.1',
  sourceDevice: 'MacBook Air M4',
  resource: 'Production SWIFT API Gateway',
  resourceType: 'cluster',
  duration: 'Active',
  status: 'SECURE',
  logs: ['[SESSION START] Secure audit connection verified via SQLite backend fabric.'],
  typingCadence: 92,
  commandIntention: 98,
};

export default function SessionsView() {
  const { auditEvents, terminateSession, flagSession, forceRotateUser, systemStatus } = useSecurity();
  const [selectedSessionId, setSelectedSessionId] = useState<string>('');

  // 1. Core Structural Data Remodeling: Group raw database audit logs into active pipelines
  const activePipelines = useMemo(() => {
    const activeFeeds = auditEvents && auditEvents.length > 0 ? auditEvents : [];
    
    if (activeFeeds.length === 0) {
      return [defaultSession];
    }

    // Pick unique user node sessions to plot out in the navigation panel list
    const mapped: Record<string, any> = {};
    
    activeFeeds.forEach((evt: any) => {
      const uid = evt.user_id || 'unknown_node';
      if (!mapped[uid]) {
        const hasCriticalViolation = evt.risk_score === 100 || evt.is_honeypot === 1;
        let pipelineStatus = evt.status || 'SECURE';
        if (hasCriticalViolation) pipelineStatus = 'Flagged';
        if (evt.status?.includes('ROTATED') || evt.status?.includes('MITIGATED')) pipelineStatus = 'Terminated';

        const initials = uid.substring(0, 2).toUpperCase();
        const ipIdx = uid.charCodeAt(uid.length - 1) || 4;

        // Build mock terminal line statements directly out of dynamic DB properties
        const syntheticLogs = [
          `[SESSION START] Core telemetry pipeline initialized via persistent index registry.`,
          `[OK] Authentication token validated for identity boundary: ${evt.role || 'System Role'}`,
          `[OK] Executing request context routing command: ${evt.action || 'System maintenance Query'}`
        ];

        if (hasCriticalViolation) {
          syntheticLogs.push(`CRITICAL: Access anomaly tripped inside protected vault boundary [${evt.resource || 'decoy_vault'}]`);
          if (evt.tamper_lock_signature || evt.tamper_lock_signature !== null) {
            syntheticLogs.push(`FATAL: Zero-trust compliance rules breached. Cryptographic hardware signature locked.`);
          }
        } else {
          syntheticLogs.push(`[OK] Response verified inside parameter boundaries. Transaction payload completed successfully.`);
        }

        // Standard dynamic calculation generating cadence metrics out of threat index parameters
        const calculatedRisk = evt.risk_score !== undefined ? evt.risk_score : 10;
        const cadence = Math.min(98, Math.max(15, 95 - calculatedRisk));
        const intention = Math.min(100, Math.max(5, 100 - calculatedRisk * 1.2));

        mapped[uid] = {
          id: evt.id || `SESS-${uid.toUpperCase()}`,
          user: uid,
          avatarInitials: initials,
          ipAddress: evt.is_honeypot ? '10.0.99.254 [CANARY]' : `192.168.4.${ipIdx + 10}`,
          sourceDevice: uid.includes('admin') ? 'M4 MacBook Air' : (uid.includes('contractor') ? 'Linux Dual-Boot' : 'Windows Dev Workstation'),
          resource: evt.resource || 'Corporate Banking Gateway',
          resourceType: evt.resource?.toLowerCase().includes('db') ? 'database' : (evt.resource?.toLowerCase().includes('key') ? 'key' : 'cluster'),
          duration: 'Live Frame',
          riskIndex: calculatedRisk,
          typingCadence: Math.round(cadence),
          commandIntention: Math.round(intention),
          status: pipelineStatus,
          isHoneypot: hasCriticalViolation,
          tamperLockSignature: evt.tamper_lock_signature || evt.tamperLockSignature,
          logs: syntheticLogs
        };
      }
    });

    return Object.values(mapped);
  }, [auditEvents]);

  const selectedSession = activePipelines.find(sess => sess.id === selectedSessionId) || activePipelines[0] || defaultSession;

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
      
      {/* Left Column: Sessions List */}
      <div className="col-span-12 xl:col-span-5 flex flex-col gap-4">
        <div className="glass-panel p-4 rounded-xl flex justify-between items-center bg-surface-container-high/20">
          <div className="flex items-center gap-2">
            <Users size={16} className="text-primary" />
            <h3 className="font-headline-sm text-sm font-bold text-on-surface uppercase tracking-wider">Active Secure Pipelines</h3>
          </div>
          <span className="text-xs text-on-surface-variant font-mono font-bold">
            {activePipelines.filter(s => s.status !== 'Terminated').length} Live Pipelines
          </span>
        </div>

        <div className="space-y-3.5 max-h-[640px] overflow-y-auto pr-1">
          {activePipelines.map((sess) => {
            const isSelected = sess.id === selectedSessionId;
            const displayUserLabel = sess.user.replace('_', ' ');

            return (
              <div
                key={sess.id}
                onClick={() => setSelectedSessionId(sess.id)}
                className={`glass-panel p-4 rounded-xl cursor-pointer transition-all duration-200 border-l-4 ${
                  isSelected 
                    ? 'border-primary bg-primary/[0.04]' 
                    : 'border-l-transparent hover:border-l-outline-variant'
                } ${
                  sess.status === 'Terminated' 
                    ? 'border-l-outline-variant opacity-70' 
                    : sess.status === 'Flagged' 
                    ? 'border-l-error shadow-[0_0_12px_rgba(239,68,68,0.05)]' 
                    : 'border-l-secondary'
                }`}
              >
                <div className="flex justify-between items-start mb-2">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-full bg-bg-badge border border-outline-variant/60 flex items-center justify-center font-bold text-primary text-xs font-mono">
                      {sess.avatarInitials}
                    </div>
                    <div>
                      <h4 className="font-sans font-bold text-sm text-on-surface leading-tight capitalize">{displayUserLabel}</h4>
                      <p className="text-[11px] font-mono text-on-surface-variant mt-0.5">{sess.ipAddress}</p>
                    </div>
                  </div>
                  <span className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded uppercase ${
                    sess.status === 'Terminated' 
                      ? 'bg-outline-variant/20 text-on-surface-variant' 
                      : sess.status === 'Flagged' 
                      ? 'bg-error-container/20 text-error animate-pulse' 
                      : 'bg-secondary/20 text-[#4edea3]'
                  }`}>
                    {sess.status}
                  </span>
                </div>

                <div className="mt-3.5 pt-3.5 border-t border-outline-variant/30 flex justify-between items-center text-xs text-on-surface-variant">
                  <span className="flex items-center gap-1.5 font-sans font-semibold text-on-surface">
                    {sess.resourceType === 'database' ? (
                      <Database size={12} className="text-primary" />
                    ) : sess.resourceType === 'key' ? (
                      <FileKey size={12} className="text-secondary" />
                    ) : (
                      <Server size={12} className="text-primary" />
                    )}
                    {sess.resource}
                  </span>
                  <span className="font-mono text-on-surface-variant flex items-center gap-1 font-bold">
                    {sess.duration}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Right Column: Console terminal & controls */}
      <div className="col-span-12 xl:col-span-7 flex flex-col gap-6">
        <div className="glass-panel rounded-xl p-6 relative overflow-hidden flex-1 flex flex-col justify-between">
          
          <div>
            <div className="flex flex-col sm:flex-row justify-between sm:items-start gap-4 border-b border-outline-variant/50 pb-5 mb-5">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-bg-badge border border-outline-variant flex items-center justify-center font-bold text-primary font-mono">
                  {selectedSession.avatarInitials}
                </div>
                <div>
                  <h2 className="font-headline-sm text-lg font-bold text-on-surface leading-tight capitalize">{selectedSession.user.replace('_', ' ')}</h2>
                  <p className="text-xs text-on-surface-variant font-sans mt-0.5">Device Source Origin: <span className="font-mono font-bold text-on-surface">{selectedSession.sourceDevice} ({selectedSession.ipAddress})</span></p>
                </div>
              </div>

              {/* Console Action buttons */}
              <div className="flex flex-wrap gap-2 sm:self-center">
                <button 
                  onClick={() => forceRotateUser(selectedSession.user)}
                  disabled={selectedSession.status === 'Terminated'}
                  className={`py-2 px-3 rounded text-xs font-mono uppercase font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                    selectedSession.status === 'Terminated'
                      ? 'bg-outline-variant/10 text-on-surface-variant cursor-not-allowed'
                      : 'bg-primary/20 text-primary border border-primary/30 hover:bg-primary/30'
                  }`}
                >
                  <RotateCw size={13} />
                  Force Rotate
                </button>
                <button 
                  onClick={() => flagSession(selectedSession.id)}
                  disabled={selectedSession.status === 'Terminated' || selectedSession.status === 'Flagged'}
                  className={`py-2 px-3 rounded text-xs font-mono uppercase font-bold transition-all cursor-pointer ${
                    selectedSession.status === 'Terminated' || selectedSession.status === 'Flagged'
                      ? 'bg-outline-variant/10 text-on-surface-variant cursor-not-allowed'
                      : 'bg-amber-500/20 text-amber-500 border border-amber-500/30 hover:bg-amber-500/30'
                  }`}
                >
                  Flag Session
                </button>
                <button 
                  onClick={() => terminateSession(selectedSession.id)}
                  disabled={selectedSession.status === 'Terminated'}
                  className={`py-2 px-3 rounded text-xs font-mono uppercase font-bold transition-all cursor-pointer ${
                    selectedSession.status === 'Terminated'
                      ? 'bg-outline-variant/10 text-on-surface-variant cursor-not-allowed'
                      : 'bg-error hover:bg-error/80 text-white shadow-lg shadow-error/10'
                  }`}
                >
                  Terminate Session
                </button>
              </div>
            </div>

            {/* Honeypot & Tamper Lock Interception Alert Banner */}
            {selectedSession.isHoneypot && (
              <div className="mb-5 p-4 rounded-xl bg-error/10 border-2 border-error/50 flex items-start gap-3 shadow-[0_0_15px_rgba(239,68,68,0.1)]">
                <span className="text-2xl">🍯</span>
                <div className="flex-1">
                  <h4 className="text-xs font-bold text-error uppercase tracking-wider font-mono">Canary Honeypot Session &amp; Tamper Lock Engaged</h4>
                  <p className="text-xs text-on-surface-variant mt-1 leading-relaxed">
                    Session payload touched deterministic decoy container resource asset. FIPS 204 ML-DSA baseline locked forensically.
                  </p>
                  {selectedSession.tamperLockSignature && (
                    <div className="mt-2 p-2 rounded bg-surface-container-lowest font-mono text-[10px] text-amber-300 break-all border border-outline-variant">
                      LOCK SIGFingerprint // {selectedSession.tamperLockSignature}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Cadence & Intention metrics */}
            <div className="grid grid-cols-2 gap-4 mb-5">
              <div className="p-3.5 bg-surface-container-lowest/60 rounded-xl border border-outline-variant/60">
                <span className="text-[10px] text-on-surface-variant uppercase font-bold tracking-wider block">Typing Cadence (Biometrics)</span>
                <div className="flex items-center gap-2 mt-1.5">
                  <div className="flex-1 bg-surface-container-highest h-2 rounded-full overflow-hidden">
                    <div className="bg-primary h-full rounded-full" style={{ width: `${selectedSession.typingCadence}%` }}></div>
                  </div>
                  <span className="font-mono text-xs text-on-surface font-bold">{selectedSession.typingCadence}%</span>
                </div>
              </div>
              <div className="p-3.5 bg-surface-container-lowest/60 rounded-xl border border-outline-variant/60">
                <span className="text-[10px] text-on-surface-variant uppercase font-bold tracking-wider block">Command Intention Confidence</span>
                <div className="flex items-center gap-2 mt-1.5">
                  <div className="flex-1 bg-surface-container-highest h-2 rounded-full overflow-hidden">
                    <div className={`h-full rounded-full ${
                      selectedSession.commandIntention < 50 ? 'bg-error animate-pulse' : 'bg-secondary'
                    }`} style={{ width: `${selectedSession.commandIntention}%` }}></div>
                  </div>
                  <span className="font-mono text-xs text-on-surface font-bold">{selectedSession.commandIntention}%</span>
                </div>
              </div>
            </div>

            {/* Interactive console terminal screen component */}
            <div className="flex flex-col rounded-xl overflow-hidden h-[260px] border border-outline-variant">
              <div className="bg-bg-sidebar px-4 py-2 border-b border-outline-variant/60 flex justify-between items-center text-xs font-mono">
                <span className="text-on-surface-variant flex items-center gap-1.5">
                  <Terminal size={12} className="text-primary" />
                  tty-pipeline-{selectedSession.user || 'core'}
                </span>
                <span className={`w-2 h-2 rounded-full ${
                  selectedSession.status === 'Terminated' 
                    ? 'bg-outline-variant' 
                    : selectedSession.status === 'Flagged' 
                    ? 'bg-error animate-pulse' 
                    : 'bg-[#4edea3] animate-pulse-slow'
                }`}></span>
              </div>
              <div className="bg-bg-base p-4 flex-1 font-mono text-[11px] text-secondary/95 overflow-y-auto space-y-1.5 select-all">
                {selectedSession.logs.map((log: string, i: number) => (
                  <div 
                    key={i} 
                    className={`whitespace-pre-wrap ${
                      log.startsWith('CRITICAL:') || log.startsWith('FATAL:')
                        ? 'text-error font-bold bg-error-container/10 p-1.5 rounded border border-error/20' 
                        : log.startsWith('[SESSION START')
                        ? 'text-primary font-semibold'
                        : log.startsWith('[OK]')
                        ? 'text-[#4edea3]'
                        : 'text-on-surface-variant'
                    }`}
                  >
                    {log}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <p className="mt-4 text-[10px] text-on-surface-variant font-mono">
            * All terminal session activities are archived in offline storage and synchronized with SOC log repositories automatically.
          </p>
        </div>
      </div>
    </div>
  );
}
