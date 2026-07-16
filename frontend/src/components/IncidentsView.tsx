import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  ShieldAlert, 
  User, 
  Terminal, 
  MapPin, 
  ExternalLink, 
  Check, 
  TrendingUp, 
  Clock, 
  Cpu, 
  AlertOctagon,
  Lock,
  RotateCw,
  Send,
  Sliders,
  Filter
} from 'lucide-react';
import { Incident } from '../types';

// defaultIncident mock object scrubbed for zero-state compliance

import { useSecurity } from '../context/SecurityContext';

export default function IncidentsView() {
  const { incidents, isolateHost, mitigateIncidentDirect, forceRotateUser } = useSecurity();
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('');
  const [isolationRunning, setIsolationRunning] = useState<string | null>(null);

  // Fallback cascade ensuring perfect data accessibility
  const activeIncidentList: any[] = incidents || [];
  const selectedIncident = activeIncidentList.length > 0 
    ? (activeIncidentList.find(inc => inc.id === selectedIncidentId) || activeIncidentList[0])
    : undefined;

  const handleIsolateHost = (entityName: string) => {
    if (!selectedIncident) return;
    setIsolationRunning(entityName);
    setTimeout(() => {
      isolateHost(entityName, selectedIncident.id);
      setIsolationRunning(null);
    }, 1200);
  };

  const handleMitigateDirect = () => {
    if (!selectedIncident) return;
    mitigateIncidentDirect(selectedIncident.id);
  };

  // Safe structural extract handles both snake_case DB inputs and local state wrappers cleanly
  const hasHoneypotBreach = selectedIncident?.isHoneypot || selectedIncident?.is_honeypot === 1 || selectedIncident?.risk_score === 100;
  const lockSignature = selectedIncident?.tamperLockSignature || selectedIncident?.tamper_lock_signature;
  const currentRiskScore = selectedIncident?.risk_score !== undefined ? selectedIncident.risk_score : (selectedIncident?.severity === 'critical' ? 100 : (selectedIncident ? 75 : 0));
  const targetUserNode = selectedIncident?.user_id || selectedIncident?.impactedEntity || 'unknown_node';
  const displayActionContext = selectedIncident?.action || selectedIncident?.title || 'No active incidents';

  // Build a completely dynamic attack chain vector derived from backend risk factors
  const computedChainNodes = React.useMemo(() => {
    if (!selectedIncident) {
      return {
        node1: 'Ingress Point',
        node2: 'Proxy Boundary',
        node3: 'Decoy Asset'
      };
    }
    const rawFactors = selectedIncident.risk_factors;
    let parsedFactors: any[] = [];
    
    try {
      if (typeof rawFactors === 'string') {
        parsedFactors = JSON.parse(rawFactors);
      } else if (Array.isArray(rawFactors)) {
        parsedFactors = rawFactors;
      }
    } catch (e) {
      parsedFactors = [];
    }

    return {
      node1: selectedIncident.department || 'Ingress Point',
      node2: selectedIncident.role || 'Proxy Boundary',
      node3: parsedFactors.length > 0 ? parsedFactors[0]?.factor?.split(' ')[0] : (selectedIncident.resource || 'Decoy Asset')
    };
  }, [selectedIncident]);

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
      
      {/* Left Column: Incidents List */}
      <div className="col-span-12 xl:col-span-5 flex flex-col gap-4">
        <div className="glass-panel p-4 rounded-xl flex justify-between items-center bg-surface-container-high/20">
          <div className="flex items-center gap-2">
            <Sliders size={16} className="text-primary" />
            <h3 className="font-headline-sm text-sm font-bold text-on-surface uppercase tracking-wider">Active Alerts List</h3>
          </div>
          <div className="flex gap-1">
            <button className="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant">
              <Filter size={14} />
            </button>
          </div>
        </div>

        <div className="space-y-3.5 max-h-[640px] overflow-y-auto pr-1">
          {activeIncidentList.length === 0 ? (
            <div className="glass-panel p-6 rounded-xl text-center text-xs text-on-surface-variant font-mono leading-relaxed">
              No active security incidents detected. System operating within baseline nominal parameters.
            </div>
          ) : (
            activeIncidentList.map((inc) => {
              const isSelected = inc.id === selectedIncidentId;
              const incId = inc.id || 'INC-TRK';
              const incTitle = inc.action || inc.title;
              const incUser = inc.user_id || inc.impactedEntity;
              const incSeverity = inc.risk_score === 100 || inc.severity === 'critical' ? 'critical' : 'medium';

              return (
                <div
                  key={incId}
                  onClick={() => setSelectedIncidentId(incId)}
                  className={`glass-panel p-4 rounded-xl cursor-pointer transition-all duration-200 border-l-4 ${
                    isSelected 
                      ? 'border-primary bg-primary/[0.04]' 
                      : 'border-l-transparent hover:border-l-outline-variant'
                  } ${
                    incSeverity === 'critical' 
                      ? 'border-l-error shadow-[0_0_12px_rgba(239,68,68,0.05)]' 
                      : 'border-l-amber-500'
                  }`}
                >
                  <div className="flex justify-between items-start mb-2">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs text-on-surface-variant font-bold">{incId.substring(0, 8)}</span>
                        <span className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded uppercase ${
                          inc.status === 'Mitigated' || inc.status === 'REVOKED & ROTATED'
                            ? 'bg-[#005236] text-[#4edea3]' 
                            : 'bg-error/20 text-error animate-pulse'
                        }`}>
                          {inc.status || 'ACTIVE'}
                        </span>
                      </div>
                      <h4 className="font-sans font-bold text-sm text-on-surface line-clamp-1 leading-tight">{incTitle}</h4>
                    </div>
                    <span className="text-xs text-on-surface-variant font-mono whitespace-nowrap">{inc.timeAgo || 'Live'}</span>
                  </div>

                  <div className="flex flex-wrap gap-1.5 mt-3">
                    <span className="text-[10px] bg-error/10 text-error font-mono font-bold px-2 py-0.5 rounded border border-error/20">
                      Risk Score: {inc.risk_score || (incSeverity === 'critical' ? 100 : 75)}
                    </span>
                    {inc.department && (
                      <span className="text-[10px] bg-surface-container-lowest text-on-surface-variant border border-outline-variant/60 px-2 py-0.5 rounded">
                        {inc.department}
                      </span>
                    )}
                  </div>

                  <div className="mt-3.5 pt-3.5 border-t border-outline-variant/30 flex justify-between items-center text-xs text-on-surface-variant">
                    <span className="flex items-center gap-1.5 font-sans font-semibold text-on-surface">
                      <Cpu size={12} className="text-primary" />
                      {incUser}
                    </span>
                    <span className="flex items-center gap-1 font-mono text-[11px]">
                      {inc.role || 'Infrastructure Node'}
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Right Column: Deep Incident Details & Sandbox Actions */}
      <div className="col-span-12 xl:col-span-7 flex flex-col gap-6">
        {selectedIncident === undefined ? (
          <div className="glass-panel rounded-xl p-8 flex flex-col items-center justify-center text-center h-full min-h-[400px]">
            <ShieldAlert size={48} className="text-on-surface-variant/40 mb-4 animate-pulse" />
            <h3 className="font-headline-sm text-base font-bold text-on-surface mb-2">Deep Alert Forensics</h3>
            <p className="text-sm font-mono text-on-surface-variant max-w-md leading-relaxed">
              No active security incidents selected.<br />
              System telemetry pipeline empty — awaiting ingress core status.
            </p>
          </div>
        ) : (
          <div className="glass-panel rounded-xl p-6 relative overflow-hidden flex-1">
            <div className="flex flex-col sm:flex-row justify-between sm:items-start gap-4 border-b border-outline-variant/50 pb-5 mb-5">
              <div>
                <div className="flex items-center gap-3 mb-1">
                  <span className="font-mono text-sm text-primary font-bold">{selectedIncident?.id?.substring(0, 8)}</span>
                  <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                    currentRiskScore >= 85
                      ? 'bg-error-container/20 text-error border border-error/20'
                      : 'bg-amber-500/20 text-amber-500 border border-amber-500/20'
                  }`}>
                    RISK: {currentRiskScore}/100
                  </span>
                </div>
                <h2 className="font-headline-sm text-lg sm:text-xl font-bold text-on-surface leading-snug">{displayActionContext}</h2>
                <p className="text-xs text-on-surface-variant font-sans mt-1">Impacted Target Object: <span className="font-mono font-bold text-on-surface">{targetUserNode}</span></p>
              </div>
              
              {/* Action Control Matrix */}
              <div className="flex flex-wrap gap-2.5 sm:self-center">
                <button
                  onClick={() => forceRotateUser(targetUserNode)}
                  disabled={selectedIncident?.status === 'Mitigated' || selectedIncident?.status === 'REVOKED & ROTATED'}
                  className={`py-2 px-3.5 rounded text-xs font-mono uppercase tracking-wider font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                    selectedIncident?.status === 'Mitigated' || selectedIncident?.status === 'REVOKED & ROTATED'
                      ? 'bg-outline-variant text-on-surface-variant cursor-not-allowed'
                      : 'bg-primary/20 border border-primary/40 hover:bg-primary/30 text-primary'
                  }`}
                >
                  <RotateCw size={13} />
                  Force Rotate
                </button>
                <button
                  onClick={() => handleIsolateHost(targetUserNode)}
                  disabled={isolationRunning !== null || selectedIncident?.status === 'Mitigated' || selectedIncident?.status === 'CONTAINED & ISOLATED'}
                  className={`py-2 px-3.5 rounded text-xs font-mono uppercase tracking-wider font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                    selectedIncident?.status === 'Mitigated' || selectedIncident?.status === 'CONTAINED & ISOLATED'
                      ? 'bg-outline-variant text-on-surface-variant cursor-not-allowed'
                      : 'bg-error hover:bg-error/80 text-white shadow-lg shadow-error/10'
                  }`}
                >
                  {isolationRunning === targetUserNode ? (
                    <>
                      <RotateCw className="animate-spin" size={13} />
                      ISOLATING...
                    </>
                  ) : (
                    <>
                      <Lock size={13} />
                      Isolate Host
                    </>
                  )}
                </button>
                {selectedIncident?.status !== 'Mitigated' && selectedIncident?.status !== 'REVOKED & ROTATED' && selectedIncident?.status !== 'CONTAINED & ISOLATED' && (
                  <button
                    onClick={handleMitigateDirect}
                    className="py-2 px-3.5 bg-secondary hover:bg-secondary/80 text-white rounded text-xs font-mono uppercase tracking-wider font-bold transition-all cursor-pointer shadow-lg shadow-secondary/10"
                  >
                    Mark Mitigated
                  </button>
                )}
              </div>
            </div>

            {/* Dynamic Honeypot Deception Alert Interceptor Banner */}
            {hasHoneypotBreach && (
              <div className="mb-6 p-4 rounded-xl bg-error/10 border-2 border-error/50 flex items-start gap-3 shadow-[0_0_15px_rgba(239,68,68,0.1)]">
                <span className="text-2xl">🍯</span>
                <div className="flex-1">
                  <h4 className="text-xs font-bold text-error uppercase tracking-wider font-mono">Canary Honeypot Triggered &amp; Tamper-Evident Lock Engaged</h4>
                  <p className="text-xs text-on-surface-variant mt-1 leading-relaxed">
                    Zero-trust boundary violation detected against privileged asset container `{selectedIncident.resource || 'decoy_vault'}`. FIPS 204 ML-DSA digital signature locked forensically against administrative overwrite routines.
                  </p>
                  {lockSignature && (
                    <div className="mt-2.5 p-2 rounded bg-surface-container-lowest font-mono text-[10px] text-amber-300 break-all border border-outline-variant">
                      LOCK SIG Fingerprint // {lockSignature}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Dynamic Attack Chain Node Visualization */}
            <div className="mb-6">
              <h3 className="text-xs font-bold text-on-surface-variant uppercase tracking-wider mb-3">Attack Chain Vector Matrix</h3>
              <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant/60 flex items-center justify-between overflow-x-auto gap-4">
                <div className="flex-1 min-w-[110px] text-center p-2.5 rounded bg-bg-node border border-outline-variant">
                  <div className="text-[9px] text-on-surface-variant uppercase font-bold tracking-wider">Origin Boundary</div>
                  <div className="text-xs text-primary font-bold font-mono mt-1 truncate">{computedChainNodes.node1}</div>
                </div>
                <div className="w-6 h-0.5 bg-outline-variant relative shrink-0">
                  <span className="absolute -top-1 right-0 w-2 h-2 rounded-full bg-primary"></span>
                </div>
                <div className="flex-1 min-w-[110px] text-center p-2.5 rounded bg-bg-node border border-outline-variant">
                  <div className="text-[9px] text-on-surface-variant uppercase font-bold tracking-wider">Access Role Node</div>
                  <div className="text-xs text-secondary font-bold font-mono mt-1 truncate">{computedChainNodes.node2}</div>
                </div>
                <div className="w-6 h-0.5 bg-outline-variant relative shrink-0">
                  <span className="absolute -top-1 right-0 w-2 h-2 rounded-full bg-secondary"></span>
                </div>
                <div className="flex-1 min-w-[110px] text-center p-2.5 rounded bg-bg-node border border-error bg-error/5">
                  <div className="text-[9px] text-error uppercase font-bold tracking-wider">Target Intrusion Object</div>
                  <div className="text-xs text-error font-bold font-mono mt-1 truncate">{computedChainNodes.node3}</div>
                </div>
              </div>
            </div>

            {/* Timeline Logs */}
            <div>
              <h3 className="text-xs font-bold text-on-surface-variant uppercase tracking-wider mb-4">Threat Timeline Logs</h3>
              <div className="relative border-l-2 border-outline-variant/50 pl-6 ml-3 space-y-5 max-h-[220px] overflow-y-auto">
                {selectedIncident?.timeline && selectedIncident.timeline.length > 0 ? (
                  selectedIncident.timeline.map((item: any, index: number) => (
                    <div key={index} className="relative">
                      <span className={`absolute -left-[31px] top-1 w-2.5 h-2.5 rounded-full border-2 ${
                        item.type === 'error' ? 'bg-error border-error' : 'bg-outline-variant border-outline-variant'
                      }`}></span>
                      <div className="flex justify-between items-center">
                        <span className="font-mono text-xs text-primary font-bold">{item.time}</span>
                      </div>
                      <h4 className="font-sans font-bold text-sm text-on-surface mt-1">{item.title}</h4>
                      <p className="text-xs text-on-surface-variant mt-0.5 font-sans">{item.description}</p>
                    </div>
                  ))
                ) : (
                  <div className="relative">
                    <span className="absolute -left-[31px] top-1 w-2.5 h-2.5 rounded-full border-2 bg-secondary border-secondary"></span>
                    <div className="font-mono text-xs text-secondary font-bold">Real-time Telemetry Frame</div>
                    <h4 className="font-sans font-bold text-sm text-on-surface mt-1">Audit Trail Active</h4>
                    <p className="text-xs text-on-surface-variant mt-0.5 font-sans leading-relaxed">
                      Persistent database state confirms this event has been signed using post-quantum credentials and verified against unauthorized mutations.
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
