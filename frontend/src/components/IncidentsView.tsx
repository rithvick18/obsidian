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

const defaultIncident: Incident = {
  id: 'N/A',
  title: 'No Incident Selected',
  timeAgo: '',
  severity: 'medium',
  tags: [],
  impactedEntity: 'N/A',
  assignee: 'Unassigned',
  status: 'Investigating',
  attackChain: {
    node1: 'N/A',
    node2: 'N/A',
    node3: 'N/A',
  },
  timeline: [],
};

import { useSecurity } from '../context/SecurityContext';

export default function IncidentsView() {
  const { incidents, isolateHost, mitigateIncidentDirect, forceRotateUser } = useSecurity();
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('');
  const [isolationRunning, setIsolationRunning] = useState<string | null>(null);

  const selectedIncident = incidents.find(inc => inc.id === selectedIncidentId) || incidents[0] || defaultIncident;

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

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
      
      {/* Left Column: Incidents List (span 5) */}
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
          {incidents.map((inc) => {
            const isSelected = inc.id === selectedIncidentId;
            return (
              <div
                key={inc.id}
                onClick={() => setSelectedIncidentId(inc.id)}
                className={`glass-panel p-4 rounded-xl cursor-pointer transition-all duration-200 border-l-4 ${
                  isSelected 
                    ? 'border-primary bg-primary/[0.04]' 
                    : 'border-l-transparent hover:border-l-outline-variant'
                } ${
                  inc.severity === 'critical' 
                    ? 'border-l-error' 
                    : 'border-l-amber-500'
                }`}
              >
                <div className="flex justify-between items-start mb-2">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-on-surface-variant font-bold">{inc.id}</span>
                      <span className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded uppercase ${
                        inc.status === 'Mitigated' 
                          ? 'bg-[#005236] text-[#4edea3]' 
                          : inc.status === 'Investigating' 
                          ? 'bg-primary/20 text-primary' 
                          : 'bg-error/20 text-error'
                      }`}>
                        {inc.status}
                      </span>
                    </div>
                    <h4 className="font-sans font-bold text-sm text-on-surface line-clamp-1 leading-tight">{inc.title}</h4>
                  </div>
                  <span className="text-xs text-on-surface-variant font-mono whitespace-nowrap">{inc.timeAgo}</span>
                </div>

                <div className="flex flex-wrap gap-1.5 mt-3">
                  {inc.tags.map(tag => (
                    <span key={tag} className="text-[10px] bg-surface-container-lowest text-on-surface-variant border border-outline-variant/60 px-2 py-0.5 rounded">
                      {tag}
                    </span>
                  ))}
                </div>

                <div className="mt-3.5 pt-3.5 border-t border-outline-variant/30 flex justify-between items-center text-xs text-on-surface-variant">
                  <span className="flex items-center gap-1.5 font-sans">
                    <Cpu size={12} className="text-primary" />
                    {inc.impactedEntity}
                  </span>
                  <span className="flex items-center gap-1">
                    <User size={12} className="text-on-surface-variant" />
                    {inc.assignee}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Right Column: Deep Incident Details & Sandbox Actions (span 7) */}
      <div className="col-span-12 xl:col-span-7 flex flex-col gap-6">
        <div className="glass-panel rounded-xl p-6 relative overflow-hidden flex-1">
      <div className="flex flex-col sm:flex-row justify-between sm:items-start gap-4 border-b border-outline-variant/50 pb-5 mb-5">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <span className="font-mono text-sm text-primary font-bold">{selectedIncident?.id}</span>
            <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
              selectedIncident?.severity === 'critical'
                ? 'bg-error-container/20 text-error border border-error/20'
                : 'bg-amber-500/20 text-amber-500 border border-amber-500/20'
            }`}>
              {selectedIncident?.severity?.toUpperCase()}
            </span>
          </div>
          <h2 className="font-headline-sm text-lg sm:text-xl font-bold text-on-surface leading-snug">{selectedIncident?.title}</h2>
          <p className="text-xs text-on-surface-variant font-sans mt-1">Impacted Target Object: <span className="font-mono font-bold text-on-surface">{selectedIncident?.impactedEntity}</span></p>
        </div>
            
            {/* Action Group */}
            <div className="flex flex-wrap gap-2.5 sm:self-center">
              <button
                onClick={() => forceRotateUser(selectedIncident?.impactedEntity || '')}
                disabled={selectedIncident?.status === 'Mitigated'}
                className={`py-2 px-3.5 rounded text-xs font-mono uppercase tracking-wider font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                  selectedIncident?.status === 'Mitigated'
                    ? 'bg-outline-variant text-on-surface-variant cursor-not-allowed'
                    : 'bg-primary/20 border border-primary/40 hover:bg-primary/30 text-primary'
                }`}
              >
                <RotateCw size={13} />
                Force Rotate
              </button>
              <button
                onClick={() => handleIsolateHost(selectedIncident?.impactedEntity || '')}
                disabled={isolationRunning !== null || selectedIncident?.status === 'Mitigated'}
                className={`py-2 px-3.5 rounded text-xs font-mono uppercase tracking-wider font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                  selectedIncident?.status === 'Mitigated'
                    ? 'bg-outline-variant text-on-surface-variant cursor-not-allowed'
                    : 'bg-error hover:bg-error/80 text-white'
                }`}
              >
                {isolationRunning === selectedIncident?.impactedEntity ? (
                  <>
                    <RotateCw className="animate-spin" size={13} />
                    ISOLATING...
                  </>
                ) : (
                  <>
                    <Lock size={13} />
                    Isolate Impacted Host
                  </>
                )}
              </button>
              {selectedIncident?.status !== 'Mitigated' && (
                <button
                  onClick={handleMitigateDirect}
                  className="py-2 px-3.5 bg-secondary hover:bg-secondary/80 text-white rounded text-xs font-mono uppercase tracking-wider font-bold transition-all cursor-pointer"
                >
                  Mark Mitigated
                </button>
              )}
            </div>
          </div>

          {/* Honeypot & Tamper Lock Banner if present */}
          {selectedIncident?.isHoneypot && (
            <div className="mb-6 p-4 rounded-xl bg-error/10 border-2 border-error/50 flex items-start gap-3">
              <span className="text-2xl">🍯</span>
              <div className="flex-1">
                <h4 className="text-xs font-bold text-error uppercase tracking-wider">Canary Honeypot Triggered & Tamper-Evident Lock Engaged</h4>
                <p className="text-xs text-on-surface-variant mt-1">Zero-tolerance IoC tripped. ML-DSA signature baseline locked against root modification.</p>
                {selectedIncident.tamperLockSignature && (
                  <div className="mt-2 p-2 rounded bg-surface-container-lowest font-mono text-[10px] text-amber-300 break-all border border-outline-variant">
                    LOCK SIG: {selectedIncident.tamperLockSignature}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Attack Chain Node Visualization */}
          <div className="mb-6">
            <h3 className="text-xs font-bold text-on-surface-variant uppercase tracking-wider mb-3">Attack Chain Vector</h3>
            <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant/60 flex items-center justify-between overflow-x-auto gap-4">
              <div className="flex-1 min-w-[110px] text-center p-2.5 rounded bg-bg-node border border-outline-variant">
                <div className="text-[9px] text-on-surface-variant uppercase font-bold tracking-wider">Node 1</div>
                <div className="text-xs text-primary font-bold font-mono mt-1">{selectedIncident?.attackChain?.node1}</div>
              </div>
              <div className="w-6 h-0.5 bg-outline-variant relative">
                <span className="absolute -top-1 right-0 w-2 h-2 rounded-full bg-primary"></span>
              </div>
              <div className="flex-1 min-w-[110px] text-center p-2.5 rounded bg-bg-node border border-outline-variant">
                <div className="text-[9px] text-on-surface-variant uppercase font-bold tracking-wider">Node 2</div>
                <div className="text-xs text-secondary font-bold font-mono mt-1">{selectedIncident?.attackChain?.node2}</div>
              </div>
              <div className="w-6 h-0.5 bg-outline-variant relative">
                <span className="absolute -top-1 right-0 w-2 h-2 rounded-full bg-secondary"></span>
              </div>
              <div className="flex-1 min-w-[110px] text-center p-2.5 rounded bg-bg-node border border-error">
                <div className="text-[9px] text-error uppercase font-bold tracking-wider">Node 3</div>
                <div className="text-xs text-error font-bold font-mono mt-1">{selectedIncident?.attackChain?.node3}</div>
              </div>
            </div>
          </div>

          {/* Timeline of Incident Events */}
          <div>
            <h3 className="text-xs font-bold text-on-surface-variant uppercase tracking-wider mb-4">Threat Timeline Logs</h3>
            <div className="relative border-l-2 border-outline-variant/50 pl-6 ml-3 space-y-5 max-h-[300px] overflow-y-auto">
              {selectedIncident?.timeline?.map((item: any, index: number) => (
                <div key={index} className="relative">
                  {/* Dot */}
                  <span className={`absolute -left-[31px] top-1 w-2.5 h-2.5 rounded-full border-2 ${
                    item.type === 'error' 
                      ? 'bg-error border-error' 
                      : item.type === 'success' 
                      ? 'bg-secondary border-secondary' 
                      : item.type === 'warning' 
                      ? 'bg-amber-500 border-amber-500' 
                      : 'bg-outline-variant border-outline-variant'
                  }`}></span>
                  
                  <div className="flex flex-col sm:flex-row sm:justify-between items-start gap-1">
                    <span className="font-mono text-xs text-primary font-bold">{item.time}</span>
                    {item.statusBadge && (
                      <span className="px-1.5 py-0.2 bg-surface-container-highest text-on-surface text-[8px] font-mono font-bold rounded">
                        {item.statusBadge}
                      </span>
                    )}
                  </div>
                  <h4 className="font-sans font-bold text-sm text-on-surface mt-1">{item.title}</h4>
                  <p className="text-xs text-on-surface-variant mt-0.5 font-sans leading-relaxed">{item.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
