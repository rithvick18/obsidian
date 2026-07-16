import React, { useState } from 'react';
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
  HelpCircle,
  Play
} from 'lucide-react';
import { INITIAL_SESSIONS } from '../mockData';
import { PrivilegedSession } from '../types';

export default function SessionsView() {
  const [sessions, setSessions] = useState<PrivilegedSession[]>(INITIAL_SESSIONS);
  const [selectedSessionId, setSelectedSessionId] = useState<string>(INITIAL_SESSIONS[0].id);

  const selectedSession = sessions.find(sess => sess.id === selectedSessionId) || sessions[0];

  const handleTerminateSession = () => {
    setSessions(prevSessions => 
      prevSessions.map(sess => {
        if (sess.id === selectedSession.id) {
          // Check if already terminated
          if (sess.status === 'Terminated') return sess;
          
          const updatedLogs = [
            ...sess.logs,
            '-------------------------------------------------------',
            `[ADMIN LOCKOUT TRIGGERED AT ${new Date().toLocaleTimeString()}]`,
            'FATAL: Session forcefully severed by Security Operator command.',
            'Connection closed. Return Code: 137'
          ];
          
          return {
            ...sess,
            status: 'Terminated' as const,
            logs: updatedLogs,
            riskIndex: 100
          };
        }
        return sess;
      })
    );
  };

  const handleFlagSession = () => {
    setSessions(prevSessions => 
      prevSessions.map(sess => {
        if (sess.id === selectedSession.id) {
          if (sess.status === 'Flagged') return sess;
          return {
            ...sess,
            status: 'Flagged' as const,
            riskIndex: Math.min(100, sess.riskIndex + 15)
          };
        }
        return sess;
      })
    );
  };

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
      
      {/* Left Column: Sessions List (span 5) */}
      <div className="col-span-12 xl:col-span-5 flex flex-col gap-4">
        <div className="glass-panel p-4 rounded-xl flex justify-between items-center bg-surface-container-high/20">
          <div className="flex items-center gap-2">
            <Users size={16} className="text-primary" />
            <h3 className="font-headline-sm text-sm font-bold text-on-surface uppercase tracking-wider">Active Secure Pipelines</h3>
          </div>
          <span className="text-xs text-on-surface-variant font-mono">{sessions.filter(s => s.status !== 'Terminated').length} Live Pipelines</span>
        </div>

        <div className="space-y-3.5 max-h-[640px] overflow-y-auto pr-1">
          {sessions.map((sess) => {
            const isSelected = sess.id === selectedSessionId;
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
                    ? 'border-l-error' 
                    : 'border-l-secondary'
                }`}
              >
                <div className="flex justify-between items-start mb-2">
                  <div className="flex items-center gap-3">
                    {/* Initials Avatar */}
                    <div className="w-9 h-9 rounded-full bg-bg-badge border border-outline-variant/60 flex items-center justify-center font-bold text-primary text-xs">
                      {sess.avatarInitials}
                    </div>
                    <div>
                      <h4 className="font-sans font-bold text-sm text-on-surface leading-tight">{sess.user}</h4>
                      <p className="text-[11px] font-mono text-on-surface-variant mt-0.5">{sess.ipAddress}</p>
                    </div>
                  </div>
                  <span className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded uppercase ${
                    sess.status === 'Terminated' 
                      ? 'bg-outline-variant/20 text-on-surface-variant' 
                      : sess.status === 'Flagged' 
                      ? 'bg-error-container/20 text-error' 
                      : 'bg-secondary/20 text-[#4edea3]'
                  }`}>
                    {sess.status}
                  </span>
                </div>

                <div className="mt-3.5 pt-3.5 border-t border-outline-variant/30 flex justify-between items-center text-xs text-on-surface-variant">
                  <span className="flex items-center gap-1.5 font-sans">
                    {sess.resourceType === 'database' ? (
                      <Database size={12} className="text-primary" />
                    ) : sess.resourceType === 'key' ? (
                      <FileKey size={12} className="text-secondary" />
                    ) : (
                      <Server size={12} className="text-primary" />
                    )}
                    {sess.resource}
                  </span>
                  <span className="font-mono text-on-surface-variant flex items-center gap-1">
                    <Clock size={11} />
                    {sess.duration}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Right Column: Console terminal & sliders (span 7) */}
      <div className="col-span-12 xl:col-span-7 flex flex-col gap-6">
        <div className="glass-panel rounded-xl p-6 relative overflow-hidden flex-1 flex flex-col justify-between">
          
          <div>
            {/* Upper console header */}
            <div className="flex flex-col sm:flex-row justify-between sm:items-start gap-4 border-b border-outline-variant/50 pb-5 mb-5">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-bg-badge border border-outline-variant flex items-center justify-center font-bold text-primary">
                  {selectedSession.avatarInitials}
                </div>
                <div>
                  <h2 className="font-headline-sm text-lg font-bold text-on-surface leading-tight">{selectedSession.user}</h2>
                  <p className="text-xs text-on-surface-variant font-sans mt-0.5">Device Source Origin: <span className="font-mono font-bold text-on-surface">{selectedSession.sourceDevice} ({selectedSession.ipAddress})</span></p>
                </div>
              </div>

              {/* Console Action buttons */}
              <div className="flex gap-2 sm:self-center">
                <button 
                  onClick={handleFlagSession}
                  disabled={selectedSession.status === 'Terminated' || selectedSession.status === 'Flagged'}
                  className={`py-2 px-3 rounded text-xs font-mono uppercase font-bold transition-all ${
                    selectedSession.status === 'Terminated' || selectedSession.status === 'Flagged'
                      ? 'bg-outline-variant/10 text-on-surface-variant cursor-not-allowed'
                      : 'bg-amber-500/20 text-amber-500 border border-amber-500/30 hover:bg-amber-500/30'
                  }`}
                >
                  Flag Session
                </button>
                <button 
                  onClick={handleTerminateSession}
                  disabled={selectedSession.status === 'Terminated'}
                  className={`py-2 px-3 rounded text-xs font-mono uppercase font-bold transition-all ${
                    selectedSession.status === 'Terminated'
                      ? 'bg-outline-variant/10 text-on-surface-variant cursor-not-allowed'
                      : 'bg-error hover:bg-error/80 text-white'
                  }`}
                >
                  Terminate Session
                </button>
              </div>
            </div>

            {/* Dials / stats bar (Cadence & Intention) */}
            <div className="grid grid-cols-2 gap-4 mb-5">
              <div className="p-3.5 bg-surface-container-lowest/60 rounded-xl border border-outline-variant/60">
                <span className="text-[10px] text-on-surface-variant uppercase font-bold tracking-wider">Typing Cadence (Biometrics)</span>
                <div className="flex items-center gap-2 mt-1.5">
                  <div className="flex-1 bg-surface-container-highest h-2 rounded-full overflow-hidden">
                    <div className="bg-primary h-full rounded-full" style={{ width: `${selectedSession.typingCadence}%` }}></div>
                  </div>
                  <span className="font-mono text-xs text-on-surface font-bold">{selectedSession.typingCadence}%</span>
                </div>
              </div>
              <div className="p-3.5 bg-surface-container-lowest/60 rounded-xl border border-outline-variant/60">
                <span className="text-[10px] text-on-surface-variant uppercase font-bold tracking-wider">Command Intention Confidence</span>
                <div className="flex items-center gap-2 mt-1.5">
                  <div className="flex-1 bg-surface-container-highest h-2 rounded-full overflow-hidden">
                    <div className={`h-full rounded-full ${
                      selectedSession.commandIntention < 50 ? 'bg-error' : 'bg-secondary'
                    }`} style={{ width: `${selectedSession.commandIntention}%` }}></div>
                  </div>
                  <span className="font-mono text-xs text-on-surface font-bold">{selectedSession.commandIntention}%</span>
                </div>
              </div>
            </div>

            {/* Interactive console screen */}
            <div className="flex flex-col rounded-xl overflow-hidden h-[260px] border border-outline-variant">
              <div className="bg-bg-sidebar px-4 py-2 border-b border-outline-variant/60 flex justify-between items-center text-xs font-mono">
                <span className="text-on-surface-variant flex items-center gap-1.5">
                  <Terminal size={12} className="text-primary" />
                  tty-pipeline-{selectedSession.id}
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
                {selectedSession.logs.map((log, i) => (
                  <div 
                    key={i} 
                    className={`whitespace-pre-wrap ${
                      log.startsWith('CRITICAL:') || log.startsWith('Policy Breach:') || log.startsWith('FATAL:')
                        ? 'text-error font-bold bg-error-container/10 p-1.5 rounded border border-error/20' 
                        : log.startsWith('[SESSION START') || log.startsWith('[ADMIN TERMINATED') || log.startsWith('[ADMIN LOCKOUT')
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
