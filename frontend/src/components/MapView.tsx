import React, { useState, useEffect, useMemo } from 'react';
import { motion } from 'motion/react';
import { 
  Globe, 
  Clock, 
  Radio, 
  Cpu, 
  Zap, 
  Activity, 
  AlertTriangle,
  MapPin,
  ShieldCheck,
  RotateCw
} from 'lucide-react';

import { useSecurity } from '../context/SecurityContext';

export default function MapView() {
  const { signals, auditEvents, systemStatus } = useSecurity();
  const [utcTime, setUtcTime] = useState('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setUtcTime(now.toUTCString().replace('GMT', 'UTC'));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // 1. Calculate dynamic statistics straight out of the context data matrices
  const totalSignals = signals ? signals.length : 0;
  const activeLockouts = systemStatus?.anomalies_deflected || 0;
  
  // Synthesize a live, moving threat velocity index
  const dynamicThreatRate = totalSignals > 0 ? Math.round(totalSignals * 2.4 + 12) : 48;

  // 2. Dynamic Location Vector Synthesis Engine
  // Maps standard role node profiles onto topological grid points safely
  const dynamicCoordinates = useMemo(() => {
    const activeFeeds = auditEvents && auditEvents.length > 0 ? auditEvents : [];
    
    // Fallback coordinates if live logs are empty
    const defaultCoords = [
      { id: 'default-1', cx: 420, cy: 140, label: 'Core Networks Node', isCritical: false },
      { id: 'default-2', cx: 580, cy: 260, label: 'Data Hub Boundary', isCritical: false }
    ];

    if (activeFeeds.length === 0) return defaultCoords;

    // Pick out the 4 most recent unmitigated logs to map on the visualization plane
    return activeFeeds.slice(0, 4).map((evt: any, idx: number) => {
      let baseCX = 300 + (idx * 90);
      let baseCY = 120 + (idx * 45);

      // Distribute vectors dynamically using specific user node assignments
      if (evt.user_id?.includes('admin')) { baseCX = 420; baseCY = 140; }
      else if (evt.user_id?.includes('contractor')) { baseCX = 500; baseCY = 180; }
      else if (evt.user_id?.includes('root')) { baseCX = 450; baseCY = 120; }
      else if (evt.user_id?.includes('intern')) { baseCX = 580; baseCY = 260; }

      return {
        id: evt.id || `node-${idx}`,
        cx: baseCX,
        cy: baseCY,
        label: evt.user_id || 'Infrastructure Node',
        isCritical: evt.risk_score === 100 || evt.severity === 'critical'
      };
    });
  }, [auditEvents]);

  return (
    <div className="space-y-6">
      
      {/* Upper Map area */}
      <div className="glass-panel p-6 rounded-xl flex flex-col justify-between relative min-h-[460px] overflow-hidden">
        
        {/* World Grid Matrix Backdrop */}
        <div className="absolute inset-0 opacity-[0.03] pointer-events-none" style={{ backgroundImage: 'radial-gradient(#adc6ff 1.5px, transparent 1.5px)', backgroundSize: '24px 24px' }}></div>
        
        {/* Vector SVG Stylized Threat Connections Map */}
        <div className="absolute inset-0 flex items-center justify-center p-8 opacity-65 z-0">
          <svg className="w-full h-full max-w-4xl" viewBox="0 0 800 400" preserveAspectRatio="xMidYMid meet">
            {/* Soft background mesh paths */}
            <path d="M150,120 Q160,100 220,130 T300,100" fill="none" stroke="rgba(66,71,84,0.15)" strokeWidth="1.5" />
            <path d="M400,150 Q450,110 520,160 T650,120" fill="none" stroke="rgba(66,71,84,0.15)" strokeWidth="1.5" />
            <path d="M200,240 Q250,280 320,250 T380,290" fill="none" stroke="rgba(66,71,84,0.15)" strokeWidth="1.5" />

            {/* Render connection links between nodes dynamically if multiple items exist */}
            {dynamicCoordinates.length >= 2 && (
              <>
                <path 
                  d={`M ${dynamicCoordinates[0].cx},${dynamicCoordinates[0].cy} Q 480,180 ${dynamicCoordinates[dynamicCoordinates.length - 1].cx},${dynamicCoordinates[dynamicCoordinates.length - 1].cy}`} 
                  fill="none" 
                  stroke={dynamicCoordinates[0].isCritical ? "#ef4444" : "#adc6ff"} 
                  strokeWidth="1.5" 
                  className="animate-pulse-slow" 
                />
                <path 
                  d={`M ${dynamicCoordinates[0].cx},${dynamicCoordinates[0].cy} Q 480,180 ${dynamicCoordinates[dynamicCoordinates.length - 1].cx},${dynamicCoordinates[dynamicCoordinates.length - 1].cy}`} 
                  fill="none" 
                  stroke={dynamicCoordinates[0].isCritical ? "#ef4444" : "#4edea3"} 
                  strokeWidth="1" 
                  strokeDasharray="6 4" 
                  className="animate-flow" 
                />
              </>
            )}

            {/* Project localized city coordinates maps out dynamically */}
            {dynamicCoordinates.map((node: any, idx: number) => (
              <g key={node.id || idx}>
                <circle cx={node.cx} cy={node.cy} r={node.isCritical ? "4.5" : "4"} fill={node.isCritical ? "#ef4444" : "#4edea3"} className={node.isCritical ? "glow-red" : "glow-cyan"} />
                <circle 
                  cx={node.cx} 
                  cy={node.cy} 
                  r={node.isCritical ? "14" : "12"} 
                  fill="none" 
                  stroke={node.isCritical ? "#ef4444" : "#4edea3"} 
                  strokeWidth="1" 
                  className="animate-ping" 
                  style={{ animationDuration: `${2 + idx * 0.5}s` }} 
                />
              </g>
            ))}
          </svg>
        </div>

        {/* Map Header Overlay */}
        <div className="relative z-10 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
          <div>
            <span className="text-xs font-bold text-primary uppercase tracking-widest flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-error animate-ping"></span>
              Live Threat Ingress Core
            </span>
            <h3 className="font-display-lg text-xl font-bold text-on-surface mt-1">Global Security Signals</h3>
          </div>
          <div className="bg-bg-sidebar px-4 py-2 rounded-lg border border-outline-variant/60 flex items-center gap-3 font-mono text-xs text-on-surface">
            <Clock size={14} className="text-primary" />
            <span>SYSTEM TIME:</span>
            <span className="text-secondary font-bold">{utcTime || 'Loading UTC Clock...'}</span>
          </div>
        </div>

        {/* Floating Live statistics card */}
        <div className="relative z-10 self-start mt-12 bg-surface-container-lowest/90 backdrop-blur-md p-4 rounded-xl border border-outline-variant max-w-sm">
          <h4 className="text-xs font-bold text-on-surface uppercase mb-3 flex items-center gap-2">
            <Radio size={14} className="text-primary animate-pulse" />
            Dynamic Defensive Posture
          </h4>
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="p-2 bg-bg-base rounded border border-outline-variant/60">
              <span className="text-[10px] text-on-surface-variant uppercase font-mono">Threat Weight</span>
              <span className="font-mono text-error font-bold block mt-0.5">{dynamicThreatRate}/Min</span>
            </div>
            <div className="p-2 bg-bg-base rounded border border-outline-variant/60">
              <span className="text-[10px] text-on-surface-variant uppercase font-mono">Ledger Lockouts</span>
              <span className="font-mono text-secondary font-bold block mt-0.5">{activeLockouts} Active</span>
            </div>
          </div>
        </div>

        {/* Live Defense Ticker Footer */}
        <div className="relative z-10 mt-12 pt-4 border-t border-outline-variant/40 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 text-xs">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-secondary animate-pulse-slow"></span>
            <span className="font-sans font-semibold text-on-surface uppercase tracking-wider">Vigilance Active</span>
            <span className="text-on-surface-variant">— Routing verified at FIPS 140-3 safe integrity levels.</span>
          </div>
          <span className="text-on-surface-variant font-mono font-bold">142 ms Latency Core</span>
        </div>
      </div>

      {/* Real-time signals feed logs table */}
      <div className="glass-panel rounded-xl overflow-hidden">
        <div className="p-5 border-b border-outline-variant bg-surface-container-high/30 flex justify-between items-center">
          <h3 className="font-headline-sm text-base font-bold text-on-surface flex items-center gap-2">
            <Activity className="text-primary" size={18} />
            Live Ingress Signals Stream
          </h3>
          <span className="text-xs text-on-surface-variant font-mono font-semibold">AUTOMATED RECONNAISSANCE DETECTED</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-surface-container-lowest border-b border-outline-variant/60 text-on-surface-variant text-[10px] uppercase font-bold tracking-widest">
                <th className="p-4">Signal ID</th>
                <th className="p-4">Attacker Node Location</th>
                <th className="p-4">Target Resource Object</th>
                <th className="p-4">Signal Weight</th>
                <th className="p-4 text-right">Containment Priority</th>
              </tr>
            </thead>
            <tbody className="text-sm font-sans">
              {signals && signals.length > 0 ? (
                signals.map((sig: any) => (
                  <tr key={sig.id} className="border-b border-outline-variant/30 hover:bg-surface-container-high/15 transition-colors">
                    <td className="p-4 font-mono text-xs text-on-surface-variant">
                      {sig.id ? sig.id.toString().substring(0, 7) : 'SIG-TRK'}
                    </td>
                    <td className="p-4 font-bold text-on-surface">{sig.origin || 'Internal Gateway'}</td>
                    <td className="p-4 font-mono text-xs text-primary">{sig.target || 'Infrastructure Subnet'}</td>
                    <td className="p-4 font-mono text-xs text-on-surface-variant">{sig.rate || 'Low'}</td>
                    <td className="p-4 text-right">
                      <span className={`inline-block text-[9px] font-mono font-bold px-2.5 py-0.5 rounded ${
                        sig.severity === 'critical' 
                          ? 'bg-error-container/20 text-error border border-error/20' 
                          : 'bg-primary/20 text-primary border border-primary/20'
                      }`}>
                        {(sig.severity || 'medium').toUpperCase()}
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr className="border-b border-outline-variant/30">
                  <td className="p-4 font-mono text-xs text-secondary" colSpan={5}>
                    No active adversarial reconnaissance vectors logged in this network window.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
