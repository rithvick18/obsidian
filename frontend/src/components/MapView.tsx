import React, { useState, useEffect } from 'react';
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

interface AttackSignal {
  id: number;
  origin: string;
  target: string;
  severity: 'critical' | 'high' | 'medium';
  rate: string;
}

export default function MapView() {
  const [utcTime, setUtcTime] = useState('');
  const [signals, setSignals] = useState<AttackSignal[]>([
    { id: 1, origin: 'Frankfurt, DE (185.12.99.102)', target: 'Chennai Cloud Hub', severity: 'high', rate: '1.2 GB/s' },
    { id: 2, origin: 'Kiev, UA (45.128.11.94)', target: 'SV-PROD-DB-02', severity: 'critical', rate: 'Bulk SQL' },
    { id: 3, origin: 'Beijing, CN (112.90.1.18)', target: 'EMEA Subnet Router', severity: 'medium', rate: '600 KB/s' },
  ]);

  useEffect(() => {
    // Update live clock
    const updateTime = () => {
      const now = new Date();
      setUtcTime(now.toUTCString().replace('GMT', 'UTC'));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Simulate new signals appearing dynamically over time
  useEffect(() => {
    const generator = setInterval(() => {
      const origins = [
        'Seoul, KR (210.12.9.4)',
        'Amsterdam, NL (82.11.9.155)',
        'Singapore, SG (103.4.12.22)',
        'Sao Paulo, BR (177.10.22.9)'
      ];
      const targets = [
        'London Financial Vault',
        'US-West Endpoint Node',
        'K8s Core Cluster',
        'Corporate VPN Gateway'
      ];
      const severities: ('critical' | 'high' | 'medium')[] = ['medium', 'high', 'critical'];
      const rates = ['800 KB/s', '1.4 GB/s', 'Sync Request', 'SSH Brute'];

      const randomSignal: AttackSignal = {
        id: Date.now(),
        origin: origins[Math.floor(Math.random() * origins.length)],
        target: targets[Math.floor(Math.random() * targets.length)],
        severity: severities[Math.floor(Math.random() * severities.length)],
        rate: rates[Math.floor(Math.random() * rates.length)]
      };

      setSignals(prev => [randomSignal, ...prev.slice(0, 4)]);
    }, 4000);

    return () => clearInterval(generator);
  }, []);

  return (
    <div className="space-y-6">
      
      {/* Upper Map area */}
      <div className="glass-panel p-6 rounded-xl flex flex-col justify-between relative min-h-[460px] overflow-hidden">
        
        {/* World Grid Matrix Backdrop */}
        <div className="absolute inset-0 opacity-[0.03] pointer-events-none" style={{ backgroundImage: 'radial-gradient(#adc6ff 1.5px, transparent 1.5px)', backgroundSize: '24px 24px' }}></div>
        
        {/* Vector SVG Stylized Threat Connections Map */}
        <div className="absolute inset-0 flex items-center justify-center p-8 opacity-65 z-0">
          <svg className="w-full h-full max-w-4xl" viewBox="0 0 800 400" preserveAspectRatio="xMidYMid meet">
            {/* Soft background outlines for continents / global mesh */}
            <path d="M150,120 Q160,100 220,130 T300,100" fill="none" stroke="rgba(66,71,84,0.15)" strokeWidth="1.5" />
            <path d="M400,150 Q450,110 520,160 T650,120" fill="none" stroke="rgba(66,71,84,0.15)" strokeWidth="1.5" />
            <path d="M200,240 Q250,280 320,250 T380,290" fill="none" stroke="rgba(66,71,84,0.15)" strokeWidth="1.5" />

            {/* Glowing lines representing connections */}
            {/* Connection 1: Frankfurt -> Chennai */}
            <path d="M420,140 Q510,180 580,260" fill="none" stroke="#adc6ff" strokeWidth="1.5" className="animate-pulse-slow" />
            <path d="M420,140 Q510,180 580,260" fill="none" stroke="#4edea3" strokeWidth="1" strokeDasharray="6 4" className="animate-flow" />

            {/* Connection 2: Kiev -> San Jose */}
            <path d="M450,120 Q300,100 200,180" fill="none" stroke="#ef4444" strokeWidth="1.5" className="animate-pulse-slow" />
            <path d="M450,120 Q300,100 200,180" fill="none" stroke="#ef4444" strokeWidth="1" strokeDasharray="5 5" className="animate-flow" />

            {/* Glowing city beacons */}
            {/* San Jose */}
            <circle cx="200" cy="180" r="4" fill="#4edea3" className="glow-cyan" />
            <circle cx="200" cy="180" r="12" fill="none" stroke="#4edea3" strokeWidth="1" className="animate-ping" style={{ animationDuration: '3s' }} />

            {/* Kiev */}
            <circle cx="450" cy="120" r="4.5" fill="#ef4444" />
            <circle cx="450" cy="120" r="14" fill="none" stroke="#ef4444" strokeWidth="1" className="animate-ping" style={{ animationDuration: '2s' }} />

            {/* Frankfurt */}
            <circle cx="420" cy="140" r="4" fill="#ef4444" />
            <circle cx="420" cy="140" r="12" fill="none" stroke="#ef4444" strokeWidth="1" className="animate-ping" style={{ animationDuration: '2.5s' }} />

            {/* Chennai */}
            <circle cx="580" cy="260" r="4" fill="#4edea3" />
            <circle cx="580" cy="260" r="12" fill="none" stroke="#4edea3" strokeWidth="1" className="animate-ping" style={{ animationDuration: '4s' }} />
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
              <span className="text-[10px] text-on-surface-variant uppercase">Threat Rate</span>
              <span className="font-mono text-error font-bold block mt-0.5">48/Min</span>
            </div>
            <div className="p-2 bg-bg-base rounded border border-outline-variant/60">
              <span className="text-[10px] text-on-surface-variant uppercase">Lockouts Applied</span>
              <span className="font-mono text-secondary font-bold block mt-0.5">14 Active</span>
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
              {signals.map((sig, idx) => (
                <tr key={sig.id} className="border-b border-outline-variant/30 hover:bg-surface-container-high/15 transition-colors">
                  <td className="p-4 font-mono text-xs text-on-surface-variant">{sig.id.toString().substring(5, 12)}</td>
                  <td className="p-4 font-bold text-on-surface">{sig.origin}</td>
                  <td className="p-4 font-mono text-xs text-primary">{sig.target}</td>
                  <td className="p-4 font-mono text-xs text-on-surface-variant">{sig.rate}</td>
                  <td className="p-4 text-right">
                    <span className={`inline-block text-[9px] font-mono font-bold px-2.5 py-0.5 rounded ${
                      sig.severity === 'critical' 
                        ? 'bg-error-container/20 text-error border border-error/20' 
                        : sig.severity === 'high'
                        ? 'bg-amber-500/20 text-amber-500 border border-amber-500/20'
                        : 'bg-primary/20 text-primary border border-primary/20'
                    }`}>
                      {sig.severity.toUpperCase()}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
