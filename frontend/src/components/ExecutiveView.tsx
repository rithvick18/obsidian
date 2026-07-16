import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { 
  ShieldAlert, 
  Cpu, 
  Clock, 
  BrainCircuit, 
  TrendingUp, 
  AlertTriangle,
  FileSpreadsheet,
  Zap,
  Activity,
  CheckCircle,
  HelpCircle,
  Lock
} from 'lucide-react';

import { useSecurity } from '../context/SecurityContext';

export default function ExecutiveView() {
  const { systemStatus, incidents } = useSecurity();

  const activeIncidents = incidents.filter(i => i.status !== 'Mitigated');
  const riskIndex = activeIncidents.length > 0 
    ? Math.max(...activeIncidents.map(i => i.severity === 'critical' ? 95 : 80)) 
    : 12.4;

  const healthScore = parseFloat(Math.max(10, 100 - (activeIncidents.length * 24.2)).toFixed(1));

  return (
    <div className="space-y-6">
      {/* Top Header Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Risk Index Card */}
        <div className="glass-panel p-6 rounded-xl relative overflow-hidden group hover:border-secondary/40 transition-colors duration-300">
          <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
            <ShieldAlert size={64} className="text-secondary" />
          </div>
          <div className="flex justify-between items-start mb-4">
            <div>
              <p className="font-label-md text-on-surface-variant uppercase tracking-wider text-xs">Risk Index</p>
              <h2 className="font-display-lg text-4xl font-bold mt-1 text-on-surface">{riskIndex}</h2>
            </div>
            <span className={`font-label-md px-2.5 py-1 rounded text-xs font-semibold ${
              activeIncidents.length > 0 ? 'text-error bg-error/10' : 'text-secondary bg-[#005236]'
            }`}>
              {activeIncidents.length > 0 ? `+${(activeIncidents.length * 15).toFixed(1)}%` : '-4.2%'}
            </span>
          </div>
          <div className="w-full h-1 bg-surface-container-highest rounded-full overflow-hidden">
            <div className="h-full bg-secondary" style={{ width: `${Math.min(100, riskIndex)}%` }}></div>
          </div>
          <p className="mt-4 text-sm text-on-surface-variant">Optimal range maintained across all 48 secure nodes.</p>
        </div>

        {/* Quantum Readiness Card */}
        <div className="glass-panel p-6 rounded-xl relative overflow-hidden group hover:border-primary/40 transition-colors duration-300">
          <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
            <Cpu size={64} className="text-primary" />
          </div>
          <div>
            <p className="font-label-md text-on-surface-variant uppercase tracking-wider text-xs">Quantum Readiness</p>
            <h2 className="font-display-lg text-4xl font-bold mt-1 text-primary">88%</h2>
          </div>
          <div className="flex gap-1.5 mt-4">
            <div className="flex-1 h-8 bg-primary/20 border-t-2 border-primary/50 rounded-sm"></div>
            <div className="flex-1 h-8 bg-primary/20 border-t-2 border-primary/50 rounded-sm"></div>
            <div className="flex-1 h-8 bg-primary/20 border-t-2 border-primary/50 rounded-sm"></div>
            <div className="flex-1 h-8 bg-primary/5 border-t border-outline-variant rounded-sm"></div>
          </div>
          <p className="mt-4 text-sm text-on-surface-variant font-sans">Lattice-based cryptography deployment at 92%.</p>
        </div>

        {/* Mean Response Time Card */}
        <div className="glass-panel p-6 rounded-xl relative overflow-hidden group hover:border-primary/40 transition-colors duration-300">
          <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
            <Clock size={64} className="text-primary" />
          </div>
          <div>
            <p className="font-label-md text-on-surface-variant uppercase tracking-wider text-xs">Mean Response Time</p>
            <h2 className="font-display-lg text-4xl font-bold mt-1 text-on-surface">1.8m</h2>
          </div>
          <div className="mt-4 flex items-end gap-1.5 h-10">
            <div className="w-3 h-1/2 bg-outline-variant rounded-t-sm"></div>
            <div className="w-3 h-2/3 bg-outline-variant rounded-t-sm"></div>
            <div className="w-3 h-full bg-primary rounded-t-sm"></div>
            <div className="w-3 h-3/4 bg-outline-variant rounded-t-sm"></div>
            <div className="w-3 h-1/2 bg-outline-variant rounded-t-sm"></div>
          </div>
          <p className="mt-4 text-sm text-on-surface-variant">42% mitigation speed improvement vs last quarter.</p>
        </div>
      </div>

      {/* Center Circle Gauge and Sidebar Insights */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        
        {/* Center Health Ring (Left Column) */}
        <div className="col-span-12 lg:col-span-8 glass-panel rounded-xl p-8 flex flex-col items-center justify-center relative min-h-[460px]">
          <div className="absolute inset-0 opacity-[0.03] pointer-events-none" style={{ backgroundImage: 'radial-gradient(#adc6ff 1px, transparent 1px)', backgroundSize: '16px 16px' }}></div>
          
          <div className="relative z-10 flex flex-col items-center">
            {/* Health Ring Gauge */}
            <div className="relative w-72 h-72 flex items-center justify-center animate-pulse-slow">
              <svg className="absolute inset-0 w-full h-full -rotate-90" viewBox="0 0 100 100">
                <circle className="text-surface-container-highest" cx="50" cy="50" fill="none" r="43" stroke="currentColor" strokeWidth="2"></circle>
                <circle 
                  className="text-primary health-ring-glow transition-all duration-1000" 
                  cx="50" 
                  cy="50" 
                  fill="none" 
                  r="43" 
                  stroke="currentColor" 
                  strokeDasharray="270" 
                  strokeDashoffset={270 - (270 * 97.6) / 100} 
                  strokeWidth="3.5"
                  strokeLinecap="round"
                ></circle>
              </svg>
              <div className="text-center px-4">
                <div className="font-label-md text-on-surface-variant text-xs tracking-[0.25em] uppercase mb-1">Overall Health</div>
                <div className="font-display-lg text-6xl font-bold gradient-text">{healthScore}</div>
                <div className={`font-headline-sm text-lg font-bold tracking-widest uppercase mt-2 ${
                  healthScore < 60 ? 'text-error animate-pulse' : healthScore < 85 ? 'text-amber-500' : 'text-secondary'
                }`}>
                  {healthScore < 60 ? 'Critical' : healthScore < 85 ? 'Warning' : 'Excellent'}
                </div>
              </div>
            </div>

            {/* Ingress stats bar below ring */}
            <div className="mt-10 glass-panel px-8 py-3 rounded-full border border-primary/20 flex gap-8 items-center bg-surface-container-lowest/80 backdrop-blur-md">
              <div className="text-center">
                <div className="text-[10px] text-on-surface-variant uppercase font-bold tracking-wider">Sessions Monitored</div>
                <div className="font-headline-sm text-primary font-bold text-lg">{systemStatus?.sessions_monitored ?? '1,240'}</div>
              </div>
              <div className="w-px h-8 bg-outline-variant"></div>
              <div className="text-center">
                <div className="text-[10px] text-on-surface-variant uppercase font-bold tracking-wider">Throughput</div>
                <div className="font-headline-sm text-primary font-bold text-lg">4.2 GB/s</div>
              </div>
              <div className="w-px h-8 bg-outline-variant"></div>
              <div className="text-center">
                <div className="text-[10px] text-on-surface-variant uppercase font-bold tracking-wider">Threats Deflected</div>
                <div className="font-headline-sm text-secondary font-bold text-lg">{systemStatus?.anomalies_deflected ?? '821'}</div>
              </div>
            </div>
          </div>
        </div>

        {/* AI Strategy Insights (Right Column) */}
        <div className="col-span-12 lg:col-span-4 glass-panel rounded-xl flex flex-col justify-between overflow-hidden">
          <div className="p-6 border-b border-outline-variant bg-surface-container-high/40">
            <h3 className="font-headline-sm text-lg font-bold text-on-surface flex items-center gap-2">
              <BrainCircuit className="text-primary" size={20} />
              AI Strategy Insights
            </h3>
          </div>
          <div className="p-6 flex-1 flex flex-col gap-5 overflow-y-auto">
            <div className="border-l-2 border-secondary pl-4 py-1">
              <p className="text-xs font-bold text-secondary uppercase tracking-widest mb-1">High Confidence</p>
              <p className="text-sm text-on-surface">Predictive intelligence model suggests a 12% rise in phish query activities targeting local vendor routes next week.</p>
            </div>
            <div className="border-l-2 border-primary pl-4 py-1 opacity-90">
              <p className="text-xs font-bold text-primary uppercase tracking-widest mb-1">Policy Recommendation</p>
              <p className="text-sm text-on-surface">Recommend certificate rotation in EMEA subnet branches to proactively eliminate entropy decay patterns.</p>
            </div>
            <div className="border-l-2 border-outline-variant pl-4 py-1 opacity-70">
              <p className="text-xs font-bold text-on-surface-variant uppercase tracking-widest mb-1">Operational Note</p>
              <p className="text-sm text-on-surface">Alert response bandwidth can be reduced by 14% via automation rules for local directory diagnostics.</p>
            </div>
          </div>
          <div className="p-4 bg-surface-container-lowest/30 border-t border-outline-variant/30">
            <button className="w-full py-2.5 bg-primary hover:bg-primary-container text-on-primary font-bold text-xs rounded transition-all uppercase tracking-widest cursor-pointer">
              Open Strategy Board
            </button>
          </div>
        </div>
      </div>

      {/* Bottom Row Bento Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Business Impact Card */}
        <div className="col-span-12 lg:col-span-4 glass-panel rounded-xl p-6 border-l-4 border-l-primary flex flex-col justify-between">
          <div className="flex justify-between items-center mb-6">
            <h3 className="font-headline-sm text-base font-bold text-on-surface">Business Impact</h3>
            <TrendingUp className="text-primary" size={20} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-surface-container-lowest p-3 rounded-lg border border-outline-variant">
              <div className="text-xs text-on-surface-variant">Uptime Value</div>
              <div className="text-lg font-bold text-primary mt-1">$1.2M</div>
            </div>
            <div className="bg-surface-container-lowest p-3 rounded-lg border border-outline-variant">
              <div className="text-xs text-on-surface-variant">Loss Avoidance</div>
              <div className="text-lg font-bold text-secondary mt-1">$480K</div>
            </div>
          </div>
          <p className="mt-4 text-xs text-on-surface-variant">Cyber liability insurance reporting values verified at 100% compliance levels.</p>
        </div>

        {/* Critical Risks & Vulnerabilities List */}
        <div className="col-span-12 lg:col-span-8 glass-panel rounded-xl p-6 border-l-4 border-l-error">
          <div className="flex justify-between items-center mb-4">
            <h3 className="font-headline-sm text-base font-bold text-on-surface flex items-center gap-2">
              <AlertTriangle className="text-error" size={18} />
              Critical Risks &amp; Vulnerabilities
            </h3>
            <div className="flex gap-2">
              <span className="px-2.5 py-0.5 rounded bg-error-container/20 text-error text-[10px] font-bold uppercase tracking-wider border border-error/30">
                2 Critical
              </span>
              <span className="px-2.5 py-0.5 rounded bg-surface-container-highest text-on-surface-variant text-[10px] font-bold uppercase tracking-wider">
                14 Moderate
              </span>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="text-on-surface-variant text-[10px] uppercase font-bold tracking-widest border-b border-outline-variant/60 pb-2">
                  <th className="pb-2">Risk Factor</th>
                  <th className="pb-2">Source</th>
                  <th className="pb-2">Remediation Status</th>
                  <th className="pb-2 text-right">Impact Score</th>
                </tr>
              </thead>
              <tbody className="text-sm font-sans">
                <tr className="border-b border-outline-variant/30 hover:bg-surface-container-high/20 transition-colors">
                  <td className="py-3 font-semibold text-on-surface">Zero-Day: "Frostbyte"</td>
                  <td className="py-3 font-mono text-xs text-on-surface-variant">172.16.0.42</td>
                  <td className="py-3 flex items-center gap-2 text-error">
                    <span className="w-2 h-2 rounded-full bg-error animate-pulse"></span>
                    In Progress
                  </td>
                  <td className="py-3 text-right text-error font-bold font-mono">9.8/10</td>
                </tr>
                <tr className="hover:bg-surface-container-high/20 transition-colors">
                  <td className="py-3 font-semibold text-on-surface">Lateral Movement Detected</td>
                  <td className="py-3 font-mono text-xs text-on-surface-variant">EMEA-DB-01</td>
                  <td className="py-3 flex items-center gap-2 text-secondary">
                    <span className="w-2 h-2 rounded-full bg-secondary"></span>
                    Quarantined
                  </td>
                  <td className="py-3 text-right text-on-surface font-bold font-mono">7.2/10</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
