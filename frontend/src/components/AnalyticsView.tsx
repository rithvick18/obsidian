import React, { useState } from 'react';
import { motion } from 'motion/react';
import { 
  Activity, 
  BookOpen, 
  FileCheck, 
  Calendar, 
  RefreshCcw, 
  ArrowUpRight,
  TrendingUp,
  Award,
  AlertOctagon,
  CheckCircle,
  Clock,
  HelpCircle
} from 'lucide-react';
import { AuditEvent } from '../types';

export default function AnalyticsView() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [auditScore, setAuditScore] = useState(94.2);

  const runComplianceScan = () => {
    setIsScanning(true);
    
    setTimeout(() => {
      const newEvent: AuditEvent = {
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        eventType: 'Automated Agent Scan Completed',
        framework: 'NIST-CSF',
        artifactId: `SCN-RES-${Math.floor(Math.random() * 900) + 100}`,
        status: 'Verified',
        icon: 'check_circle',
      };
      setEvents(prev => [newEvent, ...prev]);
      setAuditScore(prev => Math.min(100.0, parseFloat((prev + 0.5).toFixed(1))));
      setIsScanning(false);
    }, 1500);
  };

  return (
    <div className="space-y-6">
      
      {/* Top row: Graph & Audit scorecard */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Network Threat Surface (Left, span 8) */}
        <div className="col-span-12 lg:col-span-8 glass-panel p-6 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex justify-between items-center mb-6">
              <div>
                <span className="text-xs font-bold text-primary uppercase tracking-wider">Live Surface</span>
                <h3 className="font-headline-sm text-lg font-bold text-on-surface mt-0.5">Network Threat Surface Area</h3>
              </div>
              <div className="flex items-center gap-4 text-xs font-mono text-on-surface-variant">
                <span className="flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded-full bg-primary/80"></span> Ingress Rate
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#4edea3]"></span> Safety Margin
                </span>
              </div>
            </div>

            {/* Custom SVG Area Curve Chart */}
            <div className="relative w-full h-56 bg-surface-container-lowest/20 rounded-lg border border-outline-variant/30 flex items-end">
              <svg className="w-full h-full absolute inset-0 overflow-visible" preserveAspectRatio="none" viewBox="0 0 400 120">
                <defs>
                  <linearGradient id="gradientPrimary" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#adc6ff" stopOpacity="0.3"/>
                    <stop offset="100%" stopColor="#adc6ff" stopOpacity="0"/>
                  </linearGradient>
                </defs>
                
                {/* Grid Lines */}
                <line x1="0" y1="30" x2="400" y2="30" stroke="rgba(66,71,84,0.15)" strokeWidth="1" />
                <line x1="0" y1="60" x2="400" y2="60" stroke="rgba(66,71,84,0.15)" strokeWidth="1" />
                <line x1="0" y1="90" x2="400" y2="90" stroke="rgba(66,71,84,0.15)" strokeWidth="1" />

                {/* Main Area curve */}
                <path 
                  d="M0,110 C40,90 60,105 100,70 C140,35 160,80 200,45 C240,10 260,95 300,55 C340,15 360,60 400,25 L400,120 L0,120 Z" 
                  fill="url(#gradientPrimary)"
                />
                
                {/* Top line of area */}
                <path 
                  d="M0,110 C40,90 60,105 100,70 C140,35 160,80 200,45 C240,10 260,95 300,55 C340,15 360,60 400,25" 
                  fill="none" 
                  stroke="#adc6ff" 
                  strokeWidth="2.5"
                  className="animate-pulse-slow"
                />

                {/* Animated flowing line */}
                <path 
                  d="M0,110 C40,90 60,105 100,70 C140,35 160,80 200,45 C240,10 260,95 300,55 C340,15 360,60 400,25" 
                  fill="none" 
                  stroke="#4edea3" 
                  strokeWidth="1.5"
                  strokeDasharray="8 6"
                  className="animate-flow"
                />
                
                {/* Interactive Dot indicators */}
                <circle cx="200" cy="45" r="5" fill="#4edea3" stroke="#000" strokeWidth="1.5" />
                <circle cx="300" cy="55" r="5" fill="#adc6ff" stroke="#000" strokeWidth="1.5" />
              </svg>
              
              {/* Bottom labels */}
              <div className="absolute bottom-1 w-full px-4 flex justify-between font-mono text-[9px] text-on-surface-variant">
                <span>08:00 UTC</span>
                <span>09:00 UTC</span>
                <span>10:00 UTC</span>
                <span>11:00 UTC</span>
                <span>12:00 UTC</span>
              </div>
            </div>
          </div>

          <div className="mt-5 grid grid-cols-3 gap-4 pt-5 border-t border-outline-variant/40">
            <div className="text-center">
              <span className="text-[10px] text-on-surface-variant uppercase font-bold block">Current Peak</span>
              <span className="text-base font-bold font-mono text-on-surface mt-1">481 MB/s</span>
            </div>
            <div className="text-center">
              <span className="text-[10px] text-on-surface-variant uppercase font-bold block">Deflection Efficiency</span>
              <span className="text-base font-bold font-mono text-secondary mt-1">99.98%</span>
            </div>
            <div className="text-center">
              <span className="text-[10px] text-on-surface-variant uppercase font-bold block">Anomalous Spike</span>
              <span className="text-base font-bold font-mono text-error mt-1">None</span>
            </div>
          </div>
        </div>

        {/* Compliance Rating Card (Right, span 4) */}
        <div className="col-span-12 lg:col-span-4 glass-panel p-6 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex justify-between items-center mb-4">
              <h3 className="font-headline-sm text-base font-bold text-on-surface">Audit Assessment</h3>
              <Award className="text-secondary" size={22} />
            </div>
            <p className="text-xs text-on-surface-variant leading-relaxed mb-6">
              Evaluation metrics cross-referenced with regional compliance directories (including GDPR Chapter 4, SOC2 CC3, and NIST-800).
            </p>

            <div className="text-center bg-bg-base border border-outline-variant/60 rounded-xl p-6 mb-6">
              <span className="text-[10px] text-on-surface-variant uppercase tracking-widest font-bold">Consolidated Score</span>
              <h2 className="text-4xl font-bold font-mono text-secondary mt-2">{auditScore}%</h2>
              <span className="text-[10px] text-[#4edea3] font-semibold bg-[#005236] px-2 py-0.5 rounded mt-2 inline-block">
                EXCELLENT STANDING
              </span>
            </div>
          </div>

          <button
            onClick={runComplianceScan}
            disabled={isScanning}
            className={`w-full py-2.5 font-mono text-xs rounded transition-all uppercase tracking-widest font-bold flex items-center justify-center gap-2 cursor-pointer ${
              isScanning
                ? 'bg-outline-variant text-on-surface-variant cursor-not-allowed'
                : 'bg-primary hover:bg-primary-container text-on-primary'
            }`}
          >
            {isScanning ? (
              <>
                <RefreshCcw className="animate-spin" size={13} />
                Scanning Local Nodes...
              </>
            ) : (
              <>
                <FileCheck size={13} />
                Run Compliance Scan
              </>
            )}
          </button>
        </div>
      </div>

      {/* Governance & Compliance Audit timeline list */}
      <div className="glass-panel rounded-xl overflow-hidden">
        <div className="p-5 border-b border-outline-variant bg-surface-container-high/30 flex justify-between items-center">
          <h3 className="font-headline-sm text-base font-bold text-on-surface flex items-center gap-2.5">
            <BookOpen className="text-primary" size={18} />
            Governance &amp; Compliance Audit Logs
          </h3>
          <span className="text-xs text-on-surface-variant font-sans font-medium">Real-Time Evidence Logs</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-surface-container-lowest border-b border-outline-variant/60 text-on-surface-variant text-[10px] uppercase font-bold tracking-widest">
                <th className="p-4">Timestamp</th>
                <th className="p-4">Event Type</th>
                <th className="p-4">Framework</th>
                <th className="p-4">Artifact ID</th>
                <th className="p-4 text-right">Verification Status</th>
              </tr>
            </thead>
            <tbody className="text-sm">
              {events.map((ev, i) => (
                <tr key={i} className="border-b border-outline-variant/30 hover:bg-surface-container-high/15 transition-colors">
                  <td className="p-4 font-mono text-xs text-on-surface-variant">{ev.timestamp}</td>
                  <td className="p-4 font-semibold text-on-surface">{ev.eventType}</td>
                  <td className="p-4 font-bold text-primary font-mono text-xs">{ev.framework}</td>
                  <td className="p-4 font-mono text-xs text-on-surface-variant">{ev.artifactId}</td>
                  <td className="p-4 text-right">
                    <span className={`inline-block text-[9px] font-mono font-bold px-2 py-0.5 rounded ${
                      ev.status === 'Verified' || ev.status === 'Signed'
                        ? 'bg-[#005236] text-[#4edea3]'
                        : ev.status === 'Pending'
                        ? 'bg-amber-500/20 text-amber-500'
                        : 'bg-error/20 text-error'
                    }`}>
                      {ev.status.toUpperCase()}
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
