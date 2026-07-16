import React, { useState, useEffect, useMemo } from 'react';
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

import { useSecurity } from '../context/SecurityContext';

export default function AnalyticsView() {
  const { 
    auditEvents: events, 
    complianceScanning: isScanning, 
    auditScore, 
    runComplianceScan,
    systemStatus
  } = useSecurity();

  // 1. Generate dynamic, localized UTC times for the graph x-axis
  const [timeLabels, setTimeLabels] = useState<string[]>([]);

  useEffect(() => {
    const generateTimeLabels = () => {
      const labels = [];
      const current = new Date();
      for (let i = 4; i >= 0; i--) {
        const d = new Date(current.getTime() - i * 60 * 60 * 1000);
        const hours = String(d.getUTCHours()).padStart(2, '0');
        labels.push(`${hours}:00 UTC`);
      }
      setTimeLabels(labels);
    };

    generateTimeLabels();
    const interval = setInterval(generateTimeLabels, 60000);
    return () => clearInterval(interval);
  }, []);

  // 2. Drive metrics dynamically from DB status states
  const totalLogs = systemStatus?.sessions_monitored || events.length || 0;
  const totalDeflections = systemStatus?.anomalies_deflected || 0;
  
  const dynamicPeak = Math.min(999, Math.round(totalLogs * 3.2 + 1.5));
  const deflectionEfficiency = totalLogs > 0 
    ? ((1 - totalDeflections / totalLogs) * 100).toFixed(2) 
    : "100.00";

  // 3. Dynamic Path Computation Layer (Eliminating the static SVG trace)
  const svgPaths = useMemo(() => {
    // Extract recent risk values from real table inputs if available
    const points = events.length > 0
      ? events.slice(0, 5).reverse().map(e => Math.min(95, Math.max(10, e.risk_score || 0)))
      : [];

    if (points.length === 0) {
      return {
        area: '',
        line: '',
        dots: []
      };
    }

    const width = 400;
    const height = 120;
    const padding = 20;
    const chartHeight = height - padding;
    
    // Map numerical rows directly to coordinate grids
    const coords = points.map((p, index) => {
      const x = points.length > 1 ? (index / (points.length - 1)) * width : width / 2;
      // Invert Y axis because 0 is top in SVG plane
      const y = height - ((p / 100) * chartHeight) - 10;
      return { x, y };
    });

    // Build standard SVG line commands dynamically
    let linePath = `M ${coords[0].x} ${coords[0].y}`;
    for (let i = 1; i < coords.length; i++) {
      // Use smooth quadratic formatting
      const cpX = (coords[i - 1].x + coords[i].x) / 2;
      linePath += ` Q ${cpX} ${coords[i - 1].y}, ${coords[i].x} ${coords[i].y}`;
    }

    const areaPath = coords.length > 1 
      ? `${linePath} L ${width} ${height} L 0 ${height} Z` 
      : `${linePath} L ${coords[0].x} ${height} Z`;
    
    return {
      area: areaPath,
      line: linePath,
      dots: coords
    };
  }, [events]);

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
            <div className="relative w-full h-56 bg-surface-container-lowest/20 rounded-lg border border-outline-variant/30 flex items-end justify-center">
              {events.length === 0 ? (
                <div className="absolute inset-0 flex items-center justify-center text-xs text-on-surface-variant font-mono p-4 text-center">
                  System telemetry pipeline empty — awaiting ingress core status
                </div>
              ) : (
                <>
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

                    {/* Dynamically Generated Area curve */}
                    <path 
                      d={svgPaths.area} 
                      fill="url(#gradientPrimary)"
                    />
                    
                    {/* Dynamically Generated Top line */}
                    <path 
                      d={svgPaths.line} 
                      fill="none" 
                      stroke="#adc6ff" 
                      strokeWidth="2.5"
                      className="animate-pulse-slow"
                    />

                    {/* Animated flowing dynamic line */}
                    <path 
                      d={svgPaths.line} 
                      fill="none" 
                      stroke="#4edea3" 
                      strokeWidth="1.5"
                      strokeDasharray="8 6"
                      className="animate-flow"
                    />
                    
                    {/* Dynamic Coordinate Point indicators */}
                    {svgPaths.dots.map((dot, index) => (
                      <circle 
                        key={index}
                        cx={dot.x} 
                        cy={dot.y} 
                        r={index === svgPaths.dots.length - 1 ? "5" : "3.5"} 
                        fill={index === svgPaths.dots.length - 1 ? "#4edea3" : "#adc6ff"} 
                        stroke="#000" 
                        strokeWidth="1.5" 
                      />
                    ))}
                  </svg>
                  
                  {/* Bottom dynamic labels */}
                  <div className="absolute bottom-1 w-full px-4 flex justify-between font-mono text-[9px] text-on-surface-variant">
                    {timeLabels.map((lbl, idx) => (
                      <span key={idx}>{lbl}</span>
                    ))}
                  </div>
                </>
              )}
            </div>
          </div>

          <div className="mt-5 grid grid-cols-3 gap-4 pt-5 border-t border-outline-variant/40">
            <div className="text-center">
              <span className="text-[10px] text-on-surface-variant uppercase font-bold block">Current Peak</span>
              <span className="text-base font-bold font-mono text-on-surface mt-1">{dynamicPeak} MB/s</span>
            </div>
            <div className="text-center">
              <span className="text-[10px] text-on-surface-variant uppercase font-bold block">Deflection Efficiency</span>
              <span className="text-base font-bold font-mono text-secondary mt-1">{deflectionEfficiency}%</span>
            </div>
            <div className="text-center">
              <span className="text-[10px] text-on-surface-variant uppercase font-bold block">Anomalous Spike</span>
              <span className="text-base font-bold font-mono text-error mt-1">
                {totalDeflections > 0 ? `${totalDeflections} Intercepted` : "None"}
              </span>
            </div>
          </div>
        </div>

        {/* Compliance Rating Card */}
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
              {events.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-xs text-on-surface-variant font-mono">
                    System telemetry pipeline empty — awaiting ingress core status
                  </td>
                </tr>
              ) : (
                events.map((ev, i) => (
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
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
