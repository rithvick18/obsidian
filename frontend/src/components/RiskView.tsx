import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  UserCheck, 
  MapPin, 
  Database, 
  ShieldAlert, 
  Server, 
  Activity, 
  FileWarning,
  Flame,
  CheckCircle,
  HelpCircle
} from 'lucide-react';
import { RiskProfile } from '../types';

const defaultProfile: RiskProfile = {
  name: 'No Profile Loaded',
  role: 'Select Profile',
  employeeId: '#N/A',
  office: 'Unknown Hub',
  image: '',
  trustScore: 100,
  anomalySummary: 'No risk profile data currently loaded.',
  heatmap: [
    [0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0],
  ],
  radar: {
    loginRisk: 0,
    accessPattern: 0,
    deviceTrust: 0,
    behaviorScore: 0,
    networkSecurity: 0,
    appIntegrity: 0,
  },
  telemetry: []
};

import { useSecurity } from '../context/SecurityContext';

export default function RiskView() {
  const { profiles } = useSecurity();
  const [selectedProfileIndex, setSelectedProfileIndex] = useState(0);
  const profile: RiskProfile = profiles[selectedProfileIndex] || defaultProfile;

  // Helper to generate the pentagram radar coordinates based on profile score
  const calculateRadarPath = (r: typeof profile.radar) => {
    // 6-axis labels: loginRisk, accessPattern, deviceTrust, behaviorScore, networkSecurity, appIntegrity
    // Let's map each to a coordinate around center (50, 50) with max radius 40.
    const center = 50;
    const maxRadius = 40;
    
    const values = [
      r.loginRisk,
      r.accessPattern,
      r.deviceTrust,
      r.behaviorScore,
      r.networkSecurity,
      r.appIntegrity
    ];
    
    const points = values.map((val, index) => {
      const angle = (index * 2 * Math.PI) / 6 - Math.PI / 2;
      const radius = (val / 100) * maxRadius;
      const x = center + radius * Math.cos(angle);
      const y = center + radius * Math.sin(angle);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    });
    
    return points.join(' ');
  };

  const getRadarOuterPolygon = () => {
    const center = 50;
    const radius = 40;
    const points = [];
    for (let i = 0; i < 6; i++) {
      const angle = (i * 2 * Math.PI) / 6 - Math.PI / 2;
      const x = center + radius * Math.cos(angle);
      const y = center + radius * Math.sin(angle);
      points.push(`${x.toFixed(1)},${y.toFixed(1)}`);
    }
    return points.join(' ');
  };

  const getRadarInnerPolygon = (scale: number) => {
    const center = 50;
    const radius = 40 * scale;
    const points = [];
    for (let i = 0; i < 6; i++) {
      const angle = (i * 2 * Math.PI) / 6 - Math.PI / 2;
      const x = center + radius * Math.cos(angle);
      const y = center + radius * Math.sin(angle);
      points.push(`${x.toFixed(1)},${y.toFixed(1)}`);
    }
    return points.join(' ');
  };

  return (
    <div className="space-y-6">
      
      {/* Switch Profiles header row */}
      <div className="flex gap-4 border-b border-outline-variant pb-4 overflow-x-auto">
        {profiles.map((prof: RiskProfile, index: number) => {
          const isSelected = index === selectedProfileIndex;
          return (
            <button
              key={prof.name}
              onClick={() => setSelectedProfileIndex(index)}
              className={`px-5 py-3 rounded-xl border text-left flex items-center gap-3.5 transition-all cursor-pointer ${
                isSelected 
                  ? 'bg-primary/10 border-primary text-on-surface font-semibold glow-cyan' 
                  : 'bg-surface-container-lowest/30 border-outline-variant text-on-surface-variant hover:border-on-surface-variant/40'
              }`}
            >
              <img 
                src={prof.image} 
                alt={prof.name} 
                className="w-10 h-10 rounded-full border object-cover bg-surface-container-high" 
                referrerPolicy="no-referrer"
              />
              <div>
                <h4 className="text-sm font-sans font-bold leading-tight">{prof.name}</h4>
                <p className="text-[11px] font-mono opacity-80 mt-0.5">{prof.role.split(' • ')[0]}</p>
              </div>
            </button>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        
        {/* Left Side: Avatar and Risk index (span 4) */}
        <div className="col-span-12 lg:col-span-4 glass-panel p-6 rounded-xl flex flex-col justify-between">
          <div className="text-center">
            <div className="relative inline-block mb-4">
              <img 
                src={profile.image} 
                alt={profile.name} 
                className="w-24 h-24 rounded-full mx-auto border-2 border-outline object-cover shadow-lg"
                referrerPolicy="no-referrer"
              />
              <span className={`absolute bottom-0 right-1 w-6 h-6 rounded-full flex items-center justify-center font-bold text-xs text-white ${
                profile.trustScore < 50 ? 'bg-error' : 'bg-secondary'
              }`}>
                !
              </span>
            </div>
            
            <h3 className="font-headline-sm text-lg font-bold text-on-surface leading-tight">{profile.name}</h3>
            <p className="text-xs text-on-surface-variant font-mono mt-1">{profile.employeeId} • {profile.office}</p>

            <div className="mt-6 bg-bg-base border border-outline-variant/60 rounded-xl p-5">
              <span className="text-[10px] text-on-surface-variant uppercase tracking-widest font-bold">Threat Trust Index</span>
              <h2 className={`text-4xl font-mono font-bold mt-1.5 ${
                profile.trustScore < 50 ? 'text-error' : 'text-secondary'
              }`}>
                {profile.trustScore}/100
              </h2>
              <p className="text-[11px] text-on-surface-variant mt-2 font-sans">
                {profile.trustScore < 50 ? 'ACTION REQUIRED: High anomalies detected.' : 'Compliant profile pattern verified.'}
              </p>
            </div>
          </div>

          <p className="text-xs text-on-surface-variant font-sans italic bg-surface-container/30 p-3 rounded border border-outline-variant/30 mt-6 leading-relaxed">
            "{profile.anomalySummary}"
          </p>
        </div>

        {/* Center: Multidimensional Radar (span 4) */}
        <div className="col-span-12 lg:col-span-4 glass-panel p-6 rounded-xl flex flex-col justify-between">
          <div>
            <h3 className="font-headline-sm text-base font-bold text-on-surface flex items-center gap-2 mb-2">
              <Activity className="text-primary" size={18} />
              Multidimensional Risk Radar
            </h3>
            <p className="text-xs text-on-surface-variant mb-4">
              Visual spectrum representing calculated threat indicators across six risk vector subnets.
            </p>
          </div>

          {/* Custom SVG Radar Pentagram Grid */}
          <div className="relative w-56 h-56 mx-auto">
            <svg className="w-full h-full overflow-visible" viewBox="0 0 100 100">
              {/* Outer grid boundary */}
              <polygon points={getRadarOuterPolygon()} fill="none" stroke="rgba(140, 144, 159, 0.2)" strokeWidth="1" />
              <polygon points={getRadarInnerPolygon(0.75)} fill="none" stroke="rgba(140, 144, 159, 0.15)" strokeWidth="0.75" />
              <polygon points={getRadarInnerPolygon(0.5)} fill="none" stroke="rgba(140, 144, 159, 0.15)" strokeWidth="0.75" />
              <polygon points={getRadarInnerPolygon(0.25)} fill="none" stroke="rgba(140, 144, 159, 0.15)" strokeWidth="0.75" />
              
              {/* 6 axes lines */}
              <line x1="50" y1="50" x2="50" y2="10" stroke="rgba(140, 144, 159, 0.2)" strokeWidth="1" />
              <line x1="50" y1="50" x2="84.6" y2="30" stroke="rgba(140, 144, 159, 0.2)" strokeWidth="1" />
              <line x1="50" y1="50" x2="84.6" y2="70" stroke="rgba(140, 144, 159, 0.2)" strokeWidth="1" />
              <line x1="50" y1="50" x2="50" y2="90" stroke="rgba(140, 144, 159, 0.2)" strokeWidth="1" />
              <line x1="50" y1="50" x2="15.4" y2="70" stroke="rgba(140, 144, 159, 0.2)" strokeWidth="1" />
              <line x1="50" y1="50" x2="15.4" y2="30" stroke="rgba(140, 144, 159, 0.2)" strokeWidth="1" />

              {/* Polygon representing the user scores */}
              <polygon 
                points={calculateRadarPath(profile.radar)} 
                fill={profile.trustScore < 50 ? 'rgba(239, 68, 68, 0.25)' : 'rgba(78, 222, 163, 0.25)'} 
                stroke={profile.trustScore < 50 ? '#ef4444' : '#4edea3'} 
                strokeWidth="1.5"
                className="transition-all duration-500"
              />
              
              {/* Micro label markers around axis */}
              <text x="50" y="7" textAnchor="middle" fill="#8c909f" fontSize="4.5" className="font-mono font-bold uppercase">Auth</text>
              <text x="89" y="29" textAnchor="start" fill="#8c909f" fontSize="4.5" className="font-mono font-bold uppercase">Access</text>
              <text x="89" y="73" textAnchor="start" fill="#8c909f" fontSize="4.5" className="font-mono font-bold uppercase">Device</text>
              <text x="50" y="95" textAnchor="middle" fill="#8c909f" fontSize="4.5" className="font-mono font-bold uppercase">Behavior</text>
              <text x="11" y="73" textAnchor="end" fill="#8c909f" fontSize="4.5" className="font-mono font-bold uppercase">Network</text>
              <text x="11" y="29" textAnchor="end" fill="#8c909f" fontSize="4.5" className="font-mono font-bold uppercase">App</text>
            </svg>
          </div>

          <div className="flex justify-between items-center text-[10px] text-on-surface-variant font-mono mt-4">
            <span>Center = 0%</span>
            <span>Edge = 100% Risk</span>
          </div>
        </div>

        {/* Right: Access Velocity Heatmap (span 4) */}
        <div className="col-span-12 lg:col-span-4 glass-panel p-6 rounded-xl flex flex-col justify-between">
          <div>
            <h3 className="font-headline-sm text-base font-bold text-on-surface flex items-center gap-2 mb-2">
              <Flame className="text-primary" size={18} />
              Access Velocity Heatmap
            </h3>
            <p className="text-xs text-on-surface-variant mb-4">
              Heat map illustrating credential usage intensity and impossible-travel login triggers.
            </p>

            {/* Weekly grid map */}
            <div className="space-y-2.5">
              {['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Spike'].map((day, dIdx) => (
                <div key={day} className="flex items-center gap-3">
                  <span className="w-9 text-xs text-on-surface-variant font-mono font-semibold">{day}</span>
                  <div className="flex-1 flex gap-1.5">
                    {((profile.heatmap && profile.heatmap[dIdx]) || [0, 0, 0, 0, 0]).map((val: number, hIdx: number) => {
                      let bgClass = 'bg-bg-node';
                      if (val > 0 && val <= 1) bgClass = 'bg-primary/20';
                      else if (val > 1 && val <= 3) bgClass = 'bg-primary/50';
                      else if (val > 3 && val <= 4) bgClass = 'bg-primary';
                      else if (val > 4) bgClass = profile.trustScore < 50 ? 'bg-error glow-cyan' : 'bg-secondary';
                      
                      return (
                        <div 
                          key={hIdx} 
                          className={`flex-1 h-6 rounded-sm border border-outline-variant/20 transition-all ${bgClass}`}
                          title={`Value: ${val}`}
                        ></div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="flex justify-between items-center text-[10px] text-on-surface-variant font-mono mt-4 pt-3 border-t border-outline-variant/30">
            <span>Low Access</span>
            <div className="flex gap-1">
              <span className="w-2.5 h-2.5 rounded-sm bg-bg-node border border-outline-variant/30"></span>
              <span className="w-2.5 h-2.5 rounded-sm bg-primary/20"></span>
              <span className="w-2.5 h-2.5 rounded-sm bg-primary"></span>
              <span className="w-2.5 h-2.5 rounded-sm bg-error"></span>
            </div>
            <span>Anomalous</span>
          </div>
        </div>
      </div>

      {/* Telemetry Timeline Table */}
      <div className="glass-panel rounded-xl overflow-hidden">
        <div className="p-5 border-b border-outline-variant bg-surface-container-high/30 flex justify-between items-center">
          <h3 className="font-headline-sm text-base font-bold text-on-surface flex items-center gap-2">
            <FileWarning className="text-primary" size={18} />
            Employee Telemetry Feed
          </h3>
          <span className="text-xs text-on-surface-variant font-mono font-bold uppercase">100% AUDITABLE ROUTING</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-surface-container-lowest border-b border-outline-variant/60 text-on-surface-variant text-[10px] uppercase font-bold tracking-widest">
                <th className="p-4">Timestamp</th>
                <th className="p-4">Event Type</th>
                <th className="p-4">Resource Route</th>
                <th className="p-4">Origin Host IP</th>
                <th className="p-4 text-right">Risk Index Delta</th>
              </tr>
            </thead>
            <tbody className="text-sm font-sans">
              {(profile.telemetry || []).map((tel: RiskProfile['telemetry'][number], idx: number) => (
                <tr key={idx} className="border-b border-outline-variant/30 hover:bg-surface-container-high/15 transition-colors">
                  <td className="p-4 font-mono text-xs text-on-surface-variant">{tel.timestamp}</td>
                  <td className="p-4 font-bold text-on-surface">{tel.eventType}</td>
                  <td className="p-4 font-mono text-xs text-primary">{tel.path}</td>
                  <td className="p-4 font-mono text-xs text-on-surface-variant">{tel.sourceIp}</td>
                  <td className={`p-4 text-right font-mono font-bold ${
                    tel.severity === 'error' 
                      ? 'text-error' 
                      : tel.severity === 'warning' 
                      ? 'text-amber-500' 
                      : 'text-secondary'
                  }`}>
                    {tel.riskDelta}
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
