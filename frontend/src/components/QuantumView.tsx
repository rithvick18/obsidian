import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Key, 
  Sparkles, 
  Activity, 
  Cpu, 
  FileLock, 
  RotateCw,
  Zap,
  Shield,
  HelpCircle
} from 'lucide-react';
import { ALGORITHM_PERFORMANCE } from '../mockData';

export default function QuantumView() {
  const [selectedAlgo, setSelectedAlgo] = useState('ML-KEM-768');
  const [entropyLevel, setEntropyLevel] = useState(92.4);
  const [isGenerating, setIsGenerating] = useState(false);
  const [generationLogs, setGenerationLogs] = useState<string[]>([
    'System status: Stable. Ready for quantum safe encryption audit.',
    'Click "Generate Safe PQC Key" above to deploy cryptographic lattice layers.'
  ]);

  const handleGenerateKey = () => {
    setIsGenerating(true);
    const newLogs = [
      `[INIT] Launching Lattice-Based Key Generator sequence...`,
      `[STEP 1] Acquiring high-entropy pool sample... (Level: ${entropyLevel}%)`,
      `[STEP 2] Running multi-dimensional matrix noise injection...`,
      `[STEP 3] Formulating secret polynomial parameters with standard lattice width (k=3)...`,
      `[SUCCESS] Key generation completed successfully under standard ML-KEM protocol.`,
      `[PUBLIC KEY SHA256] 0x${Math.random().toString(16).substring(2, 10)}...${Math.random().toString(16).substring(2, 10)}`,
      `[VERIFIED] Key verified for zero-knowledge decryption.`
    ];

    let currentStep = 0;
    setGenerationLogs([]);
    
    const interval = setInterval(() => {
      if (currentStep < newLogs.length) {
        setGenerationLogs(prev => [...prev, newLogs[currentStep]]);
        currentStep++;
      } else {
        clearInterval(interval);
        setIsGenerating(false);
        // Slightly fluctuate entropy levels for live interaction
        setEntropyLevel(prev => Math.min(100, Math.max(80, parseFloat((prev + (Math.random() * 4 - 2)).toFixed(1)))));
      }
    }, 400);
  };

  return (
    <div className="space-y-6">
      {/* Upper Quantum Summary row */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Lattice Entropy status (Left column, span 7) */}
        <div className="col-span-12 lg:col-span-7 glass-panel p-6 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex justify-between items-center mb-4">
              <div>
                <span className="text-xs font-bold text-primary uppercase tracking-wider">Lattice Security</span>
                <h3 className="font-headline-sm text-xl font-bold text-on-surface mt-1">Entropy Pool Metrics</h3>
              </div>
              <span className="px-2.5 py-1 bg-primary/20 border border-primary/40 text-primary text-xs rounded font-bold uppercase tracking-wider">
                256-bit Safe
              </span>
            </div>
            <p className="text-sm text-on-surface-variant mb-6">
              Active quantum-safe entropy streams gathered from cloud-based hardware random generators (TRNGs). Currently operating at peak coherence levels.
            </p>

            {/* Simulated Live visual pool */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              <div className="bg-surface-container-lowest p-3 rounded border border-outline-variant/60">
                <span className="text-[10px] text-on-surface-variant uppercase font-bold">Entropy Density</span>
                <div className="text-lg font-mono font-bold text-on-surface mt-1">H = 7.994</div>
              </div>
              <div className="bg-surface-container-lowest p-3 rounded border border-outline-variant/60">
                <span className="text-[10px] text-on-surface-variant uppercase font-bold">Coherence Rate</span>
                <div className="text-lg font-mono font-bold text-primary mt-1">{entropyLevel}%</div>
              </div>
              <div className="bg-surface-container-lowest p-3 rounded border border-outline-variant/60">
                <span className="text-[10px] text-on-surface-variant uppercase font-bold">Active Seeds</span>
                <div className="text-lg font-mono font-bold text-secondary mt-1">1,024/sec</div>
              </div>
              <div className="bg-surface-container-lowest p-3 rounded border border-outline-variant/60">
                <span className="text-[10px] text-on-surface-variant uppercase font-bold">Safe Subnets</span>
                <div className="text-lg font-mono font-bold text-on-surface mt-1">14/14</div>
              </div>
            </div>
          </div>

          {/* Entropy Fill Bar */}
          <div className="space-y-2">
            <div className="flex justify-between items-center text-xs">
              <span className="text-on-surface-variant">Lattice Coherence Bar</span>
              <span className="font-mono text-primary font-bold">{entropyLevel}% Stable</span>
            </div>
            <div className="w-full h-2.5 bg-surface-container-highest rounded-full overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-primary to-secondary transition-all duration-500 rounded-full"
                style={{ width: `${entropyLevel}%` }}
              ></div>
            </div>
          </div>
        </div>

        {/* Algorithm config / slider (Right column, span 5) */}
        <div className="col-span-12 lg:col-span-5 glass-panel p-6 rounded-xl flex flex-col justify-between">
          <div>
            <h3 className="font-headline-sm text-base font-bold text-on-surface flex items-center gap-2 mb-2">
              <FileLock className="text-primary" size={18} />
              Algorithm Selector
            </h3>
            <p className="text-xs text-on-surface-variant mb-4">
              Select a target post-quantum encryption primitive to seed corporate subnets.
            </p>

            <div className="space-y-2.5 mb-6">
              {['ML-KEM-768', 'ML-DSA-65', 'AES-256-GCM'].map(algo => (
                <button
                  key={algo}
                  onClick={() => setSelectedAlgo(algo)}
                  className={`w-full p-3 rounded border text-left flex justify-between items-center transition-all cursor-pointer ${
                    selectedAlgo === algo
                      ? 'border-primary bg-primary/10 text-on-surface font-semibold'
                      : 'border-outline-variant hover:border-on-surface-variant/40 bg-surface-container-lowest/40 text-on-surface-variant'
                  }`}
                >
                  <span className="flex items-center gap-2.5 text-sm font-mono">
                    <Shield size={14} className={selectedAlgo === algo ? 'text-primary' : 'text-on-surface-variant'} />
                    {algo}
                  </span>
                  <span className="text-xs uppercase px-2 py-0.5 rounded bg-surface-container-high text-[10px] font-bold">
                    {algo === 'AES-256-GCM' ? 'Quantum Safe' : 'NIST Approved'}
                  </span>
                </button>
              ))}
            </div>
          </div>

          <button
            onClick={handleGenerateKey}
            disabled={isGenerating}
            className={`w-full py-3 font-mono text-xs rounded transition-all uppercase tracking-widest font-bold flex items-center justify-center gap-2 cursor-pointer ${
              isGenerating
                ? 'bg-outline-variant text-on-surface-variant cursor-not-allowed'
                : 'bg-primary hover:bg-primary-container text-on-primary'
            }`}
          >
            {isGenerating ? (
              <>
                <RotateCw className="animate-spin" size={14} />
                Running Lattice Math...
              </>
            ) : (
              <>
                <Zap size={14} />
                Generate Safe PQC Key
              </>
            )}
          </button>
        </div>
      </div>

      {/* Generation Logs Console & Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Console logs terminal */}
        <div className="col-span-12 lg:col-span-7 glass-panel rounded-xl flex flex-col overflow-hidden h-[340px]">
          <div className="p-4 bg-bg-sidebar border-b border-outline-variant/60 flex justify-between items-center">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-error"></span>
              <span className="w-3 h-3 rounded-full bg-secondary"></span>
              <span className="w-3 h-3 rounded-full bg-primary"></span>
              <span className="text-xs font-mono text-on-surface-variant ml-2">lattice-generator-shell v2.1</span>
            </div>
            <span className="text-[10px] font-mono text-primary font-bold">ACTIVE DEPLOYMENT</span>
          </div>
          <div className="p-4 bg-bg-base flex-1 font-mono text-xs text-secondary/90 overflow-y-auto space-y-2 select-all">
            {generationLogs.map((log, i) => (
              <div 
                key={i} 
                className={`whitespace-pre-wrap transition-opacity duration-300 ${
                  log.startsWith('[SUCCESS]') 
                    ? 'text-[#4edea3] font-bold' 
                    : log.startsWith('[INIT]') 
                    ? 'text-primary font-semibold' 
                    : 'text-on-surface-variant'
                }`}
              >
                {log}
              </div>
            ))}
            {isGenerating && (
              <span className="inline-block w-2 h-4 bg-primary animate-pulse ml-1"></span>
            )}
          </div>
        </div>

        {/* Latency and Size breakdown statistics */}
        <div className="col-span-12 lg:col-span-5 glass-panel rounded-xl p-6 flex flex-col justify-between">
          <div>
            <h3 className="font-headline-sm text-base font-bold text-on-surface mb-3 flex items-center gap-2">
              <Activity className="text-primary" size={18} />
              PQC Algorithm Velocity
            </h3>
            <p className="text-xs text-on-surface-variant mb-4">
              Real-world benchmark comparing processing latency overhead across multiple key exchange variations.
            </p>

            <div className="space-y-3.5">
              {ALGORITHM_PERFORMANCE.map(algo => (
                <div key={algo.name} className="flex justify-between items-center text-xs">
                  <div>
                    <span className="font-mono font-semibold text-on-surface block">{algo.name}</span>
                    <span className="text-[10px] text-on-surface-variant">{algo.level} • {algo.size}</span>
                  </div>
                  <div className="text-right">
                    <span className="font-mono text-primary font-bold block">
                      {algo.latency > 1000 ? `${(algo.latency / 1000).toFixed(1)}s` : `${algo.latency}ms`}
                    </span>
                    <span className={`text-[9px] font-bold px-1.5 py-0.2 rounded ${
                      algo.status === 'OPTIMIZED' 
                        ? 'bg-[#005236] text-[#4edea3]' 
                        : algo.status === 'ACTIVE' 
                        ? 'bg-primary/20 text-primary' 
                        : 'bg-error/20 text-error'
                    }`}>
                      {algo.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-4 border-t border-outline-variant/40 flex justify-between items-center text-[10px] text-on-surface-variant">
            <span>* Latency measured using multi-threaded WebAssembly</span>
            <span className="text-primary hover:underline cursor-pointer">View full benchmarks</span>
          </div>
        </div>
      </div>
    </div>
  );
}
