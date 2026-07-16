import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { ShieldAlert, UserCheck, Lock, Key, AlertTriangle, CheckCircle2, X } from 'lucide-react';

interface DualControlModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAuthorize: (approver: string) => void;
  actionType: string;
  targetEntity: string;
}

const APPROVERS = [
  {
    id: 'Approver: t.daniels.sec_lead',
    name: 'T. Daniels',
    role: 'Principal Security Lead',
    department: 'SOC Architecture',
    badge: 'HSM Token ID: #902-SEC',
    avatar: 'TD',
  },
  {
    id: 'Approver: m.chen.ciso',
    name: 'M. Chen',
    role: 'Chief Information Security Officer',
    department: 'Executive Leadership',
    badge: 'Executive Root Key: #101-EX',
    avatar: 'MC',
  },
  {
    id: 'Approver: r.vance.vp_sec',
    name: 'R. Vance',
    role: 'VP of Infrastructure Security',
    department: 'Core Networks',
    badge: 'Hardware Signer: #412-VP',
    avatar: 'RV',
  },
];

export default function DualControlModal({
  isOpen,
  onClose,
  onAuthorize,
  actionType,
  targetEntity,
}: DualControlModalProps) {
  const [selectedApprover, setSelectedApprover] = useState<string>(APPROVERS[0].id);
  const [isSigning, setIsSigning] = useState(false);

  if (!isOpen) return null;

  const actionLabels: Record<string, { title: string; desc: string; color: string }> = {
    FORCE_ROTATE: {
      title: 'Manual Force-Rotate & PQC Rekeying',
      desc: 'Revoke active credentials and generate post-quantum lattice keys across targeted subnets.',
      color: 'text-primary border-primary/30 bg-primary/10',
    },
    ISOLATE_HOST: {
      title: 'Virtual Host Containment & Quarantine',
      desc: 'Sever all outbound network routes and place the targeted host into strict quarantine sandbox.',
      color: 'text-error border-error/30 bg-error/10',
    },
    TERMINATE_SESSION: {
      title: 'Forceful Privileged Session Lockout',
      desc: 'Sever active TTY pipeline and revoke underlying cryptographic session tokens immediately.',
      color: 'text-amber-500 border-amber-500/30 bg-amber-500/10',
    },
    GENERATE_KEY: {
      title: 'Corporate Lattice Seed Key Synchronization',
      desc: 'Deploy FIPS 203 ML-KEM and ML-DSA post-quantum primitives across enterprise infrastructure.',
      color: 'text-secondary border-secondary/30 bg-secondary/10',
    },
  };

  const info = actionLabels[actionType] || {
    title: `Structural Intervention: [${actionType}]`,
    desc: 'Perform high-impact enterprise operational override.',
    color: 'text-primary border-primary/30 bg-primary/10',
  };

  const handleConfirm = () => {
    setIsSigning(true);
    setTimeout(() => {
      setIsSigning(false);
      onAuthorize(selectedApprover);
    }, 600);
  };

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-md">
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 15 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 15 }}
          transition={{ duration: 0.2 }}
          className="w-full max-w-lg glass-panel rounded-2xl border border-outline-variant shadow-2xl overflow-hidden bg-bg-card/95"
        >
          {/* Header */}
          <div className="p-5 bg-bg-sidebar border-b border-outline-variant/60 flex justify-between items-start">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-error/15 border border-error/30 text-error glow-red">
                <ShieldAlert size={24} />
              </div>
              <div>
                <span className="text-[10px] font-mono uppercase tracking-widest text-error font-bold block">
                  DUAL-CONTROL PROTOCOL ENFORCED
                </span>
                <h3 className="font-headline-sm text-lg font-bold text-on-surface">
                  The Four-Eyes Principle
                </h3>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high transition-colors"
            >
              <X size={18} />
            </button>
          </div>

          {/* Body Content */}
          <div className="p-6 space-y-5">
            {/* Intervention Summary Banner */}
            <div className={`p-4 rounded-xl border ${info.color}`}>
              <div className="flex justify-between items-start">
                <span className="text-xs font-mono font-bold uppercase tracking-wider block">
                  {actionType}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface-container-highest/80 font-bold uppercase">
                  Target: {targetEntity}
                </span>
              </div>
              <h4 className="font-sans font-bold text-sm mt-1">{info.title}</h4>
              <p className="text-xs opacity-90 mt-1 leading-relaxed">{info.desc}</p>
            </div>

            {/* Primary Operator Display */}
            <div className="flex items-center justify-between p-3.5 rounded-xl bg-surface-container-lowest/60 border border-outline-variant/60">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center font-bold text-xs text-primary">
                  OP
                </div>
                <div>
                  <div className="text-[10px] text-on-surface-variant uppercase font-bold tracking-wider">
                    Primary Initiating Operator
                  </div>
                  <div className="text-xs font-bold text-on-surface font-mono">
                    SOC_Operator_04 (Tier-3 Analyst)
                  </div>
                </div>
              </div>
              <span className="text-[10px] font-bold text-[#4edea3] bg-[#005236]/30 border border-[#005236] px-2 py-0.5 rounded font-mono">
                VERIFIED
              </span>
            </div>

            {/* Secondary Approver Selection */}
            <div>
              <label className="text-xs font-bold text-on-surface uppercase tracking-wider block mb-2.5 flex items-center gap-1.5">
                <UserCheck size={14} className="text-secondary" />
                Select Secondary Security Approver (Required Sign-Off):
              </label>
              <div className="space-y-2.5">
                {APPROVERS.map((appr) => {
                  const isSelected = selectedApprover === appr.id;
                  return (
                    <div
                      key={appr.id}
                      onClick={() => setSelectedApprover(appr.id)}
                      className={`p-3.5 rounded-xl border cursor-pointer flex items-center justify-between transition-all ${
                        isSelected
                          ? 'bg-secondary/15 border-secondary text-on-surface shadow-md'
                          : 'bg-surface-container-lowest/30 border-outline-variant/60 text-on-surface-variant hover:border-on-surface-variant/40'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <div
                          className={`w-9 h-9 rounded-full flex items-center justify-center font-bold text-xs ${
                            isSelected
                              ? 'bg-secondary text-on-primary font-black'
                              : 'bg-surface-container-high text-on-surface-variant'
                          }`}
                        >
                          {appr.avatar}
                        </div>
                        <div>
                          <div className="text-sm font-bold text-on-surface leading-tight">
                            {appr.name}{' '}
                            <span className="text-xs font-normal opacity-80">({appr.role})</span>
                          </div>
                          <div className="text-[10px] font-mono opacity-80 mt-0.5">
                            {appr.department} • {appr.badge}
                          </div>
                        </div>
                      </div>
                      <div
                        className={`w-5 h-5 rounded-full border flex items-center justify-center ${
                          isSelected
                            ? 'border-secondary bg-secondary text-on-primary'
                            : 'border-outline-variant'
                        }`}
                      >
                        {isSelected && <CheckCircle2 size={13} />}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Cryptographic notice */}
            <div className="flex items-center gap-2 text-[11px] text-on-surface-variant font-mono bg-surface-container/40 p-2.5 rounded border border-outline-variant/40">
              <Key size={14} className="text-primary shrink-0" />
              <span>
                Both profiles must cryptographically co-sign this action using ML-DSA-85 keys before execution.
              </span>
            </div>
          </div>

          {/* Footer Actions */}
          <div className="p-5 bg-bg-sidebar border-t border-outline-variant/60 flex justify-end gap-3">
            <button
              onClick={onClose}
              disabled={isSigning}
              className="px-4 py-2 rounded-lg text-xs font-mono uppercase font-bold text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleConfirm}
              disabled={isSigning}
              className={`px-5 py-2.5 rounded-lg text-xs font-mono uppercase font-bold flex items-center gap-2 transition-all shadow-lg ${
                isSigning
                  ? 'bg-outline-variant text-on-surface-variant cursor-not-allowed'
                  : 'bg-secondary hover:bg-secondary/85 text-on-primary glow-cyan'
              }`}
            >
              {isSigning ? (
                <>
                  <Lock className="animate-spin" size={14} />
                  Co-Signing Payload...
                </>
              ) : (
                <>
                  <UserCheck size={14} />
                  Authorize & Dispatch Payload
                </>
              )}
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
