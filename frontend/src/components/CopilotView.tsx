import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  BrainCircuit, 
  Send, 
  Terminal, 
  Sparkles, 
  User, 
  Bot, 
  Lock, 
  Cpu, 
  Activity, 
  ChevronRight,
  ShieldAlert
} from 'lucide-react';

interface ChatMessage {
  sender: 'user' | 'assistant';
  text: string;
  timestamp: string;
  isStreaming?: boolean;
}

import { useSecurity } from '../context/SecurityContext';

export default function CopilotView() {
  const { sendCopilotMessage } = useSecurity();
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      sender: 'assistant',
      text: "Welcome to **Obsidian Copilot**. I am synchronized with your active XDR telemetry and ready to assist with live triage, automated containment, or cryptographic risk modeling.\n\nHow can I help you secure your enterprise environment today?",
      timestamp: '09:00'
    }
  ]);
  const [inputText, setInputText] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  const SUGGESTIONS = [
    'Explain lateral movement in INC-8429',
    'List vulnerable subnets',
    'Provide post-quantum migration advice',
    'Verify trust score for Arjun Vardhan'
  ];

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  const generateAnswer = (query: string): string => {
    const q = query.toLowerCase();
    
    if (q.includes('inc-8429') || q.includes('lateral')) {
      return `### Threat Analysis: INC-8429 (Unauthorized Database Bulk Export)

**Attack Path Overview:**
The attacker compromised the credential set for **j.smith@obsidian.io** from a Ukrainian IP. They achieved **UAC Bypass (T1068)** to elevate privileges and executed direct mass query exports targeting \`SV-PROD-DB-02\`.

**Recommended Mitigation Playbook:**
1. **Isolate the workstation:** Apply the virtual quarantine sandbox rules to sever outbound routes. *(Click "Isolate Impacted Host" in the Incidents dashboard)*.
2. **Revoke Active SAML Sessions:** Invalidate Smith's SAML tokens to block subsequent database access attempts.
3. **Trigger Password Vault Rotation:** Force immediate rotation of administrative database connection strings.`;
    }
    
    if (q.includes('quantum') || q.includes('pqc') || q.includes('lattice')) {
      return `### Post-Quantum Cryptographic Migration Guide

We are currently transitioning local subnets from legacy asymmetric algorithms (RSA-4096) to NIST-approved **FIPS 203 Lattice Cryptography** standards.

**Current Readiness Standing:**
- **ML-KEM-768 Deployment:** **88% Active**. Remaining subnets include legacy logistics offices in APAC.
- **Latency Impact:** ML-KEM-768 latency is highly optimized (~152.4ms overhead), whereas RSA-4096 exhibits extreme latency (~14.2s) under quantum emulation testing.

*Recommendation:* Proceed to the **Quantum Center** to trigger corporate lattice seed keys for the remainder of legacy APAC routers.`;
    }

    if (q.includes('arjun') || q.includes('trust') || q.includes('risk')) {
      return `### User Risk Triage: Arjun Vardhan

**Identity Security Audit:**
- **Current Trust Score:** **28/100 (HIGH RISK)**
- **Critical Trigger Event:** "Impossible Travel" detected between Chennai, IN and Frankfurt, DE within a 45-minute window.
- **Access Anomaly:** Attempted to access financial buckets S3://prod-fin-records/* from the unrecognized Frankfurt IP.

**Mitigation Protocol:**
- Proactively place user on temporary SAML quarantine.
- Verify whether user initiated an authorized VPN tunnel.`;
    }

    if (q.includes('vulnerab') || q.includes('subnet') || q.includes('port')) {
      return `### Corporate Subnet Vulnerability Matrix

Active scanning of internal subnets reveals **2 Critical** and **14 Moderate** vulnerabilities:

1. **Subnet EMEA-PROD-DB:** Exposed to unpatched CVE-2026-9021 (Remote Code Execution, named "Frostbyte").
2. **Subnet MKT-WS:** High incidence of endpoint systems running UAC bypass configurations.

*Remediation action:* Trigger an automated patch schedule via the **Security Analytics** scanning board to apply the security patch instantly.`;
    }

    return `### Obsidian Security Copilot Response

I have analyzed your request: *"${query}"*. 

As an AI-powered security architect, I can assist you with:
- **Incident Investigation:** Triage of active threat alerts like INC-8429 or INC-8395.
- **Quantum Cryptography:** Guidance on lattice-based keys, ML-KEM or ML-DSA protocols.
- **Risk Remediation:** Analyzing employee anomalies, impossible travel, or credential risk.
- **Remediation Execution:** Generating sandboxing commands for infected target hosts.

Please select one of the suggested query chips below or provide a more specific security telemetry question.`;
  };

  const handleSendMessage = async (textToSend: string) => {
    if (!textToSend.trim()) return;

    const userMsg: ChatMessage = {
      sender: 'user',
      text: textToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages(prev => [...prev, userMsg]);
    setInputText('');
    setIsTyping(true);

    const fullResponse = await sendCopilotMessage(textToSend);

    setIsTyping(false);
    const assistantMsg: ChatMessage = {
      sender: 'assistant',
      text: '',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      isStreaming: true
    };
    
    setMessages(prev => [...prev, assistantMsg]);

    let currentLength = 0;
    const speed = 10;
    const interval = setInterval(() => {
      if (currentLength < fullResponse.length) {
        currentLength += Math.min(6, fullResponse.length - currentLength);
        const chunk = fullResponse.substring(0, currentLength);
        
        setMessages(prev => {
          const updated = [...prev];
          const last = updated[updated.length - 1];
          if (last && last.sender === 'assistant' && last.isStreaming) {
            last.text = chunk;
          }
          return updated;
        });
      } else {
        clearInterval(interval);
        setMessages(prev => {
          const updated = [...prev];
          const last = updated[updated.length - 1];
          if (last && last.sender === 'assistant') {
            last.isStreaming = false;
          }
          return updated;
        });
      }
    }, speed);
  };

  return (
    <div className="glass-panel rounded-xl overflow-hidden flex flex-col h-[540px] relative">
      
      {/* Header bar */}
      <div className="p-4 bg-bg-sidebar border-b border-outline-variant/60 flex justify-between items-center">
        <div className="flex items-center gap-2">
          <BrainCircuit className="text-primary animate-pulse" size={20} />
          <div>
            <h3 className="text-sm font-bold text-on-surface leading-tight">Obsidian Security Copilot</h3>
            <span className="text-[10px] text-secondary font-semibold uppercase tracking-wider">SECURE GENAI AGENT ACTIVE</span>
          </div>
        </div>
        <div className="flex items-center gap-1.5 bg-secondary/10 px-2 py-0.5 rounded border border-secondary/30 text-secondary text-[10px] font-mono font-semibold">
          <Sparkles size={10} />
          HIGH CONFIDENCE
        </div>
      </div>

      {/* Messages area */}
      <div className="flex-1 p-5 overflow-y-auto space-y-4 bg-bg-base">
        {messages.map((msg, i) => {
          const isAssistant = msg.sender === 'assistant';
          return (
            <div 
              key={i} 
              className={`flex gap-3.5 max-w-[85%] ${
                isAssistant ? 'self-start' : 'self-end flex-row-reverse ml-auto'
              }`}
            >
              {/* Avatar circle */}
              <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 border ${
                isAssistant 
                  ? 'bg-primary/10 border-primary/30 text-primary' 
                  : 'bg-secondary/10 border-secondary/30 text-secondary'
              }`}>
                {isAssistant ? <Bot size={16} /> : <User size={16} />}
              </div>

              {/* Chat bubble body */}
              <div className={`p-4 rounded-xl text-sm leading-relaxed ${
                isAssistant 
                  ? 'bg-surface-container-low/80 text-on-surface border border-outline-variant/50' 
                  : 'bg-primary text-on-primary font-medium'
              }`}>
                
                {/* Parse Markdown-like titles manually or render text safely */}
                <div className="whitespace-pre-wrap font-sans space-y-2">
                  {msg.text.split('\n\n').map((para, pIdx) => {
                    if (para.startsWith('### ')) {
                      return <h4 key={pIdx} className="font-bold text-base text-secondary mt-2 mb-1">{para.replace('### ', '')}</h4>;
                    }
                    if (para.startsWith('**')) {
                      return <p key={pIdx} className="font-semibold text-on-surface">{para}</p>;
                    }
                    return <p key={pIdx} className="opacity-95">{para}</p>;
                  })}
                </div>
                
                <span className="text-[9px] opacity-60 font-mono mt-2 block text-right">
                  {msg.timestamp}
                </span>
              </div>
            </div>
          );
        })}

        {isTyping && (
          <div className="flex gap-3.5 max-w-[80%] self-start">
            <div className="w-8 h-8 rounded-full flex items-center justify-center border bg-primary/10 border-primary/30 text-primary">
              <Bot size={16} />
            </div>
            <div className="bg-surface-container-low/80 p-4 rounded-xl border border-outline-variant/50 flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-primary animate-bounce" style={{ animationDelay: '0ms' }}></span>
              <span className="w-2.5 h-2.5 rounded-full bg-primary animate-bounce" style={{ animationDelay: '150ms' }}></span>
              <span className="w-2.5 h-2.5 rounded-full bg-primary animate-bounce" style={{ animationDelay: '300ms' }}></span>
            </div>
          </div>
        )}
        <div ref={scrollRef}></div>
      </div>

      {/* Suggestion Chips */}
      <div className="p-3 bg-bg-sidebar border-t border-outline-variant/40 flex gap-2 overflow-x-auto whitespace-nowrap">
        {SUGGESTIONS.map(chip => (
          <button
            key={chip}
            onClick={() => handleSendMessage(chip)}
            className="text-[10px] bg-bg-badge hover:bg-primary/15 hover:text-on-surface text-on-surface-variant font-medium px-3 py-1.5 rounded-full border border-outline-variant/60 cursor-pointer transition-colors"
          >
            {chip}
          </button>
        ))}
      </div>

      {/* Input row */}
      <div className="p-3.5 bg-bg-sidebar border-t border-outline-variant flex gap-3">
        <input
          type="text"
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') handleSendMessage(inputText);
          }}
          placeholder="Ask Copilot for analysis, mitigation strategies, or algorithm info..."
          className="flex-1 bg-bg-input border border-outline-variant/80 rounded-lg px-4 py-2.5 text-sm text-on-surface placeholder:text-on-surface-variant focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary font-sans"
        />
        <button
          onClick={() => handleSendMessage(inputText)}
          className="p-2.5 bg-primary hover:bg-primary-container text-on-primary rounded-lg transition-all flex items-center justify-center cursor-pointer"
        >
          <Send size={16} />
        </button>
      </div>
    </div>
  );
}
