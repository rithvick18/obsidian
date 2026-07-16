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
      text: "Welcome to **Obsidian Copilot**. I am synchronized with your active XDR telemetry database and ready to assist with live triage, automated containment, or cryptographic risk modeling.\n\nHow can I help you secure your enterprise environment today?",
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);
  const [inputText, setInputText] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Synced cleanly with the anonymized role nodes in your SQLite fabric
  const SUGGESTIONS = [
    'Analyze anomalies for contractor_node_02',
    'List critical database telemetry logs',
    'Provide post-quantum migration advice',
    'Verify active honeypot status keys'
  ];

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

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

    // Queries your backend, which handles Gemini API tunneling OR the live SQLite fallback analysis dynamically!
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
              <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 border ${
                isAssistant 
                  ? 'bg-primary/10 border-primary/30 text-primary' 
                  : 'bg-secondary/10 border-secondary/30 text-secondary'
              }`}>
                {isAssistant ? <Bot size={16} /> : <User size={16} />}
              </div>

              <div className={`p-4 rounded-xl text-sm leading-relaxed ${
                isAssistant 
                  ? 'bg-surface-container-low/80 text-on-surface border border-outline-variant/50' 
                  : 'bg-primary text-on-primary font-medium'
              }`}>
                
                {/* Parse Markdown structural response keys cleanly */}
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
