/**
 * AI-Powered Conversational Security Assistant
 * Natural language security queries with contextual intelligence
 */

import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  MessageCircle, 
  Send, 
  Mic, 
  MicOff, 
  Bot, 
  User, 
  Shield, 
  AlertTriangle,
  CheckCircle,
  Lightbulb,
  Code,
  FileText,
  Zap
} from 'lucide-react';

const ConversationalSecurityAssistant = ({ 
  onSecurityQuery, 
  vulnerabilityData, 
  scanResults,
  isOpen = false,
  onToggle 
}) => {
  const [messages, setMessages] = useState([
    {
      id: 1,
      type: 'assistant',
      content: "Hello! I'm your AI Security Assistant. I can help you analyze vulnerabilities, explain security findings, and provide remediation guidance. Try asking me something like 'Show me all critical vulnerabilities in production' or 'Explain this SQL injection finding'.",
      timestamp: new Date(),
      suggestions: [
        "Show me critical vulnerabilities",
        "Analyze security trends",
        "Explain this finding",
        "How do I fix this issue?"
      ]
    }
  ]);
  
  const [inputValue, setInputValue] = useState('');
  const [isListening, setIsListening] = useState(false);
  const [isTyping, setIsTyping] = useState(false);
  const [voiceSupported, setVoiceSupported] = useState(false);
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);
  const recognitionRef = useRef(null);

  // Initialize speech recognition
  useEffect(() => {
    if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
      setVoiceSupported(true);
      const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
      recognitionRef.current = new SpeechRecognition();
      recognitionRef.current.continuous = false;
      recognitionRef.current.interimResults = false;
      recognitionRef.current.lang = 'en-US';

      recognitionRef.current.onresult = (event) => {
        const transcript = event.results[0][0].transcript;
        setInputValue(transcript);
        setIsListening(false);
      };

      recognitionRef.current.onerror = () => {
        setIsListening(false);
      };

      recognitionRef.current.onend = () => {
        setIsListening(false);
      };
    }
  }, []);

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSendMessage = async () => {
    if (!inputValue.trim()) return;

    const userMessage = {
      id: Date.now(),
      type: 'user',
      content: inputValue,
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMessage]);
    setInputValue('');
    setIsTyping(true);

    // Simulate AI processing
    setTimeout(async () => {
      const response = await processSecurityQuery(inputValue, vulnerabilityData, scanResults);
      const assistantMessage = {
        id: Date.now() + 1,
        type: 'assistant',
        content: response.content,
        timestamp: new Date(),
        data: response.data,
        actions: response.actions,
        visualizations: response.visualizations
      };

      setMessages(prev => [...prev, assistantMessage]);
      setIsTyping(false);
    }, 1500);
  };

  const handleVoiceInput = () => {
    if (!voiceSupported) return;

    if (isListening) {
      recognitionRef.current?.stop();
      setIsListening(false);
    } else {
      recognitionRef.current?.start();
      setIsListening(true);
    }
  };

  const handleSuggestionClick = (suggestion) => {
    setInputValue(suggestion);
    inputRef.current?.focus();
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  if (!isOpen) {
    return (
      <motion.button
        onClick={onToggle}
        className="fixed bottom-6 right-6 w-14 h-14 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-full shadow-lg hover:shadow-xl transition-all duration-300 flex items-center justify-center z-50"
        whileHover={{ scale: 1.1 }}
        whileTap={{ scale: 0.9 }}
      >
        <MessageCircle className="w-6 h-6 text-white" />
      </motion.button>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, y: 20, scale: 0.95 }}
      className="fixed bottom-6 right-6 w-96 h-[600px] glass-panel rounded-2xl shadow-2xl flex flex-col z-50"
    >
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-white/10">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-full flex items-center justify-center">
            <Bot className="w-5 h-5 text-white" />
          </div>
          <div>
            <h3 className="font-semibold text-white">Security Assistant</h3>
            <p className="text-xs text-gray-400">AI-Powered Analysis</p>
          </div>
        </div>
        <button
          onClick={onToggle}
          className="w-8 h-8 rounded-full bg-white/10 hover:bg-white/20 flex items-center justify-center transition-colors"
        >
          <span className="text-gray-400">×</span>
        </button>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        <AnimatePresence>
          {messages.map((message) => (
            <MessageBubble key={message.id} message={message} onSuggestionClick={handleSuggestionClick} />
          ))}
        </AnimatePresence>
        
        {isTyping && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center space-x-2"
          >
            <div className="w-8 h-8 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-full flex items-center justify-center">
              <Bot className="w-4 h-4 text-white" />
            </div>
            <div className="bg-white/10 rounded-2xl px-4 py-2">
              <div className="flex space-x-1">
                <div className="w-2 h-2 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                <div className="w-2 h-2 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                <div className="w-2 h-2 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
              </div>
            </div>
          </motion.div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="p-4 border-t border-white/10">
        <div className="flex items-end space-x-2">
          <div className="flex-1 relative">
            <textarea
              ref={inputRef}
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="Ask about security findings, vulnerabilities, or get remediation advice..."
              className="w-full bg-white/10 border border-white/20 rounded-xl px-4 py-3 text-white placeholder-gray-400 resize-none focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
              rows={1}
              style={{ minHeight: '44px', maxHeight: '120px' }}
            />
            {voiceSupported && (
              <button
                onClick={handleVoiceInput}
                className={`absolute right-2 top-2 w-8 h-8 rounded-full flex items-center justify-center transition-colors ${
                  isListening 
                    ? 'bg-red-500 text-white' 
                    : 'bg-white/10 text-gray-400 hover:bg-white/20'
                }`}
              >
                {isListening ? <MicOff className="w-4 h-4" /> : <Mic className="w-4 h-4" />}
              </button>
            )}
          </div>
          <button
            onClick={handleSendMessage}
            disabled={!inputValue.trim()}
            className="w-11 h-11 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-xl flex items-center justify-center disabled:opacity-50 disabled:cursor-not-allowed hover:shadow-lg transition-all"
          >
            <Send className="w-5 h-5 text-white" />
          </button>
        </div>
      </div>
    </motion.div>
  );
};

// Message Bubble Component
const MessageBubble = ({ message, onSuggestionClick }) => {
  const isUser = message.type === 'user';

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}
    >
      <div className={`flex items-start space-x-2 max-w-[85%] ${isUser ? 'flex-row-reverse space-x-reverse' : ''}`}>
        {/* Avatar */}
        <div className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 ${
          isUser 
            ? 'bg-gradient-to-r from-purple-500 to-pink-500' 
            : 'bg-gradient-to-r from-cyan-500 to-blue-600'
        }`}>
          {isUser ? <User className="w-4 h-4 text-white" /> : <Bot className="w-4 h-4 text-white" />}
        </div>

        {/* Message Content */}
        <div className={`rounded-2xl px-4 py-3 ${
          isUser 
            ? 'bg-gradient-to-r from-purple-500 to-pink-500 text-white' 
            : 'bg-white/10 text-gray-100'
        }`}>
          <p className="text-sm leading-relaxed">{message.content}</p>
          
          {/* Data Visualizations */}
          {message.data && (
            <div className="mt-3 space-y-2">
              {message.data.vulnerabilities && (
                <VulnerabilityList vulnerabilities={message.data.vulnerabilities} />
              )}
              {message.data.metrics && (
                <SecurityMetrics metrics={message.data.metrics} />
              )}
            </div>
          )}

          {/* Action Buttons */}
          {message.actions && (
            <div className="mt-3 flex flex-wrap gap-2">
              {message.actions.map((action, index) => (
                <button
                  key={index}
                  onClick={() => action.handler()}
                  className="px-3 py-1 bg-white/20 hover:bg-white/30 rounded-lg text-xs font-medium transition-colors"
                >
                  {action.label}
                </button>
              ))}
            </div>
          )}

          {/* Suggestions */}
          {message.suggestions && (
            <div className="mt-3 space-y-1">
              <p className="text-xs text-gray-400 mb-2">Try asking:</p>
              {message.suggestions.map((suggestion, index) => (
                <button
                  key={index}
                  onClick={() => onSuggestionClick(suggestion)}
                  className="block w-full text-left px-3 py-2 bg-white/10 hover:bg-white/20 rounded-lg text-xs transition-colors"
                >
                  {suggestion}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </motion.div>
  );
};

// Vulnerability List Component
const VulnerabilityList = ({ vulnerabilities }) => (
  <div className="space-y-2">
    {vulnerabilities.slice(0, 3).map((vuln, index) => (
      <div key={index} className="flex items-center space-x-2 p-2 bg-black/20 rounded-lg">
        <div className={`w-2 h-2 rounded-full ${
          vuln.severity === 'critical' ? 'bg-red-500' :
          vuln.severity === 'high' ? 'bg-orange-500' :
          vuln.severity === 'medium' ? 'bg-yellow-500' :
          'bg-green-500'
        }`} />
        <span className="text-xs font-medium">{vuln.title}</span>
      </div>
    ))}
    {vulnerabilities.length > 3 && (
      <p className="text-xs text-gray-400">+{vulnerabilities.length - 3} more vulnerabilities</p>
    )}
  </div>
);

// Security Metrics Component
const SecurityMetrics = ({ metrics }) => (
  <div className="grid grid-cols-2 gap-2">
    {Object.entries(metrics).map(([key, value]) => (
      <div key={key} className="p-2 bg-black/20 rounded-lg">
        <p className="text-xs text-gray-400 capitalize">{key.replace('_', ' ')}</p>
        <p className="text-sm font-semibold">{value}</p>
      </div>
    ))}
  </div>
);

// AI Query Processing Function
const processSecurityQuery = async (query, vulnerabilityData, scanResults) => {
  const lowerQuery = query.toLowerCase();
  
  // Critical vulnerabilities query
  if (lowerQuery.includes('critical') && lowerQuery.includes('vulnerabilit')) {
    const criticalVulns = vulnerabilityData.filter(v => v.severity === 'critical');
    return {
      content: `I found ${criticalVulns.length} critical vulnerabilities that require immediate attention. These pose the highest risk to your security posture.`,
      data: { vulnerabilities: criticalVulns },
      actions: [
        { label: 'View Details', handler: () => console.log('View details') },
        { label: 'Generate Report', handler: () => console.log('Generate report') }
      ]
    };
  }
  
  // Security trends query
  if (lowerQuery.includes('trend') || lowerQuery.includes('analyz')) {
    return {
      content: "Based on your recent scans, I've identified several security trends. Your overall security posture has improved by 15% this month, with a significant reduction in SQL injection vulnerabilities.",
      data: {
        metrics: {
          security_score: '87/100',
          trend: '+15%',
          fixed_issues: 23,
          new_issues: 8
        }
      },
      actions: [
        { label: 'View Trends', handler: () => console.log('View trends') },
        { label: 'Export Data', handler: () => console.log('Export data') }
      ]
    };
  }
  
  // Default response
  return {
    content: "I understand you're asking about security. Could you be more specific? I can help with vulnerability analysis, security trends, remediation guidance, or explaining specific findings.",
    suggestions: [
      "Show me high-severity vulnerabilities",
      "What's my security score?",
      "How do I fix SQL injection issues?",
      "Generate a security report"
    ]
  };
};

export default ConversationalSecurityAssistant;
