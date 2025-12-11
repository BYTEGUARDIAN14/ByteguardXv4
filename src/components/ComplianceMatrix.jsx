/**
 * Regulatory Compliance Matrix UI Component
 * Visual compliance dashboard with toggles for different frameworks
 */

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Info,
  Download,
  Filter,
  BarChart3,
  FileText,
  Settings,
  Eye,
  Lock,
  Database,
  Globe,
  Users,
  Clock
} from 'lucide-react';

const ComplianceMatrix = ({ data, onFrameworkToggle, onExportReport }) => {
  const [selectedFrameworks, setSelectedFrameworks] = useState(['PCI', 'SOC2', 'OWASP']);
  const [filterStatus, setFilterStatus] = useState('all');
  const [viewMode, setViewMode] = useState('matrix'); // 'matrix' or 'detailed'

  // Compliance frameworks configuration
  const frameworks = {
    PCI: {
      name: 'PCI DSS',
      fullName: 'Payment Card Industry Data Security Standard',
      icon: Lock,
      color: 'blue',
      description: 'Security standards for organizations that handle credit card information',
      categories: ['Access Control', 'Network Security', 'Data Protection', 'Monitoring', 'Testing', 'Policy']
    },
    SOC2: {
      name: 'SOC 2',
      fullName: 'Service Organization Control 2',
      icon: Shield,
      color: 'green',
      description: 'Trust service criteria for security, availability, and confidentiality',
      categories: ['Security', 'Availability', 'Processing Integrity', 'Confidentiality', 'Privacy']
    },
    HIPAA: {
      name: 'HIPAA',
      fullName: 'Health Insurance Portability and Accountability Act',
      icon: Users,
      color: 'purple',
      description: 'Privacy and security standards for healthcare information',
      categories: ['Administrative', 'Physical', 'Technical', 'Organizational']
    },
    OWASP: {
      name: 'OWASP Top 10',
      fullName: 'Open Web Application Security Project',
      icon: Globe,
      color: 'orange',
      description: 'Top 10 web application security risks',
      categories: ['Injection', 'Authentication', 'Exposure', 'XXE', 'Access Control', 'Configuration', 'XSS', 'Deserialization', 'Components', 'Logging']
    },
    GDPR: {
      name: 'GDPR',
      fullName: 'General Data Protection Regulation',
      icon: Database,
      color: 'indigo',
      description: 'EU data protection and privacy regulation',
      categories: ['Lawfulness', 'Data Minimization', 'Accuracy', 'Storage Limitation', 'Security', 'Accountability']
    },
    ISO27001: {
      name: 'ISO 27001',
      fullName: 'Information Security Management System',
      icon: Settings,
      color: 'gray',
      description: 'International standard for information security management',
      categories: ['Leadership', 'Planning', 'Support', 'Operation', 'Evaluation', 'Improvement']
    }
  };

  // Mock compliance data - in production, this would come from props
  const complianceData = data || {
    PCI: {
      overall_score: 85,
      controls: [
        { id: 'PCI-1', name: 'Install and maintain firewall', status: 'compliant', coverage: 95, last_assessed: '2024-01-15' },
        { id: 'PCI-2', name: 'Change default passwords', status: 'compliant', coverage: 100, last_assessed: '2024-01-15' },
        { id: 'PCI-3', name: 'Protect stored cardholder data', status: 'partial', coverage: 75, last_assessed: '2024-01-10' },
        { id: 'PCI-4', name: 'Encrypt transmission of cardholder data', status: 'compliant', coverage: 90, last_assessed: '2024-01-15' },
        { id: 'PCI-6', name: 'Develop secure systems', status: 'non_compliant', coverage: 45, last_assessed: '2024-01-08' },
      ]
    },
    SOC2: {
      overall_score: 92,
      controls: [
        { id: 'CC1', name: 'Control Environment', status: 'compliant', coverage: 95, last_assessed: '2024-01-14' },
        { id: 'CC2', name: 'Communication and Information', status: 'compliant', coverage: 88, last_assessed: '2024-01-14' },
        { id: 'CC3', name: 'Risk Assessment', status: 'partial', coverage: 70, last_assessed: '2024-01-12' },
        { id: 'CC6', name: 'Logical Access Controls', status: 'compliant', coverage: 92, last_assessed: '2024-01-15' },
        { id: 'CC7', name: 'System Operations', status: 'compliant', coverage: 85, last_assessed: '2024-01-13' },
      ]
    },
    OWASP: {
      overall_score: 78,
      controls: [
        { id: 'A01', name: 'Injection', status: 'compliant', coverage: 85, last_assessed: '2024-01-15' },
        { id: 'A02', name: 'Broken Authentication', status: 'partial', coverage: 65, last_assessed: '2024-01-12' },
        { id: 'A03', name: 'Sensitive Data Exposure', status: 'non_compliant', coverage: 40, last_assessed: '2024-01-10' },
        { id: 'A05', name: 'Broken Access Control', status: 'compliant', coverage: 80, last_assessed: '2024-01-14' },
        { id: 'A07', name: 'Cross-Site Scripting', status: 'compliant', coverage: 90, last_assessed: '2024-01-15' },
      ]
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'compliant':
        return <CheckCircle className="h-5 w-5 text-green-400" />;
      case 'partial':
        return <AlertTriangle className="h-5 w-5 text-yellow-400" />;
      case 'non_compliant':
        return <XCircle className="h-5 w-5 text-red-400" />;
      default:
        return <Info className="h-5 w-5 text-gray-400" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'compliant':
        return 'bg-green-500/20 border-green-500/30';
      case 'partial':
        return 'bg-yellow-500/20 border-yellow-500/30';
      case 'non_compliant':
        return 'bg-red-500/20 border-red-500/30';
      default:
        return 'bg-gray-500/20 border-gray-500/30';
    }
  };

  const getCoverageColor = (coverage) => {
    if (coverage >= 90) return 'text-green-400';
    if (coverage >= 70) return 'text-yellow-400';
    return 'text-red-400';
  };

  const handleFrameworkToggle = (frameworkId) => {
    const newSelection = selectedFrameworks.includes(frameworkId)
      ? selectedFrameworks.filter(id => id !== frameworkId)
      : [...selectedFrameworks, frameworkId];
    
    setSelectedFrameworks(newSelection);
    onFrameworkToggle?.(newSelection);
  };

  const filteredControls = (frameworkData) => {
    if (filterStatus === 'all') return frameworkData.controls;
    return frameworkData.controls.filter(control => control.status === filterStatus);
  };

  const getOverallComplianceScore = () => {
    const scores = selectedFrameworks.map(fw => complianceData[fw]?.overall_score || 0);
    return scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Regulatory Compliance Matrix</h2>
          <p className="text-gray-400 mt-1">Monitor compliance across multiple security frameworks</p>
        </div>
        
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <span className="text-sm text-gray-400">Overall Score:</span>
            <div className="flex items-center space-x-2">
              <div className="text-2xl font-bold text-white">{getOverallComplianceScore()}%</div>
              <div className={`h-2 w-16 rounded-full bg-gray-700`}>
                <div 
                  className={`h-full rounded-full transition-all duration-500 ${
                    getOverallComplianceScore() >= 90 ? 'bg-green-500' :
                    getOverallComplianceScore() >= 70 ? 'bg-yellow-500' : 'bg-red-500'
                  }`}
                  style={{ width: `${getOverallComplianceScore()}%` }}
                />
              </div>
            </div>
          </div>
          
          <button
            onClick={() => onExportReport?.()}
            className="flex items-center space-x-2 px-4 py-2 bg-primary-600 hover:bg-primary-700 rounded-lg transition-colors"
          >
            <Download className="h-4 w-4" />
            <span>Export Report</span>
          </button>
        </div>
      </div>

      {/* Framework Selection */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">Select Frameworks</h3>
          <div className="flex items-center space-x-2">
            <Filter className="h-4 w-4 text-gray-400" />
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="bg-gray-800 border border-gray-600 rounded px-3 py-1 text-sm text-white"
            >
              <option value="all">All Controls</option>
              <option value="compliant">Compliant</option>
              <option value="partial">Partial</option>
              <option value="non_compliant">Non-Compliant</option>
            </select>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {Object.entries(frameworks).map(([id, framework]) => {
            const Icon = framework.icon;
            const isSelected = selectedFrameworks.includes(id);
            const frameworkData = complianceData[id];
            
            return (
              <motion.div
                key={id}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                className={`p-4 rounded-lg border cursor-pointer transition-all ${
                  isSelected 
                    ? `bg-${framework.color}-500/10 border-${framework.color}-500/30` 
                    : 'bg-gray-800/50 border-gray-600 hover:border-gray-500'
                }`}
                onClick={() => handleFrameworkToggle(id)}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <Icon className={`h-5 w-5 ${isSelected ? `text-${framework.color}-400` : 'text-gray-400'}`} />
                    <span className="font-medium text-white">{framework.name}</span>
                  </div>
                  {frameworkData && (
                    <div className="text-sm font-medium text-white">
                      {frameworkData.overall_score}%
                    </div>
                  )}
                </div>
                
                <p className="text-xs text-gray-400 mb-2">{framework.description}</p>
                
                {frameworkData && (
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-gray-400">
                      {frameworkData.controls.length} controls
                    </span>
                    <div className="flex space-x-1">
                      {frameworkData.controls.slice(0, 3).map((control, idx) => (
                        <div
                          key={idx}
                          className={`w-2 h-2 rounded-full ${getStatusColor(control.status).split(' ')[0]}`}
                        />
                      ))}
                    </div>
                  </div>
                )}
              </motion.div>
            );
          })}
        </div>
      </div>

      {/* Compliance Matrix */}
      <AnimatePresence>
        {selectedFrameworks.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            {selectedFrameworks.map(frameworkId => {
              const framework = frameworks[frameworkId];
              const frameworkData = complianceData[frameworkId];
              
              if (!frameworkData) return null;
              
              return (
                <div key={frameworkId} className="card">
                  <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center space-x-3">
                      <framework.icon className={`h-6 w-6 text-${framework.color}-400`} />
                      <div>
                        <h3 className="text-lg font-semibold text-white">{framework.fullName}</h3>
                        <p className="text-sm text-gray-400">{framework.description}</p>
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-4">
                      <div className="text-right">
                        <div className="text-2xl font-bold text-white">{frameworkData.overall_score}%</div>
                        <div className="text-xs text-gray-400">Overall Score</div>
                      </div>
                      <div className={`h-12 w-2 rounded-full bg-gray-700`}>
                        <div 
                          className={`w-full rounded-full transition-all duration-500 ${
                            frameworkData.overall_score >= 90 ? 'bg-green-500' :
                            frameworkData.overall_score >= 70 ? 'bg-yellow-500' : 'bg-red-500'
                          }`}
                          style={{ height: `${frameworkData.overall_score}%` }}
                        />
                      </div>
                    </div>
                  </div>
                  
                  <div className="grid gap-3">
                    {filteredControls(frameworkData).map((control, index) => (
                      <motion.div
                        key={control.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: index * 0.1 }}
                        className={`p-4 rounded-lg border ${getStatusColor(control.status)}`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-3">
                            {getStatusIcon(control.status)}
                            <div>
                              <div className="font-medium text-white">{control.id}: {control.name}</div>
                              <div className="text-xs text-gray-400 flex items-center space-x-2">
                                <Clock className="h-3 w-3" />
                                <span>Last assessed: {control.last_assessed}</span>
                              </div>
                            </div>
                          </div>
                          
                          <div className="text-right">
                            <div className={`text-lg font-semibold ${getCoverageColor(control.coverage)}`}>
                              {control.coverage}%
                            </div>
                            <div className="text-xs text-gray-400">Coverage</div>
                          </div>
                        </div>
                      </motion.div>
                    ))}
                  </div>
                </div>
              );
            })}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default ComplianceMatrix;
