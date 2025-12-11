/**
 * Enhanced Security Dashboard with Next-Generation UI/UX
 * Integrates 3D visualization, AI assistance, spatial design, and advanced accessibility
 */

import React, { useState, useEffect, Suspense } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  Brain,
  Box,
  Zap,
  Activity,
  Settings,
  Eye,
  MessageCircle,
  BarChart3,
  Network,
  AlertTriangle,
  CheckCircle,
  TrendingUp,
  Globe
} from 'lucide-react';

// Import advanced components
import { QuantumGlassCard, MicroAnimationWrapper, ProgressiveDisclosure } from '../advanced/QuantumGlassmorphism';
import ConversationalSecurityAssistant from '../ai/ConversationalSecurityAssistant';
import ImmersiveSecurityVisualization from '../3d/ImmersiveSecurityVisualization';
import SpatialSecurityExplorer from '../spatial/SpatialSecurityExplorer';
import { useAccessibility, ScreenReaderAnnouncer } from '../accessibility/UniversalAccessibility';

// Lazy load heavy components
const SecurityHeatmap3D = React.lazy(() => import('../3d/SecurityHeatmap3D'));
const SecurityAnalyticsDashboard = React.lazy(() => import('../SecurityAnalyticsDashboard'));

const EnhancedSecurityDashboard = () => {
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState('overview'); // 'overview', '3d', 'spatial', 'analytics'
  const [aiAssistantOpen, setAiAssistantOpen] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);
  const [threatLevel, setThreatLevel] = useState('medium');
  
  const { settings } = useAccessibility();

  // Fetch dashboard data
  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/dashboard/enhanced-stats');
      if (!response.ok) {
        throw new Error('Failed to fetch dashboard data');
      }
      const data = await response.json();
      setDashboardData(data);
      setThreatLevel(data.overallThreatLevel || 'medium');
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      // Use mock data for demo
      setDashboardData({
        overallScore: 78,
        totalVulnerabilities: 23,
        criticalVulnerabilities: 3,
        highVulnerabilities: 7,
        mediumVulnerabilities: 13,
        overallThreatLevel: 'high',
        networkNodes: [
          { id: 1, type: 'server', threatLevel: 'high', vulnerabilities: ['SQL Injection', 'XSS'] },
          { id: 2, type: 'database', threatLevel: 'critical', vulnerabilities: ['Weak Auth'] },
          { id: 3, type: 'endpoint', threatLevel: 'medium', vulnerabilities: [] }
        ],
        recentScans: 15,
        pluginsActive: 22,
        complianceScore: 85
      });
    } finally {
      setLoading(false);
    }
  };

  const handleNodeSelect = (node) => {
    setSelectedNode(node.id);
  };

  const viewModes = [
    { id: 'overview', label: 'Overview', icon: BarChart3, description: 'Comprehensive security overview' },
    { id: '3d', label: '3D Visualization', icon: Box, description: 'Immersive 3D security topology' },
    { id: 'spatial', label: 'Spatial Explorer', icon: Network, description: 'Gesture-based spatial navigation' },
    { id: 'analytics', label: 'Advanced Analytics', icon: TrendingUp, description: 'Deep security analytics' }
  ];

  const securityMetrics = [
    {
      title: 'Security Score',
      value: dashboardData?.overallScore || 0,
      change: '+5%',
      changeType: 'positive',
      icon: Shield,
      color: 'cyan'
    },
    {
      title: 'Critical Vulnerabilities',
      value: dashboardData?.criticalVulnerabilities || 0,
      change: '-2',
      changeType: 'positive',
      icon: AlertTriangle,
      color: 'red'
    },
    {
      title: 'Active Plugins',
      value: dashboardData?.pluginsActive || 0,
      change: '+3',
      changeType: 'positive',
      icon: Zap,
      color: 'green'
    },
    {
      title: 'Compliance Score',
      value: `${dashboardData?.complianceScore || 0}%`,
      change: '+8%',
      changeType: 'positive',
      icon: CheckCircle,
      color: 'blue'
    }
  ];

  if (loading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <MicroAnimationWrapper type="pulse">
          <QuantumGlassCard variant="elevated" className="p-8">
            <div className="flex items-center space-x-4">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400"></div>
              <span className="text-white text-lg">Loading Enhanced Security Dashboard...</span>
            </div>
          </QuantumGlassCard>
        </MicroAnimationWrapper>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-white p-6">
      <ScreenReaderAnnouncer message="Enhanced Security Dashboard loaded" />
      
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-8"
      >
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
              ByteGuardX Security Command Center
            </h1>
            <p className="text-gray-400 mt-2">
              Next-generation security visualization with AI-powered insights
            </p>
          </div>
          
          <div className="flex items-center space-x-4">
            <MicroAnimationWrapper type="glow">
              <button
                onClick={() => setAiAssistantOpen(!aiAssistantOpen)}
                className="p-3 bg-gradient-to-r from-purple-500 to-pink-500 rounded-2xl hover:from-purple-600 hover:to-pink-600 transition-all"
                aria-label="Toggle AI Assistant"
              >
                <Brain className="h-6 w-6" />
              </button>
            </MicroAnimationWrapper>
            
            <button className="p-3 bg-white/10 rounded-2xl hover:bg-white/20 transition-colors">
              <Settings className="h-6 w-6" />
            </button>
          </div>
        </div>
      </motion.div>

      {/* View Mode Selector */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="mb-8"
      >
        <QuantumGlassCard variant="minimal" className="p-4">
          <div className="flex items-center space-x-4 overflow-x-auto">
            {viewModes.map((mode) => (
              <motion.button
                key={mode.id}
                onClick={() => setViewMode(mode.id)}
                className={`flex items-center space-x-3 px-6 py-3 rounded-2xl transition-all whitespace-nowrap ${
                  viewMode === mode.id
                    ? 'bg-gradient-to-r from-cyan-500 to-blue-500 text-white'
                    : 'bg-white/5 text-gray-300 hover:bg-white/10 hover:text-white'
                }`}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <mode.icon className="h-5 w-5" />
                <div className="text-left">
                  <div className="font-medium">{mode.label}</div>
                  {!settings.simplifiedUI && (
                    <div className="text-xs opacity-75">{mode.description}</div>
                  )}
                </div>
              </motion.button>
            ))}
          </div>
        </QuantumGlassCard>
      </motion.div>

      {/* Main Content */}
      <AnimatePresence mode="wait">
        <motion.div
          key={viewMode}
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -20 }}
          transition={{ duration: 0.3 }}
        >
          {viewMode === 'overview' && (
            <div className="space-y-8">
              {/* Security Metrics */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {securityMetrics.map((metric, index) => (
                  <motion.div
                    key={metric.title}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                  >
                    <QuantumGlassCard 
                      variant="interactive" 
                      className="p-6 hover:shadow-cyan-500/20"
                      quantumEffect={true}
                    >
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-sm font-medium text-gray-300">
                          {metric.title}
                        </h3>
                        <div className={`p-2 rounded-lg bg-${metric.color}-500/20 text-${metric.color}-400`}>
                          <metric.icon className="h-4 w-4" />
                        </div>
                      </div>
                      
                      <div className="flex items-end justify-between">
                        <div>
                          <div className="text-2xl font-bold text-white mb-1">
                            {metric.value}
                          </div>
                          <div className={`flex items-center text-xs ${
                            metric.changeType === 'positive' ? 'text-green-400' : 'text-red-400'
                          }`}>
                            <TrendingUp className="h-3 w-3 mr-1" />
                            {metric.change}
                          </div>
                        </div>
                      </div>
                    </QuantumGlassCard>
                  </motion.div>
                ))}
              </div>

              {/* Progressive Disclosure Sections */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <ProgressiveDisclosure 
                  title="Recent Security Events" 
                  complexity="simple"
                  defaultOpen={true}
                >
                  <div className="space-y-3">
                    {[
                      { type: 'critical', message: 'SQL Injection detected in user authentication', time: '2 min ago' },
                      { type: 'warning', message: 'Outdated dependency found: express@4.16.1', time: '15 min ago' },
                      { type: 'info', message: 'Security scan completed successfully', time: '1 hour ago' }
                    ].map((event, index) => (
                      <div key={index} className="flex items-center space-x-3 p-3 bg-white/5 rounded-lg">
                        <div className={`w-2 h-2 rounded-full ${
                          event.type === 'critical' ? 'bg-red-500' :
                          event.type === 'warning' ? 'bg-yellow-500' : 'bg-green-500'
                        }`} />
                        <div className="flex-1">
                          <p className="text-white text-sm">{event.message}</p>
                          <p className="text-gray-400 text-xs">{event.time}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </ProgressiveDisclosure>

                <ProgressiveDisclosure 
                  title="Security Recommendations" 
                  complexity="intermediate"
                >
                  <div className="space-y-3">
                    {[
                      'Enable 2FA for all admin accounts',
                      'Update 5 outdated dependencies',
                      'Configure stricter CSP headers',
                      'Implement rate limiting on API endpoints'
                    ].map((recommendation, index) => (
                      <div key={index} className="flex items-center space-x-3 p-3 bg-white/5 rounded-lg">
                        <CheckCircle className="h-4 w-4 text-cyan-400" />
                        <span className="text-white text-sm">{recommendation}</span>
                      </div>
                    ))}
                  </div>
                </ProgressiveDisclosure>
              </div>
            </div>
          )}

          {viewMode === '3d' && (
            <Suspense fallback={
              <QuantumGlassCard className="h-[600px] flex items-center justify-center">
                <div className="text-center">
                  <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-400 mx-auto mb-4"></div>
                  <p className="text-gray-400">Loading 3D Visualization...</p>
                </div>
              </QuantumGlassCard>
            }>
              <ImmersiveSecurityVisualization
                networkData={dashboardData?.networkNodes}
                vulnerabilityData={dashboardData}
                onNodeSelect={handleNodeSelect}
                selectedNode={selectedNode}
              />
            </Suspense>
          )}

          {viewMode === 'spatial' && (
            <SpatialSecurityExplorer
              securityData={dashboardData}
              onDataPointSelect={handleNodeSelect}
            />
          )}

          {viewMode === 'analytics' && (
            <Suspense fallback={
              <QuantumGlassCard className="h-[600px] flex items-center justify-center">
                <div className="text-center">
                  <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-400 mx-auto mb-4"></div>
                  <p className="text-gray-400">Loading Advanced Analytics...</p>
                </div>
              </QuantumGlassCard>
            }>
              <SecurityAnalyticsDashboard data={dashboardData} />
            </Suspense>
          )}
        </motion.div>
      </AnimatePresence>

      {/* AI Assistant */}
      <ConversationalSecurityAssistant
        isOpen={aiAssistantOpen}
        onToggle={() => setAiAssistantOpen(!aiAssistantOpen)}
        vulnerabilityData={dashboardData}
        position="bottom-right"
      />
    </div>
  );
};

export default EnhancedSecurityDashboard;
