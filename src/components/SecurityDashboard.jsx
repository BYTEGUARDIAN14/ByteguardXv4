import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Shield, 
  AlertTriangle, 
  Activity, 
  Lock, 
  Eye, 
  Users, 
  Key,
  Zap,
  TrendingUp,
  Clock,
  Globe,
  Smartphone
} from 'lucide-react';

const SecurityDashboard = () => {
  const [dashboardData, setDashboardData] = useState(null);
  const [threats, setThreats] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedTimeRange, setSelectedTimeRange] = useState('24h');

  useEffect(() => {
    fetchDashboardData();
    fetchThreats();
    fetchSessions();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(() => {
      fetchDashboardData();
      fetchThreats();
    }, 30000);
    
    return () => clearInterval(interval);
  }, [selectedTimeRange]);

  const fetchDashboardData = async () => {
    try {
      const response = await fetch('/api/admin/security/dashboard', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setDashboardData(data);
      }
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchThreats = async () => {
    try {
      const hours = selectedTimeRange === '24h' ? 24 : selectedTimeRange === '7d' ? 168 : 1;
      const response = await fetch(`/api/admin/security/threats?hours=${hours}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setThreats(data.threats || []);
      }
    } catch (error) {
      console.error('Failed to fetch threats:', error);
    }
  };

  const fetchSessions = async () => {
    try {
      const response = await fetch('/api/admin/security/sessions', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setSessions(data.sessions || []);
      }
    } catch (error) {
      console.error('Failed to fetch sessions:', error);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'CRITICAL': return 'text-red-400 bg-red-500/10 border-red-500/20';
      case 'HIGH': return 'text-orange-400 bg-orange-500/10 border-orange-500/20';
      case 'MEDIUM': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20';
      case 'LOW': return 'text-green-400 bg-green-500/10 border-green-500/20';
      default: return 'text-gray-400 bg-gray-500/10 border-gray-500/20';
    }
  };

  const getRiskColor = (riskScore) => {
    if (riskScore >= 0.8) return 'text-red-400';
    if (riskScore >= 0.6) return 'text-orange-400';
    if (riskScore >= 0.4) return 'text-yellow-400';
    return 'text-green-400';
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-cyan-400"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-white p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-cyan-400" />
            <h1 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
              Security Command Center
            </h1>
          </div>
          
          <div className="flex items-center space-x-4">
            <select
              value={selectedTimeRange}
              onChange={(e) => setSelectedTimeRange(e.target.value)}
              className="bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-white focus:border-cyan-400 focus:outline-none"
            >
              <option value="1h">Last Hour</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
            </select>
            
            <div className="flex items-center space-x-2 text-sm text-gray-400">
              <Activity className="h-4 w-4 text-green-400" />
              <span>Live Monitoring</span>
            </div>
          </div>
        </div>
      </div>

      {/* Security Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {/* Threat Level */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-gray-900/50 backdrop-blur-sm border border-gray-800 rounded-xl p-6"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Threat Level</p>
              <p className="text-2xl font-bold text-red-400">
                {dashboardData?.threat_summary?.total_threats || 0}
              </p>
            </div>
            <AlertTriangle className="h-8 w-8 text-red-400" />
          </div>
          <div className="mt-4 text-sm text-gray-400">
            {dashboardData?.threat_summary?.severity_breakdown?.CRITICAL || 0} Critical
          </div>
        </motion.div>

        {/* Active Sessions */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-gray-900/50 backdrop-blur-sm border border-gray-800 rounded-xl p-6"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Active Sessions</p>
              <p className="text-2xl font-bold text-cyan-400">
                {dashboardData?.security_metrics?.total_active_sessions || 0}
              </p>
            </div>
            <Users className="h-8 w-8 text-cyan-400" />
          </div>
          <div className="mt-4 text-sm text-gray-400">
            {dashboardData?.security_metrics?.high_risk_sessions || 0} High Risk
          </div>
        </motion.div>

        {/* 2FA Adoption */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-gray-900/50 backdrop-blur-sm border border-gray-800 rounded-xl p-6"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">2FA Adoption</p>
              <p className="text-2xl font-bold text-green-400">
                {Math.round(dashboardData?.security_metrics?.mfa_adoption_rate || 0)}%
              </p>
            </div>
            <Smartphone className="h-8 w-8 text-green-400" />
          </div>
          <div className="mt-4 text-sm text-gray-400">
            WebAuthn: {Math.round(dashboardData?.security_metrics?.webauthn_adoption_rate || 0)}%
          </div>
        </motion.div>

        {/* Crypto Operations */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-gray-900/50 backdrop-blur-sm border border-gray-800 rounded-xl p-6"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Crypto Operations</p>
              <p className="text-2xl font-bold text-purple-400">
                {dashboardData?.crypto_stats?.total_operations || 0}
              </p>
            </div>
            <Key className="h-8 w-8 text-purple-400" />
          </div>
          <div className="mt-4 text-sm text-gray-400">
            {Math.round(dashboardData?.crypto_stats?.success_rate || 0)}% Success Rate
          </div>
        </motion.div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Recent Threats */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="bg-gray-900/50 backdrop-blur-sm border border-gray-800 rounded-xl p-6"
        >
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-semibold flex items-center">
              <AlertTriangle className="h-5 w-5 text-red-400 mr-2" />
              Recent Threats
            </h2>
            <span className="text-sm text-gray-400">Last {selectedTimeRange}</span>
          </div>
          
          <div className="space-y-4 max-h-96 overflow-y-auto">
            {threats.slice(0, 10).map((threat, index) => (
              <div
                key={index}
                className="border border-gray-700 rounded-lg p-4 hover:border-gray-600 transition-colors"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className={`px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(threat.severity)}`}>
                    {threat.severity}
                  </span>
                  <span className="text-xs text-gray-400">
                    {new Date(threat.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                
                <p className="text-sm text-white mb-2">{threat.event_type}</p>
                <p className="text-xs text-gray-400 mb-2">
                  Source: {threat.source_ip} | Risk: {(threat.risk_score * 100).toFixed(0)}%
                </p>
                
                {threat.mitigation_actions && threat.mitigation_actions.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {threat.mitigation_actions.map((action, i) => (
                      <span
                        key={i}
                        className="px-2 py-1 bg-blue-500/20 text-blue-400 text-xs rounded"
                      >
                        {action}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
            
            {threats.length === 0 && (
              <div className="text-center py-8 text-gray-400">
                <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No threats detected in the selected time range</p>
              </div>
            )}
          </div>
        </motion.div>

        {/* Active Sessions */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="bg-gray-900/50 backdrop-blur-sm border border-gray-800 rounded-xl p-6"
        >
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-semibold flex items-center">
              <Users className="h-5 w-5 text-cyan-400 mr-2" />
              Active Sessions
            </h2>
            <span className="text-sm text-gray-400">{sessions.length} total</span>
          </div>
          
          <div className="space-y-4 max-h-96 overflow-y-auto">
            {sessions.slice(0, 10).map((session, index) => (
              <div
                key={index}
                className="border border-gray-700 rounded-lg p-4 hover:border-gray-600 transition-colors"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-white">
                    {session.user_id}
                  </span>
                  <span className={`text-sm font-medium ${getRiskColor(session.risk_score)}`}>
                    Risk: {(session.risk_score * 100).toFixed(0)}%
                  </span>
                </div>
                
                <div className="grid grid-cols-2 gap-4 text-xs text-gray-400">
                  <div>
                    <p>IP: {session.ip_address}</p>
                    <p>Platform: {session.device_info.platform}</p>
                  </div>
                  <div>
                    <p>Security: {session.security_level}</p>
                    <p>Last Activity: {new Date(session.last_activity).toLocaleTimeString()}</p>
                  </div>
                </div>
                
                <div className="flex items-center space-x-4 mt-3">
                  {session.mfa_verified && (
                    <span className="flex items-center text-xs text-green-400">
                      <Lock className="h-3 w-3 mr-1" />
                      2FA
                    </span>
                  )}
                  {session.webauthn_verified && (
                    <span className="flex items-center text-xs text-blue-400">
                      <Key className="h-3 w-3 mr-1" />
                      WebAuthn
                    </span>
                  )}
                  {session.device_info.is_trusted && (
                    <span className="flex items-center text-xs text-cyan-400">
                      <Shield className="h-3 w-3 mr-1" />
                      Trusted Device
                    </span>
                  )}
                </div>
              </div>
            ))}
            
            {sessions.length === 0 && (
              <div className="text-center py-8 text-gray-400">
                <Users className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No active sessions</p>
              </div>
            )}
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default SecurityDashboard;
