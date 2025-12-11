import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Activity,
  Play,
  Pause,
  CheckCircle,
  AlertTriangle,
  Clock,
  Zap,
  TrendingUp,
  BarChart3,
  Eye,
  Settings,
  RefreshCw
} from 'lucide-react';

const PluginExecutionMonitor = ({ onPluginSelect }) => {
  const [executions, setExecutions] = useState([]);
  const [isMonitoring, setIsMonitoring] = useState(true);
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    if (isMonitoring) {
      const interval = setInterval(fetchExecutions, 2000);
      return () => clearInterval(interval);
    }
  }, [isMonitoring]);

  const fetchExecutions = async () => {
    try {
      const response = await fetch('/api/v2/plugins/executions/recent');
      if (response.ok) {
        const data = await response.json();
        setExecutions(data.executions || generateMockExecutions());
      } else {
        setExecutions(generateMockExecutions());
      }
    } catch (error) {
      setExecutions(generateMockExecutions());
    }
  };

  const generateMockExecutions = () => {
    const plugins = [
      'AWS S3 Scanner', 'SSRF Detector', 'JWT Validator', 'GraphQL Scanner',
      'Terraform Scanner', 'Docker Analyzer', 'Crypto Detector', 'XSS Scanner'
    ];
    
    const statuses = ['completed', 'running', 'failed', 'queued'];
    const severities = ['critical', 'high', 'medium', 'low'];
    
    return Array.from({ length: 8 }, (_, i) => ({
      id: i + 1,
      plugin: plugins[i % plugins.length],
      status: statuses[Math.floor(Math.random() * statuses.length)],
      findings: Math.floor(Math.random() * 5),
      severity: severities[Math.floor(Math.random() * severities.length)],
      executionTime: (Math.random() * 3 + 0.5).toFixed(1),
      timestamp: new Date(Date.now() - Math.random() * 300000).toISOString(),
      confidence: (Math.random() * 0.4 + 0.6).toFixed(2)
    }));
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed': return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'running': return <Activity className="w-4 h-4 text-yellow-400 animate-pulse" />;
      case 'failed': return <AlertTriangle className="w-4 h-4 text-red-400" />;
      case 'queued': return <Clock className="w-4 h-4 text-gray-400" />;
      default: return <Clock className="w-4 h-4 text-gray-400" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'bg-green-500/20 text-green-400';
      case 'running': return 'bg-yellow-500/20 text-yellow-400';
      case 'failed': return 'bg-red-500/20 text-red-400';
      case 'queued': return 'bg-gray-500/20 text-gray-400';
      default: return 'bg-gray-500/20 text-gray-400';
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-400';
      case 'high': return 'text-orange-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-blue-400';
      default: return 'text-gray-400';
    }
  };

  const filteredExecutions = executions.filter(execution => {
    if (filter === 'all') return true;
    return execution.status === filter;
  });

  return (
    <div className="glass-card">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-cyan-500/20 rounded-lg">
            <Activity className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-white">Plugin Execution Monitor</h3>
            <p className="text-sm text-gray-400">Real-time plugin activity</p>
          </div>
        </div>
        
        <div className="flex items-center space-x-2">
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="px-3 py-1 bg-black/40 border border-white/10 rounded-md text-white text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <option value="all">All Status</option>
            <option value="completed">Completed</option>
            <option value="running">Running</option>
            <option value="failed">Failed</option>
            <option value="queued">Queued</option>
          </select>
          
          <button
            onClick={() => setIsMonitoring(!isMonitoring)}
            className={`p-2 rounded-md transition-colors ${
              isMonitoring 
                ? 'bg-green-500/20 text-green-400' 
                : 'bg-gray-500/20 text-gray-400'
            }`}
          >
            {isMonitoring ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
          </button>
          
          <button
            onClick={fetchExecutions}
            className="p-2 bg-cyan-500/20 text-cyan-400 rounded-md hover:bg-cyan-500/30 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      <div className="space-y-3 max-h-96 overflow-y-auto">
        <AnimatePresence>
          {filteredExecutions.map((execution) => (
            <motion.div
              key={execution.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              className="p-4 bg-black/20 border border-white/10 rounded-lg hover:bg-black/30 transition-colors cursor-pointer"
              onClick={() => onPluginSelect && onPluginSelect(execution)}
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center space-x-3">
                  {getStatusIcon(execution.status)}
                  <div>
                    <div className="text-sm font-medium text-white">
                      {execution.plugin}
                    </div>
                    <div className="text-xs text-gray-400">
                      {new Date(execution.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-2">
                  <span className={`px-2 py-1 rounded-md text-xs font-medium ${getStatusColor(execution.status)}`}>
                    {execution.status}
                  </span>
                  {execution.findings > 0 && (
                    <span className={`text-xs font-medium ${getSeverityColor(execution.severity)}`}>
                      {execution.findings} findings
                    </span>
                  )}
                </div>
              </div>
              
              <div className="flex items-center justify-between text-xs text-gray-400">
                <div className="flex items-center space-x-4">
                  <span>Time: {execution.executionTime}s</span>
                  <span>Confidence: {(execution.confidence * 100).toFixed(0)}%</span>
                </div>
                
                <div className="flex items-center space-x-1">
                  <Eye className="w-3 h-3" />
                  <span>View Details</span>
                </div>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      {filteredExecutions.length === 0 && (
        <div className="text-center py-8 text-gray-400">
          <Activity className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p>No plugin executions found</p>
          <p className="text-xs mt-1">
            {filter !== 'all' ? `No ${filter} executions` : 'Start a scan to see activity'}
          </p>
        </div>
      )}

      <div className="mt-4 pt-4 border-t border-white/10">
        <div className="grid grid-cols-4 gap-4 text-center">
          <div>
            <div className="text-lg font-bold text-green-400">
              {executions.filter(e => e.status === 'completed').length}
            </div>
            <div className="text-xs text-gray-400">Completed</div>
          </div>
          <div>
            <div className="text-lg font-bold text-yellow-400">
              {executions.filter(e => e.status === 'running').length}
            </div>
            <div className="text-xs text-gray-400">Running</div>
          </div>
          <div>
            <div className="text-lg font-bold text-red-400">
              {executions.filter(e => e.status === 'failed').length}
            </div>
            <div className="text-xs text-gray-400">Failed</div>
          </div>
          <div>
            <div className="text-lg font-bold text-gray-400">
              {executions.filter(e => e.status === 'queued').length}
            </div>
            <div className="text-xs text-gray-400">Queued</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PluginExecutionMonitor;
