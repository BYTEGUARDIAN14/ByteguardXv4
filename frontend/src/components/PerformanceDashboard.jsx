import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { Line, Bar, Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { useRealTimeQuery } from '../hooks/useAdvancedQuery';
import { usePerformanceOptimization } from '../hooks/usePerformanceOptimization';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

/**
 * Real-time Performance Dashboard
 * Features: Live metrics, performance alerts, optimization recommendations
 */
const PerformanceDashboard = ({ className = '' }) => {
  const [timeRange, setTimeRange] = useState('1h');
  const [selectedMetrics, setSelectedMetrics] = useState(['cpu', 'memory', 'response_time']);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const { performanceMetrics, getPerformanceRecommendations } = usePerformanceOptimization();

  // Fetch real-time performance data
  const { data: performanceData, isLoading } = useRealTimeQuery(
    ['performance', timeRange],
    () => fetch(`/api/admin/performance/metrics?window=${timeRange}`).then(res => res.json()),
    'ws://localhost:5000/api/admin/performance/stream',
    {
      enabled: autoRefresh,
      refetchInterval: autoRefresh ? 5000 : false,
      updateFn: (oldData, newData) => {
        if (!oldData) return newData;
        
        // Update with new real-time data
        return {
          ...oldData,
          metrics: { ...oldData.metrics, ...newData.metrics },
          timestamp: newData.timestamp
        };
      }
    }
  );

  // Chart configurations
  const chartOptions = useMemo(() => ({
    responsive: true,
    maintainAspectRatio: false,
    interaction: {
      mode: 'index',
      intersect: false,
    },
    plugins: {
      legend: {
        position: 'top',
        labels: {
          usePointStyle: true,
          padding: 20
        }
      },
      tooltip: {
        backgroundColor: 'rgba(0, 0, 0, 0.8)',
        titleColor: '#fff',
        bodyColor: '#fff',
        borderColor: '#00bcd4',
        borderWidth: 1
      }
    },
    scales: {
      x: {
        grid: {
          color: 'rgba(255, 255, 255, 0.1)'
        },
        ticks: {
          color: '#9ca3af'
        }
      },
      y: {
        grid: {
          color: 'rgba(255, 255, 255, 0.1)'
        },
        ticks: {
          color: '#9ca3af'
        }
      }
    },
    elements: {
      line: {
        tension: 0.4
      },
      point: {
        radius: 3,
        hoverRadius: 6
      }
    }
  }), []);

  // Generate chart data
  const generateChartData = useCallback((metric) => {
    if (!performanceData?.metrics?.[metric]) return null;

    const data = performanceData.metrics[metric];
    const labels = data.map(point => new Date(point.timestamp).toLocaleTimeString());
    const values = data.map(point => point.value);

    const colors = {
      cpu: { border: '#ef4444', background: 'rgba(239, 68, 68, 0.1)' },
      memory: { border: '#f59e0b', background: 'rgba(245, 158, 11, 0.1)' },
      response_time: { border: '#10b981', background: 'rgba(16, 185, 129, 0.1)' },
      error_rate: { border: '#8b5cf6', background: 'rgba(139, 92, 246, 0.1)' }
    };

    return {
      labels,
      datasets: [{
        label: metric.replace('_', ' ').toUpperCase(),
        data: values,
        borderColor: colors[metric]?.border || '#00bcd4',
        backgroundColor: colors[metric]?.background || 'rgba(0, 188, 212, 0.1)',
        fill: true
      }]
    };
  }, [performanceData]);

  // Performance status calculation
  const systemStatus = useMemo(() => {
    if (!performanceData?.metrics) return 'unknown';

    const cpu = performanceData.metrics.cpu_usage?.current || 0;
    const memory = performanceData.metrics.memory_usage?.current || 0;
    const responseTime = performanceData.metrics.response_time?.current || 0;

    if (cpu > 80 || memory > 85 || responseTime > 2000) return 'critical';
    if (cpu > 60 || memory > 70 || responseTime > 1000) return 'warning';
    return 'healthy';
  }, [performanceData]);

  // Status indicator component
  const StatusIndicator = ({ status }) => {
    const statusConfig = {
      healthy: { color: 'text-green-500', bg: 'bg-green-500/20', label: 'Healthy' },
      warning: { color: 'text-yellow-500', bg: 'bg-yellow-500/20', label: 'Warning' },
      critical: { color: 'text-red-500', bg: 'bg-red-500/20', label: 'Critical' },
      unknown: { color: 'text-gray-500', bg: 'bg-gray-500/20', label: 'Unknown' }
    };

    const config = statusConfig[status] || statusConfig.unknown;

    return (
      <div className={`flex items-center space-x-2 px-3 py-1 rounded-full ${config.bg}`}>
        <div className={`w-2 h-2 rounded-full ${config.color.replace('text-', 'bg-')}`} />
        <span className={`text-sm font-medium ${config.color}`}>{config.label}</span>
      </div>
    );
  };

  // Metric card component
  const MetricCard = ({ title, value, unit, trend, status }) => (
    <div className="bg-base-200 rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-medium text-base-content/70">{title}</h3>
        <StatusIndicator status={status} />
      </div>
      
      <div className="flex items-end space-x-2">
        <span className="text-2xl font-bold text-base-content">
          {typeof value === 'number' ? value.toFixed(1) : value}
        </span>
        <span className="text-sm text-base-content/70">{unit}</span>
        
        {trend && (
          <div className={`flex items-center text-xs ${
            trend > 0 ? 'text-red-500' : 'text-green-500'
          }`}>
            <svg className="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d={
                trend > 0 
                  ? "M5.293 7.707a1 1 0 010-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 01-1.414 1.414L11 5.414V17a1 1 0 11-2 0V5.414L6.707 7.707a1 1 0 01-1.414 0z"
                  : "M14.707 12.293a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 111.414-1.414L9 14.586V3a1 1 0 112 0v11.586l2.293-2.293a1 1 0 011.414 0z"
              } clipRule="evenodd" />
            </svg>
            {Math.abs(trend).toFixed(1)}%
          </div>
        )}
      </div>
    </div>
  );

  // Recommendations component
  const RecommendationsPanel = () => {
    const recommendations = getPerformanceRecommendations();

    if (recommendations.length === 0) {
      return (
        <div className="bg-base-200 rounded-lg p-6 text-center">
          <div className="text-green-500 mb-2">
            <svg className="w-8 h-8 mx-auto" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
          </div>
          <p className="text-base-content/70">All systems performing optimally</p>
        </div>
      );
    }

    return (
      <div className="space-y-3">
        {recommendations.map((rec, index) => (
          <div key={index} className={`p-4 rounded-lg border-l-4 ${
            rec.priority === 'HIGH' ? 'border-red-500 bg-red-500/10' :
            rec.priority === 'MEDIUM' ? 'border-yellow-500 bg-yellow-500/10' :
            'border-blue-500 bg-blue-500/10'
          }`}>
            <div className="flex items-start justify-between">
              <div>
                <h4 className="font-medium text-base-content mb-1">{rec.issue}</h4>
                <p className="text-sm text-base-content/70">{rec.recommendation}</p>
              </div>
              <span className={`px-2 py-1 text-xs rounded ${
                rec.priority === 'HIGH' ? 'bg-red-500 text-white' :
                rec.priority === 'MEDIUM' ? 'bg-yellow-500 text-white' :
                'bg-blue-500 text-white'
              }`}>
                {rec.priority}
              </span>
            </div>
          </div>
        ))}
      </div>
    );
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="loading loading-spinner loading-lg"></div>
      </div>
    );
  }

  return (
    <div className={`performance-dashboard space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-base-content">Performance Dashboard</h2>
          <p className="text-base-content/70">Real-time system performance monitoring</p>
        </div>
        
        <div className="flex items-center space-x-4">
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="select select-sm select-bordered"
          >
            <option value="5m">Last 5 minutes</option>
            <option value="1h">Last hour</option>
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
          </select>
          
          <label className="flex items-center space-x-2 cursor-pointer">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="checkbox checkbox-sm"
            />
            <span className="text-sm">Auto-refresh</span>
          </label>
        </div>
      </div>

      {/* System Status */}
      <div className="bg-base-200 rounded-lg p-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold mb-2">System Status</h3>
            <StatusIndicator status={systemStatus} />
          </div>
          
          <div className="text-right">
            <div className="text-sm text-base-content/70">Last Updated</div>
            <div className="text-sm font-medium">
              {performanceData?.timestamp ? new Date(performanceData.timestamp).toLocaleString() : 'Never'}
            </div>
          </div>
        </div>
      </div>

      {/* Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="CPU Usage"
          value={performanceData?.metrics?.cpu_usage?.current || 0}
          unit="%"
          status={performanceData?.metrics?.cpu_usage?.current > 80 ? 'critical' : 
                  performanceData?.metrics?.cpu_usage?.current > 60 ? 'warning' : 'healthy'}
        />
        
        <MetricCard
          title="Memory Usage"
          value={performanceData?.metrics?.memory_usage?.current || 0}
          unit="%"
          status={performanceData?.metrics?.memory_usage?.current > 85 ? 'critical' : 
                  performanceData?.metrics?.memory_usage?.current > 70 ? 'warning' : 'healthy'}
        />
        
        <MetricCard
          title="Response Time"
          value={performanceData?.metrics?.response_time?.current || 0}
          unit="ms"
          status={performanceData?.metrics?.response_time?.current > 2000 ? 'critical' : 
                  performanceData?.metrics?.response_time?.current > 1000 ? 'warning' : 'healthy'}
        />
        
        <MetricCard
          title="Active Connections"
          value={performanceData?.metrics?.active_connections?.current || 0}
          unit=""
          status="healthy"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {selectedMetrics.map(metric => {
          const chartData = generateChartData(metric);
          if (!chartData) return null;

          return (
            <div key={metric} className="bg-base-200 rounded-lg p-6">
              <h3 className="text-lg font-semibold mb-4 capitalize">
                {metric.replace('_', ' ')} Trend
              </h3>
              <div className="h-64">
                <Line data={chartData} options={chartOptions} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Recommendations */}
      <div className="bg-base-200 rounded-lg p-6">
        <h3 className="text-lg font-semibold mb-4">Performance Recommendations</h3>
        <RecommendationsPanel />
      </div>

      {/* Active Alerts */}
      {performanceData?.active_alerts?.length > 0 && (
        <div className="bg-base-200 rounded-lg p-6">
          <h3 className="text-lg font-semibold mb-4">Active Alerts</h3>
          <div className="space-y-3">
            {performanceData.active_alerts.map((alert, index) => (
              <div key={index} className="flex items-center justify-between p-3 bg-red-500/10 border border-red-500/20 rounded">
                <div>
                  <div className="font-medium text-red-500">{alert.message}</div>
                  <div className="text-sm text-base-content/70">
                    {new Date(alert.triggered_at).toLocaleString()}
                  </div>
                </div>
                <span className="px-2 py-1 text-xs bg-red-500 text-white rounded">
                  {alert.severity}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default React.memo(PerformanceDashboard);
