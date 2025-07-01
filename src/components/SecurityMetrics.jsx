import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { Progress } from './ui/progress';
import { 
  TrendingUp, 
  TrendingDown, 
  Minus,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  BarChart3,
  PieChart,
  Activity
} from 'lucide-react';

const SecurityMetrics = ({ data }) => {
  const [metrics, setMetrics] = useState(null);
  const [timeRange, setTimeRange] = useState('7d');

  useEffect(() => {
    if (data) {
      calculateMetrics(data);
    }
  }, [data, timeRange]);

  const calculateMetrics = (rawData) => {
    // Calculate security metrics from raw data
    const totalFindings = rawData.totalFindings || 0;
    const criticalFindings = rawData.criticalFindings || 0;
    const highFindings = rawData.highFindings || 0;
    const mediumFindings = rawData.mediumFindings || 0;
    const lowFindings = rawData.lowFindings || 0;

    // Calculate percentages
    const criticalPercentage = totalFindings > 0 ? (criticalFindings / totalFindings) * 100 : 0;
    const highPercentage = totalFindings > 0 ? (highFindings / totalFindings) * 100 : 0;
    const mediumPercentage = totalFindings > 0 ? (mediumFindings / totalFindings) * 100 : 0;
    const lowPercentage = totalFindings > 0 ? (lowFindings / totalFindings) * 100 : 0;

    // Calculate risk score
    const riskScore = rawData.riskScore || calculateRiskScore(criticalFindings, highFindings, mediumFindings, lowFindings);

    // Calculate trends (mock data for demo)
    const trends = {
      critical: { value: criticalFindings, change: -12, direction: 'down' },
      high: { value: highFindings, change: -8, direction: 'down' },
      medium: { value: mediumFindings, change: 5, direction: 'up' },
      low: { value: lowFindings, change: 2, direction: 'up' },
      overall: { value: riskScore, change: -15, direction: 'down' }
    };

    setMetrics({
      totalFindings,
      criticalFindings,
      highFindings,
      mediumFindings,
      lowFindings,
      criticalPercentage,
      highPercentage,
      mediumPercentage,
      lowPercentage,
      riskScore,
      trends,
      scanCount: rawData.totalScans || 0,
      lastScan: rawData.lastScanTime || new Date().toISOString()
    });
  };

  const calculateRiskScore = (critical, high, medium, low) => {
    // Weighted risk calculation
    const weights = { critical: 10, high: 5, medium: 2, low: 1 };
    const totalWeight = (critical * weights.critical) + 
                       (high * weights.high) + 
                       (medium * weights.medium) + 
                       (low * weights.low);
    
    // Normalize to 0-100 scale (assuming max reasonable findings)
    const maxPossibleWeight = 100; // Adjust based on your scale
    return Math.min(100, Math.max(0, 100 - (totalWeight / maxPossibleWeight * 100)));
  };

  const getTrendIcon = (direction) => {
    switch (direction) {
      case 'up': return <TrendingUp className="h-4 w-4 text-red-500" />;
      case 'down': return <TrendingDown className="h-4 w-4 text-green-500" />;
      default: return <Minus className="h-4 w-4 text-gray-500" />;
    }
  };

  const getTrendColor = (direction) => {
    switch (direction) {
      case 'up': return 'text-red-600';
      case 'down': return 'text-green-600';
      default: return 'text-gray-600';
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  const getRiskLevel = (score) => {
    if (score >= 80) return { level: 'Low Risk', color: 'text-green-600', bg: 'bg-green-100' };
    if (score >= 60) return { level: 'Medium Risk', color: 'text-yellow-600', bg: 'bg-yellow-100' };
    if (score >= 40) return { level: 'High Risk', color: 'text-orange-600', bg: 'bg-orange-100' };
    return { level: 'Critical Risk', color: 'text-red-600', bg: 'bg-red-100' };
  };

  if (!metrics) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <BarChart3 className="h-5 w-5 mr-2" />
            Security Metrics
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center h-32">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div>
          </div>
        </CardContent>
      </Card>
    );
  }

  const riskLevel = getRiskLevel(metrics.riskScore);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <div className="flex items-center">
            <BarChart3 className="h-5 w-5 mr-2" />
            Security Metrics
          </div>
          <div className="flex space-x-2">
            {['7d', '30d', '90d'].map((range) => (
              <button
                key={range}
                onClick={() => setTimeRange(range)}
                className={`px-3 py-1 text-xs rounded-md transition-colors ${
                  timeRange === range
                    ? 'bg-cyan-100 text-cyan-700'
                    : 'text-gray-600 hover:bg-gray-100'
                }`}
              >
                {range}
              </button>
            ))}
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Overall Risk Score */}
        <div className="text-center p-6 bg-gradient-to-r from-gray-50 to-gray-100 rounded-lg">
          <div className="text-3xl font-bold mb-2">{metrics.riskScore}/100</div>
          <Badge className={`${riskLevel.bg} ${riskLevel.color} border-0`}>
            {riskLevel.level}
          </Badge>
          <div className="flex items-center justify-center mt-2 text-sm">
            {getTrendIcon(metrics.trends.overall.direction)}
            <span className={`ml-1 ${getTrendColor(metrics.trends.overall.direction)}`}>
              {Math.abs(metrics.trends.overall.change)}% vs last period
            </span>
          </div>
        </div>

        {/* Findings Breakdown */}
        <div className="space-y-4">
          <h4 className="font-semibold text-gray-900">Findings Breakdown</h4>
          
          {[
            { 
              severity: 'critical', 
              label: 'Critical', 
              count: metrics.criticalFindings, 
              percentage: metrics.criticalPercentage,
              trend: metrics.trends.critical
            },
            { 
              severity: 'high', 
              label: 'High', 
              count: metrics.highFindings, 
              percentage: metrics.highPercentage,
              trend: metrics.trends.high
            },
            { 
              severity: 'medium', 
              label: 'Medium', 
              count: metrics.mediumFindings, 
              percentage: metrics.mediumPercentage,
              trend: metrics.trends.medium
            },
            { 
              severity: 'low', 
              label: 'Low', 
              count: metrics.lowFindings, 
              percentage: metrics.lowPercentage,
              trend: metrics.trends.low
            }
          ].map(({ severity, label, count, percentage, trend }) => (
            <div key={severity} className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <div className={`w-3 h-3 rounded-full ${getSeverityColor(severity)}`}></div>
                  <span className="font-medium">{label}</span>
                  <span className="text-gray-600">({count})</span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-sm text-gray-600">{percentage.toFixed(1)}%</span>
                  <div className="flex items-center">
                    {getTrendIcon(trend.direction)}
                    <span className={`text-xs ml-1 ${getTrendColor(trend.direction)}`}>
                      {Math.abs(trend.change)}%
                    </span>
                  </div>
                </div>
              </div>
              <Progress 
                value={percentage} 
                className="h-2"
                style={{
                  '--progress-background': getSeverityColor(severity).replace('bg-', '')
                }}
              />
            </div>
          ))}
        </div>

        {/* Key Metrics */}
        <div className="grid grid-cols-2 gap-4 pt-4 border-t">
          <div className="text-center">
            <div className="text-2xl font-bold text-gray-900">{metrics.scanCount}</div>
            <div className="text-sm text-gray-600">Total Scans</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-gray-900">{metrics.totalFindings}</div>
            <div className="text-sm text-gray-600">Total Findings</div>
          </div>
        </div>

        {/* Last Scan Info */}
        <div className="flex items-center justify-between pt-4 border-t text-sm text-gray-600">
          <div className="flex items-center">
            <Clock className="h-4 w-4 mr-1" />
            Last scan: {new Date(metrics.lastScan).toLocaleString()}
          </div>
          <div className="flex items-center">
            <Activity className="h-4 w-4 mr-1" />
            {timeRange} view
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default SecurityMetrics;
