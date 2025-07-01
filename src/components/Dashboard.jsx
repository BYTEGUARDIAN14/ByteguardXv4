import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Alert, AlertDescription } from './ui/alert';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Progress } from './ui/progress';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  TrendingUp,
  FileText,
  Zap,
  Activity
} from 'lucide-react';
import SecurityMetrics from './SecurityMetrics';
import VulnerabilityHeatmap from './VulnerabilityHeatmap';
import RiskMeter from './RiskMeter';

const Dashboard = () => {
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/dashboard');
      if (!response.ok) {
        throw new Error('Failed to fetch dashboard data');
      }
      const data = await response.json();
      setDashboardData(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
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

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical': return <AlertTriangle className="h-4 w-4" />;
      case 'high': return <AlertTriangle className="h-4 w-4" />;
      case 'medium': return <Clock className="h-4 w-4" />;
      case 'low': return <CheckCircle className="h-4 w-4" />;
      default: return <Shield className="h-4 w-4" />;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex items-center space-x-2">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div>
          <span className="text-gray-600">Loading dashboard...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <Alert className="border-red-200 bg-red-50">
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription className="text-red-800">
          Error loading dashboard: {error}
        </AlertDescription>
      </Alert>
    );
  }

  const mockData = dashboardData || {
    summary: {
      totalScans: 156,
      totalFindings: 89,
      criticalFindings: 3,
      highFindings: 12,
      mediumFindings: 34,
      lowFindings: 40,
      lastScanTime: '2024-01-15T10:30:00Z',
      riskScore: 65
    },
    recentScans: [
      {
        id: '1',
        path: '/src/components',
        status: 'completed',
        findings: 5,
        timestamp: '2024-01-15T10:30:00Z'
      },
      {
        id: '2',
        path: '/src/utils',
        status: 'completed',
        findings: 2,
        timestamp: '2024-01-15T09:15:00Z'
      },
      {
        id: '3',
        path: '/api/routes',
        status: 'running',
        findings: 0,
        timestamp: '2024-01-15T10:45:00Z'
      }
    ],
    trends: {
      weeklyFindings: [12, 8, 15, 6, 9, 11, 7],
      scanFrequency: [3, 5, 2, 4, 6, 3, 4]
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
          <p className="text-gray-600 mt-1">
            Monitor your application's security posture
          </p>
        </div>
        <Button onClick={fetchDashboardData} className="bg-cyan-600 hover:bg-cyan-700">
          <Activity className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card className="border-l-4 border-l-cyan-500">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
            <Shield className="h-4 w-4 text-cyan-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{mockData.summary.totalScans}</div>
            <p className="text-xs text-gray-600">
              +12% from last month
            </p>
          </CardContent>
        </Card>

        <Card className="border-l-4 border-l-red-500">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical Issues</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">
              {mockData.summary.criticalFindings}
            </div>
            <p className="text-xs text-gray-600">
              Requires immediate attention
            </p>
          </CardContent>
        </Card>

        <Card className="border-l-4 border-l-orange-500">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">High Priority</CardTitle>
            <TrendingUp className="h-4 w-4 text-orange-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-600">
              {mockData.summary.highFindings}
            </div>
            <p className="text-xs text-gray-600">
              -8% from last week
            </p>
          </CardContent>
        </Card>

        <Card className="border-l-4 border-l-green-500">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Risk Score</CardTitle>
            <Zap className="h-4 w-4 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">
              {mockData.summary.riskScore}/100
            </div>
            <Progress value={mockData.summary.riskScore} className="mt-2" />
          </CardContent>
        </Card>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Security Metrics */}
        <div className="lg:col-span-2">
          <SecurityMetrics data={mockData.summary} />
        </div>

        {/* Risk Meter */}
        <div>
          <RiskMeter score={mockData.summary.riskScore} />
        </div>
      </div>

      {/* Vulnerability Heatmap */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <VulnerabilityHeatmap data={mockData.trends} />
        
        {/* Recent Scans */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <FileText className="h-5 w-5 mr-2" />
              Recent Scans
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {mockData.recentScans.map((scan) => (
                <div key={scan.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className={`w-2 h-2 rounded-full ${
                      scan.status === 'completed' ? 'bg-green-500' : 
                      scan.status === 'running' ? 'bg-yellow-500' : 'bg-red-500'
                    }`}></div>
                    <div>
                      <p className="font-medium text-sm">{scan.path}</p>
                      <p className="text-xs text-gray-600">
                        {new Date(scan.timestamp).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Badge variant={scan.findings > 0 ? "destructive" : "secondary"}>
                      {scan.findings} issues
                    </Badge>
                    <Badge variant="outline">
                      {scan.status}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Severity Breakdown */}
      <Card>
        <CardHeader>
          <CardTitle>Findings by Severity</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { severity: 'critical', count: mockData.summary.criticalFindings, label: 'Critical' },
              { severity: 'high', count: mockData.summary.highFindings, label: 'High' },
              { severity: 'medium', count: mockData.summary.mediumFindings, label: 'Medium' },
              { severity: 'low', count: mockData.summary.lowFindings, label: 'Low' }
            ].map(({ severity, count, label }) => (
              <div key={severity} className="text-center p-4 bg-gray-50 rounded-lg">
                <div className={`inline-flex items-center justify-center w-12 h-12 rounded-full ${getSeverityColor(severity)} text-white mb-2`}>
                  {getSeverityIcon(severity)}
                </div>
                <div className="text-2xl font-bold">{count}</div>
                <div className="text-sm text-gray-600">{label}</div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default Dashboard;
