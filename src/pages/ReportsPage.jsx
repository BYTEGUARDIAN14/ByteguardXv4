import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Alert, AlertDescription } from '../components/ui/alert';
import { 
  FileText, 
  Download, 
  Calendar, 
  Filter,
  Eye,
  Trash2,
  Plus,
  BarChart3,
  PieChart,
  TrendingUp,
  Clock,
  CheckCircle,
  AlertTriangle
} from 'lucide-react';

const ReportsPage = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedFormat, setSelectedFormat] = useState('pdf');
  const [selectedScan, setSelectedScan] = useState('');
  const [availableScans, setAvailableScans] = useState([]);
  const [generatingReport, setGeneratingReport] = useState(false);

  useEffect(() => {
    loadReports();
    loadAvailableScans();
  }, []);

  const loadReports = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/report/list');
      if (response.ok) {
        const data = await response.json();
        setReports(data.reports || []);
      }
    } catch (error) {
      console.error('Failed to load reports:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadAvailableScans = async () => {
    try {
      const response = await fetch('/api/scan/list?status=completed&limit=50');
      if (response.ok) {
        const data = await response.json();
        setAvailableScans(data.scans || []);
      }
    } catch (error) {
      console.error('Failed to load scans:', error);
    }
  };

  const generateReport = async () => {
    if (!selectedScan) {
      alert('Please select a scan to generate a report for');
      return;
    }

    setGeneratingReport(true);
    try {
      const response = await fetch('/api/report/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          scan_id: selectedScan,
          format: selectedFormat
        }),
      });

      if (response.ok) {
        const data = await response.json();
        alert('Report generation started. You will be notified when it\'s ready.');
        loadReports(); // Refresh the reports list
      } else {
        throw new Error('Failed to generate report');
      }
    } catch (error) {
      console.error('Report generation failed:', error);
      alert('Failed to generate report: ' + error.message);
    } finally {
      setGeneratingReport(false);
    }
  };

  const downloadReport = async (reportId, filename) => {
    try {
      const response = await fetch(`/api/report/download/${reportId}`);
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = filename || `report_${reportId}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } else {
        throw new Error('Failed to download report');
      }
    } catch (error) {
      console.error('Download failed:', error);
      alert('Failed to download report: ' + error.message);
    }
  };

  const deleteReport = async (reportId) => {
    if (!confirm('Are you sure you want to delete this report?')) {
      return;
    }

    try {
      const response = await fetch(`/api/report/delete/${reportId}`, {
        method: 'DELETE'
      });

      if (response.ok) {
        setReports(reports.filter(report => report.report_id !== reportId));
      } else {
        throw new Error('Failed to delete report');
      }
    } catch (error) {
      console.error('Delete failed:', error);
      alert('Failed to delete report: ' + error.message);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-4 w-4 text-green-600" />;
      case 'generating': return <Clock className="h-4 w-4 text-yellow-600" />;
      case 'failed': return <AlertTriangle className="h-4 w-4 text-red-600" />;
      default: return <Clock className="h-4 w-4 text-gray-600" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'text-green-600';
      case 'generating': return 'text-yellow-600';
      case 'failed': return 'text-red-600';
      default: return 'text-gray-600';
    }
  };

  const getFormatIcon = (format) => {
    switch (format) {
      case 'pdf': return <FileText className="h-4 w-4" />;
      case 'json': return <BarChart3 className="h-4 w-4" />;
      case 'csv': return <PieChart className="h-4 w-4" />;
      default: return <FileText className="h-4 w-4" />;
    }
  };

  const mockReports = reports.length === 0 ? [
    {
      report_id: '1',
      scan_id: 'scan_123',
      format: 'pdf',
      status: 'completed',
      generated_at: '2024-01-15T10:30:00Z',
      file_size: '2.4 MB',
      scan_path: '/src/components',
      total_findings: 15
    },
    {
      report_id: '2',
      scan_id: 'scan_124',
      format: 'json',
      status: 'completed',
      generated_at: '2024-01-14T15:45:00Z',
      file_size: '156 KB',
      scan_path: '/api/routes',
      total_findings: 8
    },
    {
      report_id: '3',
      scan_id: 'scan_125',
      format: 'pdf',
      status: 'generating',
      generated_at: '2024-01-15T11:00:00Z',
      file_size: null,
      scan_path: '/src/utils',
      total_findings: null
    }
  ] : reports;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Security Reports</h1>
          <p className="text-gray-600 mt-1">
            Generate and manage security scan reports
          </p>
        </div>
      </div>

      {/* Generate New Report */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Plus className="h-5 w-5 mr-2" />
            Generate New Report
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Scan Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Select Scan
              </label>
              <select
                value={selectedScan}
                onChange={(e) => setSelectedScan(e.target.value)}
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
                disabled={generatingReport}
              >
                <option value="">Choose a completed scan...</option>
                {availableScans.map((scan) => (
                  <option key={scan.scan_id} value={scan.scan_id}>
                    {scan.directory_path} - {new Date(scan.started_at).toLocaleDateString()} 
                    ({scan.total_findings} findings)
                  </option>
                ))}
              </select>
            </div>

            {/* Format Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Report Format
              </label>
              <select
                value={selectedFormat}
                onChange={(e) => setSelectedFormat(e.target.value)}
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
                disabled={generatingReport}
              >
                <option value="pdf">PDF Report</option>
                <option value="json">JSON Data</option>
                <option value="csv">CSV Export</option>
                <option value="html">HTML Report</option>
              </select>
            </div>
          </div>

          <Button
            onClick={generateReport}
            disabled={!selectedScan || generatingReport}
            className="bg-cyan-600 hover:bg-cyan-700"
          >
            {generatingReport ? (
              <>
                <Clock className="h-4 w-4 mr-2 animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <FileText className="h-4 w-4 mr-2" />
                Generate Report
              </>
            )}
          </Button>
        </CardContent>
      </Card>

      {/* Reports List */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center">
              <FileText className="h-5 w-5 mr-2" />
              Generated Reports
            </div>
            <div className="flex items-center space-x-2">
              <Button variant="outline" size="sm" onClick={loadReports}>
                <TrendingUp className="h-4 w-4 mr-1" />
                Refresh
              </Button>
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center h-32">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div>
            </div>
          ) : mockReports.length > 0 ? (
            <div className="space-y-3">
              {mockReports.map((report) => (
                <div
                  key={report.report_id}
                  className="flex items-center justify-between p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
                >
                  <div className="flex items-center space-x-4">
                    <div className="flex items-center space-x-2">
                      {getFormatIcon(report.format)}
                      {getStatusIcon(report.status)}
                    </div>
                    <div>
                      <p className="font-medium text-sm">
                        {report.scan_path || 'Unknown path'}
                      </p>
                      <p className="text-xs text-gray-600">
                        Generated: {new Date(report.generated_at).toLocaleString()}
                      </p>
                      {report.total_findings !== null && (
                        <p className="text-xs text-gray-600">
                          {report.total_findings} findings
                        </p>
                      )}
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-3">
                    <div className="text-right">
                      <Badge 
                        variant="outline" 
                        className={`text-xs ${getStatusColor(report.status)}`}
                      >
                        {report.status}
                      </Badge>
                      <p className="text-xs text-gray-600 mt-1">
                        {report.format.toUpperCase()}
                        {report.file_size && ` • ${report.file_size}`}
                      </p>
                    </div>
                    
                    <div className="flex space-x-1">
                      {report.status === 'completed' && (
                        <>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => downloadReport(report.report_id, `report_${report.scan_id}.${report.format}`)}
                          >
                            <Download className="h-3 w-3" />
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => window.open(`/api/report/view/${report.report_id}`, '_blank')}
                          >
                            <Eye className="h-3 w-3" />
                          </Button>
                        </>
                      )}
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => deleteReport(report.report_id)}
                        className="text-red-600 hover:text-red-700"
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              <FileText className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No reports generated yet</p>
              <p className="text-sm">Generate your first report to see it here</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Report Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Total Reports</p>
                <p className="text-2xl font-bold text-gray-900">{mockReports.length}</p>
              </div>
              <FileText className="h-8 w-8 text-cyan-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">This Month</p>
                <p className="text-2xl font-bold text-gray-900">
                  {mockReports.filter(r => new Date(r.generated_at).getMonth() === new Date().getMonth()).length}
                </p>
              </div>
              <Calendar className="h-8 w-8 text-green-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Completed</p>
                <p className="text-2xl font-bold text-gray-900">
                  {mockReports.filter(r => r.status === 'completed').length}
                </p>
              </div>
              <CheckCircle className="h-8 w-8 text-blue-600" />
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default ReportsPage;
