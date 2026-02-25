import React, { useState, useEffect } from 'react'
import {
  FileText,
  Download,
  Calendar,
  Eye,
  Trash2,
  Plus,
  BarChart3,
  PieChart,
  TrendingUp,
  Clock,
  CheckCircle,
  AlertTriangle
} from 'lucide-react'

const ReportsPage = () => {
  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedFormat, setSelectedFormat] = useState('pdf')
  const [selectedScan, setSelectedScan] = useState('')
  const [availableScans, setAvailableScans] = useState([])
  const [generatingReport, setGeneratingReport] = useState(false)

  useEffect(() => {
    loadReports()
    loadAvailableScans()
  }, [])

  const loadReports = async () => {
    try {
      setLoading(true)
      const response = await fetch('/api/report/list')
      if (response.ok) {
        const data = await response.json()
        setReports(data.reports || [])
      }
    } catch (error) {
      console.error('Failed to load reports:', error)
    } finally {
      setLoading(false)
    }
  }

  const loadAvailableScans = async () => {
    try {
      const response = await fetch('/api/scan/list?status=completed&limit=50')
      if (response.ok) {
        const data = await response.json()
        setAvailableScans(data.scans || [])
      }
    } catch (error) {
      console.error('Failed to load scans:', error)
    }
  }

  const generateReport = async () => {
    if (!selectedScan) return
    setGeneratingReport(true)
    try {
      const response = await fetch('/api/report/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: selectedScan, format: selectedFormat }),
      })
      if (response.ok) {
        loadReports()
      } else {
        throw new Error('Failed to generate report')
      }
    } catch (error) {
      console.error('Report generation failed:', error)
    } finally {
      setGeneratingReport(false)
    }
  }

  const downloadReport = async (reportId, filename) => {
    try {
      const response = await fetch(`/api/report/download/${reportId}`)
      if (response.ok) {
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.style.display = 'none'
        a.href = url
        a.download = filename || `report_${reportId}.pdf`
        document.body.appendChild(a)
        a.click()
        window.URL.revokeObjectURL(url)
        document.body.removeChild(a)
      }
    } catch (error) {
      console.error('Download failed:', error)
    }
  }

  const deleteReport = async (reportId) => {
    if (!confirm('Delete this report?')) return
    try {
      const response = await fetch(`/api/report/delete/${reportId}`, { method: 'DELETE' })
      if (response.ok) {
        setReports(reports.filter(r => r.report_id !== reportId))
      }
    } catch (error) {
      console.error('Delete failed:', error)
    }
  }

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />
      case 'generating': return <Clock className="h-3.5 w-3.5 text-amber-400 animate-spin" />
      case 'failed': return <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
      default: return <Clock className="h-3.5 w-3.5 text-text-disabled" />
    }
  }

  const getFormatIcon = (format) => {
    switch (format) {
      case 'pdf': return <FileText className="h-3.5 w-3.5" />
      case 'json': return <BarChart3 className="h-3.5 w-3.5" />
      case 'csv': return <PieChart className="h-3.5 w-3.5" />
      default: return <FileText className="h-3.5 w-3.5" />
    }
  }

  const mockReports = reports.length === 0 ? [
    {
      report_id: '1', scan_id: 'scan_123', format: 'pdf', status: 'completed',
      generated_at: '2024-01-15T10:30:00Z', file_size: '2.4 MB',
      scan_path: '/src/components', total_findings: 15
    },
    {
      report_id: '2', scan_id: 'scan_124', format: 'json', status: 'completed',
      generated_at: '2024-01-14T15:45:00Z', file_size: '156 KB',
      scan_path: '/api/routes', total_findings: 8
    },
    {
      report_id: '3', scan_id: 'scan_125', format: 'pdf', status: 'generating',
      generated_at: '2024-01-15T11:00:00Z', file_size: null,
      scan_path: '/src/utils', total_findings: null
    }
  ] : reports

  return (
    <div className="p-6 space-y-5 overflow-y-auto">
      {/* Header */}
      <div>
        <h1 className="text-lg font-semibold text-text-primary">Security Reports</h1>
        <p className="text-xs text-text-muted mt-0.5">Generate and manage security scan reports</p>
      </div>

      {/* Generate New Report */}
      <div className="desktop-panel p-4 space-y-3">
        <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5">
          <Plus className="h-3.5 w-3.5 text-primary-400" />
          Generate New Report
        </h3>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs text-text-muted mb-1">Select Scan</label>
            <select
              value={selectedScan}
              onChange={(e) => setSelectedScan(e.target.value)}
              className="input text-xs py-1.5"
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
          <div>
            <label className="block text-xs text-text-muted mb-1">Format</label>
            <select
              value={selectedFormat}
              onChange={(e) => setSelectedFormat(e.target.value)}
              className="input text-xs py-1.5"
              disabled={generatingReport}
            >
              <option value="pdf">PDF Report</option>
              <option value="json">JSON Data</option>
              <option value="csv">CSV Export</option>
              <option value="html">HTML Report</option>
            </select>
          </div>
        </div>

        <button
          onClick={generateReport}
          disabled={!selectedScan || generatingReport}
          className="btn-primary text-xs px-4 py-1.5 inline-flex items-center gap-1.5"
        >
          {generatingReport ? (
            <>
              <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Generating...
            </>
          ) : (
            <>
              <FileText className="h-3.5 w-3.5" />
              Generate Report
            </>
          )}
        </button>
      </div>

      {/* Reports List */}
      <div className="desktop-panel">
        <div className="flex items-center justify-between px-4 py-3 border-b border-desktop-border">
          <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5">
            <FileText className="h-3.5 w-3.5 text-primary-400" />
            Generated Reports
          </h3>
          <button onClick={loadReports} className="btn-ghost text-[11px] px-2 py-1 inline-flex items-center gap-1">
            <TrendingUp className="h-3 w-3" />
            Refresh
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-10">
            <div className="w-5 h-5 border-2 border-primary-600 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : mockReports.length > 0 ? (
          <div className="divide-y divide-desktop-border">
            {mockReports.map((report) => (
              <div
                key={report.report_id}
                className="flex items-center justify-between px-4 py-2.5 hover:bg-white/[0.02] transition-colors"
              >
                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-1.5 text-text-muted">
                    {getFormatIcon(report.format)}
                    {getStatusIcon(report.status)}
                  </div>
                  <div>
                    <p className="text-xs font-medium text-text-primary">
                      {report.scan_path || 'Unknown path'}
                    </p>
                    <p className="text-[11px] text-text-disabled">
                      {new Date(report.generated_at).toLocaleString()}
                      {report.total_findings !== null && ` · ${report.total_findings} findings`}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span className={`text-[11px] px-1.5 py-0.5 rounded-desktop border ${report.status === 'completed' ? 'border-emerald-400/20 text-emerald-400 bg-emerald-400/5' :
                      report.status === 'generating' ? 'border-amber-400/20 text-amber-400 bg-amber-400/5' :
                        report.status === 'failed' ? 'border-red-400/20 text-red-400 bg-red-400/5' :
                          'border-desktop-border text-text-disabled bg-desktop-card'
                    }`}>
                    {report.status}
                  </span>
                  <span className="text-[11px] text-text-disabled">
                    {report.format.toUpperCase()}{report.file_size && ` · ${report.file_size}`}
                  </span>

                  <div className="flex gap-0.5">
                    {report.status === 'completed' && (
                      <>
                        <button
                          onClick={() => downloadReport(report.report_id, `report_${report.scan_id}.${report.format}`)}
                          className="p-1 text-text-muted hover:text-text-primary hover:bg-white/[0.04] rounded transition-colors"
                          title="Download"
                        >
                          <Download className="h-3.5 w-3.5" />
                        </button>
                        <button
                          onClick={() => window.open(`/api/report/view/${report.report_id}`, '_blank')}
                          className="p-1 text-text-muted hover:text-text-primary hover:bg-white/[0.04] rounded transition-colors"
                          title="View"
                        >
                          <Eye className="h-3.5 w-3.5" />
                        </button>
                      </>
                    )}
                    <button
                      onClick={() => deleteReport(report.report_id)}
                      className="p-1 text-text-muted hover:text-red-400 hover:bg-red-400/5 rounded transition-colors"
                      title="Delete"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-10">
            <FileText className="h-8 w-8 mx-auto mb-2 text-text-disabled" />
            <p className="text-xs text-text-muted">No reports generated yet</p>
          </div>
        )}
      </div>

      {/* Report Statistics */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Total Reports', value: mockReports.length, icon: FileText, color: 'text-primary-400' },
          { label: 'This Month', value: mockReports.filter(r => new Date(r.generated_at).getMonth() === new Date().getMonth()).length, icon: Calendar, color: 'text-emerald-400' },
          { label: 'Completed', value: mockReports.filter(r => r.status === 'completed').length, icon: CheckCircle, color: 'text-blue-400' }
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="desktop-panel p-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[11px] text-text-muted">{label}</p>
                <p className="text-lg font-semibold text-text-primary">{value}</p>
              </div>
              <Icon className={`h-5 w-5 ${color}`} />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default ReportsPage
