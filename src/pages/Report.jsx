import React, { useState, useEffect } from 'react'
import { useParams, useLocation, Link } from 'react-router-dom'
import toast from 'react-hot-toast'
import {
  FileText,
  Download,
  Share2,
  ArrowLeft,
  Calendar,
  Clock,
  FileCode,
  AlertTriangle,
  CheckCircle,
  Wrench,
  Eye,
  Filter,
  Shield,
  Bug,
  Lock,
  Zap
} from 'lucide-react'
import GlassCard from '../components/ui/GlassCard'
import Button from '../components/ui/Button'
import { SkeletonLoader } from '../components/ui/LoadingStates'
import { CircularProgress } from '../components/ui/ProgressIndicator'
import ScanResults from '../components/ScanResults'
import FixSuggestions from '../components/FixSuggestions'
import ExecutiveSummary from '../components/ExecutiveSummary'
import CVSSScore from '../components/CVSSScore'
import apiService from '../services/api'

const { scan: scanService } = apiService

const Report = () => {
  const { scanId } = useParams()
  const location = useLocation()
  const [reportData, setReportData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState('summary')
  const [isGeneratingPDF, setIsGeneratingPDF] = useState(false)
  const [filterSeverity, setFilterSeverity] = useState('all')

  useEffect(() => {
    if (location.state?.scanResults) {
      setReportData(location.state.scanResults)
      setLoading(false)
    } else if (scanId) {
      fetchReportData(scanId)
    } else {
      loadSampleData()
    }
  }, [scanId, location.state])

  const fetchReportData = async (id) => {
    try {
      const data = await scanService.getScanResults(id)
      setReportData(data)
    } catch (error) {
      console.error('Failed to fetch report data:', error)
      toast.error('Failed to load report data')
      loadSampleData()
    } finally {
      setLoading(false)
    }
  }

  const loadSampleData = () => {
    const sampleData = {
      scan_id: 'sample-scan-123',
      timestamp: new Date().toISOString(),
      total_files: 45,
      total_findings: 23,
      total_fixes: 18,
      findings: [
        {
          type: 'secret',
          subtype: 'api_keys.github_token',
          severity: 'critical',
          confidence: 0.95,
          file_path: 'src/config/auth.js',
          line_number: 12,
          description: 'GitHub Personal Access Token detected',
          context: "const token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'",
          recommendation: 'Move token to environment variable'
        },
        {
          type: 'vulnerability',
          subtype: 'dependency',
          severity: 'high',
          package_name: 'lodash',
          current_version: '4.17.20',
          fixed_version: '4.17.21',
          cve_id: 'CVE-2021-23337',
          file_path: 'package.json',
          line_number: 15,
          description: 'Lodash command injection vulnerability',
          recommendation: 'Update lodash to version 4.17.21 or later'
        },
        {
          type: 'ai_pattern',
          subtype: 'input_validation.no_input_sanitization',
          severity: 'medium',
          confidence: 0.82,
          file_path: 'src/utils/validator.js',
          line_number: 8,
          description: 'Direct use of user input without validation',
          context: "const name = input('Enter your name: ')",
          recommendation: 'Add input validation and sanitization'
        }
      ],
      fixes: [
        {
          vulnerability_type: 'api_keys.github_token',
          original_code: "const token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'",
          fixed_code: "const token = process.env.GITHUB_TOKEN",
          explanation: 'Store GitHub token in environment variable for security',
          confidence: 0.95,
          file_path: 'src/config/auth.js',
          line_number: 12
        }
      ],
      summary: {
        secrets: { total: 8, by_severity: { critical: 3, high: 2, medium: 2, low: 1 } },
        dependencies: { total: 12, by_severity: { critical: 1, high: 4, medium: 5, low: 2 } },
        ai_patterns: { total: 3, by_severity: { critical: 0, high: 0, medium: 2, low: 1 } }
      }
    }
    setReportData(sampleData)
    setLoading(false)
  }

  const handleGeneratePDF = async () => {
    if (!reportData) return

    setIsGeneratingPDF(true)
    try {
      const response = await scanService.generatePDFReport(reportData.scan_id)
      const link = document.createElement('a')
      link.href = response.download_url
      link.download = `byteguardx-report-${reportData.scan_id}.pdf`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      toast.success('PDF report generated successfully!')
    } catch (error) {
      console.error('PDF generation failed:', error)
      toast.error('Failed to generate PDF report')
    } finally {
      setIsGeneratingPDF(false)
    }
  }

  const handleShare = async () => {
    if (navigator.share) {
      try {
        await navigator.share({
          title: 'ByteGuardX Security Report',
          text: `Security scan report with ${reportData?.total_findings || 0} findings`,
          url: window.location.href
        })
      } catch (error) {
        // User cancelled sharing
      }
    } else {
      navigator.clipboard.writeText(window.location.href)
      toast.success('Report URL copied to clipboard!')
    }
  }

  const tabs = [
    { id: 'summary', label: 'Summary', icon: Eye },
    { id: 'findings', label: 'Findings', icon: AlertTriangle },
    { id: 'fixes', label: 'Fixes', icon: Wrench }
  ]

  if (loading) {
    return (
      <div className="p-6">
        <div className="flex items-center gap-3">
          <div className="w-4 h-4 border-2 border-primary-600 border-t-transparent rounded-full animate-spin" />
          <span className="text-sm text-text-muted">Loading report...</span>
        </div>
      </div>
    )
  }

  if (!reportData) {
    return (
      <div className="p-6 flex items-center justify-center h-full">
        <div className="text-center">
          <AlertTriangle className="h-8 w-8 text-red-400 mx-auto mb-3" />
          <h2 className="text-sm font-semibold text-text-primary mb-1">Report Not Found</h2>
          <p className="text-xs text-text-muted mb-4">The requested report could not be loaded.</p>
          <Link to="/scan" className="btn-primary text-xs px-4 py-2">
            Start New Scan
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-5 overflow-y-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <button
            onClick={() => window.history.back()}
            className="p-1.5 rounded-desktop text-text-muted hover:text-text-primary hover:bg-white/[0.04] transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
          </button>
          <div>
            <h1 className="text-lg font-semibold text-text-primary">Security Report</h1>
            <div className="flex items-center gap-3 mt-0.5 text-xs text-text-muted">
              <div className="flex items-center gap-1">
                <Calendar className="h-3 w-3" />
                <span>{new Date(reportData.timestamp).toLocaleDateString()}</span>
              </div>
              <div className="flex items-center gap-1">
                <Clock className="h-3 w-3" />
                <span>{new Date(reportData.timestamp).toLocaleTimeString()}</span>
              </div>
              <div className="flex items-center gap-1">
                <FileCode className="h-3 w-3" />
                <span>{reportData.total_files} files</span>
              </div>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button onClick={handleShare} className="btn-ghost text-xs px-3 py-1.5">
            <Share2 className="h-3.5 w-3.5 mr-1.5" />
            Share
          </button>
          <button
            onClick={handleGeneratePDF}
            disabled={isGeneratingPDF}
            className="btn-primary text-xs px-3 py-1.5"
          >
            {isGeneratingPDF ? (
              <>
                <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin mr-1.5" />
                Generating...
              </>
            ) : (
              <>
                <Download className="h-3.5 w-3.5 mr-1.5" />
                Download PDF
              </>
            )}
          </button>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-4 gap-4">
        <div className="desktop-panel p-3 text-center">
          <div className="text-xl font-semibold text-text-primary">{reportData.total_findings}</div>
          <div className="text-xs text-text-muted">Total Issues</div>
        </div>
        <div className="desktop-panel p-3 text-center">
          <div className="text-xl font-semibold text-red-400">
            {reportData.findings?.filter(f => f.severity === 'critical').length || 0}
          </div>
          <div className="text-xs text-text-muted">Critical</div>
        </div>
        <div className="desktop-panel p-3 text-center">
          <div className="text-xl font-semibold text-amber-400">
            {reportData.findings?.filter(f => f.severity === 'high').length || 0}
          </div>
          <div className="text-xs text-text-muted">High Risk</div>
        </div>
        <div className="desktop-panel p-3 text-center">
          <div className="text-xl font-semibold text-primary-400">{reportData.total_fixes || 0}</div>
          <div className="text-xs text-text-muted">Fix Suggestions</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-desktop-border">
        <nav className="flex gap-4">
          {tabs.map((tab) => {
            const Icon = tab.icon
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`
                  flex items-center gap-1.5 py-2 px-1 border-b-2 text-xs font-medium transition-colors
                  ${activeTab === tab.id
                    ? 'border-primary-500 text-primary-400'
                    : 'border-transparent text-text-muted hover:text-text-secondary'
                  }
                `}
              >
                <Icon className="h-3.5 w-3.5" />
                <span>{tab.label}</span>
              </button>
            )
          })}
        </nav>
      </div>

      {/* Tab Content */}
      <div>
        {activeTab === 'summary' && <ExecutiveSummary data={reportData} />}
        {activeTab === 'findings' && <ScanResults results={reportData} />}
        {activeTab === 'fixes' && <FixSuggestions fixes={reportData.fixes || []} />}
      </div>
    </div>
  )
}

export default Report
