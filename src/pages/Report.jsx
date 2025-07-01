import React, { useState, useEffect } from 'react'
import { useParams, useLocation, Link } from 'react-router-dom'
import { motion } from 'framer-motion'
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
  Filter
} from 'lucide-react'
import ScanResults from '../components/ScanResults'
import FixSuggestions from '../components/FixSuggestions'
import ExecutiveSummary from '../components/ExecutiveSummary'
import apiService from '../services/api'

const { scan: scanService } = apiService

const Report = () => {
  const { scanId } = useParams()
  const location = useLocation()
  const [reportData, setReportData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState('summary')
  const [isGeneratingPDF, setIsGeneratingPDF] = useState(false)

  useEffect(() => {
    // Try to get data from navigation state first
    if (location.state?.scanResults) {
      setReportData(location.state.scanResults)
      setLoading(false)
    } else if (scanId) {
      // Fetch data from API if scanId is provided
      fetchReportData(scanId)
    } else {
      // Load sample data for demo
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
      loadSampleData() // Fallback to sample data
    } finally {
      setLoading(false)
    }
  }

  const loadSampleData = () => {
    // Sample data for demonstration
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
      
      // Create download link
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
      // Fallback: copy URL to clipboard
      navigator.clipboard.writeText(window.location.href)
      toast.success('Report URL copied to clipboard!')
    }
  }

  const tabs = [
    { id: 'summary', label: 'Executive Summary', icon: Eye },
    { id: 'findings', label: 'Detailed Findings', icon: AlertTriangle },
    { id: 'fixes', label: 'Fix Suggestions', icon: Wrench }
  ]

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="spinner w-8 h-8 mx-auto mb-4"></div>
          <p className="text-gray-400">Loading report...</p>
        </div>
      </div>
    )
  }

  if (!reportData) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <AlertTriangle className="h-12 w-12 text-red-400 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-white mb-2">Report Not Found</h2>
          <p className="text-gray-400 mb-6">The requested report could not be loaded.</p>
          <Link to="/scan" className="btn-primary">
            Start New Scan
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen pt-8 pb-16">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <Link
                to="/scan"
                className="p-2 text-gray-400 hover:text-white transition-colors duration-200"
              >
                <ArrowLeft className="h-5 w-5" />
              </Link>
              
              <div>
                <h1 className="text-3xl font-bold text-white">
                  Security Report
                </h1>
                <div className="flex items-center space-x-4 mt-2 text-sm text-gray-400">
                  <div className="flex items-center space-x-1">
                    <Calendar className="h-4 w-4" />
                    <span>
                      {new Date(reportData.timestamp).toLocaleDateString()}
                    </span>
                  </div>
                  <div className="flex items-center space-x-1">
                    <Clock className="h-4 w-4" />
                    <span>
                      {new Date(reportData.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="flex items-center space-x-1">
                    <FileCode className="h-4 w-4" />
                    <span>{reportData.total_files} files scanned</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="flex items-center space-x-3">
              <button
                onClick={handleShare}
                className="btn-ghost"
              >
                <Share2 className="h-4 w-4 mr-2" />
                Share
              </button>
              
              <button
                onClick={handleGeneratePDF}
                disabled={isGeneratingPDF}
                className="btn-primary"
              >
                {isGeneratingPDF ? (
                  <>
                    <div className="spinner w-4 h-4 mr-2"></div>
                    Generating...
                  </>
                ) : (
                  <>
                    <Download className="h-4 w-4 mr-2" />
                    Download PDF
                  </>
                )}
              </button>
            </div>
          </div>
        </motion.div>

        {/* Quick Stats */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8"
        >
          <div className="card text-center">
            <div className="text-3xl font-bold text-white mb-2">
              {reportData.total_findings}
            </div>
            <div className="text-gray-400">Total Issues</div>
          </div>
          
          <div className="card text-center">
            <div className="text-3xl font-bold text-red-400 mb-2">
              {reportData.findings?.filter(f => f.severity === 'critical').length || 0}
            </div>
            <div className="text-gray-400">Critical</div>
          </div>
          
          <div className="card text-center">
            <div className="text-3xl font-bold text-orange-400 mb-2">
              {reportData.findings?.filter(f => f.severity === 'high').length || 0}
            </div>
            <div className="text-gray-400">High Risk</div>
          </div>
          
          <div className="card text-center">
            <div className="text-3xl font-bold text-primary-400 mb-2">
              {reportData.total_fixes || 0}
            </div>
            <div className="text-gray-400">Fix Suggestions</div>
          </div>
        </motion.div>

        {/* Tabs */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="mb-8"
        >
          <div className="border-b border-gray-700">
            <nav className="flex space-x-8">
              {tabs.map((tab) => {
                const Icon = tab.icon
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`
                      flex items-center space-x-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors duration-200
                      ${activeTab === tab.id
                        ? 'border-primary-500 text-primary-400'
                        : 'border-transparent text-gray-400 hover:text-gray-300'
                      }
                    `}
                  >
                    <Icon className="h-4 w-4" />
                    <span>{tab.label}</span>
                  </button>
                )
              })}
            </nav>
          </div>
        </motion.div>

        {/* Tab Content */}
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
        >
          {activeTab === 'summary' && (
            <ExecutiveSummary data={reportData} />
          )}
          
          {activeTab === 'findings' && (
            <ScanResults results={reportData} />
          )}
          
          {activeTab === 'fixes' && (
            <FixSuggestions fixes={reportData.fixes || []} />
          )}
        </motion.div>
      </div>
    </div>
  )
}

export default Report
