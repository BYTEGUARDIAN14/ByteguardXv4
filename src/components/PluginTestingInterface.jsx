import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Play,
  Code,
  FileText,
  TestTube,
  CheckCircle,
  AlertTriangle,
  Clock,
  Zap,
  Settings,
  Download,
  Copy,
  Eye,
  BarChart3
} from 'lucide-react';
import tauriAPI from '../services/tauri-api';

const PluginTestingInterface = ({ pluginData }) => {
  const [selectedPlugin, setSelectedPlugin] = useState('');
  const [testContent, setTestContent] = useState('');
  const [testResults, setTestResults] = useState(null);
  const [isRunning, setIsRunning] = useState(false);
  const [testHistory, setTestHistory] = useState([]);

  const testCases = {
    'aws_s3_exposure_scanner': {
      name: 'AWS S3 Exposure Scanner',
      content: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}`,
      fileName: 'bucket-policy.json'
    },
    'ssrf_detector': {
      name: 'SSRF Detector',
      content: `import requests

def fetch_url():
    url = request.args.get('url')
    response = requests.get(url)  # Vulnerable to SSRF
    return response.text`,
      fileName: 'app.py'
    },
    'jwt_security_validator': {
      name: 'JWT Security Validator',
      content: `JWT_SECRET = "weak123"
token = jwt.encode(payload, JWT_SECRET, algorithm="none")`,
      fileName: 'auth.py'
    },
    'terraform_security_scanner': {
      name: 'Terraform Security Scanner',
      content: `resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"
  
  server_side_encryption_configuration = []
}`,
      fileName: 'main.tf'
    }
  };

  useEffect(() => {
    if (selectedPlugin && testCases[selectedPlugin]) {
      setTestContent(testCases[selectedPlugin].content);
    }
  }, [selectedPlugin]);

  const runPluginTest = async () => {
    if (!selectedPlugin || !testContent) return;

    setIsRunning(true);
    setTestResults(null);

    try {
      const testCase = testCases[selectedPlugin];
      const response = await tauriAPI.plugins.execute(selectedPlugin, {
        content: testContent,
        file_path: testCase.fileName,
        context: { test_mode: true }
      });

      if (response && response.result) {
        setTestResults(response.result);

        // Add to history
        const historyEntry = {
          id: Date.now(),
          plugin: selectedPlugin,
          timestamp: new Date().toISOString(),
          status: response.result.status,
          findings: response.result.findings?.length || 0,
          executionTime: response.result.execution_time_ms
        };
        setTestHistory(prev => [historyEntry, ...prev.slice(0, 9)]);
      } else {
        throw new Error('Test execution failed');
      }
    } catch (error) {
      console.error('Plugin test error:', error);
      setTestResults({
        status: 'failed',
        error_message: error.message,
        findings: []
      });
    } finally {
      setIsRunning(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  const renderPluginSelector = () => (
    <div className="glass-card mb-6">
      <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
        <TestTube className="w-5 h-5 mr-2 text-cyan-400" />
        Plugin Testing Interface
      </h3>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Select Plugin to Test
          </label>
          <select
            value={selectedPlugin}
            onChange={(e) => setSelectedPlugin(e.target.value)}
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <option value="">Choose a plugin...</option>
            {Object.entries(testCases).map(([key, testCase]) => (
              <option key={key} value={key}>
                {testCase.name}
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-end">
          <motion.button
            onClick={runPluginTest}
            disabled={!selectedPlugin || !testContent || isRunning}
            className={`flex items-center space-x-2 px-6 py-2 rounded-lg font-medium transition-all ${!selectedPlugin || !testContent || isRunning
              ? 'bg-gray-600 text-gray-400 cursor-not-allowed'
              : 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white hover:from-cyan-600 hover:to-blue-700'
              }`}
            whileHover={!selectedPlugin || !testContent || isRunning ? {} : { scale: 1.02 }}
            whileTap={!selectedPlugin || !testContent || isRunning ? {} : { scale: 0.98 }}
          >
            {isRunning ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white" />
                <span>Testing...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                <span>Run Test</span>
              </>
            )}
          </motion.button>
        </div>
      </div>
    </div>
  );

  const renderTestInput = () => (
    <div className="glass-card mb-6">
      <div className="flex items-center justify-between mb-4">
        <h4 className="text-md font-semibold text-white flex items-center">
          <Code className="w-4 h-4 mr-2 text-cyan-400" />
          Test Content
        </h4>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => copyToClipboard(testContent)}
            className="p-2 text-gray-400 hover:text-white transition-colors"
            title="Copy to clipboard"
          >
            <Copy className="w-4 h-4" />
          </button>
          <span className="text-xs text-gray-400">
            {selectedPlugin && testCases[selectedPlugin] ? testCases[selectedPlugin].fileName : 'No file selected'}
          </span>
        </div>
      </div>

      <textarea
        value={testContent}
        onChange={(e) => setTestContent(e.target.value)}
        placeholder="Enter test content or select a plugin to load sample data..."
        className="w-full h-64 px-4 py-3 bg-black/40 border border-white/10 rounded-lg text-white font-mono text-sm resize-none focus:outline-none focus:ring-2 focus:ring-cyan-500"
      />
    </div>
  );

  const renderTestResults = () => {
    if (!testResults) return null;

    const getStatusColor = (status) => {
      switch (status) {
        case 'completed': return 'text-green-400';
        case 'failed': return 'text-red-400';
        default: return 'text-gray-400';
      }
    };

    const getSeverityColor = (severity) => {
      switch (severity) {
        case 'critical': return 'text-red-400 bg-red-500/20';
        case 'high': return 'text-orange-400 bg-orange-500/20';
        case 'medium': return 'text-yellow-400 bg-yellow-500/20';
        case 'low': return 'text-blue-400 bg-blue-500/20';
        default: return 'text-gray-400 bg-gray-500/20';
      }
    };

    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass-card mb-6"
      >
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-md font-semibold text-white flex items-center">
            <BarChart3 className="w-4 h-4 mr-2 text-cyan-400" />
            Test Results
          </h4>
          <div className="flex items-center space-x-2">
            <span className={`text-sm font-medium ${getStatusColor(testResults.status)}`}>
              {testResults.status.toUpperCase()}
            </span>
            {testResults.execution_time_ms && (
              <span className="text-xs text-gray-400">
                {testResults.execution_time_ms.toFixed(1)}ms
              </span>
            )}
          </div>
        </div>

        {testResults.error_message && (
          <div className="mb-4 p-3 bg-red-500/20 border border-red-500/30 rounded-lg">
            <div className="flex items-center space-x-2 text-red-400">
              <AlertTriangle className="w-4 h-4" />
              <span className="font-medium">Error</span>
            </div>
            <p className="text-sm text-red-300 mt-1">{testResults.error_message}</p>
          </div>
        )}

        {testResults.findings && testResults.findings.length > 0 ? (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">
                Found {testResults.findings.length} finding(s)
              </span>
            </div>

            {testResults.findings.map((finding, index) => (
              <div key={index} className="p-4 bg-black/20 border border-white/10 rounded-lg">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-1">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(finding.severity)}`}>
                        {finding.severity?.toUpperCase()}
                      </span>
                      <span className="text-white font-medium">{finding.title}</span>
                    </div>
                    <p className="text-gray-400 text-sm">{finding.description}</p>
                  </div>
                </div>

                <div className="flex items-center justify-between text-xs text-gray-500 mt-3">
                  <div className="flex items-center space-x-4">
                    {finding.line_number && (
                      <span>Line {finding.line_number}</span>
                    )}
                    {finding.confidence && (
                      <span>Confidence: {(finding.confidence * 100).toFixed(0)}%</span>
                    )}
                  </div>
                  {finding.cwe_id && (
                    <span className="text-cyan-400">{finding.cwe_id}</span>
                  )}
                </div>

                {finding.context && (
                  <div className="mt-2 p-2 bg-black/40 rounded border-l-2 border-cyan-500">
                    <code className="text-xs text-gray-300">{finding.context}</code>
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8 text-gray-400">
            <CheckCircle className="w-8 h-8 mx-auto mb-2 text-green-400" />
            <p>No security issues found</p>
            <p className="text-xs mt-1">The test content appears to be secure</p>
          </div>
        )}
      </motion.div>
    );
  };

  const renderTestHistory = () => (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card"
    >
      <h4 className="text-md font-semibold text-white mb-4 flex items-center">
        <Clock className="w-4 h-4 mr-2 text-cyan-400" />
        Test History
      </h4>

      {testHistory.length > 0 ? (
        <div className="space-y-2">
          {testHistory.map((entry) => (
            <div key={entry.id} className="flex items-center justify-between p-3 bg-black/20 rounded-lg">
              <div className="flex items-center space-x-3">
                <div className={`w-2 h-2 rounded-full ${entry.status === 'completed' ? 'bg-green-400' : 'bg-red-400'
                  }`} />
                <div>
                  <div className="text-sm font-medium text-white">
                    {testCases[entry.plugin]?.name || entry.plugin}
                  </div>
                  <div className="text-xs text-gray-400">
                    {new Date(entry.timestamp).toLocaleTimeString()}
                  </div>
                </div>
              </div>
              <div className="text-right">
                <div className="text-sm text-cyan-400">
                  {entry.findings} findings
                </div>
                <div className="text-xs text-gray-400">
                  {entry.executionTime?.toFixed(1)}ms
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-center py-8 text-gray-400">
          <TestTube className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p>No test history</p>
          <p className="text-xs mt-1">Run some plugin tests to see history</p>
        </div>
      )}
    </motion.div>
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white mb-2">Plugin Testing</h2>
          <p className="text-gray-400">
            Test individual plugins with custom content and analyze results
          </p>
        </div>
      </div>

      {renderPluginSelector()}
      {renderTestInput()}
      {renderTestResults()}
      {renderTestHistory()}
    </div>
  );
};

export default PluginTestingInterface;
