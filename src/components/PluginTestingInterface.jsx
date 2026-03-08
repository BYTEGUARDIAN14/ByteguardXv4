import React, { useState, useEffect } from 'react';
import {
  Play, Code, FileText, TestTube, CheckCircle, AlertTriangle,
  Clock, Zap, Settings, Download, Copy, Eye, BarChart3
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
      content: `{\n  "Version": "2012-10-17",\n  "Statement": [{\n    "Effect": "Allow",\n    "Principal": "*",\n    "Action": "s3:GetObject",\n    "Resource": "arn:aws:s3:::my-bucket/*"\n  }]\n}`,
      fileName: 'bucket-policy.json'
    },
    'ssrf_detector': {
      name: 'SSRF Detector',
      content: `import requests\n\ndef fetch_url():\n    url = request.args.get('url')\n    response = requests.get(url)  # Vulnerable\n    return response.text`,
      fileName: 'app.py'
    },
    'jwt_security_validator': {
      name: 'JWT Security Validator',
      content: `JWT_SECRET = "weak123"\ntoken = jwt.encode(payload, JWT_SECRET, algorithm="none")`,
      fileName: 'auth.py'
    },
    'terraform_security_scanner': {
      name: 'Terraform Security Scanner',
      content: `resource "aws_s3_bucket" "example" {\n  bucket = "my-bucket"\n  acl    = "public-read"\n  server_side_encryption_configuration = []\n}`,
      fileName: 'main.tf'
    }
  };

  useEffect(() => {
    if (selectedPlugin && testCases[selectedPlugin]) setTestContent(testCases[selectedPlugin].content);
  }, [selectedPlugin]);

  const runPluginTest = async () => {
    if (!selectedPlugin || !testContent) return;
    setIsRunning(true); setTestResults(null);
    try {
      const testCase = testCases[selectedPlugin];
      const response = await tauriAPI.plugins.execute(selectedPlugin, {
        content: testContent, file_path: testCase.fileName, context: { test_mode: true }
      });
      if (response?.result) {
        setTestResults(response.result);
        setTestHistory(prev => [{
          id: Date.now(), plugin: selectedPlugin, timestamp: new Date().toISOString(),
          status: response.result.status, findings: response.result.findings?.length || 0,
          executionTime: response.result.execution_time_ms
        }, ...prev.slice(0, 9)]);
      } else throw new Error('Test execution failed');
    } catch (error) {
      console.error('Plugin test error:', error);
      setTestResults({ status: 'failed', error_message: error.message, findings: [] });
    } finally { setIsRunning(false); }
  };

  const copyToClipboard = (text) => navigator.clipboard.writeText(text);

  const getSeverityStyle = (severity) => ({
    critical: 'text-red-400 border-red-400/15', high: 'text-amber-400 border-amber-400/15',
    medium: 'text-yellow-400 border-yellow-400/15', low: 'text-blue-400 border-blue-400/15'
  }[severity] || 'text-text-disabled border-desktop-border');

  return (
    <div className="space-y-4">
      {/* Header */}
      <div>
        <h2 className="text-sm font-semibold text-text-primary">Plugin Testing</h2>
        <p className="text-[11px] text-text-muted">Test plugins with custom content</p>
      </div>

      {/* Plugin Selector + Run */}
      <div className="desktop-panel p-4">
        <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5 mb-3">
          <TestTube className="h-3.5 w-3.5 text-primary-400" /> Select & Run
        </h3>
        <div className="flex gap-2">
          <select value={selectedPlugin} onChange={(e) => setSelectedPlugin(e.target.value)} className="input text-xs py-1.5 flex-1">
            <option value="">Choose a plugin...</option>
            {Object.entries(testCases).map(([key, tc]) => <option key={key} value={key}>{tc.name}</option>)}
          </select>
          <button onClick={runPluginTest} disabled={!selectedPlugin || !testContent || isRunning}
            className={`text-xs px-4 py-1.5 rounded-desktop inline-flex items-center gap-1.5 transition-colors ${!selectedPlugin || !testContent || isRunning
                ? 'bg-desktop-card text-text-disabled cursor-not-allowed border border-desktop-border'
                : 'btn-primary'
              }`}
          >
            {isRunning ? (
              <><div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Testing...</>
            ) : (
              <><Play className="h-3.5 w-3.5" /> Run Test</>
            )}
          </button>
        </div>
      </div>

      {/* Test Content */}
      <div className="desktop-panel p-4">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5">
            <Code className="h-3.5 w-3.5 text-primary-400" /> Test Content
          </h3>
          <div className="flex items-center gap-2">
            <button onClick={() => copyToClipboard(testContent)} className="p-1 text-text-muted hover:text-text-primary rounded transition-colors" title="Copy">
              <Copy className="h-3 w-3" />
            </button>
            <span className="text-[10px] text-text-disabled">
              {selectedPlugin && testCases[selectedPlugin] ? testCases[selectedPlugin].fileName : 'No file'}
            </span>
          </div>
        </div>
        <textarea value={testContent} onChange={(e) => setTestContent(e.target.value)}
          placeholder="Enter test content or select a plugin..."
          className="w-full h-40 px-3 py-2 bg-desktop-bg border border-desktop-border rounded-desktop text-text-primary font-mono text-[11px] resize-none focus:outline-none focus:ring-1 focus:ring-primary-500" />
      </div>

      {/* Test Results */}
      {testResults && (
        <div className="desktop-panel p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5">
              <BarChart3 className="h-3.5 w-3.5 text-primary-400" /> Results
            </h3>
            <div className="flex items-center gap-2">
              <span className={`text-[11px] font-medium ${testResults.status === 'completed' ? 'text-emerald-400' : 'text-red-400'}`}>
                {testResults.status.toUpperCase()}
              </span>
              {testResults.execution_time_ms && (
                <span className="text-[10px] text-text-disabled">{testResults.execution_time_ms.toFixed(1)}ms</span>
              )}
            </div>
          </div>

          {testResults.error_message && (
            <div className="mb-3 p-2 bg-red-400/5 border border-red-400/10 rounded-desktop">
              <div className="flex items-center gap-1 text-red-400 text-[11px] font-medium">
                <AlertTriangle className="h-3 w-3" /> Error
              </div>
              <p className="text-[11px] text-red-300 mt-0.5">{testResults.error_message}</p>
            </div>
          )}

          {testResults.findings?.length > 0 ? (
            <div className="space-y-1.5">
              <p className="text-[11px] text-text-muted">{testResults.findings.length} finding(s)</p>
              {testResults.findings.map((finding, i) => (
                <div key={i} className="p-2 bg-desktop-card rounded-desktop border border-desktop-border">
                  <div className="flex items-center gap-1.5 mb-0.5">
                    <span className={`text-[10px] px-1 py-0 rounded border ${getSeverityStyle(finding.severity)}`}>
                      {finding.severity?.toUpperCase()}
                    </span>
                    <span className="text-xs text-text-primary">{finding.title}</span>
                  </div>
                  <p className="text-[11px] text-text-muted mb-1">{finding.description}</p>
                  <div className="flex items-center justify-between text-[10px] text-text-disabled">
                    <div className="flex gap-3">
                      {finding.line_number && <span>L{finding.line_number}</span>}
                      {finding.confidence && <span>{(finding.confidence * 100).toFixed(0)}%</span>}
                    </div>
                    {finding.cwe_id && <span className="text-primary-400">{finding.cwe_id}</span>}
                  </div>
                  {finding.context && (
                    <pre className="mt-1.5 p-1.5 bg-desktop-bg rounded border-l-2 border-primary-500 text-[10px] text-text-muted font-mono overflow-x-auto">
                      {finding.context}
                    </pre>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-6">
              <CheckCircle className="h-5 w-5 text-emerald-400 mx-auto mb-1" />
              <p className="text-xs text-text-muted">No issues found</p>
            </div>
          )}
        </div>
      )}

      {/* Test History */}
      <div className="desktop-panel">
        <div className="flex items-center justify-between px-4 py-3 border-b border-desktop-border">
          <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5">
            <Clock className="h-3.5 w-3.5 text-primary-400" /> History
          </h3>
        </div>
        {testHistory.length > 0 ? (
          <div className="divide-y divide-desktop-border">
            {testHistory.map((entry) => (
              <div key={entry.id} className="flex items-center justify-between px-4 py-2">
                <div className="flex items-center gap-2">
                  <div className={`w-1.5 h-1.5 rounded-full ${entry.status === 'completed' ? 'bg-emerald-400' : 'bg-red-400'}`} />
                  <div>
                    <p className="text-xs text-text-primary">{testCases[entry.plugin]?.name || entry.plugin}</p>
                    <p className="text-[10px] text-text-disabled">{new Date(entry.timestamp).toLocaleTimeString()}</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-xs text-primary-400">{entry.findings} findings</p>
                  <p className="text-[10px] text-text-disabled">{entry.executionTime?.toFixed(1)}ms</p>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-6">
            <TestTube className="h-5 w-5 text-text-disabled mx-auto mb-1" />
            <p className="text-xs text-text-muted">No test history</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default PluginTestingInterface;
