import React from 'react'
import { motion } from 'framer-motion'
import { BookOpen, ExternalLink, Code, Terminal, Puzzle, Shield, Zap, FileText } from 'lucide-react'

const Docs: React.FC = () => {
  const docSections = [
    {
      title: 'Getting Started',
      icon: Zap,
      description: 'Quick start guides and installation instructions',
      links: [
        { name: 'Installation Guide', href: '#installation', description: 'Install ByteGuardX on your platform' },
        { name: 'First Scan', href: '#first-scan', description: 'Run your first security scan' },
        { name: 'Configuration', href: '#configuration', description: 'Configure ByteGuardX for your needs' },
        { name: 'Troubleshooting', href: '#troubleshooting', description: 'Common issues and solutions' },
      ]
    },
    {
      title: 'CLI Reference',
      icon: Terminal,
      description: 'Complete command-line interface documentation',
      links: [
        { name: 'Command Overview', href: '#cli-overview', description: 'All available CLI commands' },
        { name: 'Scan Options', href: '#scan-options', description: 'Scanning configuration and options' },
        { name: 'Report Generation', href: '#report-generation', description: 'Generate and customize reports' },
        { name: 'CI/CD Integration', href: '#cicd-integration', description: 'Use ByteGuardX in your pipelines' },
      ]
    },
    {
      title: 'API Documentation',
      icon: Code,
      description: 'REST API reference and SDK documentation',
      links: [
        { name: 'REST API Reference', href: 'https://api.byteguardx.com/docs', description: 'Complete API documentation', external: true },
        { name: 'Python SDK', href: '#python-sdk', description: 'Python SDK documentation and examples' },
        { name: 'JavaScript SDK', href: '#javascript-sdk', description: 'JavaScript/TypeScript SDK guide' },
        { name: 'Authentication', href: '#authentication', description: 'API authentication methods' },
      ]
    },
    {
      title: 'Extensions',
      icon: Puzzle,
      description: 'IDE and browser extension documentation',
      links: [
        { name: 'VS Code Extension', href: '#vscode-extension', description: 'VS Code integration guide' },
        { name: 'Browser Extensions', href: '#browser-extensions', description: 'Chrome and Firefox extensions' },
        { name: 'Git Hooks', href: '#git-hooks', description: 'Pre-commit hook setup' },
        { name: 'Custom Extensions', href: '#custom-extensions', description: 'Build your own extensions' },
      ]
    },
    {
      title: 'Security Features',
      icon: Shield,
      description: 'Detailed security feature documentation',
      links: [
        { name: 'Secret Detection', href: '#secret-detection', description: 'Configure secret scanning rules' },
        { name: 'Dependency Scanning', href: '#dependency-scanning', description: 'CVE and dependency analysis' },
        { name: 'AI Pattern Analysis', href: '#ai-patterns', description: 'AI-powered vulnerability detection' },
        { name: 'Custom Rules', href: '#custom-rules', description: 'Create custom security rules' },
      ]
    },
    {
      title: 'Enterprise',
      icon: FileText,
      description: 'Enterprise features and deployment guides',
      links: [
        { name: 'SSO Integration', href: '#sso-integration', description: 'Single sign-on configuration' },
        { name: 'RBAC & Permissions', href: '#rbac', description: 'Role-based access control' },
        { name: 'Audit Logging', href: '#audit-logging', description: 'Security audit and compliance' },
        { name: 'On-Premise Deployment', href: '#on-premise', description: 'Self-hosted deployment guide' },
      ]
    }
  ]

  const quickLinks = [
    { name: 'Installation', href: '#installation' },
    { name: 'CLI Commands', href: '#cli-overview' },
    { name: 'API Reference', href: 'https://api.byteguardx.com/docs', external: true },
    { name: 'VS Code Extension', href: '#vscode-extension' },
    { name: 'Examples', href: '#examples' },
    { name: 'FAQ', href: '#faq' },
  ]

  const examples = [
    {
      title: 'Basic CLI Scan',
      language: 'bash',
      code: `# Scan a directory
byteguardx scan /path/to/project

# Scan with PDF report
byteguardx scan /path/to/project --pdf

# Scan with fix suggestions
byteguardx scan /path/to/project --fix`
    },
    {
      title: 'Python SDK Usage',
      language: 'python',
      code: `from byteguardx import ByteGuardXClient

# Initialize client
client = ByteGuardXClient(api_key="your-api-key")

# Scan a directory
result = client.scan_directory("/path/to/project")

# Generate report
report = client.generate_report(result.scan_id, format="pdf")`
    },
    {
      title: 'JavaScript SDK Usage',
      language: 'javascript',
      code: `import { ByteGuardXClient } from '@byteguardx/sdk';

// Initialize client
const client = new ByteGuardXClient({
  apiKey: 'your-api-key'
});

// Scan a file
const result = await client.scanFile('/path/to/file.js');

// Get fix suggestions
const fixes = await client.getFixSuggestions(result.findings[0].id);`
    }
  ]

  return (
    <div className="min-h-screen section-padding">
      <div className="max-w-7xl mx-auto container-padding">
        {/* Header */}
        <div className="text-center mb-16">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
          >
            <div className="flex justify-center mb-8">
              <div className="glass-panel p-6 rounded-3xl">
                <BookOpen className="h-16 w-16 text-cyan-400" />
              </div>
            </div>
            <h1 className="text-4xl md:text-5xl font-bold mb-8">
              <span className="gradient-text">Documentation</span>
            </h1>
            <p className="text-xl text-gray-300 max-w-2xl mx-auto font-light leading-relaxed">
              Everything you need to know about using ByteGuardX effectively in your development workflow.
            </p>
          </motion.div>
        </div>

        {/* Quick Links */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="glass-card mb-20"
        >
          <h2 className="text-xl font-semibold mb-6 text-white">Quick Links</h2>
          <div className="flex flex-wrap gap-3">
            {quickLinks.map((link) => (
              <motion.a
                key={link.name}
                href={link.href}
                target={link.external ? '_blank' : undefined}
                rel={link.external ? 'noopener noreferrer' : undefined}
                className="inline-flex items-center space-x-2 px-4 py-2 glass-panel rounded-xl text-sm hover-lift transition-all duration-300"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <span className="text-gray-300">{link.name}</span>
                {link.external && <ExternalLink className="h-3 w-3 text-cyan-400" />}
              </motion.a>
            ))}
          </div>
        </motion.div>

        {/* Documentation Sections */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 mb-16">
          {docSections.map((section, index) => {
            const Icon = section.icon
            return (
              <motion.div
                key={section.title}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: 0.1 * index }}
                className="card p-6 card-hover"
              >
                <div className="flex items-center space-x-3 mb-4">
                  <div className="p-2 bg-primary-500/10 rounded-lg">
                    <Icon className="h-6 w-6 text-primary-400" />
                  </div>
                  <h3 className="text-xl font-semibold">{section.title}</h3>
                </div>
                
                <p className="text-gray-400 mb-6">{section.description}</p>
                
                <div className="space-y-3">
                  {section.links.map((link) => (
                    <a
                      key={link.name}
                      href={link.href}
                      target={link.external ? '_blank' : undefined}
                      rel={link.external ? 'noopener noreferrer' : undefined}
                      className="block p-3 bg-gray-800/50 hover:bg-gray-800 rounded-lg transition-colors group"
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="font-medium group-hover:text-primary-400 transition-colors">
                            {link.name}
                          </div>
                          <div className="text-sm text-gray-400">{link.description}</div>
                        </div>
                        {link.external && <ExternalLink className="h-4 w-4 text-gray-400" />}
                      </div>
                    </a>
                  ))}
                </div>
              </motion.div>
            )
          })}
        </div>

        {/* Code Examples */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.4 }}
          className="mb-16"
        >
          <h2 className="text-3xl font-bold text-center mb-12">
            Code <span className="gradient-text">Examples</span>
          </h2>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {examples.map((example) => (
              <div key={example.title} className="card p-6">
                <h3 className="text-lg font-semibold mb-4">{example.title}</h3>
                <div className="bg-gray-900 rounded-lg p-4 overflow-x-auto">
                  <pre className="text-sm">
                    <code className="text-gray-300">{example.code}</code>
                  </pre>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Support CTA */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.6 }}
          className="card p-12 text-center"
        >
          <h3 className="text-2xl font-bold mb-4">Need More Help?</h3>
          <p className="text-gray-400 mb-8 max-w-2xl mx-auto">
            Can't find what you're looking for? Our support team is here to help you get the most out of ByteGuardX.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <a href="/support" className="btn-primary">
              Contact Support
            </a>
            <a
              href="https://github.com/byteguardx/byteguardx/discussions"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-secondary"
            >
              <ExternalLink className="h-4 w-4 mr-2" />
              Community Forum
            </a>
          </div>
        </motion.div>
      </div>
    </div>
  )
}

export default Docs
