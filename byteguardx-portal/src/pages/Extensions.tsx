import React from 'react'
import { motion } from 'framer-motion'
import { Code, Chrome, Puzzle, Terminal, Download, ExternalLink, CheckCircle, Star } from 'lucide-react'

const Extensions: React.FC = () => {
  const extensions = [
    {
      name: 'VS Code Extension',
      icon: Code,
      description: 'Integrate ByteGuardX directly into your VS Code workflow with real-time scanning and inline security warnings.',
      features: [
        'Real-time vulnerability detection',
        'Inline security warnings',
        'Quick fix suggestions',
        'Custom rule configuration',
        'Team sharing capabilities'
      ],
      stats: { downloads: '50K+', rating: 4.8, reviews: 1200 },
      links: {
        marketplace: 'https://marketplace.visualstudio.com/items?itemName=byteguardx.vscode',
        github: 'https://github.com/byteguardx/vscode-extension'
      }
    },
    {
      name: 'Chrome Extension',
      icon: Chrome,
      description: 'Scan code repositories and snippets directly in your browser on GitHub, GitLab, and other platforms.',
      features: [
        'GitHub/GitLab integration',
        'Code snippet scanning',
        'Repository security overview',
        'Pull request analysis',
        'Security badge display'
      ],
      stats: { downloads: '25K+', rating: 4.6, reviews: 800 },
      links: {
        marketplace: 'https://chrome.google.com/webstore/detail/byteguardx',
        github: 'https://github.com/byteguardx/browser-extension'
      }
    },
    {
      name: 'Firefox Extension',
      icon: Puzzle,
      description: 'Privacy-focused browser extension for Firefox users who want to scan code without compromising their data.',
      features: [
        'Complete offline operation',
        'No data collection',
        'GitHub/GitLab support',
        'Custom security rules',
        'Export scan results'
      ],
      stats: { downloads: '15K+', rating: 4.7, reviews: 450 },
      links: {
        marketplace: 'https://addons.mozilla.org/en-US/firefox/addon/byteguardx/',
        github: 'https://github.com/byteguardx/browser-extension'
      }
    },
    {
      name: 'Git Pre-commit Hook',
      icon: Terminal,
      description: 'Automatically scan your code before commits to prevent security vulnerabilities from entering your repository.',
      features: [
        'Automatic pre-commit scanning',
        'Configurable security rules',
        'Fast incremental scanning',
        'Team policy enforcement',
        'CI/CD integration ready'
      ],
      stats: { downloads: '35K+', rating: 4.9, reviews: 950 },
      links: {
        github: 'https://github.com/byteguardx/git-hooks',
        docs: '/docs#git-hooks'
      }
    }
  ]

  const sdks = [
    {
      name: 'Python SDK',
      language: 'Python',
      description: 'Full-featured Python SDK for integrating ByteGuardX into your Python applications and workflows.',
      install: 'pip install byteguardx-sdk',
      features: ['Async/await support', 'Type hints', 'Comprehensive API coverage', 'Django/Flask helpers']
    },
    {
      name: 'JavaScript SDK',
      language: 'JavaScript',
      description: 'Modern JavaScript/TypeScript SDK with full Node.js and browser support for web applications.',
      install: 'npm install @byteguardx/sdk',
      features: ['TypeScript support', 'Promise-based API', 'Browser compatibility', 'React/Vue helpers']
    }
  ]

  return (
    <div className="min-h-screen section-padding">
      <div className="max-w-7xl mx-auto container-padding">
        {/* Header */}
        <div className="text-center mb-20">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
          >
            <div className="flex justify-center mb-8">
              <div className="glass-panel p-6 rounded-3xl">
                <Puzzle className="h-16 w-16 text-cyan-400" />
              </div>
            </div>
            <h1 className="text-4xl md:text-5xl font-bold mb-8">
              Extensions & <span className="gradient-text">Integrations</span>
            </h1>
            <p className="text-xl text-gray-300 max-w-2xl mx-auto font-light leading-relaxed">
              Integrate ByteGuardX into your existing development workflow with our comprehensive set of extensions and SDKs.
            </p>
          </motion.div>
        </div>

        {/* Extensions Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-20">
          {extensions.map((extension, index) => {
            const Icon = extension.icon
            return (
              <motion.div
                key={extension.name}
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.8, delay: index * 0.1 }}
                className="glass-card hover-lift"
              >
                <div className="flex items-start space-x-4 mb-6">
                  <div className="p-3 bg-primary-500/10 rounded-lg">
                    <Icon className="h-8 w-8 text-primary-400" />
                  </div>
                  <div className="flex-1">
                    <h3 className="text-2xl font-semibold mb-2">{extension.name}</h3>
                    <p className="text-gray-400 mb-4">{extension.description}</p>
                    
                    {/* Stats */}
                    <div className="flex items-center space-x-6 mb-4 text-sm">
                      <div className="flex items-center space-x-1">
                        <Download className="h-4 w-4 text-gray-400" />
                        <span>{extension.stats.downloads}</span>
                      </div>
                      <div className="flex items-center space-x-1">
                        <Star className="h-4 w-4 text-yellow-500" />
                        <span>{extension.stats.rating}</span>
                      </div>
                      <div className="text-gray-400">
                        {extension.stats.reviews} reviews
                      </div>
                    </div>
                  </div>
                </div>

                {/* Features */}
                <div className="mb-6">
                  <h4 className="font-semibold mb-3">Key Features</h4>
                  <div className="space-y-2">
                    {extension.features.map((feature) => (
                      <div key={feature} className="flex items-center space-x-2">
                        <CheckCircle className="h-4 w-4 text-green-500 flex-shrink-0" />
                        <span className="text-sm text-gray-300">{feature}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Links */}
                <div className="flex flex-wrap gap-3">
                  {extension.links.marketplace && (
                    <a
                      href={extension.links.marketplace}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="btn-primary text-sm"
                    >
                      <Download className="h-4 w-4 mr-2" />
                      Install
                    </a>
                  )}
                  {extension.links.github && (
                    <a
                      href={extension.links.github}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="btn-secondary text-sm"
                    >
                      <ExternalLink className="h-4 w-4 mr-2" />
                      Source Code
                    </a>
                  )}
                  {extension.links.docs && (
                    <a
                      href={extension.links.docs}
                      className="btn-outline text-sm"
                    >
                      Documentation
                    </a>
                  )}
                </div>
              </motion.div>
            )
          })}
        </div>

        {/* SDKs Section */}
        <div className="mb-16">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Developer <span className="gradient-text">SDKs</span>
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto">
              Build custom integrations with our comprehensive SDKs for popular programming languages.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {sdks.map((sdk, index) => (
              <motion.div
                key={sdk.name}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: 0.4 + index * 0.1 }}
                className="card p-8"
              >
                <div className="flex items-center space-x-3 mb-4">
                  <div className="p-2 bg-primary-500/10 rounded-lg">
                    <Terminal className="h-6 w-6 text-primary-400" />
                  </div>
                  <div>
                    <h3 className="text-xl font-semibold">{sdk.name}</h3>
                    <span className="text-sm text-gray-400">{sdk.language}</span>
                  </div>
                </div>

                <p className="text-gray-400 mb-4">{sdk.description}</p>

                <div className="bg-gray-900 rounded-lg p-4 mb-4">
                  <code className="text-primary-400 text-sm">{sdk.install}</code>
                </div>

                <div className="mb-6">
                  <h4 className="font-semibold mb-3">Features</h4>
                  <div className="grid grid-cols-2 gap-2">
                    {sdk.features.map((feature) => (
                      <div key={feature} className="flex items-center space-x-2">
                        <CheckCircle className="h-3 w-3 text-green-500 flex-shrink-0" />
                        <span className="text-xs text-gray-300">{feature}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex space-x-3">
                  <a href="/docs#sdks" className="btn-primary text-sm">
                    Documentation
                  </a>
                  <a
                    href={`https://github.com/byteguardx/${sdk.language.toLowerCase()}-sdk`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn-secondary text-sm"
                  >
                    <ExternalLink className="h-4 w-4 mr-2" />
                    GitHub
                  </a>
                </div>
              </motion.div>
            ))}
          </div>
        </div>

        {/* Installation Guide */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.6 }}
          className="card p-8 text-center"
        >
          <h3 className="text-2xl font-bold mb-4">Need Help Getting Started?</h3>
          <p className="text-gray-400 mb-6">
            Check out our comprehensive installation guides and tutorials to get up and running quickly.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <a href="/docs" className="btn-primary">
              View Documentation
            </a>
            <a href="/support" className="btn-secondary">
              Get Support
            </a>
          </div>
        </motion.div>
      </div>
    </div>
  )
}

export default Extensions
