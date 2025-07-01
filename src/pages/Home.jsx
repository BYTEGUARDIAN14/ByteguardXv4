import React from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { 
  Shield, 
  Zap, 
  Eye, 
  FileText, 
  Lock, 
  Cpu, 
  ArrowRight,
  CheckCircle,
  Star,
  Github
} from 'lucide-react'

const Home = () => {
  const features = [
    {
      icon: Lock,
      title: 'Secret Detection',
      description: 'Find hardcoded API keys, tokens, and credentials with high-entropy analysis',
      color: 'text-red-400'
    },
    {
      icon: Shield,
      title: 'Dependency Scanning',
      description: 'Identify vulnerable packages across Python, Node.js, Rust, Go, and more',
      color: 'text-orange-400'
    },
    {
      icon: Cpu,
      title: 'AI Pattern Analysis',
      description: 'Detect unsafe AI-generated code patterns and security anti-patterns',
      color: 'text-primary-400'
    },
    {
      icon: Zap,
      title: 'Fix Suggestions',
      description: 'Get intelligent fix recommendations with code examples',
      color: 'text-green-400'
    },
    {
      icon: FileText,
      title: 'Professional Reports',
      description: 'Generate detailed PDF reports with executive summaries',
      color: 'text-blue-400'
    },
    {
      icon: Eye,
      title: 'Offline-First',
      description: 'Complete privacy - no data sent to external services',
      color: 'text-purple-400'
    }
  ]

  const stats = [
    { label: 'Security Patterns', value: '500+' },
    { label: 'CVE Database', value: '50K+' },
    { label: 'Languages Supported', value: '15+' },
    { label: 'Scan Speed', value: '<1min' }
  ]

  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-primary-500/5 via-transparent to-transparent" />
        
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-16">
          <div className="text-center">
            <motion.div
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6 }}
            >
              <h1 className="text-4xl sm:text-6xl lg:text-7xl font-bold tracking-tight">
                <span className="gradient-text">AI-Powered</span>
                <br />
                <span className="text-white">Security Scanner</span>
              </h1>
              
              <p className="mt-6 text-xl text-gray-300 max-w-3xl mx-auto">
                Detect secrets, vulnerable dependencies, and AI-generated security issues 
                in your codebase. Built for developers who value privacy and security.
              </p>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.2 }}
              className="mt-10 flex flex-col sm:flex-row gap-4 justify-center"
            >
              <Link
                to="/scan"
                className="btn-primary text-lg px-8 py-4 hover-lift"
              >
                Start Scanning
                <ArrowRight className="ml-2 h-5 w-5" />
              </Link>
              
              <a
                href="https://github.com/byteguardx/byteguardx"
                target="_blank"
                rel="noopener noreferrer"
                className="btn-secondary text-lg px-8 py-4 hover-lift"
              >
                <Github className="mr-2 h-5 w-5" />
                View on GitHub
              </a>
            </motion.div>

            {/* Stats */}
            <motion.div
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.4 }}
              className="mt-16 grid grid-cols-2 lg:grid-cols-4 gap-8"
            >
              {stats.map((stat, index) => (
                <div key={index} className="text-center">
                  <div className="text-3xl font-bold text-primary-400">{stat.value}</div>
                  <div className="text-sm text-gray-400 mt-1">{stat.label}</div>
                </div>
              ))}
            </motion.div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 bg-gray-950/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
              Comprehensive Security Analysis
            </h2>
            <p className="text-xl text-gray-300 max-w-3xl mx-auto">
              ByteGuardX combines traditional static analysis with AI-powered pattern detection 
              to provide the most thorough security scanning available.
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {features.map((feature, index) => {
              const Icon = feature.icon
              return (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, y: 30 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.6, delay: index * 0.1 }}
                  viewport={{ once: true }}
                  className="card-hover group"
                >
                  <div className={`inline-flex p-3 rounded-lg bg-opacity-10 ${feature.color.replace('text-', 'bg-').replace('-400', '-500')} mb-4`}>
                    <Icon className={`h-6 w-6 ${feature.color}`} />
                  </div>
                  
                  <h3 className="text-xl font-semibold text-white mb-2 group-hover:text-primary-400 transition-colors duration-200">
                    {feature.title}
                  </h3>
                  
                  <p className="text-gray-400 leading-relaxed">
                    {feature.description}
                  </p>
                </motion.div>
              )
            })}
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section className="py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
              How It Works
            </h2>
            <p className="text-xl text-gray-300 max-w-3xl mx-auto">
              Simple, fast, and secure - get comprehensive security analysis in minutes
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {[
              {
                step: '01',
                title: 'Upload or Connect',
                description: 'Upload files, paste code, or connect your repository'
              },
              {
                step: '02',
                title: 'AI Analysis',
                description: 'Our AI scans for secrets, vulnerabilities, and patterns'
              },
              {
                step: '03',
                title: 'Get Results',
                description: 'Receive detailed reports with fix suggestions'
              }
            ].map((item, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.2 }}
                viewport={{ once: true }}
                className="text-center"
              >
                <div className="inline-flex items-center justify-center w-16 h-16 bg-primary-500 bg-opacity-10 rounded-full mb-6">
                  <span className="text-2xl font-bold text-primary-400">{item.step}</span>
                </div>
                
                <h3 className="text-xl font-semibold text-white mb-3">
                  {item.title}
                </h3>
                
                <p className="text-gray-400">
                  {item.description}
                </p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 bg-gradient-to-r from-primary-500/10 via-transparent to-primary-500/10">
        <div className="max-w-4xl mx-auto text-center px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            viewport={{ once: true }}
          >
            <h2 className="text-3xl sm:text-4xl font-bold text-white mb-6">
              Ready to Secure Your Code?
            </h2>
            
            <p className="text-xl text-gray-300 mb-8">
              Join thousands of developers using ByteGuardX to build more secure applications
            </p>
            
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link
                to="/scan"
                className="btn-primary text-lg px-8 py-4 hover-lift"
              >
                Start Free Scan
                <ArrowRight className="ml-2 h-5 w-5" />
              </Link>
              
              <Link
                to="/report"
                className="btn-ghost text-lg px-8 py-4 hover-lift"
              >
                View Sample Report
              </Link>
            </div>
          </motion.div>
        </div>
      </section>
    </div>
  )
}

export default Home
