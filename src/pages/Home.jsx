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
import Navbar from '../components/Navbar'
import Footer from '../components/Footer'
import Button from '../components/ui/Button'

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
      <Navbar />
      {/* Hero Section */}
      <section className="relative overflow-hidden min-h-screen flex items-center">
        <div className="absolute inset-0 bg-gradient-to-br from-black/10 via-transparent to-black/10" />

        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 sm:py-20">
          <div className="text-center">
            {/* Logo Icon */}
            <motion.div
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.8 }}
              className="flex justify-center mb-8"
            >
              <div className="glass-card p-6 rounded-3xl hover-glow">
                <Shield className="h-16 w-16 text-cyan-400" />
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.2 }}
            >
              <h1 className="text-3xl sm:text-5xl lg:text-7xl font-bold tracking-tight">
                <span className="text-gradient">AI-Powered</span>
                <br />
                <span className="text-white font-light">Security Scanner</span>
              </h1>

              <p className="mt-6 sm:mt-8 text-base sm:text-xl text-gray-300 max-w-3xl mx-auto font-light leading-relaxed px-4">
                Detect secrets, vulnerable dependencies, and AI-generated security issues
                in your codebase. Built for developers who value privacy and security.
              </p>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.4 }}
              className="mt-8 sm:mt-12 flex flex-col sm:flex-row gap-4 sm:gap-6 justify-center px-4"
            >
              <Button
                as={Link}
                to="/scan"
                variant="primary"
                size="lg"
                className="shadow-2xl shadow-cyan-500/20 sm:text-lg"
                icon={ArrowRight}
                iconPosition="right"
              >
                Start Scanning
              </Button>

              <Button
                as="a"
                href="https://github.com/byteguardx/byteguardx"
                target="_blank"
                rel="noopener noreferrer"
                variant="secondary"
                size="lg"
                className="sm:text-lg"
                icon={Github}
                iconPosition="left"
              >
                View on GitHub
              </Button>
            </motion.div>

            {/* Stats */}
            <motion.div
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.6 }}
              className="mt-12 sm:mt-20 grid grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-8 px-4"
            >
              {stats.map((stat, index) => (
                <motion.div
                  key={index}
                  className="glass-panel text-center p-6 rounded-2xl hover-lift"
                  whileHover={{ scale: 1.05 }}
                  transition={{ duration: 0.3 }}
                >
                  <div className="text-3xl font-bold text-gradient mb-2">{stat.value}</div>
                  <div className="text-sm text-gray-300 font-light">{stat.label}</div>
                </motion.div>
              ))}
            </motion.div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-24 relative">
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-gray-950/30 to-transparent" />
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            viewport={{ once: true }}
            className="text-center mb-20"
          >
            <h2 className="text-3xl sm:text-4xl font-bold text-white mb-6">
              <span className="text-gradient">Comprehensive</span> Security Analysis
            </h2>
            <p className="text-xl text-gray-300 max-w-3xl mx-auto font-light leading-relaxed">
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
                  transition={{ duration: 0.8, delay: index * 0.1 }}
                  viewport={{ once: true }}
                  className="glass-card group hover-lift"
                  whileHover={{ scale: 1.02 }}
                >
                  <div className="glass-panel p-4 rounded-2xl mb-6 w-fit">
                    <Icon className="h-8 w-8 text-white group-hover:text-cyan-400 transition-colors duration-300" />
                  </div>

                  <h3 className="text-xl font-semibold text-white mb-4 group-hover:text-cyan-400 transition-colors duration-300">
                    {feature.title}
                  </h3>

                  <p className="text-gray-300 leading-relaxed font-light">
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
              <Button
                as={Link}
                to="/scan"
                variant="primary"
                size="lg"
                icon={ArrowRight}
                iconPosition="right"
              >
                Start Free Scan
              </Button>

              <Button
                as={Link}
                to="/report"
                variant="secondary"
                size="lg"
              >
                View Sample Report
              </Button>
            </div>
          </motion.div>
        </div>
      </section>

      <Footer />
    </div>
  )
}

export default Home
