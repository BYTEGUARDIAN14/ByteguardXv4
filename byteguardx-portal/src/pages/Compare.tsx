import React from 'react'
import { motion } from 'framer-motion'
import { CheckCircle, X, Crown, Shield, Zap, Eye, Lock, BarChart3 } from 'lucide-react'

// Import logo assets
import CheckmarxLogo from '../assets/logos/CHECKMARKZ.jpeg'
import SonarQubeLogo from '../assets/logos/SONARQUBE.png'
import VeracodeLogo from '../assets/logos/VERACODE.png'
import SnykLogo from '../assets/logos/Synk.png'

const Compare: React.FC = () => {
  const competitors = [
    {
      name: 'ByteGuardX',
      logo: Shield,
      logoType: 'icon',
      tagline: 'AI-Powered, Offline-First',
      price: 'Free / $29/mo',
      highlight: true,
    },
    {
      name: 'Snyk',
      logo: SnykLogo,
      logoType: 'image',
      tagline: 'Developer Security Platform',
      price: 'Free / $52/mo',
      highlight: false,
    },
    {
      name: 'SonarQube',
      logo: SonarQubeLogo,
      logoType: 'image',
      tagline: 'Code Quality & Security',
      price: 'Free / $150/mo',
      highlight: false,
    },
    {
      name: 'GitLeaks',
      logo: null,
      logoType: 'none',
      tagline: 'Secret Detection',
      price: 'Free / OSS',
      highlight: false,
    },
    {
      name: 'Veracode',
      logo: VeracodeLogo,
      logoType: 'image',
      tagline: 'Application Security',
      price: 'Enterprise Only',
      highlight: false,
    },
  ]

  const features = [
    {
      category: 'Core Features',
      items: [
        {
          name: 'AI-Powered Detection',
          byteguardx: true,
          snyk: false,
          sonarqube: false,
          gitleaks: false,
          veracode: true,
        },
        {
          name: 'Offline-First Operation',
          byteguardx: true,
          snyk: false,
          sonarqube: true,
          gitleaks: true,
          veracode: false,
        },
        {
          name: 'Secret Detection',
          byteguardx: true,
          snyk: true,
          sonarqube: false,
          gitleaks: true,
          veracode: true,
        },
        {
          name: 'Dependency Scanning',
          byteguardx: true,
          snyk: true,
          sonarqube: true,
          gitleaks: false,
          veracode: true,
        },
        {
          name: 'Code Quality Analysis',
          byteguardx: true,
          snyk: false,
          sonarqube: true,
          gitleaks: false,
          veracode: true,
        },
      ]
    },
    {
      category: 'Platform Support',
      items: [
        {
          name: 'Desktop Application',
          byteguardx: true,
          snyk: false,
          sonarqube: false,
          gitleaks: false,
          veracode: false,
        },
        {
          name: 'VS Code Extension',
          byteguardx: true,
          snyk: true,
          sonarqube: true,
          gitleaks: false,
          veracode: false,
        },
        {
          name: 'Browser Extensions',
          byteguardx: true,
          snyk: false,
          sonarqube: false,
          gitleaks: false,
          veracode: false,
        },
        {
          name: 'Mobile App',
          byteguardx: true,
          snyk: false,
          sonarqube: false,
          gitleaks: false,
          veracode: false,
        },
        {
          name: 'CLI Tool',
          byteguardx: true,
          snyk: true,
          sonarqube: true,
          gitleaks: true,
          veracode: true,
        },
      ]
    },
    {
      category: 'Enterprise Features',
      items: [
        {
          name: 'SSO Integration',
          byteguardx: true,
          snyk: true,
          sonarqube: true,
          gitleaks: false,
          veracode: true,
        },
        {
          name: 'RBAC & Permissions',
          byteguardx: true,
          snyk: true,
          sonarqube: true,
          gitleaks: false,
          veracode: true,
        },
        {
          name: 'Audit Logging',
          byteguardx: true,
          snyk: true,
          sonarqube: true,
          gitleaks: false,
          veracode: true,
        },
        {
          name: 'Custom Rules',
          byteguardx: true,
          snyk: true,
          sonarqube: true,
          gitleaks: true,
          veracode: true,
        },
        {
          name: 'Plugin System',
          byteguardx: true,
          snyk: false,
          sonarqube: true,
          gitleaks: false,
          veracode: false,
        },
      ]
    },
    {
      category: 'Privacy & Security',
      items: [
        {
          name: 'No Data Collection',
          byteguardx: true,
          snyk: false,
          sonarqube: true,
          gitleaks: true,
          veracode: false,
        },
        {
          name: 'On-Premise Deployment',
          byteguardx: true,
          snyk: true,
          sonarqube: true,
          gitleaks: true,
          veracode: true,
        },
        {
          name: 'Air-Gapped Support',
          byteguardx: true,
          snyk: false,
          sonarqube: true,
          gitleaks: true,
          veracode: false,
        },
        {
          name: 'End-to-End Encryption',
          byteguardx: true,
          snyk: true,
          sonarqube: false,
          gitleaks: false,
          veracode: true,
        },
      ]
    },
  ]

  const getFeatureValue = (feature: any, competitor: string) => {
    switch (competitor) {
      case 'ByteGuardX': return feature.byteguardx
      case 'Snyk': return feature.snyk
      case 'SonarQube': return feature.sonarqube
      case 'GitLeaks': return feature.gitleaks
      case 'Veracode': return feature.veracode
      default: return false
    }
  }

  return (
    <div className="min-h-screen py-20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-20">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
          >
            <div className="flex justify-center mb-8">
              <div className="glass-panel p-6 rounded-3xl">
                <BarChart3 className="h-16 w-16 text-cyan-400" />
              </div>
            </div>
            <h1 className="text-4xl md:text-5xl font-bold mb-8">
              How <span className="gradient-text">ByteGuardX</span> Compares
            </h1>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto">
              See how ByteGuardX stacks up against other security scanning solutions in the market.
            </p>
          </motion.div>
        </div>

        {/* Comparison Table */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.2 }}
          className="card overflow-hidden"
        >
          {/* Header Row */}
          <div className="grid grid-cols-2 md:grid-cols-6 gap-4 p-6 border-b border-gray-800 bg-gray-900/50">
            <div className="font-semibold">Features</div>
            {competitors.map((competitor) => {
              const Logo = competitor.logo
              return (
                <div key={competitor.name} className={`text-center group ${competitor.highlight ? 'relative' : ''}`}>
                  {competitor.highlight && (
                    <div className="absolute -top-3 left-1/2 transform -translate-x-1/2">
                      <div className="bg-primary-500 text-white text-xs px-2 py-1 rounded-full flex items-center space-x-1">
                        <Crown className="h-3 w-3" />
                        <span>Recommended</span>
                      </div>
                    </div>
                  )}
                  <div className="flex flex-col items-center space-y-2">
                    {competitor.logoType === 'icon' && Logo && (
                      <motion.div
                        className="p-3 rounded-xl glass-panel border border-primary-400/30 group-hover:border-primary-400/50 transition-all duration-300"
                        whileHover={{ scale: 1.05 }}
                      >
                        <Logo className="h-8 w-8 text-primary-400 group-hover:text-primary-300 transition-colors duration-300" />
                      </motion.div>
                    )}
                    {competitor.logoType === 'image' && Logo && (
                      <motion.div
                        className="p-3 rounded-xl glass-panel border border-gray-600/30 group-hover:border-primary-400/50 transition-all duration-300"
                        whileHover={{ scale: 1.05 }}
                      >
                        <img
                          src={Logo as string}
                          alt={`${competitor.name} logo`}
                          className="w-8 h-8 object-contain filter group-hover:brightness-110 transition-all duration-300"
                        />
                      </motion.div>
                    )}
                    {competitor.logoType === 'none' && (
                      <div className="p-3 rounded-xl glass-panel border border-gray-600/30 w-14 h-14 flex items-center justify-center">
                        <div className="w-6 h-6 bg-gray-600 rounded"></div>
                      </div>
                    )}
                    <div>
                      <div className={`font-semibold ${competitor.highlight ? 'text-primary-400' : ''} group-hover:text-primary-400 transition-colors duration-300`}>
                        {competitor.name}
                      </div>
                      <div className="text-xs text-gray-400">{competitor.tagline}</div>
                      <div className="text-sm font-medium mt-1">{competitor.price}</div>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>

          {/* Feature Categories */}
          {features.map((category) => (
            <div key={category.category}>
              <div className="px-6 py-4 bg-gray-800/30 border-b border-gray-800">
                <h3 className="font-semibold text-lg">{category.category}</h3>
              </div>
              {category.items.map((feature, featureIndex) => (
                <div
                  key={feature.name}
                  className={`grid grid-cols-2 md:grid-cols-6 gap-4 p-4 border-b border-gray-800/50 hover:bg-gray-800/20 transition-colors ${
                    featureIndex % 2 === 0 ? 'bg-gray-900/20' : ''
                  }`}
                >
                  <div className="font-medium">{feature.name}</div>
                  {competitors.map((competitor) => {
                    const hasFeature = getFeatureValue(feature, competitor.name)
                    return (
                      <div key={competitor.name} className="text-center">
                        {hasFeature ? (
                          <CheckCircle className={`h-5 w-5 mx-auto ${
                            competitor.highlight ? 'text-primary-400' : 'text-green-500'
                          }`} />
                        ) : (
                          <X className="h-5 w-5 text-gray-500 mx-auto" />
                        )}
                      </div>
                    )
                  })}
                </div>
              ))}
            </div>
          ))}
        </motion.div>

        {/* Key Differentiators */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.4 }}
          className="mt-16"
        >
          <h2 className="text-3xl font-bold text-center mb-12">
            Why Choose <span className="gradient-text">ByteGuardX</span>?
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {[
              {
                icon: Zap,
                title: 'AI-Powered',
                description: 'Advanced machine learning models for accurate vulnerability detection with minimal false positives.'
              },
              {
                icon: Lock,
                title: 'Privacy-First',
                description: 'Complete offline operation ensures your code never leaves your environment.'
              },
              {
                icon: Eye,
                title: 'Comprehensive',
                description: 'All-in-one solution covering secrets, dependencies, code quality, and AI patterns.'
              },
              {
                icon: Shield,
                title: 'Enterprise-Ready',
                description: 'Full enterprise features including SSO, RBAC, audit logging, and compliance support.'
              }
            ].map((differentiator) => {
              const Icon = differentiator.icon
              return (
                <div key={differentiator.title} className="card p-6 text-center card-hover">
                  <div className="p-3 rounded-lg w-fit mx-auto mb-4" style={{backgroundColor: 'rgba(14, 165, 233, 0.1)'}}>
                    <Icon className="h-8 w-8 text-primary-400" />
                  </div>
                  <h3 className="text-xl font-semibold mb-3">{differentiator.title}</h3>
                  <p className="text-gray-400">{differentiator.description}</p>
                </div>
              )
            })}
          </div>
        </motion.div>

        {/* CTA */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.6 }}
          className="mt-16 text-center card p-12"
        >
          <h3 className="text-2xl font-bold mb-4">Ready to Experience the Difference?</h3>
          <p className="text-gray-400 mb-8 max-w-2xl mx-auto">
            Try ByteGuardX today and see why developers choose our AI-powered, privacy-first approach to security scanning.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <a href="/download" className="btn-primary text-lg px-8 py-4 glow-effect">
              Download Free
            </a>
            <a href="/docs" className="btn-secondary text-lg px-8 py-4">
              View Documentation
            </a>
          </div>
        </motion.div>
      </div>
    </div>
  )
}

export default Compare
