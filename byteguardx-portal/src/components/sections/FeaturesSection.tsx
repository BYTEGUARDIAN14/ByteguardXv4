import React from 'react'
import { motion } from 'framer-motion'
import { 
  Shield, 
  Lock, 
  Zap, 
  Eye, 
  Brain, 
  Database, 
  FileSearch, 
  AlertTriangle,
  CheckCircle,
  Code,
  Layers,
  Activity
} from 'lucide-react'
import ScrollSection from '../ScrollSection'

const FeaturesSection: React.FC = () => {
  const mainFeatures = [
    {
      icon: Shield,
      title: 'AI-Powered Detection',
      description: 'Advanced machine learning models identify security vulnerabilities with high accuracy and minimal false positives.',
      highlights: ['99.9% accuracy', 'ML-based analysis', 'Pattern recognition']
    },
    {
      icon: Lock,
      title: 'Offline-First Security',
      description: 'Complete privacy protection - no data sent to external services. All scanning happens locally on your machine.',
      highlights: ['Zero data transmission', 'Local processing', 'Privacy guaranteed']
    },
    {
      icon: Zap,
      title: 'Lightning Fast',
      description: 'Optimized scanning engine processes thousands of files per second with intelligent caching and parallel processing.',
      highlights: ['Parallel processing', 'Smart caching', 'Instant results']
    },
    {
      icon: Eye,
      title: 'Comprehensive Coverage',
      description: 'Detects secrets, CVEs, AI patterns, dependency vulnerabilities, and custom security rules across 50+ languages.',
      highlights: ['50+ languages', 'Multiple scan types', 'Custom rules']
    }
  ]

  const detectionTypes = [
    {
      icon: FileSearch,
      title: 'Secret Detection',
      description: 'API keys, passwords, tokens, and sensitive data',
      color: 'text-red-400'
    },
    {
      icon: AlertTriangle,
      title: 'CVE Detection',
      description: 'Known vulnerabilities in dependencies',
      color: 'text-orange-400'
    },
    {
      icon: Brain,
      title: 'AI Pattern Analysis',
      description: 'Machine learning-based threat detection',
      color: 'text-cyan-400'
    },
    {
      icon: Database,
      title: 'Dependency Scanning',
      description: 'Third-party library vulnerability assessment',
      color: 'text-purple-400'
    },
    {
      icon: Code,
      title: 'Code Quality',
      description: 'Security anti-patterns and best practices',
      color: 'text-green-400'
    },
    {
      icon: Layers,
      title: 'Custom Rules',
      description: 'Organization-specific security policies',
      color: 'text-blue-400'
    }
  ]

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.2
      }
    }
  }

  const itemVariants = {
    hidden: { opacity: 0, y: 30 },
    visible: {
      opacity: 1,
      y: 0,
      transition: {
        duration: 0.6,
        ease: [0.25, 0.46, 0.45, 0.94]
      }
    }
  }

  return (
    <ScrollSection id="features" background="gradient">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
        {/* Section Header */}
        <motion.div 
          className="text-center mb-16"
          variants={itemVariants}
        >
          <motion.div
            className="inline-flex items-center space-x-2 glass-panel px-4 py-2 rounded-full mb-6"
            whileHover={{ scale: 1.05 }}
          >
            <Activity className="h-4 w-4 text-cyan-400" />
            <span className="text-sm text-gray-300 uppercase tracking-wide">Features</span>
          </motion.div>
          
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
            Advanced Security <span className="gradient-text">Intelligence</span>
          </h2>
          
          <p className="text-xl text-gray-300 max-w-3xl mx-auto">
            Comprehensive vulnerability detection powered by cutting-edge AI technology
            and industry-leading security research.
          </p>
        </motion.div>

        {/* Main Features Grid */}
        <motion.div 
          className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-20"
          variants={containerVariants}
        >
          {mainFeatures.map((feature, index) => (
            <motion.div
              key={feature.title}
              className="glass-card group hover:border-cyan-400/30 transition-all duration-500"
              variants={itemVariants}
              whileHover={{ y: -5 }}
            >
              <div className="flex items-start space-x-4">
                <div className="glass-panel p-3 rounded-xl group-hover:border-cyan-400/30 transition-all duration-300">
                  <feature.icon className="h-6 w-6 text-cyan-400 group-hover:scale-110 transition-transform duration-300" />
                </div>
                
                <div className="flex-1">
                  <h3 className="text-xl font-semibold text-white mb-3 group-hover:text-cyan-400 transition-colors duration-300">
                    {feature.title}
                  </h3>
                  
                  <p className="text-gray-300 mb-4 leading-relaxed">
                    {feature.description}
                  </p>
                  
                  <div className="flex flex-wrap gap-2">
                    {feature.highlights.map((highlight) => (
                      <span
                        key={highlight}
                        className="inline-flex items-center space-x-1 text-xs bg-white/5 border border-white/10 rounded-full px-3 py-1 text-gray-400"
                      >
                        <CheckCircle className="h-3 w-3 text-green-400" />
                        <span>{highlight}</span>
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </motion.div>
          ))}
        </motion.div>

        {/* Detection Types */}
        <motion.div variants={itemVariants}>
          <div className="text-center mb-12">
            <h3 className="text-3xl font-bold text-white mb-4">
              Detection <span className="gradient-text">Capabilities</span>
            </h3>
            <p className="text-gray-300 max-w-2xl mx-auto">
              Multiple scanning engines working together to provide comprehensive security coverage
            </p>
          </div>

          <motion.div 
            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
            variants={containerVariants}
          >
            {detectionTypes.map((type, index) => (
              <motion.div
                key={type.title}
                className="glass-panel p-6 rounded-xl text-center group hover:border-cyan-400/20 transition-all duration-300"
                variants={itemVariants}
                whileHover={{ y: -3, scale: 1.02 }}
              >
                <type.icon className={`h-8 w-8 ${type.color} mx-auto mb-4 group-hover:scale-110 transition-transform duration-300`} />
                <h4 className="text-lg font-semibold text-white mb-2 group-hover:text-cyan-400 transition-colors duration-300">
                  {type.title}
                </h4>
                <p className="text-gray-400 text-sm">
                  {type.description}
                </p>
              </motion.div>
            ))}
          </motion.div>
        </motion.div>
      </div>
    </ScrollSection>
  )
}

export default FeaturesSection
