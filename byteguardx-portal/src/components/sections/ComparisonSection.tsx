import React from 'react'
import { motion } from 'framer-motion'
import {
  Check,
  X,
  Shield,
  Zap,
  Lock,
  Eye,
  Brain,
  Users,
  BarChart3
} from 'lucide-react'
import ScrollSection from '../ScrollSection'

// Import logo assets
import CheckmarxLogo from '../../assets/logos/CHECKMARKZ.jpeg'
import SonarQubeLogo from '../../assets/logos/SONARQUBE.png'
import VeracodeLogo from '../../assets/logos/VERACODE.png'
import SnykLogo from '../../assets/logos/Synk.png'

const ComparisonSection: React.FC = () => {
  const features = [
    { name: 'AI-Powered Detection', icon: Brain },
    { name: 'Offline-First Security', icon: Lock },
    { name: 'Real-time Scanning', icon: Zap },
    { name: 'Multi-language Support', icon: Eye },
    { name: 'Team Collaboration', icon: Users },
    { name: 'Custom Rules', icon: Shield },
    { name: 'CI/CD Integration', icon: BarChart3 },
    { name: 'Mobile Apps', icon: Shield },
    { name: 'Free Tier Available', icon: Check },
    { name: 'Enterprise Support', icon: Users }
  ]

  const competitors = [
    {
      name: 'ByteGuardX',
      logo: Shield,
      logoType: 'icon',
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-400/10',
      borderColor: 'border-cyan-400/30',
      features: [true, true, true, true, true, true, true, true, true, true],
      highlight: true
    },
    {
      name: 'Snyk',
      logo: SnykLogo,
      logoType: 'image',
      color: 'text-purple-400',
      bgColor: 'bg-purple-400/10',
      borderColor: 'border-purple-400/30',
      features: [false, false, true, true, true, false, true, false, true, true]
    },
    {
      name: 'SonarQube',
      logo: SonarQubeLogo,
      logoType: 'image',
      color: 'text-blue-400',
      bgColor: 'bg-blue-400/10',
      borderColor: 'border-blue-400/30',
      features: [false, true, true, true, true, true, true, false, true, true]
    },
    {
      name: 'Veracode',
      logo: VeracodeLogo,
      logoType: 'image',
      color: 'text-green-400',
      bgColor: 'bg-green-400/10',
      borderColor: 'border-green-400/30',
      features: [false, false, false, true, true, false, true, false, false, true]
    },
    {
      name: 'Checkmarx',
      logo: CheckmarxLogo,
      logoType: 'image',
      color: 'text-orange-400',
      bgColor: 'bg-orange-400/10',
      borderColor: 'border-orange-400/30',
      features: [false, false, true, true, false, true, true, false, false, true]
    }
  ]

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1
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
    <ScrollSection id="comparison" background="gradient">
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
            <BarChart3 className="h-4 w-4 text-cyan-400" />
            <span className="text-sm text-gray-300 uppercase tracking-wide">Comparison</span>
          </motion.div>
          
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
            Why Choose <span className="gradient-text">ByteGuardX</span>
          </h2>
          
          <p className="text-xl text-gray-300 max-w-3xl mx-auto">
            See how ByteGuardX compares to other security scanning solutions. 
            We offer unique features that set us apart from the competition.
          </p>
        </motion.div>

        {/* Comparison Table */}
        <motion.div 
          className="glass-card overflow-hidden"
          variants={itemVariants}
        >
          {/* Table Header */}
          <div className="grid grid-cols-2 md:grid-cols-6 gap-4 p-6 border-b border-white/10">
            <div className="text-lg font-semibold text-white col-span-2 md:col-span-1">Features</div>
            <div className="hidden md:contents">
              {competitors.map((competitor) => (
                <div key={competitor.name} className="text-center group">
                  <motion.div
                    className={`inline-flex items-center justify-center w-16 h-16 rounded-xl mb-2 glass-panel ${competitor.borderColor} border group-hover:border-cyan-400/40 transition-all duration-300`}
                    whileHover={{ scale: 1.05 }}
                  >
                    {competitor.logoType === 'icon' ? (
                      <competitor.logo className={`h-8 w-8 ${competitor.color} group-hover:text-cyan-400 transition-colors duration-300`} />
                    ) : (
                      <img
                        src={competitor.logo as string}
                        alt={`${competitor.name} logo`}
                        className="w-10 h-10 object-contain filter group-hover:brightness-110 transition-all duration-300"
                      />
                    )}
                  </motion.div>
                  <div className={`text-sm font-semibold ${competitor.highlight ? 'text-cyan-400' : 'text-gray-300'} group-hover:text-cyan-400 transition-colors duration-300`}>
                    {competitor.name}
                  </div>
                </div>
              ))}
            </div>
            {/* Mobile competitor logos */}
            <div className="md:hidden col-span-1 flex flex-wrap gap-2 justify-end">
              {competitors.map((competitor) => (
                <div key={competitor.name} className="group">
                  <motion.div
                    className={`inline-flex items-center justify-center w-12 h-12 rounded-lg glass-panel ${competitor.borderColor} border group-hover:border-cyan-400/40 transition-all duration-300`}
                    whileHover={{ scale: 1.05 }}
                    title={competitor.name}
                  >
                    {competitor.logoType === 'icon' ? (
                      <competitor.logo className={`h-6 w-6 ${competitor.color} group-hover:text-cyan-400 transition-colors duration-300`} />
                    ) : (
                      <img
                        src={competitor.logo as string}
                        alt={`${competitor.name} logo`}
                        className="w-6 h-6 object-contain filter group-hover:brightness-110 transition-all duration-300"
                      />
                    )}
                  </motion.div>
                </div>
              ))}
            </div>
          </div>

          {/* Table Body */}
          <motion.div variants={containerVariants}>
            {features.map((feature, featureIndex) => (
              <motion.div
                key={feature.name}
                className="grid grid-cols-2 md:grid-cols-6 gap-4 p-4 border-b border-white/5 hover:bg-white/5 transition-colors duration-200"
                variants={itemVariants}
              >
                <div className="flex items-center space-x-3 col-span-2 md:col-span-1">
                  <feature.icon className="h-4 w-4 text-cyan-400" />
                  <span className="text-gray-300 text-sm font-medium">{feature.name}</span>
                </div>

                {/* Desktop feature indicators */}
                <div className="hidden md:contents">
                  {competitors.map((competitor, competitorIndex) => (
                    <div key={competitorIndex} className="flex justify-center">
                      {competitor.features[featureIndex] ? (
                        <motion.div
                          className={`p-1 rounded-full ${competitor.highlight ? 'bg-cyan-400/20' : 'bg-green-400/20'}`}
                          whileHover={{ scale: 1.1 }}
                        >
                          <Check className={`h-4 w-4 ${competitor.highlight ? 'text-cyan-400' : 'text-green-400'}`} />
                        </motion.div>
                      ) : (
                        <motion.div
                          className="p-1 rounded-full bg-red-400/20"
                          whileHover={{ scale: 1.1 }}
                        >
                          <X className="h-4 w-4 text-red-400" />
                        </motion.div>
                      )}
                    </div>
                  ))}
                </div>

                {/* Mobile feature indicators */}
                <div className="md:hidden flex justify-end space-x-1">
                  {competitors.map((competitor, competitorIndex) => (
                    <div key={competitorIndex} className="flex justify-center">
                      {competitor.features[featureIndex] ? (
                        <motion.div
                          className={`p-1 rounded-full ${competitor.highlight ? 'bg-cyan-400/20' : 'bg-green-400/20'}`}
                          whileHover={{ scale: 1.1 }}
                          title={competitor.name}
                        >
                          <Check className={`h-3 w-3 ${competitor.highlight ? 'text-cyan-400' : 'text-green-400'}`} />
                        </motion.div>
                      ) : (
                        <motion.div
                          className="p-1 rounded-full bg-red-400/20"
                          whileHover={{ scale: 1.1 }}
                          title={competitor.name}
                        >
                          <X className="h-3 w-3 text-red-400" />
                        </motion.div>
                      )}
                    </div>
                  ))}
                </div>
              </motion.div>
            ))}
          </motion.div>
        </motion.div>

        {/* Key Differentiators */}
        <motion.div 
          className="mt-16"
          variants={itemVariants}
        >
          <div className="text-center mb-12">
            <h3 className="text-3xl font-bold text-white mb-4">
              Key <span className="gradient-text">Differentiators</span>
            </h3>
            <p className="text-gray-300 max-w-2xl mx-auto">
              What makes ByteGuardX unique in the security scanning landscape
            </p>
          </div>

          <motion.div 
            className="grid grid-cols-1 md:grid-cols-3 gap-6"
            variants={containerVariants}
          >
            <motion.div
              className="glass-panel p-6 rounded-xl text-center group hover:border-cyan-400/20 transition-all duration-300"
              variants={itemVariants}
              whileHover={{ y: -3 }}
            >
              <Brain className="h-8 w-8 text-cyan-400 mx-auto mb-4 group-hover:scale-110 transition-transform duration-300" />
              <h4 className="text-lg font-semibold text-white mb-2 group-hover:text-cyan-400 transition-colors duration-300">
                AI-First Approach
              </h4>
              <p className="text-gray-400 text-sm">
                Advanced machine learning models trained specifically for vulnerability detection with 99.9% accuracy
              </p>
            </motion.div>

            <motion.div
              className="glass-panel p-6 rounded-xl text-center group hover:border-cyan-400/20 transition-all duration-300"
              variants={itemVariants}
              whileHover={{ y: -3 }}
            >
              <Lock className="h-8 w-8 text-cyan-400 mx-auto mb-4 group-hover:scale-110 transition-transform duration-300" />
              <h4 className="text-lg font-semibold text-white mb-2 group-hover:text-cyan-400 transition-colors duration-300">
                Privacy-First Design
              </h4>
              <p className="text-gray-400 text-sm">
                Complete offline operation ensures your code never leaves your infrastructure
              </p>
            </motion.div>

            <motion.div
              className="glass-panel p-6 rounded-xl text-center group hover:border-cyan-400/20 transition-all duration-300"
              variants={itemVariants}
              whileHover={{ y: -3 }}
            >
              <Zap className="h-8 w-8 text-cyan-400 mx-auto mb-4 group-hover:scale-110 transition-transform duration-300" />
              <h4 className="text-lg font-semibold text-white mb-2 group-hover:text-cyan-400 transition-colors duration-300">
                Lightning Performance
              </h4>
              <p className="text-gray-400 text-sm">
                Optimized scanning engine processes thousands of files per second with intelligent caching
              </p>
            </motion.div>
          </motion.div>
        </motion.div>
      </div>
    </ScrollSection>
  )
}

export default ComparisonSection
