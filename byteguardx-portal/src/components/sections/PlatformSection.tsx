import React from 'react'
import { motion } from 'framer-motion'
import { 
  Terminal, 
  Monitor, 
  Globe, 
  Smartphone, 
  Code, 
  Chrome,
  Puzzle,
  ArrowRight,
  Download,
  ExternalLink
} from 'lucide-react'
import ScrollSection from '../ScrollSection'

const PlatformSection: React.FC = () => {
  const platforms = [
    {
      icon: Terminal,
      name: 'CLI Tool',
      description: 'Full-featured command line interface for developers and CI/CD pipelines',
      features: ['Cross-platform support', 'CI/CD integration', 'Automated scanning', 'JSON/XML output'],
      status: 'Available',
      color: 'text-green-400',
      bgColor: 'bg-green-400/10'
    },
    {
      icon: Monitor,
      name: 'Desktop App',
      description: 'Electron-based GUI application with intuitive interface and advanced features',
      features: ['Visual reports', 'Real-time scanning', 'Project management', 'Export options'],
      status: 'Available',
      color: 'text-blue-400',
      bgColor: 'bg-blue-400/10'
    },
    {
      icon: Globe,
      name: 'Web Dashboard',
      description: 'React-based web interface for team collaboration and centralized management',
      features: ['Team collaboration', 'Centralized reports', 'User management', 'API access'],
      status: 'Available',
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-400/10'
    },
    {
      icon: Smartphone,
      name: 'Mobile App',
      description: 'iOS & Android applications for on-the-go security monitoring',
      features: ['Push notifications', 'Quick scans', 'Report viewing', 'Offline access'],
      status: 'Available',
      color: 'text-purple-400',
      bgColor: 'bg-purple-400/10'
    }
  ]

  const integrations = [
    {
      icon: Code,
      name: 'VS Code Extension',
      description: 'Real-time vulnerability detection in your favorite editor',
      status: 'Available'
    },
    {
      icon: Chrome,
      name: 'Browser Extension',
      description: 'Scan web applications and JavaScript code directly in browser',
      status: 'Available'
    },
    {
      icon: Puzzle,
      name: 'Plugin Marketplace',
      description: 'Extend functionality with community and enterprise plugins',
      status: 'Coming Soon'
    }
  ]

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId)
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' })
    }
  }

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.15
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
    <ScrollSection id="platforms" background="dark">
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
            <Monitor className="h-4 w-4 text-cyan-400" />
            <span className="text-sm text-gray-300 uppercase tracking-wide">Platforms</span>
          </motion.div>
          
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
            Available <span className="gradient-text">Everywhere</span>
          </h2>
          
          <p className="text-xl text-gray-300 max-w-3xl mx-auto">
            ByteGuardX runs on all major platforms and integrates seamlessly with your existing workflow.
            Choose the interface that works best for your team.
          </p>
        </motion.div>

        {/* Main Platforms Grid */}
        <motion.div 
          className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-20"
          variants={containerVariants}
        >
          {platforms.map((platform, index) => (
            <motion.div
              key={platform.name}
              className="glass-card group hover:border-cyan-400/30 transition-all duration-500 relative overflow-hidden"
              variants={itemVariants}
              whileHover={{ y: -5 }}
            >
              {/* Status Badge */}
              <div className="absolute top-4 right-4">
                <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${platform.bgColor} ${platform.color} border border-current/20`}>
                  {platform.status}
                </span>
              </div>

              <div className="flex items-start space-x-4">
                <div className={`glass-panel p-4 rounded-xl group-hover:border-cyan-400/30 transition-all duration-300 ${platform.bgColor}`}>
                  <platform.icon className={`h-8 w-8 ${platform.color} group-hover:scale-110 transition-transform duration-300`} />
                </div>
                
                <div className="flex-1 pt-1">
                  <h3 className="text-xl font-semibold text-white mb-3 group-hover:text-cyan-400 transition-colors duration-300">
                    {platform.name}
                  </h3>
                  
                  <p className="text-gray-300 mb-4 leading-relaxed">
                    {platform.description}
                  </p>
                  
                  <ul className="space-y-2 mb-6">
                    {platform.features.map((feature) => (
                      <li key={feature} className="flex items-center space-x-2 text-sm text-gray-400">
                        <div className="w-1.5 h-1.5 bg-cyan-400 rounded-full"></div>
                        <span>{feature}</span>
                      </li>
                    ))}
                  </ul>

                  <motion.button
                    onClick={() => scrollToSection('download')}
                    className="inline-flex items-center space-x-2 text-cyan-400 hover:text-cyan-300 transition-colors duration-200 group/btn"
                    whileHover={{ x: 5 }}
                  >
                    <Download className="h-4 w-4" />
                    <span className="text-sm font-medium">Get Started</span>
                    <ArrowRight className="h-3 w-3 group-hover/btn:translate-x-1 transition-transform duration-200" />
                  </motion.button>
                </div>
              </div>
            </motion.div>
          ))}
        </motion.div>

        {/* Integrations */}
        <motion.div variants={itemVariants}>
          <div className="text-center mb-12">
            <h3 className="text-3xl font-bold text-white mb-4">
              Developer <span className="gradient-text">Integrations</span>
            </h3>
            <p className="text-gray-300 max-w-2xl mx-auto">
              Seamlessly integrate ByteGuardX into your development workflow with our comprehensive suite of tools
            </p>
          </div>

          <motion.div 
            className="grid grid-cols-1 md:grid-cols-3 gap-6"
            variants={containerVariants}
          >
            {integrations.map((integration, index) => (
              <motion.div
                key={integration.name}
                className="glass-panel p-6 rounded-xl text-center group hover:border-cyan-400/20 transition-all duration-300 relative"
                variants={itemVariants}
                whileHover={{ y: -3, scale: 1.02 }}
              >
                {/* Status indicator */}
                <div className="absolute top-3 right-3">
                  <div className={`w-2 h-2 rounded-full ${
                    integration.status === 'Available' ? 'bg-green-400' : 'bg-yellow-400'
                  }`}></div>
                </div>

                <integration.icon className="h-8 w-8 text-cyan-400 mx-auto mb-4 group-hover:scale-110 transition-transform duration-300" />
                <h4 className="text-lg font-semibold text-white mb-2 group-hover:text-cyan-400 transition-colors duration-300">
                  {integration.name}
                </h4>
                <p className="text-gray-400 text-sm mb-4">
                  {integration.description}
                </p>
                
                <motion.button
                  onClick={() => scrollToSection('extensions')}
                  className="inline-flex items-center space-x-1 text-xs text-cyan-400 hover:text-cyan-300 transition-colors duration-200"
                  whileHover={{ scale: 1.05 }}
                >
                  <span>Learn More</span>
                  <ExternalLink className="h-3 w-3" />
                </motion.button>
              </motion.div>
            ))}
          </motion.div>
        </motion.div>
      </div>
    </ScrollSection>
  )
}

export default PlatformSection
