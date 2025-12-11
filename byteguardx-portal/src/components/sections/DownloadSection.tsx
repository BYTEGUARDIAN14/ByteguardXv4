import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { 
  Download, 
  Monitor, 
  Smartphone, 
  Terminal, 
  Globe,
  CheckCircle,
  ArrowRight,
  ExternalLink,
  Apple,
  Chrome
} from 'lucide-react'
import ScrollSection from '../ScrollSection'

const DownloadSection: React.FC = () => {
  const [detectedOS, setDetectedOS] = useState<string>('Unknown')

  useEffect(() => {
    const detectOS = () => {
      const userAgent = window.navigator.userAgent
      const platform = window.navigator.platform
      const macosPlatforms = ['Macintosh', 'MacIntel', 'MacPPC', 'Mac68K']
      const windowsPlatforms = ['Win32', 'Win64', 'Windows', 'WinCE']
      const iosPlatforms = ['iPhone', 'iPad', 'iPod']

      if (macosPlatforms.indexOf(platform) !== -1) {
        setDetectedOS('macOS')
      } else if (iosPlatforms.indexOf(platform) !== -1) {
        setDetectedOS('iOS')
      } else if (windowsPlatforms.indexOf(platform) !== -1) {
        setDetectedOS('Windows')
      } else if (/Android/.test(userAgent)) {
        setDetectedOS('Android')
      } else if (/Linux/.test(platform)) {
        setDetectedOS('Linux')
      }
    }

    detectOS()
  }, [])

  const downloadOptions = [
    {
      type: 'Desktop',
      icon: Monitor,
      platforms: [
        { name: 'Windows', version: 'v1.0.0', size: '45 MB', format: '.exe' },
        { name: 'macOS', version: 'v1.0.0', size: '52 MB', format: '.dmg' },
        { name: 'Linux', version: 'v1.0.0', size: '48 MB', format: '.AppImage' }
      ],
      features: ['Visual interface', 'Real-time scanning', 'Report generation', 'Project management']
    },
    {
      type: 'CLI',
      icon: Terminal,
      platforms: [
        { name: 'npm', version: 'v1.0.0', size: '12 MB', format: 'npm install -g byteguardx' },
        { name: 'pip', version: 'v1.0.0', size: '15 MB', format: 'pip install byteguardx' },
        { name: 'Binary', version: 'v1.0.0', size: '25 MB', format: 'Direct download' }
      ],
      features: ['CI/CD integration', 'Automated scanning', 'JSON output', 'Custom rules']
    },
    {
      type: 'Mobile',
      icon: Smartphone,
      platforms: [
        { name: 'iOS', version: 'v1.0.0', size: '35 MB', format: 'App Store' },
        { name: 'Android', version: 'v1.0.0', size: '28 MB', format: 'Play Store' }
      ],
      features: ['Push notifications', 'Quick scans', 'Report viewing', 'Offline access']
    },
    {
      type: 'Web',
      icon: Globe,
      platforms: [
        { name: 'Browser', version: 'Latest', size: 'N/A', format: 'Launch App' }
      ],
      features: ['No installation', 'Team collaboration', 'Cloud sync', 'Cross-platform']
    }
  ]

  const extensions = [
    {
      name: 'VS Code Extension',
      icon: Monitor,
      description: 'Real-time vulnerability detection in your editor',
      link: 'https://marketplace.visualstudio.com/items?itemName=byteguardx.vscode',
      installs: '10K+'
    },
    {
      name: 'Chrome Extension',
      icon: Chrome,
      description: 'Scan web applications and JavaScript code',
      link: 'https://chrome.google.com/webstore/detail/byteguardx',
      installs: '5K+'
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

  const handleDownload = (platform: string, format: string) => {
    // Simulate download - in real app, this would trigger actual download
    console.log(`Downloading ${platform} - ${format}`)
  }

  const getRecommendedDownload = () => {
    const option = downloadOptions.find(opt => 
      opt.platforms.some(p => p.name === detectedOS)
    )
    return option?.platforms.find(p => p.name === detectedOS)
  }

  const recommendedDownload = getRecommendedDownload()

  return (
    <ScrollSection id="download" background="gradient">
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
            <Download className="h-4 w-4 text-cyan-400" />
            <span className="text-sm text-gray-300 uppercase tracking-wide">Download</span>
          </motion.div>
          
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
            Get <span className="gradient-text">ByteGuardX</span>
          </h2>
          
          <p className="text-xl text-gray-300 max-w-3xl mx-auto">
            Choose your preferred platform and start securing your code today.
            All versions include the same powerful AI-driven vulnerability detection.
          </p>
        </motion.div>

        {/* Recommended Download */}
        {recommendedDownload && (
          <motion.div 
            className="glass-card p-6 mb-12 border-cyan-400/30"
            variants={itemVariants}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <div className="glass-panel p-3 rounded-xl bg-cyan-400/10">
                  <Monitor className="h-6 w-6 text-cyan-400" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-white">
                    Recommended for {detectedOS}
                  </h3>
                  <p className="text-gray-400 text-sm">
                    {recommendedDownload.format} • {recommendedDownload.size}
                  </p>
                </div>
              </div>
              <motion.button
                onClick={() => handleDownload(recommendedDownload.name, recommendedDownload.format)}
                className="glass-card px-6 py-3 text-cyan-400 hover:text-white hover:border-cyan-400/50 transition-all duration-300 flex items-center space-x-2"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <Download className="h-4 w-4" />
                <span>Download Now</span>
              </motion.button>
            </div>
          </motion.div>
        )}

        {/* Download Options Grid */}
        <motion.div 
          className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-16"
          variants={containerVariants}
        >
          {downloadOptions.map((option, index) => (
            <motion.div
              key={option.type}
              className="glass-card group hover:border-cyan-400/30 transition-all duration-500"
              variants={itemVariants}
              whileHover={{ y: -5 }}
            >
              <div className="flex items-start space-x-4 mb-6">
                <div className="glass-panel p-3 rounded-xl group-hover:border-cyan-400/30 transition-all duration-300">
                  <option.icon className="h-6 w-6 text-cyan-400 group-hover:scale-110 transition-transform duration-300" />
                </div>
                
                <div className="flex-1">
                  <h3 className="text-xl font-semibold text-white mb-2 group-hover:text-cyan-400 transition-colors duration-300">
                    {option.type}
                  </h3>
                  
                  <div className="flex flex-wrap gap-2 mb-4">
                    {option.features.map((feature) => (
                      <span
                        key={feature}
                        className="inline-flex items-center space-x-1 text-xs bg-white/5 border border-white/10 rounded-full px-3 py-1 text-gray-400"
                      >
                        <CheckCircle className="h-3 w-3 text-green-400" />
                        <span>{feature}</span>
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                {option.platforms.map((platform) => (
                  <div
                    key={platform.name}
                    className="flex items-center justify-between p-3 glass-panel rounded-lg hover:border-cyan-400/20 transition-all duration-300"
                  >
                    <div className="flex items-center space-x-3">
                      <div className="text-sm font-medium text-white">
                        {platform.name}
                      </div>
                      <div className="text-xs text-gray-400">
                        {platform.version} • {platform.size}
                      </div>
                    </div>
                    
                    <motion.button
                      onClick={() => handleDownload(platform.name, platform.format)}
                      className="text-cyan-400 hover:text-cyan-300 transition-colors duration-200"
                      whileHover={{ scale: 1.1 }}
                      whileTap={{ scale: 0.9 }}
                    >
                      <Download className="h-4 w-4" />
                    </motion.button>
                  </div>
                ))}
              </div>
            </motion.div>
          ))}
        </motion.div>

        {/* Extensions */}
        <motion.div variants={itemVariants}>
          <div className="text-center mb-8">
            <h3 className="text-2xl font-bold text-white mb-4">
              Editor <span className="gradient-text">Extensions</span>
            </h3>
            <p className="text-gray-300">
              Integrate ByteGuardX directly into your development environment
            </p>
          </div>

          <motion.div 
            className="grid grid-cols-1 md:grid-cols-2 gap-6"
            variants={containerVariants}
          >
            {extensions.map((extension, index) => (
              <motion.div
                key={extension.name}
                className="glass-panel p-6 rounded-xl group hover:border-cyan-400/20 transition-all duration-300"
                variants={itemVariants}
                whileHover={{ y: -3 }}
              >
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    <extension.icon className="h-6 w-6 text-cyan-400" />
                    <div>
                      <h4 className="text-lg font-semibold text-white group-hover:text-cyan-400 transition-colors duration-300">
                        {extension.name}
                      </h4>
                      <p className="text-xs text-gray-400">{extension.installs} installs</p>
                    </div>
                  </div>
                </div>
                
                <p className="text-gray-300 text-sm mb-4">
                  {extension.description}
                </p>
                
                <motion.a
                  href={extension.link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center space-x-2 text-cyan-400 hover:text-cyan-300 transition-colors duration-200 group/link"
                  whileHover={{ x: 5 }}
                >
                  <span className="text-sm font-medium">Install Extension</span>
                  <ExternalLink className="h-3 w-3 group-hover/link:translate-x-1 transition-transform duration-200" />
                </motion.a>
              </motion.div>
            ))}
          </motion.div>
        </motion.div>
      </div>
    </ScrollSection>
  )
}

export default DownloadSection
