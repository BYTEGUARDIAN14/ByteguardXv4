import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  Monitor, 
  Smartphone, 
  Terminal, 
  Globe,
  ChevronLeft,
  ChevronRight,
  Play,
  Maximize2,
  X
} from 'lucide-react'
import ScrollSection from '../ScrollSection'

const GallerySection: React.FC = () => {
  const [activeTab, setActiveTab] = useState('desktop')
  const [selectedImage, setSelectedImage] = useState<string | null>(null)

  const platforms = [
    {
      id: 'desktop',
      name: 'Desktop App',
      icon: Monitor,
      description: 'Electron-based GUI with comprehensive features'
    },
    {
      id: 'web',
      name: 'Web Dashboard',
      icon: Globe,
      description: 'React-based interface for team collaboration'
    },
    {
      id: 'mobile',
      name: 'Mobile App',
      icon: Smartphone,
      description: 'iOS & Android apps for on-the-go monitoring'
    },
    {
      id: 'cli',
      name: 'CLI Tool',
      icon: Terminal,
      description: 'Command-line interface for developers'
    }
  ]

  const screenshots = {
    desktop: [
      {
        title: 'Main Dashboard',
        description: 'Overview of all security scans and vulnerabilities',
        image: '/api/placeholder/800/500',
        type: 'image'
      },
      {
        title: 'Vulnerability Details',
        description: 'Detailed analysis with AI-powered recommendations',
        image: '/api/placeholder/800/500',
        type: 'image'
      },
      {
        title: 'Real-time Scanning',
        description: 'Watch vulnerabilities being detected in real-time',
        image: '/api/placeholder/800/500',
        type: 'video'
      }
    ],
    web: [
      {
        title: 'Team Dashboard',
        description: 'Collaborative security monitoring for teams',
        image: '/api/placeholder/800/500',
        type: 'image'
      },
      {
        title: 'Report Generation',
        description: 'Generate comprehensive security reports',
        image: '/api/placeholder/800/500',
        type: 'image'
      }
    ],
    mobile: [
      {
        title: 'Mobile Dashboard',
        description: 'Security monitoring on your mobile device',
        image: '/api/placeholder/400/700',
        type: 'image'
      },
      {
        title: 'Push Notifications',
        description: 'Get instant alerts about new vulnerabilities',
        image: '/api/placeholder/400/700',
        type: 'image'
      }
    ],
    cli: [
      {
        title: 'Command Line Interface',
        description: 'Powerful CLI for automated security scanning',
        image: '/api/placeholder/800/500',
        type: 'image'
      },
      {
        title: 'CI/CD Integration',
        description: 'Seamless integration with your build pipeline',
        image: '/api/placeholder/800/500',
        type: 'image'
      }
    ]
  }

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
    <ScrollSection id="gallery" background="default">
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
            <Maximize2 className="h-4 w-4 text-cyan-400" />
            <span className="text-sm text-gray-300 uppercase tracking-wide">Gallery</span>
          </motion.div>
          
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
            See ByteGuardX in <span className="gradient-text">Action</span>
          </h2>
          
          <p className="text-xl text-gray-300 max-w-3xl mx-auto">
            Explore our intuitive interfaces across all platforms. From desktop applications 
            to mobile apps, ByteGuardX provides a consistent and powerful experience.
          </p>
        </motion.div>

        {/* Platform Tabs */}
        <motion.div 
          className="flex flex-wrap justify-center gap-4 mb-12"
          variants={containerVariants}
        >
          {platforms.map((platform) => (
            <motion.button
              key={platform.id}
              onClick={() => setActiveTab(platform.id)}
              className={`
                flex items-center space-x-3 px-6 py-3 rounded-xl font-medium transition-all duration-300
                ${activeTab === platform.id
                  ? 'text-cyan-400 bg-cyan-400/10 border border-cyan-400/30'
                  : 'text-gray-300 hover:text-white glass-panel hover:border-cyan-400/20'
                }
              `}
              variants={itemVariants}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <platform.icon className="h-5 w-5" />
              <div className="text-left">
                <div className="text-sm font-semibold">{platform.name}</div>
                <div className="text-xs opacity-70">{platform.description}</div>
              </div>
            </motion.button>
          ))}
        </motion.div>

        {/* Screenshots Grid */}
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
            variants={containerVariants}
            initial="hidden"
            animate="visible"
            exit="hidden"
          >
            {screenshots[activeTab as keyof typeof screenshots]?.map((screenshot, index) => (
              <motion.div
                key={index}
                className="glass-card group cursor-pointer overflow-hidden"
                variants={itemVariants}
                whileHover={{ y: -5 }}
                onClick={() => setSelectedImage(screenshot.image)}
              >
                <div className="relative overflow-hidden rounded-lg mb-4">
                  <div 
                    className="w-full h-48 bg-gradient-to-br from-gray-800 to-gray-900 rounded-lg flex items-center justify-center"
                    style={{
                      backgroundImage: `url(${screenshot.image})`,
                      backgroundSize: 'cover',
                      backgroundPosition: 'center'
                    }}
                  >
                    {screenshot.type === 'video' && (
                      <motion.div
                        className="absolute inset-0 bg-black/50 flex items-center justify-center"
                        whileHover={{ backgroundColor: 'rgba(0,0,0,0.3)' }}
                      >
                        <Play className="h-12 w-12 text-white" />
                      </motion.div>
                    )}
                    
                    <div className="absolute inset-0 bg-gradient-to-t from-black/50 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
                    
                    <motion.div
                      className="absolute top-3 right-3 p-2 glass-panel rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-300"
                      whileHover={{ scale: 1.1 }}
                    >
                      <Maximize2 className="h-4 w-4 text-white" />
                    </motion.div>
                  </div>
                  
                  <div>
                    <h3 className="text-lg font-semibold text-white mb-2 group-hover:text-cyan-400 transition-colors duration-300">
                      {screenshot.title}
                    </h3>
                    <p className="text-gray-400 text-sm">
                      {screenshot.description}
                    </p>
                  </div>
                </div>
              </motion.div>
            ))}
          </motion.div>
        </AnimatePresence>

        {/* Image Modal */}
        <AnimatePresence>
          {selectedImage && (
            <motion.div
              className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setSelectedImage(null)}
            >
              <motion.div
                className="relative max-w-4xl max-h-[90vh] glass-card p-4"
                initial={{ scale: 0.8, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0.8, opacity: 0 }}
                onClick={(e) => e.stopPropagation()}
              >
                <motion.button
                  className="absolute top-4 right-4 p-2 glass-panel rounded-lg text-white hover:text-cyan-400 transition-colors duration-200"
                  onClick={() => setSelectedImage(null)}
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                >
                  <X className="h-5 w-5" />
                </motion.button>
                
                <img
                  src={selectedImage}
                  alt="Screenshot"
                  className="w-full h-auto rounded-lg"
                />
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </ScrollSection>
  )
}

export default GallerySection
