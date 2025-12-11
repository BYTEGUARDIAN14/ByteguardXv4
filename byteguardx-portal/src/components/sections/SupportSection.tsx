import React from 'react'
import { motion } from 'framer-motion'
import { 
  MessageCircle, 
  Mail, 
  FileText, 
  Github, 
  BookOpen, 
  Users,
  Clock,
  CheckCircle,
  ArrowRight,
  ExternalLink,
  Headphones
} from 'lucide-react'
import ScrollSection from '../ScrollSection'

const SupportSection: React.FC = () => {
  const supportChannels = [
    {
      icon: MessageCircle,
      title: 'Live Chat',
      description: 'Get instant help from our support team',
      availability: '24/7 for Pro & Enterprise',
      action: 'Start Chat',
      color: 'text-green-400',
      bgColor: 'bg-green-400/10'
    },
    {
      icon: Mail,
      title: 'Email Support',
      description: 'Send us detailed questions and get comprehensive answers',
      availability: 'Response within 24h',
      action: 'Send Email',
      color: 'text-blue-400',
      bgColor: 'bg-blue-400/10'
    },
    {
      icon: Github,
      title: 'GitHub Issues',
      description: 'Report bugs and request features on our public repository',
      availability: 'Community driven',
      action: 'Open Issue',
      color: 'text-purple-400',
      bgColor: 'bg-purple-400/10'
    },
    {
      icon: Users,
      title: 'Community Forum',
      description: 'Connect with other users and share knowledge',
      availability: 'Always active',
      action: 'Join Forum',
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-400/10'
    }
  ]

  const resources = [
    {
      icon: BookOpen,
      title: 'Documentation',
      description: 'Comprehensive guides and API references',
      items: ['Getting Started', 'API Reference', 'Configuration', 'Troubleshooting']
    },
    {
      icon: FileText,
      title: 'Knowledge Base',
      description: 'Common questions and detailed solutions',
      items: ['FAQ', 'Best Practices', 'Security Guidelines', 'Performance Tips']
    },
    {
      icon: Headphones,
      title: 'Video Tutorials',
      description: 'Step-by-step video guides and walkthroughs',
      items: ['Quick Start', 'Advanced Features', 'Integration Guides', 'Webinars']
    }
  ]

  const supportTiers = [
    {
      plan: 'Community',
      features: ['Community forum', 'GitHub issues', 'Documentation', 'Email support'],
      responseTime: '48-72 hours',
      availability: 'Business hours'
    },
    {
      plan: 'Professional',
      features: ['Priority email', 'Live chat', 'Phone support', 'Video calls'],
      responseTime: '4-8 hours',
      availability: '24/7'
    },
    {
      plan: 'Enterprise',
      features: ['Dedicated support', 'Custom training', 'On-site assistance', 'SLA guarantees'],
      responseTime: '1-2 hours',
      availability: '24/7 + holidays'
    }
  ]

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
    <ScrollSection id="support" background="dark">
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
            <Headphones className="h-4 w-4 text-cyan-400" />
            <span className="text-sm text-gray-300 uppercase tracking-wide">Support</span>
          </motion.div>
          
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
            We're Here to <span className="gradient-text">Help</span>
          </h2>
          
          <p className="text-xl text-gray-300 max-w-3xl mx-auto">
            Get the support you need, when you need it. Our team and community are ready to help you succeed with ByteGuardX.
          </p>
        </motion.div>

        {/* Support Channels */}
        <motion.div 
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-20"
          variants={containerVariants}
        >
          {supportChannels.map((channel, index) => (
            <motion.div
              key={channel.title}
              className="glass-card group hover:border-cyan-400/30 transition-all duration-500 text-center"
              variants={itemVariants}
              whileHover={{ y: -5 }}
            >
              <div className={`inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-4 ${channel.bgColor} border border-current/20`}>
                <channel.icon className={`h-8 w-8 ${channel.color}`} />
              </div>
              
              <h3 className="text-lg font-semibold text-white mb-2 group-hover:text-cyan-400 transition-colors duration-300">
                {channel.title}
              </h3>
              
              <p className="text-gray-400 text-sm mb-3 leading-relaxed">
                {channel.description}
              </p>
              
              <div className="text-xs text-gray-500 mb-4 flex items-center justify-center space-x-1">
                <Clock className="h-3 w-3" />
                <span>{channel.availability}</span>
              </div>

              <motion.button
                className="w-full glass-panel py-2 px-4 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:border-cyan-400/50 transition-all duration-300 flex items-center justify-center space-x-2"
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <span>{channel.action}</span>
                <ArrowRight className="h-3 w-3" />
              </motion.button>
            </motion.div>
          ))}
        </motion.div>

        {/* Resources */}
        <motion.div 
          className="mb-20"
          variants={itemVariants}
        >
          <div className="text-center mb-12">
            <h3 className="text-3xl font-bold text-white mb-4">
              Self-Service <span className="gradient-text">Resources</span>
            </h3>
            <p className="text-gray-300 max-w-2xl mx-auto">
              Find answers quickly with our comprehensive documentation and learning materials
            </p>
          </div>

          <motion.div 
            className="grid grid-cols-1 md:grid-cols-3 gap-8"
            variants={containerVariants}
          >
            {resources.map((resource, index) => (
              <motion.div
                key={resource.title}
                className="glass-panel p-6 rounded-xl group hover:border-cyan-400/20 transition-all duration-300"
                variants={itemVariants}
                whileHover={{ y: -3 }}
              >
                <div className="flex items-center space-x-3 mb-4">
                  <resource.icon className="h-6 w-6 text-cyan-400 group-hover:scale-110 transition-transform duration-300" />
                  <h4 className="text-lg font-semibold text-white group-hover:text-cyan-400 transition-colors duration-300">
                    {resource.title}
                  </h4>
                </div>
                
                <p className="text-gray-400 text-sm mb-4">
                  {resource.description}
                </p>
                
                <ul className="space-y-2">
                  {resource.items.map((item) => (
                    <li key={item} className="flex items-center space-x-2 text-sm text-gray-300">
                      <div className="w-1.5 h-1.5 bg-cyan-400 rounded-full"></div>
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>

                <motion.button
                  className="mt-4 inline-flex items-center space-x-2 text-cyan-400 hover:text-cyan-300 transition-colors duration-200 group/btn"
                  whileHover={{ x: 5 }}
                >
                  <span className="text-sm font-medium">Explore</span>
                  <ExternalLink className="h-3 w-3 group-hover/btn:translate-x-1 transition-transform duration-200" />
                </motion.button>
              </motion.div>
            ))}
          </motion.div>
        </motion.div>

        {/* Support Tiers */}
        <motion.div variants={itemVariants}>
          <div className="text-center mb-12">
            <h3 className="text-3xl font-bold text-white mb-4">
              Support <span className="gradient-text">Tiers</span>
            </h3>
            <p className="text-gray-300 max-w-2xl mx-auto">
              Different levels of support based on your plan and needs
            </p>
          </div>

          <motion.div 
            className="grid grid-cols-1 md:grid-cols-3 gap-6"
            variants={containerVariants}
          >
            {supportTiers.map((tier, index) => (
              <motion.div
                key={tier.plan}
                className={`
                  glass-panel p-6 rounded-xl transition-all duration-300
                  ${index === 1 ? 'border-cyan-400/30 bg-cyan-400/5' : 'hover:border-cyan-400/20'}
                `}
                variants={itemVariants}
                whileHover={{ y: index === 1 ? 0 : -3 }}
              >
                <div className="text-center mb-6">
                  <h4 className="text-xl font-bold text-white mb-2">{tier.plan}</h4>
                  <div className="text-sm text-gray-400 mb-1">Response time: {tier.responseTime}</div>
                  <div className="text-sm text-gray-400">Available: {tier.availability}</div>
                </div>

                <ul className="space-y-3">
                  {tier.features.map((feature) => (
                    <li key={feature} className="flex items-center space-x-3">
                      <CheckCircle className="h-4 w-4 text-green-400 flex-shrink-0" />
                      <span className="text-sm text-gray-300">{feature}</span>
                    </li>
                  ))}
                </ul>
              </motion.div>
            ))}
          </motion.div>
        </motion.div>
      </div>
    </ScrollSection>
  )
}

export default SupportSection
