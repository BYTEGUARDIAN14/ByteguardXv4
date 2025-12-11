import React, { Suspense } from 'react'
import { motion } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import { Shield, Download, Play, ArrowRight, Zap, Eye, Lock, Star } from 'lucide-react'
import ScrollSection from '../ScrollSection'
import { useAnalytics } from '../../utils/analytics'
import { useResponsive } from '../../hooks/useResponsive'
import Button from '../ui/Button'
import LoadingSpinner from '../ui/LoadingSpinner'
import { presets } from '../../utils/animations'

const HeroSection: React.FC = () => {
  const { t } = useTranslation(['home', 'common'])
  const { trackEvent } = useAnalytics()
  const { isMobile, isTablet } = useResponsive()

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId)
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' })
      trackEvent('hero_scroll_to_section', { section: sectionId })
    }
  }

  const handleCTAClick = () => {
    trackEvent('hero_cta_click', { button: 'start_scanning' })
    // Handle CTA action
  }

  const handleDemoClick = () => {
    trackEvent('hero_demo_click', { button: 'watch_demo' })
    // Handle demo action
  }

  const stats = [
    { value: '50+', label: t('home:stats.vulnerabilities', 'Languages Supported') },
    { value: '99.9%', label: t('home:stats.accuracy', 'Detection Accuracy') },
    { value: '10K+', label: t('home:stats.developers', 'Active Developers') },
    { value: '100%', label: 'Offline Security' }
  ]

  const quickFeatures = [
    { icon: Shield, text: 'AI-Powered Detection' },
    { icon: Lock, text: 'Offline-First Security' },
    { icon: Zap, text: 'Lightning Fast Scanning' },
    { icon: Eye, text: 'Comprehensive Coverage' }
  ]

  return (
    <ScrollSection id="hero" fullHeight className="flex items-center justify-center">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
        <div className="text-center">
          {/* Main Hero Content */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.2 }}
            className="mb-8"
          >
            {/* Logo and Brand */}
            <motion.div 
              className="flex items-center justify-center space-x-4 mb-6"
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ duration: 0.6, delay: 0.1 }}
            >
              <div className="glass-panel p-4 rounded-2xl">
                <Shield className="h-12 w-12 text-cyan-400" />
              </div>
              <div className="text-left">
                <h1 className="text-4xl md:text-5xl font-bold gradient-text">
                  ByteGuardX
                </h1>
                <p className="text-gray-400 text-lg font-light">
                  AI-Powered Vulnerability Scanner
                </p>
              </div>
            </motion.div>

            {/* Main Headline */}
            <motion.h2
              className={`${isMobile ? 'text-4xl' : isTablet ? 'text-5xl' : 'text-7xl'} font-bold text-white mb-6 leading-tight`}
              variants={presets.hero.item}
              initial="hidden"
              animate="visible"
            >
              {t('home:hero.description', 'Secure Your Code with')}{' '}
              <span className="gradient-text">{t('home:hero.title', 'AI Intelligence')}</span>
            </motion.h2>

            {/* Subtitle */}
            <motion.p 
              className="text-xl md:text-2xl text-gray-300 mb-12 max-w-4xl mx-auto leading-relaxed"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.6 }}
            >
              Advanced offline-first vulnerability scanning with machine learning detection.
              Protect your applications from security threats without compromising privacy.
            </motion.p>

            {/* CTA Buttons */}
            <motion.div
              className={`flex ${isMobile ? 'flex-col' : 'flex-row'} gap-4 justify-center items-center mb-16`}
              variants={presets.hero.item}
              initial="hidden"
              animate="visible"
            >
              <Button
                variant="primary"
                size="lg"
                icon={Download}
                iconPosition="left"
                onClick={handleCTAClick}
                className="min-w-[200px]"
              >
                {t('common:buttons.download')}
                <ArrowRight className="h-4 w-4 ml-2 group-hover:translate-x-1 transition-transform" />
              </Button>

              <Button
                variant="secondary"
                size="lg"
                icon={Play}
                iconPosition="left"
                onClick={handleDemoClick}
                className="min-w-[200px]"
              >
                {t('home:hero.watchDemo', 'Watch Demo')}
              </Button>
            </motion.div>
          </motion.div>

          {/* Quick Features Grid */}
          <motion.div 
            className="grid grid-cols-2 md:grid-cols-4 gap-6 mb-16"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 1.0 }}
          >
            {quickFeatures.map((feature, index) => (
              <motion.div
                key={feature.text}
                className="glass-panel p-4 rounded-xl text-center group hover:border-cyan-400/30 transition-all duration-300"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: 1.0 + index * 0.1 }}
                whileHover={{ y: -5 }}
              >
                <feature.icon className="h-8 w-8 text-cyan-400 mx-auto mb-3 group-hover:scale-110 transition-transform duration-300" />
                <p className="text-sm text-gray-300 group-hover:text-white transition-colors duration-300">
                  {feature.text}
                </p>
              </motion.div>
            ))}
          </motion.div>

          {/* Stats */}
          <motion.div 
            className="grid grid-cols-2 md:grid-cols-4 gap-8"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 1.2 }}
          >
            {stats.map((stat, index) => (
              <motion.div
                key={stat.label}
                className="text-center"
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.6, delay: 1.2 + index * 0.1 }}
              >
                <div className="text-3xl md:text-4xl font-bold gradient-text mb-2">
                  {stat.value}
                </div>
                <div className="text-gray-400 text-sm uppercase tracking-wide">
                  {stat.label}
                </div>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </div>
    </ScrollSection>
  )
}

export default HeroSection
