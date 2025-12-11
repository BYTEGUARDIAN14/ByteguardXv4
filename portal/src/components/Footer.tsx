/**
 * Enhanced Footer Component for ByteGuardX Portal
 * Responsive design with internal legal pages and improved accessibility
 */

import React from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { 
  Shield, 
  Github, 
  Twitter, 
  Linkedin, 
  Mail,
  ExternalLink,
  Heart
} from 'lucide-react';

const Footer: React.FC = () => {
  const currentYear = new Date().getFullYear();

  const footerSections = [
    {
      title: 'Product',
      links: [
        { name: 'Features', href: '/features' },
        { name: 'Pricing', href: '/pricing' },
        { name: 'Download', href: '/download' },
        { name: 'Extensions', href: '/extensions' },
        { name: 'API Documentation', href: '/docs/api' },
        { name: 'Changelog', href: '/changelog' }
      ]
    },
    {
      title: 'Resources',
      links: [
        { name: 'Documentation', href: '/docs' },
        { name: 'Tutorials', href: '/docs/tutorials' },
        { name: 'Best Practices', href: '/docs/best-practices' },
        { name: 'Security Guide', href: '/docs/security' },
        { name: 'Community', href: '/community' },
        { name: 'Blog', href: '/blog' }
      ]
    },
    {
      title: 'Support',
      links: [
        { name: 'Help Center', href: '/support' },
        { name: 'Contact Us', href: '/contact' },
        { name: 'Bug Reports', href: '/support/bugs' },
        { name: 'Feature Requests', href: '/support/features' },
        { name: 'Status Page', href: '/status' },
        { name: 'System Requirements', href: '/support/requirements' }
      ]
    },
    {
      title: 'Company',
      links: [
        { name: 'About Us', href: '/about' },
        { name: 'Careers', href: '/careers' },
        { name: 'Press Kit', href: '/press' },
        { name: 'Partners', href: '/partners' },
        { name: 'Security', href: '/security' },
        { name: 'Compliance', href: '/compliance' }
      ]
    }
  ];

  const legalLinks = [
    { name: 'Privacy Policy', href: '/legal/privacy' },
    { name: 'Terms of Service', href: '/legal/terms' },
    { name: 'Cookie Policy', href: '/legal/cookies' },
    { name: 'Data Processing', href: '/legal/data-processing' },
    { name: 'Security Policy', href: '/legal/security' }
  ];

  const socialLinks = [
    { 
      name: 'GitHub', 
      href: 'https://github.com/byteguardx', 
      icon: Github,
      ariaLabel: 'Follow ByteGuardX on GitHub'
    },
    { 
      name: 'Twitter', 
      href: 'https://twitter.com/byteguardx', 
      icon: Twitter,
      ariaLabel: 'Follow ByteGuardX on Twitter'
    },
    { 
      name: 'LinkedIn', 
      href: 'https://linkedin.com/company/byteguardx', 
      icon: Linkedin,
      ariaLabel: 'Follow ByteGuardX on LinkedIn'
    },
    { 
      name: 'Email', 
      href: 'mailto:hello@byteguardx.com', 
      icon: Mail,
      ariaLabel: 'Contact ByteGuardX via email'
    }
  ];

  return (
    <footer 
      className="relative bg-black/90 backdrop-blur-xl border-t border-white/10"
      role="contentinfo"
      aria-label="Site footer"
    >
      {/* Background gradient */}
      <div className="absolute inset-0 bg-gradient-to-t from-black via-black/95 to-transparent pointer-events-none" />
      
      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Main footer content */}
        <div className="py-12 lg:py-16">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-8 lg:gap-12">
            {/* Brand section */}
            <div className="lg:col-span-2">
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6 }}
                viewport={{ once: true }}
              >
                <Link 
                  to="/" 
                  className="flex items-center space-x-3 group"
                  aria-label="ByteGuardX home"
                >
                  <div className="relative">
                    <Shield className="h-8 w-8 text-cyan-400 group-hover:text-cyan-300 transition-colors duration-300" />
                    <div className="absolute inset-0 bg-cyan-400/20 blur-lg group-hover:bg-cyan-300/30 transition-all duration-300" />
                  </div>
                  <span className="text-xl font-bold text-white group-hover:text-cyan-400 transition-colors duration-300">
                    ByteGuardX
                  </span>
                </Link>
                
                <p className="mt-4 text-gray-300 text-sm leading-relaxed max-w-md">
                  The most advanced AI-powered code security platform. 
                  Protect your applications with enterprise-grade vulnerability detection 
                  and real-time threat analysis.
                </p>
                
                {/* Social links */}
                <div className="mt-6 flex space-x-4">
                  {socialLinks.map((social) => {
                    const Icon = social.icon;
                    return (
                      <motion.a
                        key={social.name}
                        href={social.href}
                        target={social.href.startsWith('http') ? '_blank' : undefined}
                        rel={social.href.startsWith('http') ? 'noopener noreferrer' : undefined}
                        className="text-gray-400 hover:text-cyan-400 transition-colors duration-300 p-2 rounded-lg hover:bg-white/5"
                        aria-label={social.ariaLabel}
                        whileHover={{ scale: 1.1 }}
                        whileTap={{ scale: 0.95 }}
                      >
                        <Icon className="h-5 w-5" />
                      </motion.a>
                    );
                  })}
                </div>
              </motion.div>
            </div>
            
            {/* Footer sections */}
            {footerSections.map((section, sectionIndex) => (
              <motion.div
                key={section.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: sectionIndex * 0.1 }}
                viewport={{ once: true }}
              >
                <h3 className="text-white font-semibold text-sm uppercase tracking-wider mb-4">
                  {section.title}
                </h3>
                <ul className="space-y-3" role="list">
                  {section.links.map((link) => (
                    <li key={link.name}>
                      <Link
                        to={link.href}
                        className="text-gray-300 hover:text-cyan-400 transition-colors duration-300 text-sm flex items-center group"
                      >
                        <span>{link.name}</span>
                        {link.href.startsWith('http') && (
                          <ExternalLink className="h-3 w-3 ml-1 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
                        )}
                      </Link>
                    </li>
                  ))}
                </ul>
              </motion.div>
            ))}
          </div>
        </div>
        
        {/* Bottom section */}
        <div className="border-t border-white/10 py-8">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between space-y-4 lg:space-y-0">
            {/* Legal links */}
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
              {legalLinks.map((link, index) => (
                <React.Fragment key={link.name}>
                  <Link
                    to={link.href}
                    className="text-gray-400 hover:text-cyan-400 transition-colors duration-300 text-sm"
                  >
                    {link.name}
                  </Link>
                  {index < legalLinks.length - 1 && (
                    <span className="text-gray-600 hidden sm:inline">•</span>
                  )}
                </React.Fragment>
              ))}
            </div>
            
            {/* Copyright and attribution */}
            <div className="flex flex-col sm:flex-row sm:items-center space-y-2 sm:space-y-0 sm:space-x-4 text-sm text-gray-400">
              <div className="flex items-center">
                <span>© {currentYear} ByteGuardX. All rights reserved.</span>
              </div>
              <div className="flex items-center space-x-1">
                <span>Made with</span>
                <Heart className="h-4 w-4 text-red-500 fill-current" />
                <span>for developers worldwide</span>
              </div>
            </div>
          </div>
          
          {/* Compliance badges */}
          <div className="mt-6 pt-6 border-t border-white/5">
            <div className="flex flex-wrap items-center justify-center lg:justify-start space-x-6 space-y-2">
              <div className="flex items-center space-x-2 text-xs text-gray-500">
                <Shield className="h-4 w-4" />
                <span>SOC 2 Type II Compliant</span>
              </div>
              <div className="flex items-center space-x-2 text-xs text-gray-500">
                <Shield className="h-4 w-4" />
                <span>GDPR Compliant</span>
              </div>
              <div className="flex items-center space-x-2 text-xs text-gray-500">
                <Shield className="h-4 w-4" />
                <span>ISO 27001 Certified</span>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      {/* Skip to top link for accessibility */}
      <button
        onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
        className="sr-only focus:not-sr-only fixed bottom-4 right-4 bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg transition-colors duration-300 z-50"
        aria-label="Skip to top of page"
      >
        Skip to top
      </button>
    </footer>
  );
};

export default Footer;
