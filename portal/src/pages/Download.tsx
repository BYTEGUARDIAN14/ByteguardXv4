/**
 * Enhanced Download Page for ByteGuardX Portal
 * Auto-detects user platform and highlights recommended download
 */

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Download as DownloadIcon, 
  Monitor, 
  Smartphone, 
  Terminal, 
  Chrome,
  Code,
  CheckCircle,
  ExternalLink,
  Shield,
  Zap,
  Users
} from 'lucide-react';

interface PlatformInfo {
  name: string;
  detected: boolean;
  icon: React.ComponentType<any>;
  primary?: boolean;
}

interface DownloadOption {
  id: string;
  name: string;
  description: string;
  platform: string;
  version: string;
  size: string;
  downloadUrl: string;
  icon: React.ComponentType<any>;
  features: string[];
  recommended?: boolean;
}

const Download: React.FC = () => {
  const [detectedPlatform, setDetectedPlatform] = useState<string>('');
  const [selectedCategory, setSelectedCategory] = useState<string>('desktop');

  // Detect user platform
  useEffect(() => {
    const userAgent = navigator.userAgent;
    const platform = navigator.platform;

    if (userAgent.includes('Windows') || platform.includes('Win')) {
      setDetectedPlatform('windows');
    } else if (userAgent.includes('Mac') || platform.includes('Mac')) {
      setDetectedPlatform('macos');
    } else if (userAgent.includes('Linux') || platform.includes('Linux')) {
      setDetectedPlatform('linux');
    } else {
      setDetectedPlatform('web'); // Default to web version
    }
  }, []);

  const platforms: Record<string, PlatformInfo> = {
    windows: { name: 'Windows', detected: detectedPlatform === 'windows', icon: Monitor },
    macos: { name: 'macOS', detected: detectedPlatform === 'macos', icon: Monitor },
    linux: { name: 'Linux', detected: detectedPlatform === 'linux', icon: Monitor },
    web: { name: 'Web Browser', detected: detectedPlatform === 'web', icon: Chrome }
  };

  const downloadOptions: DownloadOption[] = [
    {
      id: 'desktop-windows',
      name: 'ByteGuardX Desktop',
      description: 'Full-featured desktop application with offline scanning',
      platform: 'Windows',
      version: '1.0.0',
      size: '125 MB',
      downloadUrl: '/downloads/byteguardx-desktop-windows-1.0.0.exe',
      icon: Monitor,
      features: ['Offline scanning', 'Real-time protection', 'Plugin support', 'Advanced reporting'],
      recommended: detectedPlatform === 'windows'
    },
    {
      id: 'desktop-macos',
      name: 'ByteGuardX Desktop',
      description: 'Native macOS application with seamless integration',
      platform: 'macOS',
      version: '1.0.0',
      size: '118 MB',
      downloadUrl: '/downloads/byteguardx-desktop-macos-1.0.0.dmg',
      icon: Monitor,
      features: ['Native macOS integration', 'Keychain support', 'Touch Bar support', 'Notarized app'],
      recommended: detectedPlatform === 'macos'
    },
    {
      id: 'desktop-linux',
      name: 'ByteGuardX Desktop',
      description: 'Cross-platform Linux application with package manager support',
      platform: 'Linux',
      version: '1.0.0',
      size: '95 MB',
      downloadUrl: '/downloads/byteguardx-desktop-linux-1.0.0.AppImage',
      icon: Monitor,
      features: ['AppImage format', 'Package manager support', 'Wayland support', 'System integration'],
      recommended: detectedPlatform === 'linux'
    },
    {
      id: 'mobile-ios',
      name: 'ByteGuardX Mobile',
      description: 'iOS app for code review and security monitoring on the go',
      platform: 'iOS',
      version: '1.0.0',
      size: '45 MB',
      downloadUrl: 'https://apps.apple.com/app/byteguardx',
      icon: Smartphone,
      features: ['Code review', 'Push notifications', 'Biometric auth', 'Offline reports']
    },
    {
      id: 'mobile-android',
      name: 'ByteGuardX Mobile',
      description: 'Android app for security monitoring and team collaboration',
      platform: 'Android',
      version: '1.0.0',
      size: '38 MB',
      downloadUrl: 'https://play.google.com/store/apps/details?id=com.byteguardx.mobile',
      icon: Smartphone,
      features: ['Material Design', 'Widget support', 'Background sync', 'Fingerprint auth']
    },
    {
      id: 'cli',
      name: 'ByteGuardX CLI',
      description: 'Command-line interface for CI/CD integration and automation',
      platform: 'Cross-platform',
      version: '1.0.0',
      size: '25 MB',
      downloadUrl: '/downloads/byteguardx-cli-1.0.0.tar.gz',
      icon: Terminal,
      features: ['CI/CD integration', 'Automated scanning', 'JSON output', 'Docker support']
    },
    {
      id: 'vscode',
      name: 'VS Code Extension',
      description: 'Real-time security scanning directly in your code editor',
      platform: 'VS Code',
      version: '1.0.0',
      size: '12 MB',
      downloadUrl: 'https://marketplace.visualstudio.com/items?itemName=byteguardx.vscode',
      icon: Code,
      features: ['Real-time scanning', 'Inline suggestions', 'Problem panel', 'Auto-fix']
    },
    {
      id: 'chrome',
      name: 'Browser Extension',
      description: 'Scan code repositories and review security in your browser',
      platform: 'Chrome/Edge',
      version: '1.0.0',
      size: '8 MB',
      downloadUrl: 'https://chrome.google.com/webstore/detail/byteguardx',
      icon: Chrome,
      features: ['GitHub integration', 'GitLab support', 'Quick scan', 'Security badges']
    }
  ];

  const categories = [
    { id: 'desktop', name: 'Desktop Apps', icon: Monitor },
    { id: 'mobile', name: 'Mobile Apps', icon: Smartphone },
    { id: 'developer', name: 'Developer Tools', icon: Code }
  ];

  const getFilteredOptions = () => {
    switch (selectedCategory) {
      case 'desktop':
        return downloadOptions.filter(option => option.id.startsWith('desktop'));
      case 'mobile':
        return downloadOptions.filter(option => option.id.startsWith('mobile'));
      case 'developer':
        return downloadOptions.filter(option => ['cli', 'vscode', 'chrome'].includes(option.id));
      default:
        return downloadOptions;
    }
  };

  const handleDownload = (option: DownloadOption) => {
    // Track download
    if (typeof gtag !== 'undefined') {
      gtag('event', 'download', {
        event_category: 'Downloads',
        event_label: option.name,
        value: 1
      });
    }

    // Open download link
    if (option.downloadUrl.startsWith('http')) {
      window.open(option.downloadUrl, '_blank');
    } else {
      window.location.href = option.downloadUrl;
    }
  };

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Header */}
      <div className="relative bg-gradient-to-br from-black via-gray-900 to-black py-20">
        <div className="absolute inset-0 bg-[url('/grid.svg')] bg-center [mask-image:linear-gradient(180deg,white,rgba(255,255,255,0))]" />
        
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
          >
            <DownloadIcon className="h-16 w-16 text-cyan-400 mx-auto mb-6" />
            <h1 className="text-4xl md:text-5xl font-bold mb-6">
              Download ByteGuardX
            </h1>
            <p className="text-xl text-gray-300 max-w-2xl mx-auto mb-8">
              Get started with the most advanced AI-powered code security platform. 
              Available for all your devices and development environments.
            </p>
            
            {/* Platform detection notice */}
            {detectedPlatform && (
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.5, delay: 0.3 }}
                className="inline-flex items-center bg-cyan-600/20 border border-cyan-600/30 rounded-lg px-4 py-2 text-cyan-400"
              >
                <CheckCircle className="h-5 w-5 mr-2" />
                <span>Recommended for your device: {platforms[detectedPlatform]?.name}</span>
              </motion.div>
            )}
          </motion.div>
        </div>
      </div>

      {/* Category tabs */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex justify-center mb-12">
          <div className="glassmorphism rounded-xl p-2">
            <div className="flex space-x-2">
              {categories.map((category) => {
                const Icon = category.icon;
                return (
                  <button
                    key={category.id}
                    onClick={() => setSelectedCategory(category.id)}
                    className={`flex items-center space-x-2 px-6 py-3 rounded-lg transition-all duration-300 ${
                      selectedCategory === category.id
                        ? 'bg-cyan-600 text-white'
                        : 'text-gray-300 hover:text-white hover:bg-white/10'
                    }`}
                  >
                    <Icon className="h-5 w-5" />
                    <span className="font-medium">{category.name}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Download options */}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
          {getFilteredOptions().map((option, index) => {
            const Icon = option.icon;
            return (
              <motion.div
                key={option.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                className={`glassmorphism rounded-2xl p-6 hover:bg-white/5 transition-all duration-300 ${
                  option.recommended ? 'ring-2 ring-cyan-600/50' : ''
                }`}
              >
                {option.recommended && (
                  <div className="flex items-center justify-center mb-4">
                    <span className="bg-cyan-600 text-white text-xs font-bold px-3 py-1 rounded-full">
                      RECOMMENDED FOR YOUR DEVICE
                    </span>
                  </div>
                )}
                
                <div className="flex items-center mb-4">
                  <Icon className="h-8 w-8 text-cyan-400 mr-3" />
                  <div>
                    <h3 className="text-lg font-bold">{option.name}</h3>
                    <p className="text-sm text-gray-400">{option.platform}</p>
                  </div>
                </div>
                
                <p className="text-gray-300 text-sm mb-4">{option.description}</p>
                
                <div className="flex justify-between items-center text-xs text-gray-400 mb-4">
                  <span>Version {option.version}</span>
                  <span>{option.size}</span>
                </div>
                
                <ul className="space-y-2 mb-6">
                  {option.features.map((feature, featureIndex) => (
                    <li key={featureIndex} className="flex items-center text-sm text-gray-300">
                      <CheckCircle className="h-4 w-4 text-cyan-400 mr-2 flex-shrink-0" />
                      {feature}
                    </li>
                  ))}
                </ul>
                
                <button
                  onClick={() => handleDownload(option)}
                  className={`w-full flex items-center justify-center space-x-2 py-3 px-4 rounded-lg font-medium transition-all duration-300 ${
                    option.recommended
                      ? 'bg-cyan-600 hover:bg-cyan-700 text-white'
                      : 'bg-white/10 hover:bg-white/20 text-white'
                  }`}
                >
                  <DownloadIcon className="h-5 w-5" />
                  <span>Download</span>
                  {option.downloadUrl.startsWith('http') && (
                    <ExternalLink className="h-4 w-4" />
                  )}
                </button>
              </motion.div>
            );
          })}
        </div>

        {/* Features highlight */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.5 }}
          className="mt-16 text-center"
        >
          <h2 className="text-3xl font-bold mb-8">Why Choose ByteGuardX?</h2>
          <div className="grid md:grid-cols-3 gap-8">
            <div className="glassmorphism p-6 rounded-xl">
              <Shield className="h-12 w-12 text-cyan-400 mx-auto mb-4" />
              <h3 className="text-xl font-bold mb-2">Enterprise Security</h3>
              <p className="text-gray-300">
                Military-grade encryption and zero-trust architecture protect your code and data.
              </p>
            </div>
            <div className="glassmorphism p-6 rounded-xl">
              <Zap className="h-12 w-12 text-cyan-400 mx-auto mb-4" />
              <h3 className="text-xl font-bold mb-2">Lightning Fast</h3>
              <p className="text-gray-300">
                AI-powered scanning delivers results in seconds, not minutes or hours.
              </p>
            </div>
            <div className="glassmorphism p-6 rounded-xl">
              <Users className="h-12 w-12 text-cyan-400 mx-auto mb-4" />
              <h3 className="text-xl font-bold mb-2">Team Collaboration</h3>
              <p className="text-gray-300">
                Built for teams with advanced sharing, reporting, and integration features.
              </p>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default Download;
