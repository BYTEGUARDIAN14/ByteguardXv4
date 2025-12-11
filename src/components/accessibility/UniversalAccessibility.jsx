/**
 * Universal Accessibility Component
 * AI-powered accessibility with adaptive features and multi-modal interaction
 */

import React, { useState, useEffect, useContext, createContext } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Eye,
  EyeOff,
  Volume2,
  VolumeX,
  Type,
  Contrast,
  MousePointer,
  Keyboard,
  Settings as SettingsIcon,
  Sliders,
  Zap,
  Brain
} from 'lucide-react';
import { QuantumGlassCard } from '../advanced/QuantumGlassmorphism';

// Accessibility Context
const AccessibilityContext = createContext();

export const useAccessibility = () => {
  const context = useContext(AccessibilityContext);
  if (!context) {
    throw new Error('useAccessibility must be used within AccessibilityProvider');
  }
  return context;
};

// Accessibility Provider
export const AccessibilityProvider = ({ children }) => {
  const [settings, setSettings] = useState({
    // Visual Accessibility
    highContrast: false,
    largeText: false,
    reducedMotion: false,
    colorBlindMode: 'none', // 'none', 'protanopia', 'deuteranopia', 'tritanopia'
    fontSize: 100, // percentage

    // Audio Accessibility
    screenReader: false,
    audioDescriptions: false,
    soundEnabled: true,

    // Motor Accessibility
    keyboardNavigation: true,
    stickyKeys: false,
    slowKeys: false,
    mouseKeys: false,

    // Cognitive Accessibility
    simplifiedUI: false,
    focusAssist: false,
    readingGuide: false,

    // AI-Powered Features
    aiAssistance: false,
    voiceControl: false,
    gestureControl: false,
    eyeTracking: false
  });

  const [isOpen, setIsOpen] = useState(false);
  const [activeFeatures, setActiveFeatures] = useState([]);

  // Load settings from localStorage
  useEffect(() => {
    const savedSettings = localStorage.getItem('byteguardx-accessibility');
    if (savedSettings) {
      setSettings(JSON.parse(savedSettings));
    }
  }, []);

  // Save settings to localStorage
  useEffect(() => {
    localStorage.setItem('byteguardx-accessibility', JSON.stringify(settings));
    applyAccessibilitySettings(settings);
  }, [settings]);

  const applyAccessibilitySettings = (newSettings) => {
    const root = document.documentElement;

    // Apply visual settings
    if (newSettings.highContrast) {
      root.classList.add('high-contrast');
    } else {
      root.classList.remove('high-contrast');
    }

    if (newSettings.largeText) {
      root.classList.add('large-text');
    } else {
      root.classList.remove('large-text');
    }

    if (newSettings.reducedMotion) {
      root.classList.add('reduced-motion');
    } else {
      root.classList.remove('reduced-motion');
    }

    // Apply font size
    root.style.fontSize = `${newSettings.fontSize}%`;

    // Apply color blind mode
    root.setAttribute('data-colorblind', newSettings.colorBlindMode);

    // Update active features list
    const active = Object.entries(newSettings)
      .filter(([key, value]) => value === true)
      .map(([key]) => key);
    setActiveFeatures(active);
  };

  const updateSetting = (key, value) => {
    setSettings(prev => ({ ...prev, [key]: value }));
  };

  const resetSettings = () => {
    const defaultSettings = {
      highContrast: false,
      largeText: false,
      reducedMotion: false,
      colorBlindMode: 'none',
      fontSize: 100,
      screenReader: false,
      audioDescriptions: false,
      soundEnabled: true,
      keyboardNavigation: true,
      stickyKeys: false,
      slowKeys: false,
      mouseKeys: false,
      simplifiedUI: false,
      focusAssist: false,
      readingGuide: false,
      aiAssistance: false,
      voiceControl: false,
      gestureControl: false,
      eyeTracking: false
    };
    setSettings(defaultSettings);
  };

  const value = {
    settings,
    updateSetting,
    resetSettings,
    activeFeatures,
    isOpen,
    setIsOpen
  };

  return (
    <AccessibilityContext.Provider value={value}>
      {children}
      <AccessibilityPanel />
    </AccessibilityContext.Provider>
  );
};

// Accessibility Control Panel
const AccessibilityPanel = () => {
  const { settings, updateSetting, resetSettings, activeFeatures, isOpen, setIsOpen } = useAccessibility();

  const settingGroups = [
    {
      title: 'Visual Accessibility',
      icon: Eye,
      settings: [
        { key: 'highContrast', label: 'High Contrast Mode', icon: Contrast },
        { key: 'largeText', label: 'Large Text', icon: Type },
        { key: 'reducedMotion', label: 'Reduced Motion', icon: MousePointer }
      ]
    },
    {
      title: 'Audio Accessibility',
      icon: Volume2,
      settings: [
        { key: 'screenReader', label: 'Screen Reader Support', icon: Volume2 },
        { key: 'audioDescriptions', label: 'Audio Descriptions', icon: Volume2 },
        { key: 'soundEnabled', label: 'Sound Effects', icon: Volume2 }
      ]
    },
    {
      title: 'Motor Accessibility',
      icon: MousePointer,
      settings: [
        { key: 'keyboardNavigation', label: 'Keyboard Navigation', icon: Keyboard },
        { key: 'stickyKeys', label: 'Sticky Keys', icon: Keyboard },
        { key: 'mouseKeys', label: 'Mouse Keys', icon: MousePointer }
      ]
    },
    {
      title: 'AI-Powered Features',
      icon: Brain,
      settings: [
        { key: 'aiAssistance', label: 'AI Assistance', icon: Brain },
        { key: 'voiceControl', label: 'Voice Control', icon: Volume2 },
        { key: 'gestureControl', label: 'Gesture Control', icon: MousePointer }
      ]
    }
  ];

  return (
    <>
      <motion.button
        className="fixed bottom-4 left-4 z-50 p-3 bg-gradient-to-r from-cyan-500 to-blue-500 text-white rounded-full shadow-lg shadow-cyan-500/50"
        onClick={() => setIsOpen(!isOpen)}
        whileHover={{ scale: 1.1 }}
        whileTap={{ scale: 0.9 }}
        aria-label="Open Accessibility Settings"
      >
        <Sliders className="h-6 w-6" />
        {activeFeatures.length > 0 && (
          <motion.div
            className="absolute -top-2 -right-2 bg-red-500 text-white text-xs rounded-full h-6 w-6 flex items-center justify-center"
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
          >
            {activeFeatures.length}
          </motion.div>
        )}
      </motion.button>

      {/* Accessibility Panel */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setIsOpen(false)}
          >
            <motion.div
              className="w-full max-w-4xl max-h-[90vh] overflow-y-auto"
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.8, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
            >
              <QuantumGlassCard variant="elevated" className="m-4">
                {/* Header */}
                <div className="flex items-center justify-between p-6 border-b border-white/10">
                  <div className="flex items-center space-x-3">
                    <div className="p-2 bg-gradient-to-r from-cyan-500 to-blue-500 rounded-lg shadow-lg shadow-cyan-500/50">
                      <Sliders className="h-6 w-6 text-white" />
                    </div>
                    <div>
                      <h2 className="text-2xl font-bold text-white">Accessibility Settings</h2>
                      <p className="text-gray-400">Customize your experience with AI-powered accessibility features</p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    <button
                      onClick={resetSettings}
                      className="px-4 py-2 bg-white/10 text-white rounded-lg hover:bg-white/20 transition-colors"
                    >
                      Reset All
                    </button>
                    <button
                      onClick={() => setIsOpen(false)}
                      className="p-2 bg-white/10 text-white rounded-lg hover:bg-white/20 transition-colors"
                    >
                      ✕
                    </button>
                  </div>
                </div>

                {/* Settings Groups */}
                <div className="p-6 space-y-6">
                  {settingGroups.map((group, groupIndex) => (
                    <div key={group.title}>
                      <div className="flex items-center space-x-3 mb-4">
                        <group.icon className="h-5 w-5 text-cyan-400" />
                        <h3 className="text-lg font-semibold text-white">{group.title}</h3>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {group.settings.map((setting) => (
                          <motion.div
                            key={setting.key}
                            className="p-4 bg-white/5 rounded-lg border border-white/10 hover:border-white/20 transition-colors"
                            whileHover={{ scale: 1.02 }}
                          >
                            <div className="flex items-center justify-between mb-2">
                              <div className="flex items-center space-x-2">
                                <setting.icon className="h-4 w-4 text-gray-400" />
                                <span className="text-white font-medium">{setting.label}</span>
                              </div>

                              <motion.button
                                className={`relative w-12 h-6 rounded-full transition-colors ${settings[setting.key]
                                  ? 'bg-gradient-to-r from-cyan-500 to-blue-500'
                                  : 'bg-gray-600'
                                  }`}
                                onClick={() => updateSetting(setting.key, !settings[setting.key])}
                                whileTap={{ scale: 0.95 }}
                              >
                                <motion.div
                                  className="absolute top-1 w-4 h-4 bg-white rounded-full shadow-lg"
                                  animate={{ x: settings[setting.key] ? 26 : 2 }}
                                  transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                                />
                              </motion.button>
                            </div>
                          </motion.div>
                        ))}
                      </div>
                    </div>
                  ))}

                  {/* Advanced Settings */}
                  <div>
                    <h3 className="text-lg font-semibold text-white mb-4 flex items-center space-x-2">
                      <SettingsIcon className="h-5 w-5 text-cyan-400" />
                      <span>Advanced Settings</span>
                    </h3>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Font Size Slider */}
                      <div className="p-4 bg-white/5 rounded-lg border border-white/10">
                        <label className="block text-white font-medium mb-2">
                          Font Size: {settings.fontSize}%
                        </label>
                        <input
                          type="range"
                          min="75"
                          max="150"
                          step="5"
                          value={settings.fontSize}
                          onChange={(e) => updateSetting('fontSize', parseInt(e.target.value))}
                          className="w-full h-2 bg-gray-600 rounded-lg appearance-none cursor-pointer slider"
                        />
                      </div>

                      {/* Color Blind Mode */}
                      <div className="p-4 bg-white/5 rounded-lg border border-white/10">
                        <label className="block text-white font-medium mb-2">
                          Color Blind Support
                        </label>
                        <select
                          value={settings.colorBlindMode}
                          onChange={(e) => updateSetting('colorBlindMode', e.target.value)}
                          className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white"
                        >
                          <option value="none">None</option>
                          <option value="protanopia">Protanopia</option>
                          <option value="deuteranopia">Deuteranopia</option>
                          <option value="tritanopia">Tritanopia</option>
                        </select>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Active Features Summary */}
                {activeFeatures.length > 0 && (
                  <div className="p-6 border-t border-white/10">
                    <h4 className="text-white font-semibold mb-3">Active Accessibility Features</h4>
                    <div className="flex flex-wrap gap-2">
                      {activeFeatures.map((feature) => (
                        <motion.span
                          key={feature}
                          className="px-3 py-1 bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-400 rounded-full text-sm border border-cyan-400/30"
                          initial={{ scale: 0 }}
                          animate={{ scale: 1 }}
                          transition={{ delay: 0.1 }}
                        >
                          {feature.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                        </motion.span>
                      ))}
                    </div>
                  </div>
                )}
              </QuantumGlassCard>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
};

// Screen Reader Announcer Component
export const ScreenReaderAnnouncer = ({ message, priority = 'polite' }) => {
  const { settings } = useAccessibility();

  if (!settings.screenReader) return null;

  return (
    <div
      role="status"
      aria-live={priority}
      aria-atomic="true"
      className="sr-only"
    >
      {message}
    </div>
  );
};

// Keyboard Navigation Helper
export const useKeyboardNavigation = () => {
  const { settings } = useAccessibility();

  useEffect(() => {
    if (!settings.keyboardNavigation) return;

    const handleKeyDown = (e) => {
      // Tab navigation enhancement
      if (e.key === 'Tab') {
        document.body.classList.add('keyboard-navigation');
      }

      // Escape key to close modals
      if (e.key === 'Escape') {
        const event = new CustomEvent('escape-pressed');
        document.dispatchEvent(event);
      }
    };

    const handleMouseDown = () => {
      document.body.classList.remove('keyboard-navigation');
    };

    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('mousedown', handleMouseDown);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('mousedown', handleMouseDown);
    };
  }, [settings.keyboardNavigation]);
};

export default AccessibilityProvider;
