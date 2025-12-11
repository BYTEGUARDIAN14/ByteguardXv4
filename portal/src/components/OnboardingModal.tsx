/**
 * Enhanced Onboarding Modal for ByteGuardX Portal
 * Guided walkthrough with Framer Motion animations and i18n support
 */

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import {
  X,
  ChevronLeft,
  ChevronRight,
  Play,
  Calendar,
  Download,
  Shield,
  Zap,
  Users,
  CheckCircle,
  Globe,
  Clock,
  Sparkles
} from 'lucide-react';

interface OnboardingStep {
  id: string;
  title: string;
  description: string;
  icon: React.ComponentType<any>;
  action?: {
    label: string;
    href: string;
    primary?: boolean;
  };
  highlight?: string;
}

interface OnboardingModalProps {
  isOpen: boolean;
  onClose: () => void;
  onComplete: () => void;
  userTimezone?: string;
  userRegion?: string;
}

const OnboardingModal: React.FC<OnboardingModalProps> = ({
  isOpen,
  onClose,
  onComplete,
  userTimezone,
  userRegion
}) => {
  const { t, i18n } = useTranslation();
  const [currentStep, setCurrentStep] = useState(0);
  const [hasStarted, setHasStarted] = useState(false);
  const [userPreferences, setUserPreferences] = useState({
    timezone: userTimezone || Intl.DateTimeFormat().resolvedOptions().timeZone,
    region: userRegion || 'global',
    language: i18n.language
  });
  const shouldReduceMotion = useReducedMotion();

  // Dynamic steps based on user preferences and i18n
  const steps: OnboardingStep[] = [
    {
      id: 'welcome',
      title: t('onboarding.welcome.title'),
      description: t('onboarding.welcome.description'),
      icon: Shield,
      highlight: t('onboarding.welcome.highlight')
    },
    {
      id: 'scan-now',
      title: t('onboarding.scan_now.title'),
      description: t('onboarding.scan_now.description'),
      icon: Play,
      action: {
        label: t('scan.start_scan'),
        href: '/dashboard/scan',
        primary: true
      },
      highlight: t('onboarding.scan_now.highlight')
    },
    {
      id: 'schedule-scans',
      title: t('onboarding.schedule.title'),
      description: t('onboarding.schedule.description'),
      icon: Calendar,
      action: {
        label: t('dashboard.settings'),
        href: '/dashboard/schedule'
      },
      highlight: t('onboarding.schedule.highlight')
    },
    {
      id: 'timezone-optimization',
      title: 'Optimize for Your Region',
      description: `We've detected you're in ${userPreferences.timezone}. Let's optimize your scanning schedule for your timezone and region.`,
      icon: Globe,
      highlight: 'Get personalized recommendations based on your location'
    },
    {
      id: 'install-extensions',
      title: t('onboarding.download.title'),
      description: t('onboarding.download.description'),
      icon: Download,
      action: {
        label: t('navigation.extensions'),
        href: '/extensions'
      },
      highlight: t('onboarding.download.highlight')
    },
    {
      id: 'complete',
      title: t('onboarding.complete.title'),
      description: t('onboarding.complete.description'),
      icon: CheckCircle,
      action: {
        label: t('navigation.dashboard'),
        href: '/dashboard',
        primary: true
      },
      highlight: t('onboarding.complete.highlight')
    }
  ];

  const currentStepData = steps[currentStep];

  const handleNext = () => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      handleComplete();
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleComplete = () => {
    onComplete();
    onClose();

    // Mark onboarding as completed with user preferences
    localStorage.setItem('byteguardx-onboarding-completed', 'true');
    localStorage.setItem('byteguardx-user-preferences', JSON.stringify(userPreferences));
  };

  // Animation variants with reduced motion support
  const modalVariants = {
    hidden: {
      opacity: 0,
      scale: shouldReduceMotion ? 1 : 0.8,
      y: shouldReduceMotion ? 0 : 50
    },
    visible: {
      opacity: 1,
      scale: 1,
      y: 0,
      transition: {
        duration: shouldReduceMotion ? 0.1 : 0.3,
        ease: "easeOut"
      }
    },
    exit: {
      opacity: 0,
      scale: shouldReduceMotion ? 1 : 0.8,
      y: shouldReduceMotion ? 0 : -50,
      transition: {
        duration: shouldReduceMotion ? 0.1 : 0.2
      }
    }
  };

  const contentVariants = {
    hidden: {
      opacity: 0,
      x: shouldReduceMotion ? 0 : 20
    },
    visible: {
      opacity: 1,
      x: 0,
      transition: {
        duration: shouldReduceMotion ? 0.1 : 0.4,
        delay: shouldReduceMotion ? 0 : 0.1
      }
    },
    exit: {
      opacity: 0,
      x: shouldReduceMotion ? 0 : -20,
      transition: {
        duration: shouldReduceMotion ? 0.1 : 0.2
      }
    }
  };

  const glowVariants = {
    animate: shouldReduceMotion ? {} : {
      scale: [1, 1.2, 1],
      opacity: [0.5, 0.8, 0.5],
      transition: {
        duration: 2,
        repeat: Infinity,
        ease: "easeInOut"
      }
    }
  };

  const handleSkip = () => {
    onClose();
    localStorage.setItem('byteguardx-onboarding-skipped', 'true');
  };

  const handleRemindLater = () => {
    onClose();
    // Set reminder for 24 hours
    const reminderTime = Date.now() + (24 * 60 * 60 * 1000);
    localStorage.setItem('byteguardx-onboarding-reminder', reminderTime.toString());
  };

  const handleStart = () => {
    setHasStarted(true);
    setCurrentStep(1);
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
        onClick={(e) => e.target === e.currentTarget && onClose()}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.9, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.9, y: 20 }}
          transition={{ type: "spring", duration: 0.5 }}
          className="relative w-full max-w-2xl bg-black/90 backdrop-blur-xl border border-white/10 rounded-2xl overflow-hidden"
        >
          {/* Close button */}
          <button
            onClick={onClose}
            className="absolute top-4 right-4 z-10 p-2 text-gray-400 hover:text-white transition-colors duration-200"
            aria-label="Close onboarding"
          >
            <X className="h-6 w-6" />
          </button>

          {/* Progress bar */}
          {hasStarted && (
            <div className="absolute top-0 left-0 right-0 h-1 bg-gray-800">
              <motion.div
                className="h-full bg-gradient-to-r from-cyan-600 to-cyan-400"
                initial={{ width: 0 }}
                animate={{ width: `${((currentStep) / (steps.length - 1)) * 100}%` }}
                transition={{ duration: 0.3 }}
              />
            </div>
          )}

          <div className="p-8">
            {!hasStarted ? (
              // Welcome screen
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="text-center"
              >
                <div className="relative mb-8">
                  <Shield className="h-20 w-20 text-cyan-400 mx-auto" />
                  <motion.div
                    className="absolute inset-0 bg-cyan-400/20 blur-xl rounded-full"
                    animate={{ scale: [1, 1.2, 1] }}
                    transition={{ duration: 2, repeat: Infinity }}
                  />
                </div>
                
                <h1 className="text-3xl font-bold text-white mb-4">
                  Welcome to ByteGuardX
                </h1>
                <p className="text-gray-300 text-lg mb-8 max-w-md mx-auto">
                  Let's take a quick tour to help you get the most out of our AI-powered security platform.
                </p>
                
                <div className="grid grid-cols-3 gap-4 mb-8">
                  <div className="text-center">
                    <Zap className="h-8 w-8 text-cyan-400 mx-auto mb-2" />
                    <p className="text-sm text-gray-300">Lightning Fast</p>
                  </div>
                  <div className="text-center">
                    <Shield className="h-8 w-8 text-cyan-400 mx-auto mb-2" />
                    <p className="text-sm text-gray-300">Enterprise Security</p>
                  </div>
                  <div className="text-center">
                    <Users className="h-8 w-8 text-cyan-400 mx-auto mb-2" />
                    <p className="text-sm text-gray-300">Team Collaboration</p>
                  </div>
                </div>
                
                <div className="flex flex-col sm:flex-row gap-4 justify-center">
                  <motion.button
                    onClick={handleStart}
                    className="px-8 py-3 bg-cyan-600 hover:bg-cyan-700 text-white font-medium rounded-lg transition-colors duration-300"
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    Start Tour
                  </motion.button>
                  <button
                    onClick={handleSkip}
                    className="px-8 py-3 border border-gray-600 text-gray-300 hover:text-white hover:border-gray-500 font-medium rounded-lg transition-colors duration-300"
                  >
                    Skip for now
                  </button>
                </div>
                
                <button
                  onClick={handleRemindLater}
                  className="mt-4 text-sm text-gray-400 hover:text-gray-300 transition-colors duration-300"
                >
                  Remind me later
                </button>
              </motion.div>
            ) : (
              // Tour steps
              <AnimatePresence mode="wait">
                <motion.div
                  key={currentStep}
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  transition={{ duration: 0.3 }}
                  className="min-h-[400px] flex flex-col"
                >
                  <div className="flex-1">
                    <div className="text-center mb-8">
                      <div className="relative mb-6">
                        <currentStepData.icon className="h-16 w-16 text-cyan-400 mx-auto" />
                        <motion.div
                          className="absolute inset-0 bg-cyan-400/20 blur-xl rounded-full"
                          animate={{ scale: [1, 1.1, 1] }}
                          transition={{ duration: 1.5, repeat: Infinity }}
                        />
                      </div>
                      
                      <h2 className="text-2xl font-bold text-white mb-4">
                        {currentStepData.title}
                      </h2>
                      <p className="text-gray-300 text-lg mb-4">
                        {currentStepData.description}
                      </p>
                      
                      {currentStepData.highlight && (
                        <div className="inline-block bg-cyan-600/20 border border-cyan-600/30 rounded-lg px-4 py-2 text-cyan-400 text-sm">
                          {currentStepData.highlight}
                        </div>
                      )}
                    </div>
                    
                    {currentStepData.action && (
                      <div className="text-center mb-8">
                        <motion.a
                          href={currentStepData.action.href}
                          className={`inline-flex items-center px-6 py-3 font-medium rounded-lg transition-colors duration-300 ${
                            currentStepData.action.primary
                              ? 'bg-cyan-600 hover:bg-cyan-700 text-white'
                              : 'border border-cyan-600 text-cyan-400 hover:bg-cyan-600 hover:text-white'
                          }`}
                          whileHover={{ scale: 1.05 }}
                          whileTap={{ scale: 0.95 }}
                          onClick={(e) => {
                            e.preventDefault();
                            // Handle navigation or action
                            console.log('Navigate to:', currentStepData.action?.href);
                          }}
                        >
                          {currentStepData.action.label}
                        </motion.a>
                      </div>
                    )}
                  </div>
                  
                  {/* Navigation */}
                  <div className="flex items-center justify-between pt-6 border-t border-white/10">
                    <button
                      onClick={handlePrevious}
                      disabled={currentStep === 1}
                      className="flex items-center px-4 py-2 text-gray-400 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-300"
                    >
                      <ChevronLeft className="h-5 w-5 mr-1" />
                      Previous
                    </button>
                    
                    <div className="flex space-x-2">
                      {steps.slice(1).map((_, index) => (
                        <div
                          key={index}
                          className={`w-2 h-2 rounded-full transition-colors duration-300 ${
                            index + 1 === currentStep ? 'bg-cyan-400' : 'bg-gray-600'
                          }`}
                        />
                      ))}
                    </div>
                    
                    <button
                      onClick={handleNext}
                      className="flex items-center px-4 py-2 text-cyan-400 hover:text-cyan-300 transition-colors duration-300"
                    >
                      {currentStep === steps.length - 1 ? 'Complete' : 'Next'}
                      <ChevronRight className="h-5 w-5 ml-1" />
                    </button>
                  </div>
                </motion.div>
              </AnimatePresence>
            )}
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
};

export default OnboardingModal;
