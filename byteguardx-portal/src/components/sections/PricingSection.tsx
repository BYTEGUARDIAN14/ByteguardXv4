import React from 'react'
import { motion } from 'framer-motion'
import { 
  Check, 
  X, 
  Star, 
  Shield, 
  Users, 
  Building, 
  Zap,
  Crown,
  ArrowRight
} from 'lucide-react'
import ScrollSection from '../ScrollSection'

const PricingSection: React.FC = () => {
  const plans = [
    {
      name: 'Community',
      price: 'Free',
      period: 'Forever',
      description: 'Perfect for individual developers and small projects',
      icon: Shield,
      color: 'text-green-400',
      bgColor: 'bg-green-400/10',
      borderColor: 'border-green-400/30',
      popular: false,
      features: [
        { name: 'Basic vulnerability scanning', included: true },
        { name: 'Up to 10 projects', included: true },
        { name: 'CLI tool access', included: true },
        { name: 'Community support', included: true },
        { name: 'Basic reporting', included: true },
        { name: 'Advanced AI detection', included: false },
        { name: 'Team collaboration', included: false },
        { name: 'Priority support', included: false },
        { name: 'Custom rules', included: false },
        { name: 'API access', included: false }
      ]
    },
    {
      name: 'Professional',
      price: '$29',
      period: 'per month',
      description: 'Advanced features for professional developers and small teams',
      icon: Star,
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-400/10',
      borderColor: 'border-cyan-400/50',
      popular: true,
      features: [
        { name: 'Advanced AI-powered scanning', included: true },
        { name: 'Unlimited projects', included: true },
        { name: 'All platform access', included: true },
        { name: 'Priority support', included: true },
        { name: 'Advanced reporting & analytics', included: true },
        { name: 'Custom security rules', included: true },
        { name: 'API access', included: true },
        { name: 'Team collaboration (up to 5)', included: true },
        { name: 'CI/CD integrations', included: true },
        { name: 'Enterprise SSO', included: false }
      ]
    },
    {
      name: 'Enterprise',
      price: 'Custom',
      period: 'Contact us',
      description: 'Comprehensive solution for large organizations and enterprises',
      icon: Building,
      color: 'text-purple-400',
      bgColor: 'bg-purple-400/10',
      borderColor: 'border-purple-400/30',
      popular: false,
      features: [
        { name: 'Everything in Professional', included: true },
        { name: 'Unlimited team members', included: true },
        { name: 'Enterprise SSO & RBAC', included: true },
        { name: 'On-premise deployment', included: true },
        { name: 'Custom integrations', included: true },
        { name: 'Dedicated support', included: true },
        { name: 'SLA guarantees', included: true },
        { name: 'Custom training', included: true },
        { name: 'Compliance reporting', included: true },
        { name: 'White-label options', included: true }
      ]
    }
  ]

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.2
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

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId)
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' })
    }
  }

  return (
    <ScrollSection id="pricing" background="default">
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
            <Crown className="h-4 w-4 text-cyan-400" />
            <span className="text-sm text-gray-300 uppercase tracking-wide">Pricing</span>
          </motion.div>
          
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
            Choose Your <span className="gradient-text">Plan</span>
          </h2>
          
          <p className="text-xl text-gray-300 max-w-3xl mx-auto">
            Start free and scale as you grow. All plans include our core AI-powered vulnerability detection.
          </p>
        </motion.div>

        {/* Pricing Cards */}
        <motion.div 
          className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-16"
          variants={containerVariants}
        >
          {plans.map((plan, index) => (
            <motion.div
              key={plan.name}
              className={`
                glass-card relative group transition-all duration-500
                ${plan.popular ? 'border-cyan-400/50 scale-105' : 'hover:border-cyan-400/30'}
              `}
              variants={itemVariants}
              whileHover={{ y: plan.popular ? 0 : -5 }}
            >
              {/* Popular Badge */}
              {plan.popular && (
                <div className="absolute -top-4 left-1/2 transform -translate-x-1/2">
                  <div className="glass-panel px-4 py-1 rounded-full border-cyan-400/50 bg-cyan-400/10">
                    <span className="text-xs font-medium text-cyan-400 uppercase tracking-wide">
                      Most Popular
                    </span>
                  </div>
                </div>
              )}

              {/* Plan Header */}
              <div className="text-center mb-8">
                <div className={`inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-4 ${plan.bgColor} ${plan.borderColor} border`}>
                  <plan.icon className={`h-8 w-8 ${plan.color}`} />
                </div>
                
                <h3 className="text-2xl font-bold text-white mb-2">{plan.name}</h3>
                <p className="text-gray-400 text-sm mb-4">{plan.description}</p>
                
                <div className="mb-6">
                  <span className="text-4xl font-bold text-white">{plan.price}</span>
                  {plan.period !== 'Forever' && plan.period !== 'Contact us' && (
                    <span className="text-gray-400 text-sm ml-2">/{plan.period}</span>
                  )}
                  <div className="text-gray-400 text-sm mt-1">{plan.period}</div>
                </div>

                <motion.button
                  onClick={() => scrollToSection('download')}
                  className={`
                    w-full py-3 px-6 rounded-xl font-semibold transition-all duration-300 flex items-center justify-center space-x-2
                    ${plan.popular 
                      ? 'bg-cyan-400 text-black hover:bg-cyan-300' 
                      : 'glass-panel border border-white/20 text-white hover:border-cyan-400/50 hover:text-cyan-400'
                    }
                  `}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                >
                  <span>{plan.price === 'Custom' ? 'Contact Sales' : 'Get Started'}</span>
                  <ArrowRight className="h-4 w-4" />
                </motion.button>
              </div>

              {/* Features List */}
              <div className="space-y-3">
                {plan.features.map((feature, featureIndex) => (
                  <div
                    key={featureIndex}
                    className="flex items-center space-x-3"
                  >
                    {feature.included ? (
                      <Check className="h-4 w-4 text-green-400 flex-shrink-0" />
                    ) : (
                      <X className="h-4 w-4 text-gray-600 flex-shrink-0" />
                    )}
                    <span className={`text-sm ${feature.included ? 'text-gray-300' : 'text-gray-500'}`}>
                      {feature.name}
                    </span>
                  </div>
                ))}
              </div>
            </motion.div>
          ))}
        </motion.div>

        {/* FAQ Section */}
        <motion.div 
          className="text-center"
          variants={itemVariants}
        >
          <h3 className="text-2xl font-bold text-white mb-6">
            Frequently Asked <span className="gradient-text">Questions</span>
          </h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-4xl mx-auto">
            <div className="glass-panel p-6 rounded-xl text-left">
              <h4 className="text-lg font-semibold text-white mb-3">
                Can I upgrade or downgrade anytime?
              </h4>
              <p className="text-gray-400 text-sm">
                Yes, you can change your plan at any time. Changes take effect immediately, 
                and we'll prorate any billing adjustments.
              </p>
            </div>
            
            <div className="glass-panel p-6 rounded-xl text-left">
              <h4 className="text-lg font-semibold text-white mb-3">
                Is there a free trial for paid plans?
              </h4>
              <p className="text-gray-400 text-sm">
                All paid plans come with a 14-day free trial. No credit card required 
                to start your trial.
              </p>
            </div>
            
            <div className="glass-panel p-6 rounded-xl text-left">
              <h4 className="text-lg font-semibold text-white mb-3">
                What payment methods do you accept?
              </h4>
              <p className="text-gray-400 text-sm">
                We accept all major credit cards, PayPal, and can arrange invoicing 
                for enterprise customers.
              </p>
            </div>
            
            <div className="glass-panel p-6 rounded-xl text-left">
              <h4 className="text-lg font-semibold text-white mb-3">
                Do you offer volume discounts?
              </h4>
              <p className="text-gray-400 text-sm">
                Yes, we offer significant discounts for teams of 10+ users. 
                Contact our sales team for custom pricing.
              </p>
            </div>
          </div>
        </motion.div>
      </div>
    </ScrollSection>
  )
}

export default PricingSection
