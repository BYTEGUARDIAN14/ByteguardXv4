import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { 
  HelpCircle, 
  Mail, 
  MessageCircle, 
  Github, 
  ExternalLink, 
  ChevronDown, 
  ChevronUp,
  Send
} from 'lucide-react'

const Support: React.FC = () => {
  const [openFaq, setOpenFaq] = useState<number | null>(null)
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    subject: '',
    message: '',
    category: 'general'
  })

  const supportChannels = [
    {
      icon: Mail,
      title: 'Email Support',
      description: 'Get help via email with detailed responses',
      contact: 'support@byteguardx.com',
      responseTime: '24-48 hours',
      href: 'mailto:support@byteguardx.com'
    },
    {
      icon: MessageCircle,
      title: 'Community Forum',
      description: 'Join discussions with other developers',
      contact: 'GitHub Discussions',
      responseTime: 'Community-driven',
      href: 'https://github.com/byteguardx/byteguardx/discussions'
    },
    {
      icon: Github,
      title: 'Bug Reports',
      description: 'Report bugs and technical issues',
      contact: 'GitHub Issues',
      responseTime: '1-3 business days',
      href: 'https://github.com/byteguardx/byteguardx/issues'
    }
  ]

  const faqs = [
    {
      question: 'How do I install ByteGuardX?',
      answer: 'ByteGuardX can be installed via pip (pip install byteguardx), npm (npm install -g byteguardx), or by downloading the desktop application from our downloads page. See our installation guide for detailed instructions.'
    },
    {
      question: 'Is ByteGuardX really offline-first?',
      answer: 'Yes! ByteGuardX works completely offline with no internet connection required. All scanning, analysis, and reporting happens locally on your machine. No code or data is ever sent to external servers.'
    },
    {
      question: 'What programming languages are supported?',
      answer: 'ByteGuardX supports 50+ programming languages including Python, JavaScript, TypeScript, Java, C#, Go, Rust, PHP, Ruby, Swift, Kotlin, and many more. The AI-powered detection works across all supported languages.'
    },
    {
      question: 'How accurate is the AI-powered detection?',
      answer: 'Our AI models achieve 99.9% accuracy with minimal false positives. The system combines traditional static analysis with machine learning to provide highly accurate vulnerability detection while reducing noise.'
    },
    {
      question: 'Can I use ByteGuardX in my CI/CD pipeline?',
      answer: 'Absolutely! ByteGuardX provides CLI tools, GitHub Actions, and API integrations that make it easy to integrate into any CI/CD pipeline. Check our CI/CD integration documentation for examples.'
    },
    {
      question: 'What\'s the difference between Free and Pro plans?',
      answer: 'The Free plan includes 5 scans per month with basic features. The Pro plan ($29/month) offers unlimited scans, AI pattern analysis, advanced reporting, Git hooks, and full API access.'
    },
    {
      question: 'How do I configure custom security rules?',
      answer: 'ByteGuardX supports custom rules through YAML configuration files. You can define custom patterns, severity levels, and fix suggestions. See our custom rules documentation for detailed examples.'
    },
    {
      question: 'Is enterprise support available?',
      answer: 'Yes! We offer enterprise support with SSO integration, RBAC, audit logging, on-premise deployment, and dedicated support channels. Contact us for enterprise pricing and features.'
    }
  ]

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    // Handle form submission
    console.log('Form submitted:', formData)
    // Reset form or show success message
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    })
  }

  return (
    <div className="min-h-screen py-20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-20">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
          >
            <div className="flex justify-center mb-8">
              <div className="glass-panel p-6 rounded-3xl">
                <HelpCircle className="h-16 w-16 text-cyan-400" />
              </div>
            </div>
            <h1 className="text-4xl md:text-5xl font-bold mb-8">
              Get <span className="gradient-text">Support</span>
            </h1>
            <p className="text-xl text-gray-300 max-w-2xl mx-auto font-light leading-relaxed">
              We're here to help you get the most out of ByteGuardX. Find answers, report issues, or get in touch with our team.
            </p>
          </motion.div>
        </div>

        {/* Support Channels */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-16">
          {supportChannels.map((channel, index) => {
            const Icon = channel.icon
            return (
              <motion.div
                key={channel.title}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                className="card p-8 text-center card-hover"
              >
                <div className="p-4 bg-primary-500/10 rounded-2xl w-fit mx-auto mb-6">
                  <Icon className="h-8 w-8 text-primary-400" />
                </div>
                <h3 className="text-xl font-semibold mb-3">{channel.title}</h3>
                <p className="text-gray-400 mb-4">{channel.description}</p>
                <div className="space-y-2 mb-6">
                  <div className="text-sm">
                    <span className="text-gray-400">Contact: </span>
                    <span className="font-medium">{channel.contact}</span>
                  </div>
                  <div className="text-sm">
                    <span className="text-gray-400">Response time: </span>
                    <span className="font-medium">{channel.responseTime}</span>
                  </div>
                </div>
                <a
                  href={channel.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn-primary w-full justify-center"
                >
                  Get Help
                  <ExternalLink className="h-4 w-4 ml-2" />
                </a>
              </motion.div>
            )
          })}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16">
          {/* FAQ Section */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8, delay: 0.3 }}
          >
            <h2 className="text-3xl font-bold mb-8">
              Frequently Asked <span className="gradient-text">Questions</span>
            </h2>
            
            <div className="space-y-4">
              {faqs.map((faq, index) => (
                <div key={index} className="card overflow-hidden">
                  <button
                    onClick={() => setOpenFaq(openFaq === index ? null : index)}
                    className="w-full p-6 text-left flex items-center justify-between hover:bg-gray-800/50 transition-colors"
                  >
                    <span className="font-semibold pr-4">{faq.question}</span>
                    {openFaq === index ? (
                      <ChevronUp className="h-5 w-5 text-primary-400 flex-shrink-0" />
                    ) : (
                      <ChevronDown className="h-5 w-5 text-gray-400 flex-shrink-0" />
                    )}
                  </button>
                  {openFaq === index && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={{ duration: 0.3 }}
                      className="px-6 pb-6"
                    >
                      <p className="text-gray-400 leading-relaxed">{faq.answer}</p>
                    </motion.div>
                  )}
                </div>
              ))}
            </div>
          </motion.div>

          {/* Contact Form */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8, delay: 0.4 }}
          >
            <h2 className="text-3xl font-bold mb-8">
              Contact <span className="gradient-text">Us</span>
            </h2>
            
            <form onSubmit={handleSubmit} className="card p-8 space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label htmlFor="name" className="block text-sm font-medium mb-2">
                    Name *
                  </label>
                  <input
                    type="text"
                    id="name"
                    name="name"
                    required
                    value={formData.name}
                    onChange={handleInputChange}
                    className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-colors"
                    placeholder="Your name"
                  />
                </div>
                <div>
                  <label htmlFor="email" className="block text-sm font-medium mb-2">
                    Email *
                  </label>
                  <input
                    type="email"
                    id="email"
                    name="email"
                    required
                    value={formData.email}
                    onChange={handleInputChange}
                    className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-colors"
                    placeholder="your@email.com"
                  />
                </div>
              </div>

              <div>
                <label htmlFor="category" className="block text-sm font-medium mb-2">
                  Category
                </label>
                <select
                  id="category"
                  name="category"
                  value={formData.category}
                  onChange={handleInputChange}
                  className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-colors"
                >
                  <option value="general">General Question</option>
                  <option value="technical">Technical Support</option>
                  <option value="billing">Billing & Pricing</option>
                  <option value="enterprise">Enterprise Inquiry</option>
                  <option value="partnership">Partnership</option>
                </select>
              </div>

              <div>
                <label htmlFor="subject" className="block text-sm font-medium mb-2">
                  Subject *
                </label>
                <input
                  type="text"
                  id="subject"
                  name="subject"
                  required
                  value={formData.subject}
                  onChange={handleInputChange}
                  className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-colors"
                  placeholder="Brief description of your inquiry"
                />
              </div>

              <div>
                <label htmlFor="message" className="block text-sm font-medium mb-2">
                  Message *
                </label>
                <textarea
                  id="message"
                  name="message"
                  required
                  rows={6}
                  value={formData.message}
                  onChange={handleInputChange}
                  className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-colors resize-none"
                  placeholder="Please provide as much detail as possible..."
                />
              </div>

              <button
                type="submit"
                className="btn-primary w-full justify-center text-lg py-4"
              >
                <Send className="h-5 w-5 mr-2" />
                Send Message
              </button>

              <p className="text-sm text-gray-400 text-center">
                We typically respond within 24-48 hours during business days.
              </p>
            </form>
          </motion.div>
        </div>

        {/* Additional Resources */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.6 }}
          className="mt-16 card p-8 text-center"
        >
          <h3 className="text-2xl font-bold mb-4">Additional Resources</h3>
          <p className="text-gray-400 mb-8">
            Explore our comprehensive documentation and community resources
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <a href="/docs" className="btn-primary">
              Documentation
            </a>
            <a
              href="https://github.com/byteguardx/byteguardx/wiki"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-secondary"
            >
              <ExternalLink className="h-4 w-4 mr-2" />
              Wiki
            </a>
            <a
              href="https://github.com/byteguardx/byteguardx/releases"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-outline"
            >
              Release Notes
            </a>
          </div>
        </motion.div>
      </div>
    </div>
  )
}

export default Support
