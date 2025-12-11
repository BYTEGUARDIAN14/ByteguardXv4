/**
 * Privacy Policy Page for ByteGuardX Portal
 * GDPR compliant privacy policy with clear data handling practices
 */

import React from 'react';
import { motion } from 'framer-motion';
import { Shield, Eye, Lock, Users, FileText, Mail } from 'lucide-react';

const PrivacyPolicy: React.FC = () => {
  const lastUpdated = "January 9, 2025";

  const sections = [
    {
      id: "information-collection",
      title: "Information We Collect",
      icon: FileText,
      content: [
        {
          subtitle: "Account Information",
          text: "When you create an account, we collect your email address, username, and encrypted password. We may also collect optional profile information such as your name and organization."
        },
        {
          subtitle: "Usage Data",
          text: "We collect information about how you use ByteGuardX, including scan results, plugin usage, and feature interactions. This data helps us improve our services and provide better security insights."
        },
        {
          subtitle: "Technical Information",
          text: "We automatically collect technical information such as IP addresses, browser type, device information, and usage patterns to ensure security and optimize performance."
        }
      ]
    },
    {
      id: "data-usage",
      title: "How We Use Your Data",
      icon: Eye,
      content: [
        {
          subtitle: "Service Provision",
          text: "We use your data to provide, maintain, and improve ByteGuardX services, including vulnerability scanning, threat detection, and security reporting."
        },
        {
          subtitle: "Security Enhancement",
          text: "Your anonymized usage data helps us improve our AI models and security detection capabilities. We never share your specific code or sensitive information."
        },
        {
          subtitle: "Communication",
          text: "We may use your contact information to send important service updates, security alerts, and optional marketing communications (which you can opt out of at any time)."
        }
      ]
    },
    {
      id: "data-protection",
      title: "Data Protection & Security",
      icon: Lock,
      content: [
        {
          subtitle: "Encryption",
          text: "All data is encrypted in transit using TLS 1.3 and at rest using AES-256 encryption. Your code and scan results are never stored in plain text."
        },
        {
          subtitle: "Access Controls",
          text: "We implement strict access controls and zero-trust security principles. Only authorized personnel can access user data, and all access is logged and monitored."
        },
        {
          subtitle: "Data Minimization",
          text: "We collect and retain only the minimum data necessary to provide our services. Code snippets are processed locally when possible and deleted after analysis."
        }
      ]
    },
    {
      id: "data-sharing",
      title: "Data Sharing & Disclosure",
      icon: Users,
      content: [
        {
          subtitle: "No Sale of Data",
          text: "We never sell, rent, or trade your personal information or code data to third parties for marketing or commercial purposes."
        },
        {
          subtitle: "Service Providers",
          text: "We may share limited data with trusted service providers who help us operate ByteGuardX, such as cloud infrastructure providers. All providers are bound by strict confidentiality agreements."
        },
        {
          subtitle: "Legal Requirements",
          text: "We may disclose information if required by law, court order, or to protect our rights and the safety of our users. We will notify you of such disclosures unless prohibited by law."
        }
      ]
    }
  ];

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Header */}
      <div className="relative bg-gradient-to-br from-black via-gray-900 to-black py-20">
        <div className="absolute inset-0 bg-[url('/grid.svg')] bg-center [mask-image:linear-gradient(180deg,white,rgba(255,255,255,0))]" />
        
        <div className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
          >
            <Shield className="h-16 w-16 text-cyan-400 mx-auto mb-6" />
            <h1 className="text-4xl md:text-5xl font-bold mb-6">
              Privacy Policy
            </h1>
            <p className="text-xl text-gray-300 max-w-2xl mx-auto">
              Your privacy and data security are fundamental to everything we do at ByteGuardX.
            </p>
            <p className="text-sm text-gray-400 mt-4">
              Last updated: {lastUpdated}
            </p>
          </motion.div>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        {/* Introduction */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.2 }}
          className="mb-12"
        >
          <div className="glassmorphism p-8 rounded-2xl">
            <h2 className="text-2xl font-bold mb-4">Our Commitment to Privacy</h2>
            <p className="text-gray-300 leading-relaxed">
              At ByteGuardX, we understand that trust is earned through transparency and action. 
              This Privacy Policy explains how we collect, use, protect, and handle your information 
              when you use our AI-powered code security platform. We are committed to protecting 
              your privacy and maintaining the highest standards of data security.
            </p>
          </div>
        </motion.div>

        {/* Sections */}
        {sections.map((section, index) => {
          const Icon = section.icon;
          return (
            <motion.section
              key={section.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.3 + index * 0.1 }}
              className="mb-12"
              id={section.id}
            >
              <div className="glassmorphism p-8 rounded-2xl">
                <div className="flex items-center mb-6">
                  <Icon className="h-8 w-8 text-cyan-400 mr-4" />
                  <h2 className="text-2xl font-bold">{section.title}</h2>
                </div>
                
                <div className="space-y-6">
                  {section.content.map((item, itemIndex) => (
                    <div key={itemIndex}>
                      <h3 className="text-lg font-semibold text-cyan-400 mb-2">
                        {item.subtitle}
                      </h3>
                      <p className="text-gray-300 leading-relaxed">
                        {item.text}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </motion.section>
          );
        })}

        {/* Your Rights */}
        <motion.section
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.7 }}
          className="mb-12"
        >
          <div className="glassmorphism p-8 rounded-2xl">
            <h2 className="text-2xl font-bold mb-6 flex items-center">
              <Shield className="h-8 w-8 text-cyan-400 mr-4" />
              Your Rights & Controls
            </h2>
            
            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <h3 className="text-lg font-semibold text-cyan-400 mb-2">Access & Portability</h3>
                <p className="text-gray-300 text-sm">
                  You can access, download, or export your data at any time through your account settings.
                </p>
              </div>
              
              <div>
                <h3 className="text-lg font-semibold text-cyan-400 mb-2">Correction & Updates</h3>
                <p className="text-gray-300 text-sm">
                  You can update your personal information and preferences in your account dashboard.
                </p>
              </div>
              
              <div>
                <h3 className="text-lg font-semibold text-cyan-400 mb-2">Deletion</h3>
                <p className="text-gray-300 text-sm">
                  You can request deletion of your account and associated data at any time.
                </p>
              </div>
              
              <div>
                <h3 className="text-lg font-semibold text-cyan-400 mb-2">Opt-out</h3>
                <p className="text-gray-300 text-sm">
                  You can opt out of marketing communications and certain data processing activities.
                </p>
              </div>
            </div>
          </div>
        </motion.section>

        {/* Contact */}
        <motion.section
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.8 }}
        >
          <div className="glassmorphism p-8 rounded-2xl text-center">
            <Mail className="h-12 w-12 text-cyan-400 mx-auto mb-4" />
            <h2 className="text-2xl font-bold mb-4">Questions About Privacy?</h2>
            <p className="text-gray-300 mb-6">
              If you have any questions about this Privacy Policy or our data practices, 
              please don't hesitate to contact our privacy team.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <a
                href="mailto:privacy@byteguardx.com"
                className="inline-flex items-center justify-center px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-white font-medium rounded-lg transition-colors duration-300"
              >
                <Mail className="h-5 w-5 mr-2" />
                privacy@byteguardx.com
              </a>
              <a
                href="/contact"
                className="inline-flex items-center justify-center px-6 py-3 border border-cyan-600 text-cyan-400 hover:bg-cyan-600 hover:text-white font-medium rounded-lg transition-colors duration-300"
              >
                Contact Form
              </a>
            </div>
          </div>
        </motion.section>
      </div>
    </div>
  );
};

export default PrivacyPolicy;
