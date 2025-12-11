import React, { useRef } from 'react';
import { motion, useScroll, useTransform } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  Shield,
  Download,
  Play,
  ArrowRight,
  Zap,
  Lock,
  Eye,
  Code,
  Database,
  Globe,
  Sparkles,
  Terminal,
  Monitor,
  Smartphone,
  Chrome,
  Puzzle
} from 'lucide-react';



const Home: React.FC = () => {
  const heroRef = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({
    target: heroRef,
    offset: ["start start", "end start"]
  });

  const y = useTransform(scrollYProgress, [0, 1], ["0%", "30%"]);
  const opacity = useTransform(scrollYProgress, [0, 1], [1, 0.3]);

  const features = [
    {
      icon: Shield,
      title: 'AI-Powered Detection',
      description: 'Advanced machine learning models identify security vulnerabilities with 99.9% accuracy and minimal false positives.',
    },
    {
      icon: Lock,
      title: 'Offline-First Security',
      description: 'Complete privacy protection - no data sent to external services. All scanning happens locally on your machine.',
    },
    {
      icon: Zap,
      title: 'Lightning Fast',
      description: 'Optimized scanning engine processes thousands of files per second with intelligent caching and parallel processing.',
    },
    {
      icon: Eye,
      title: 'Comprehensive Coverage',
      description: 'Detects secrets, CVEs, AI patterns, dependency vulnerabilities, and custom security rules across 50+ languages.',
    },
  ]

  const platforms = [
    { icon: Terminal, name: 'CLI Tool', description: 'Full-featured command line' },
    { icon: Monitor, name: 'Desktop App', description: 'Electron-based GUI' },
    { icon: Globe, name: 'Web Dashboard', description: 'React-based interface' },
    { icon: Smartphone, name: 'Mobile App', description: 'iOS & Android support' },
    { icon: Code, name: 'VS Code Extension', description: 'IDE integration' },
    { icon: Chrome, name: 'Browser Extensions', description: 'Chrome & Firefox' },
    { icon: Puzzle, name: 'API & SDKs', description: 'Python & JavaScript' },
    { icon: Database, name: 'CI/CD Integration', description: 'GitHub Actions & more' },
  ]

  const stats = [
    { value: '50+', label: 'Languages Supported' },
    { value: '10K+', label: 'Vulnerabilities Detected' },
    { value: '99.9%', label: 'Accuracy Rate' },
    { value: '100%', label: 'Privacy Protected' },
  ]

  return (
    <div className="min-h-screen">
      {/* Enhanced Hero Section */}
      <motion.section
        ref={heroRef}
        className="relative min-h-screen flex items-center justify-center overflow-hidden"
        style={{ y, opacity }}
      >
        {/* Animated Background */}
        <div className="absolute inset-0 bg-gradient-to-br from-black via-gray-950 to-black">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(0,255,255,0.1),transparent_50%)]" />
          <div className="absolute inset-0 bg-[conic-gradient(from_0deg_at_50%_50%,transparent_0deg,rgba(0,255,255,0.05)_60deg,transparent_120deg)]" />
        </div>

        {/* Floating Elements */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <motion.div
            animate={{
              y: [-10, 10, -10],
              rotate: [-2, 2, -2],
            }}
            transition={{
              duration: 4,
              repeat: Infinity,
              ease: "easeInOut",
            }}
          >
            <div className="absolute top-20 left-20 w-2 h-2 bg-cyan-400 rounded-full opacity-60" />
          </motion.div>
          <motion.div
            animate={{
              y: [-15, 15, -15],
              rotate: [2, -2, 2],
            }}
            transition={{
              duration: 5,
              repeat: Infinity,
              ease: "easeInOut",
              delay: 1
            }}
          >
            <div className="absolute top-40 right-32 w-1 h-1 bg-blue-400 rounded-full opacity-80" />
          </motion.div>
        </div>

        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
          <div className="text-center">
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ duration: 0.6, delay: 0.2 }}
              className="inline-flex items-center space-x-2 bg-cyan-400/10 border border-cyan-400/20 rounded-full px-4 py-2 mb-8"
            >
              <Sparkles className="h-4 w-4 text-cyan-400" />
              <span className="text-sm text-cyan-300 font-medium">AI-Powered Security</span>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.1 }}
              className="flex justify-center mb-8"
            >
              <motion.div
                className="glass-card p-8 rounded-3xl hover-glow"
                whileHover={{ scale: 1.05, rotateY: 5 }}
                transition={{ duration: 0.3 }}
              >
                <Shield className="h-20 w-20 text-cyan-400" />
              </motion.div>
            </motion.div>

            <motion.h1
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.3 }}
              className="text-4xl md:text-6xl lg:text-7xl font-bold mb-8 leading-tight"
            >
              <span className="gradient-text">ByteGuardX</span>
              <br />
              <span className="text-white font-light">Security Scanner</span>
            </motion.h1>

            <motion.p
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.4 }}
              className="text-xl md:text-2xl text-gray-300 mb-12 leading-relaxed max-w-4xl mx-auto"
            >
              Comprehensive, offline-first vulnerability scanning with enterprise-grade security features.
              Protect your code with advanced AI pattern detection.
            </motion.p>

            <motion.div
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.5 }}
              className="flex flex-col sm:flex-row gap-6 justify-center items-center mb-16"
            >
              <Link
                to="/download"
                className="btn-primary text-lg px-10 py-4 hover-lift hover-glow group"
              >
                <Download className="h-5 w-5 mr-2 group-hover:animate-bounce" />
                Download Now
                <ArrowRight className="h-4 w-4 ml-2 group-hover:translate-x-1 transition-transform" />
              </Link>

              <Link to="/docs" className="btn-secondary text-lg px-10 py-4 hover-lift group">
                <Play className="h-5 w-5 mr-2 group-hover:scale-110 transition-transform" />
                Try Demo
              </Link>
            </motion.div>
          </div>
        </div>
      </motion.section>

      {/* Stats Section */}
      <section className="py-16 bg-black/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {stats.map((stat, index) => (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.8, delay: index * 0.1 }}
                className="text-center"
              >
                <div className="text-3xl md:text-4xl font-bold gradient-text mb-2">
                  {stat.value}
                </div>
                <div className="text-gray-400 text-sm">{stat.label}</div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>



      {/* Features Section */}
      <section className="section-padding bg-gray-950">
        <div className="max-w-7xl mx-auto container-padding">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Why Choose <span className="gradient-text">ByteGuardX</span>?
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto">
              Built for developers who prioritize security, privacy, and performance
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {features.map((feature, index) => {
              const Icon = feature.icon
              return (
                <motion.div
                  key={feature.title}
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.6, delay: index * 0.1 }}
                  viewport={{ once: true }}
                  className="card card-hover p-8"
                >
                  <div className="flex items-start space-x-4">
                    <div className="p-3 bg-primary-500/10 rounded-lg">
                      <Icon className="h-6 w-6 text-primary-400" />
                    </div>
                    <div>
                      <h3 className="text-xl font-semibold mb-3">{feature.title}</h3>
                      <p className="text-gray-400">{feature.description}</p>
                    </div>
                  </div>
                </motion.div>
              )
            })}
          </div>
        </div>
      </section>

      {/* Platforms Section */}
      <section className="section-padding">
        <div className="max-w-7xl mx-auto container-padding">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Available <span className="gradient-text">Everywhere</span>
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto">
              Use ByteGuardX across all your development environments and workflows
            </p>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
            {platforms.map((platform, index) => {
              const Icon = platform.icon
              return (
                <motion.div
                  key={platform.name}
                  initial={{ opacity: 0, scale: 0.9 }}
                  whileInView={{ opacity: 1, scale: 1 }}
                  transition={{ duration: 0.5, delay: index * 0.1 }}
                  viewport={{ once: true }}
                  className="card p-6 text-center hover:border-primary-500/50 transition-all duration-300"
                >
                  <div className="p-3 bg-primary-500/10 rounded-lg w-fit mx-auto mb-4">
                    <Icon className="h-8 w-8 text-primary-400" />
                  </div>
                  <h3 className="font-semibold mb-2">{platform.name}</h3>
                  <p className="text-sm text-gray-400">{platform.description}</p>
                </motion.div>
              )
            })}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="section-padding bg-gradient-to-r from-primary-900/20 to-primary-800/20">
        <div className="max-w-4xl mx-auto container-padding text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            viewport={{ once: true }}
          >
            <h2 className="text-3xl md:text-4xl font-bold mb-6">
              Ready to Secure Your Code?
            </h2>
            <p className="text-xl text-gray-300 mb-8">
              Join thousands of developers who trust ByteGuardX to protect their applications
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link to="/download" className="btn-primary text-lg px-8 py-4 glow-effect">
                <Download className="h-5 w-5 mr-2" />
                Get Started Free
              </Link>
              <Link to="/compare" className="btn-secondary text-lg px-8 py-4">
                Compare Features
                <ArrowRight className="h-5 w-5 ml-2" />
              </Link>
            </div>
          </motion.div>
        </div>
      </section>
    </div>
  )
}

export default Home
