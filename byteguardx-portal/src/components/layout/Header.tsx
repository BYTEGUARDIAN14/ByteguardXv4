import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Link, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { 
  Menu, 
  X, 
  Shield, 
  Globe, 
  Moon, 
  Sun, 
  Search,
  ChevronDown
} from 'lucide-react';
import { useResponsive } from '../../hooks/useResponsive';
import { useGlobalStore } from '../../store/globalStore';
import Button from '../ui/Button';
import LanguageSelector from './LanguageSelector';

const Header: React.FC = () => {
  const { t } = useTranslation('common');
  const location = useLocation();
  const { isMobile } = useResponsive();
  const [isScrolled, setIsScrolled] = useState(false);
  
  const { 
    mobileMenuOpen, 
    setMobileMenuOpen, 
    searchOpen, 
    setSearchOpen,
    theme,
    setTheme 
  } = useGlobalStore();

  // Handle scroll effect
  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 20);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const navigation = [
    { name: t('navigation.home'), href: '/' },
    { name: t('navigation.features'), href: '/features' },
    { name: t('navigation.pricing'), href: '/pricing' },
    { name: t('navigation.docs'), href: '/docs' },
    { name: t('navigation.download'), href: '/download' },
    { name: t('navigation.extensions'), href: '/extensions' },
    { name: t('navigation.compare'), href: '/compare' },
    { name: t('navigation.support'), href: '/support' }
  ];

  const toggleTheme = () => {
    setTheme(theme === 'dark' ? 'light' : 'dark');
  };

  return (
    <motion.header
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        isScrolled 
          ? 'glass-panel border-b border-white/10 backdrop-blur-xl' 
          : 'bg-transparent'
      }`}
      initial={{ y: -100 }}
      animate={{ y: 0 }}
      transition={{ duration: 0.5 }}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center space-x-2 group">
            <motion.div
              className="p-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 group-hover:shadow-lg group-hover:shadow-cyan-500/25"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <Shield className="h-6 w-6 text-white" />
            </motion.div>
            <span className="text-xl font-bold text-white group-hover:text-cyan-400 transition-colors">
              ByteGuardX
            </span>
          </Link>

          {/* Desktop Navigation */}
          {!isMobile && (
            <nav className="hidden md:flex items-center space-x-1">
              {navigation.map((item) => (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                    location.pathname === item.href
                      ? 'text-cyan-400 bg-cyan-400/10'
                      : 'text-gray-300 hover:text-cyan-400 hover:bg-white/5'
                  }`}
                >
                  {item.name}
                </Link>
              ))}
            </nav>
          )}

          {/* Right side actions */}
          <div className="flex items-center space-x-3">
            {/* Search */}
            <motion.button
              onClick={() => setSearchOpen(!searchOpen)}
              className="p-2 rounded-lg text-gray-300 hover:text-cyan-400 hover:bg-white/5 transition-all"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <Search className="h-5 w-5" />
            </motion.button>

            {/* Language Selector */}
            <LanguageSelector />

            {/* Theme Toggle */}
            <motion.button
              onClick={toggleTheme}
              className="p-2 rounded-lg text-gray-300 hover:text-cyan-400 hover:bg-white/5 transition-all"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              {theme === 'dark' ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
            </motion.button>

            {/* CTA Button */}
            {!isMobile && (
              <Button variant="primary" size="sm">
                {t('buttons.getStarted')}
              </Button>
            )}

            {/* Mobile menu button */}
            {isMobile && (
              <motion.button
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                className="p-2 rounded-lg text-gray-300 hover:text-cyan-400 hover:bg-white/5 transition-all"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                {mobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
              </motion.button>
            )}
          </div>
        </div>
      </div>

      {/* Mobile Navigation */}
      <AnimatePresence>
        {mobileMenuOpen && isMobile && (
          <motion.div
            className="md:hidden glass-panel border-t border-white/10"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.3 }}
          >
            <div className="px-4 py-4 space-y-2">
              {navigation.map((item) => (
                <Link
                  key={item.name}
                  to={item.href}
                  onClick={() => setMobileMenuOpen(false)}
                  className={`block px-3 py-2 rounded-lg text-base font-medium transition-all ${
                    location.pathname === item.href
                      ? 'text-cyan-400 bg-cyan-400/10'
                      : 'text-gray-300 hover:text-cyan-400 hover:bg-white/5'
                  }`}
                >
                  {item.name}
                </Link>
              ))}
              <div className="pt-4 border-t border-white/10">
                <Button variant="primary" fullWidth>
                  {t('buttons.getStarted')}
                </Button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Search Overlay */}
      <AnimatePresence>
        {searchOpen && (
          <motion.div
            className="absolute top-full left-0 right-0 glass-panel border-b border-white/10 p-4"
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.2 }}
          >
            <div className="max-w-2xl mx-auto">
              <input
                type="text"
                placeholder={t('common.search')}
                className="w-full px-4 py-3 bg-white/5 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                autoFocus
              />
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.header>
  );
};

export default Header;
