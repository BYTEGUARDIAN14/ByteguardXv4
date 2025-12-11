import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import { 
  Search, 
  X, 
  Clock, 
  TrendingUp, 
  FileText, 
  Code, 
  Shield,
  ArrowRight
} from 'lucide-react';
import { useGlobalStore } from '../../store/globalStore';
import { useAnalytics } from '../../utils/analytics';

interface SearchResult {
  id: string;
  title: string;
  description: string;
  type: 'page' | 'feature' | 'doc' | 'download';
  url: string;
  icon: React.ReactNode;
}

const SearchModal: React.FC = () => {
  const { t } = useTranslation('common');
  const { searchOpen, setSearchOpen } = useGlobalStore();
  const { trackEvent } = useAnalytics();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResult[]>([]);
  const [recentSearches, setRecentSearches] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Mock search data
  const searchData: SearchResult[] = [
    {
      id: '1',
      title: 'AI-Powered Vulnerability Detection',
      description: 'Learn about our advanced AI algorithms for security scanning',
      type: 'feature',
      url: '/features#ai-detection',
      icon: <Shield className="h-4 w-4" />
    },
    {
      id: '2',
      title: 'Getting Started Guide',
      description: 'Quick start guide for ByteGuardX installation and setup',
      type: 'doc',
      url: '/docs/getting-started',
      icon: <FileText className="h-4 w-4" />
    },
    {
      id: '3',
      title: 'Download CLI Tool',
      description: 'Download the ByteGuardX command-line interface',
      type: 'download',
      url: '/download#cli',
      icon: <Code className="h-4 w-4" />
    },
    {
      id: '4',
      title: 'Pricing Plans',
      description: 'Compare our pricing plans and features',
      type: 'page',
      url: '/pricing',
      icon: <TrendingUp className="h-4 w-4" />
    }
  ];

  // Focus input when modal opens
  useEffect(() => {
    if (searchOpen && inputRef.current) {
      inputRef.current.focus();
    }
  }, [searchOpen]);

  // Load recent searches from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('byteguardx-recent-searches');
    if (saved) {
      setRecentSearches(JSON.parse(saved));
    }
  }, []);

  // Handle search
  useEffect(() => {
    if (!query.trim()) {
      setResults([]);
      return;
    }

    setIsLoading(true);
    
    // Simulate search delay
    const timer = setTimeout(() => {
      const filtered = searchData.filter(item =>
        item.title.toLowerCase().includes(query.toLowerCase()) ||
        item.description.toLowerCase().includes(query.toLowerCase())
      );
      setResults(filtered);
      setIsLoading(false);
    }, 300);

    return () => clearTimeout(timer);
  }, [query]);

  const handleSearch = (searchQuery: string) => {
    if (!searchQuery.trim()) return;

    // Add to recent searches
    const updated = [searchQuery, ...recentSearches.filter(s => s !== searchQuery)].slice(0, 5);
    setRecentSearches(updated);
    localStorage.setItem('byteguardx-recent-searches', JSON.stringify(updated));

    // Track search
    trackEvent('search', { query: searchQuery, results: results.length });
  };

  const handleResultClick = (result: SearchResult) => {
    handleSearch(query);
    trackEvent('search_result_click', { 
      query, 
      result_title: result.title, 
      result_type: result.type 
    });
    setSearchOpen(false);
    setQuery('');
  };

  const handleClose = () => {
    setSearchOpen(false);
    setQuery('');
    setResults([]);
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'feature': return 'text-cyan-400 bg-cyan-400/10';
      case 'doc': return 'text-green-400 bg-green-400/10';
      case 'download': return 'text-purple-400 bg-purple-400/10';
      case 'page': return 'text-blue-400 bg-blue-400/10';
      default: return 'text-gray-400 bg-gray-400/10';
    }
  };

  return (
    <AnimatePresence>
      {searchOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={handleClose}
          />

          {/* Modal */}
          <motion.div
            className="fixed top-20 left-1/2 transform -translate-x-1/2 w-full max-w-2xl mx-4 z-50"
            initial={{ opacity: 0, y: -20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -20, scale: 0.95 }}
            transition={{ duration: 0.2 }}
          >
            <div className="glass-panel border border-white/20 rounded-2xl shadow-2xl overflow-hidden">
              {/* Search Input */}
              <div className="flex items-center px-6 py-4 border-b border-white/10">
                <Search className="h-5 w-5 text-gray-400 mr-3" />
                <input
                  ref={inputRef}
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && results.length > 0) {
                      handleResultClick(results[0]);
                    } else if (e.key === 'Escape') {
                      handleClose();
                    }
                  }}
                  placeholder={t('common.search')}
                  className="flex-1 bg-transparent text-white placeholder-gray-400 focus:outline-none"
                />
                <button
                  onClick={handleClose}
                  className="p-1 rounded-lg text-gray-400 hover:text-white hover:bg-white/10 transition-all"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              {/* Search Results */}
              <div className="max-h-96 overflow-y-auto">
                {isLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <div className="animate-spin rounded-full h-6 w-6 border-2 border-cyan-400 border-t-transparent" />
                  </div>
                ) : query && results.length > 0 ? (
                  <div className="py-2">
                    {results.map((result) => (
                      <motion.button
                        key={result.id}
                        onClick={() => handleResultClick(result)}
                        className="w-full flex items-center px-6 py-3 hover:bg-white/5 transition-all group"
                        whileHover={{ x: 4 }}
                      >
                        <div className={`p-2 rounded-lg mr-4 ${getTypeColor(result.type)}`}>
                          {result.icon}
                        </div>
                        <div className="flex-1 text-left">
                          <div className="text-white font-medium group-hover:text-cyan-400 transition-colors">
                            {result.title}
                          </div>
                          <div className="text-sm text-gray-400 mt-1">
                            {result.description}
                          </div>
                        </div>
                        <ArrowRight className="h-4 w-4 text-gray-400 group-hover:text-cyan-400 transition-colors" />
                      </motion.button>
                    ))}
                  </div>
                ) : query && !isLoading ? (
                  <div className="py-8 text-center text-gray-400">
                    <Search className="h-8 w-8 mx-auto mb-2 opacity-50" />
                    <p>No results found for "{query}"</p>
                  </div>
                ) : (
                  <div className="py-4">
                    {/* Recent Searches */}
                    {recentSearches.length > 0 && (
                      <div className="px-6 py-2">
                        <div className="flex items-center text-sm text-gray-400 mb-3">
                          <Clock className="h-4 w-4 mr-2" />
                          Recent searches
                        </div>
                        <div className="space-y-1">
                          {recentSearches.map((search, index) => (
                            <button
                              key={index}
                              onClick={() => setQuery(search)}
                              className="block w-full text-left px-3 py-2 text-gray-300 hover:text-cyan-400 hover:bg-white/5 rounded-lg transition-all"
                            >
                              {search}
                            </button>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Popular Searches */}
                    <div className="px-6 py-2 border-t border-white/10">
                      <div className="flex items-center text-sm text-gray-400 mb-3">
                        <TrendingUp className="h-4 w-4 mr-2" />
                        Popular searches
                      </div>
                      <div className="space-y-1">
                        {['AI detection', 'CLI installation', 'VS Code extension', 'Pricing'].map((search) => (
                          <button
                            key={search}
                            onClick={() => setQuery(search)}
                            className="block w-full text-left px-3 py-2 text-gray-300 hover:text-cyan-400 hover:bg-white/5 rounded-lg transition-all"
                          >
                            {search}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Footer */}
              <div className="px-6 py-3 border-t border-white/10 text-xs text-gray-500 flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <span>Press <kbd className="px-2 py-1 bg-white/10 rounded">↵</kbd> to select</span>
                  <span>Press <kbd className="px-2 py-1 bg-white/10 rounded">esc</kbd> to close</span>
                </div>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};

export default SearchModal;
