import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import Backend from 'i18next-http-backend';

// Supported languages
export const SUPPORTED_LANGUAGES = [
  { code: 'en', name: 'English', flag: '🇺🇸' },
  { code: 'es', name: 'Español', flag: '🇪🇸' },
  { code: 'fr', name: 'Français', flag: '🇫🇷' },
  { code: 'de', name: 'Deutsch', flag: '🇩🇪' },
  { code: 'ja', name: '日本語', flag: '🇯🇵' },
  { code: 'zh', name: '中文', flag: '🇨🇳' },
];

// Initialize i18next
i18n
  // Load translations from /public/locales
  .use(Backend)
  // Detect user language
  .use(LanguageDetector)
  // Pass i18n instance to react-i18next
  .use(initReactI18next)
  .init({
    // Default language
    fallbackLng: 'en',
    // Debug in development
    debug: process.env.NODE_ENV === 'development',
    // Detect language from URL, localStorage, navigator
    detection: {
      order: ['path', 'localStorage', 'navigator'],
      lookupFromPathIndex: 0,
      caches: ['localStorage'],
    },
    // Namespace for splitting translations
    ns: ['common', 'home', 'features', 'pricing', 'docs'],
    defaultNS: 'common',
    // Interpolation configuration
    interpolation: {
      escapeValue: false, // React already escapes values
    },
    // React specific options
    react: {
      useSuspense: true,
    },
  });

// Helper for language switching
export const changeLanguage = (lng: string) => {
  i18n.changeLanguage(lng);
  document.documentElement.lang = lng;
  localStorage.setItem('i18nextLng', lng);
};

// Format dates based on locale
export const formatDate = (date: Date, options?: Intl.DateTimeFormatOptions) => {
  return new Intl.DateTimeFormat(i18n.language, options).format(date);
};

// Format numbers based on locale
export const formatNumber = (num: number, options?: Intl.NumberFormatOptions) => {
  return new Intl.NumberFormat(i18n.language, options).format(num);
};

export default i18n;
