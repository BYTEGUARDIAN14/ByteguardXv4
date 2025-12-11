/**
 * Internationalization (i18n) Configuration for ByteGuardX Portal
 * Supports English, Spanish, German, and French
 */

import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

// Import translation files
import enTranslations from './locales/en.json';
import esTranslations from './locales/es.json';
import deTranslations from './locales/de.json';
import frTranslations from './locales/fr.json';
import zhTranslations from './locales/zh.json';
import hiTranslations from './locales/hi.json';
import arTranslations from './locales/ar.json';

export const defaultNS = 'common';
export const resources = {
  en: {
    common: enTranslations
  },
  es: {
    common: esTranslations
  },
  de: {
    common: deTranslations
  },
  fr: {
    common: frTranslations
  },
  zh: {
    common: zhTranslations
  },
  hi: {
    common: hiTranslations
  },
  ar: {
    common: arTranslations
  }
} as const;

// Language configuration with RTL support
export const supportedLanguages = [
  { code: 'en', name: 'English', nativeName: 'English', rtl: false },
  { code: 'es', name: 'Spanish', nativeName: 'Español', rtl: false },
  { code: 'de', name: 'German', nativeName: 'Deutsch', rtl: false },
  { code: 'fr', name: 'French', nativeName: 'Français', rtl: false },
  { code: 'zh', name: 'Chinese', nativeName: '中文', rtl: false },
  { code: 'hi', name: 'Hindi', nativeName: 'हिन्दी', rtl: false },
  { code: 'ar', name: 'Arabic', nativeName: 'العربية', rtl: true }
];

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    defaultNS,
    fallbackLng: 'en',
    
    // Language detection options
    detection: {
      order: ['localStorage', 'navigator', 'htmlTag'],
      caches: ['localStorage'],
      lookupLocalStorage: 'byteguardx-language'
    },
    
    interpolation: {
      escapeValue: false // React already escapes values
    },
    
    // Development options
    debug: process.env.NODE_ENV === 'development',
    
    // Namespace and key separator
    keySeparator: '.',
    nsSeparator: ':',
    
    // React options
    react: {
      useSuspense: false
    }
  });

export default i18n;
