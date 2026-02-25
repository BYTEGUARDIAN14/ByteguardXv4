/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Desktop Surface System
        'desktop-bg': '#0a0a0a',
        'desktop-sidebar': '#111111',
        'desktop-card': '#161616',
        'desktop-card-hover': '#1c1c1c',
        'desktop-elevated': '#1e1e1e',
        'desktop-border': '#222222',
        'desktop-border-light': '#2a2a2a',
        'desktop-input': '#141414',

        // Text Hierarchy
        'text-primary': '#e4e4e7',
        'text-secondary': '#a1a1aa',
        'text-muted': '#71717a',
        'text-disabled': '#52525b',

        // Brand Colors
        primary: {
          DEFAULT: '#06b6d4',
          50: '#ecfeff',
          100: '#cffafe',
          200: '#a5f3fc',
          300: '#67e8f9',
          400: '#22d3ee',
          500: '#06b6d4',
          600: '#0891b2',
          700: '#0e7490',
          800: '#155e75',
          900: '#164e63',
          950: '#083344',
        },
        secondary: '#3b82f6',

        // Status Colors
        success: '#10b981',
        warning: '#f59e0b',
        danger: '#ef4444',
        info: '#3b82f6',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      fontSize: {
        'xxs': '0.625rem',
      },
      spacing: {
        'sidebar': '240px',
        'sidebar-collapsed': '56px',
        'toolbar': '44px',
      },
      borderRadius: {
        'desktop': '6px',
      },
      animation: {
        'spin-slow': 'spin 3s linear infinite',
      },
    },
  },
  plugins: [],
}
