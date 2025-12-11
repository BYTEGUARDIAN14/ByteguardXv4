module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx,ts,tsx}"
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        primary: '#00bcd4', // Cyan
        background: '#0a0a0a', // Black
        glass: 'rgba(20, 20, 30, 0.6)'
      },
      backdropBlur: {
        glass: '12px'
      }
    }
  },
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography')
  ]
};

