import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// Security-focused Vite configuration
export default defineConfig({
  plugins: [
    react()
  ],
  
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  
  server: {
    port: 3001,
    host: true,
    // Security headers for development
    headers: {
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin'
    },
    // HTTPS in development (optional)
    https: process.env.VITE_HTTPS === 'true' ? {
      key: './certs/key.pem',
      cert: './certs/cert.pem'
    } : false
  },
  
  build: {
    outDir: 'dist',
    sourcemap: process.env.NODE_ENV !== 'production', // No source maps in production
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: process.env.NODE_ENV === 'production',
        drop_debugger: true,
        pure_funcs: process.env.NODE_ENV === 'production' ? ['console.log'] : []
      },
      mangle: {
        safari10: true
      },
      format: {
        comments: false // Remove comments in production
      }
    },
    rollupOptions: {
      output: {
        // Obfuscate chunk names in production
        chunkFileNames: process.env.NODE_ENV === 'production' 
          ? 'assets/[hash].js' 
          : 'assets/[name]-[hash].js',
        entryFileNames: process.env.NODE_ENV === 'production'
          ? 'assets/[hash].js'
          : 'assets/[name]-[hash].js',
        assetFileNames: process.env.NODE_ENV === 'production'
          ? 'assets/[hash].[ext]'
          : 'assets/[name]-[hash].[ext]',
        manualChunks: {
          vendor: ['react', 'react-dom'],
          router: ['react-router-dom'],
          icons: ['lucide-react'],
          animations: ['framer-motion'],
        },
      },
      // External dependencies that shouldn't be bundled
      external: process.env.NODE_ENV === 'production' ? [] : [],
    },
    // Asset handling
    assetsInlineLimit: 4096, // Inline assets smaller than 4kb
    chunkSizeWarningLimit: 500, // Warn for chunks larger than 500kb
  },
  
  // Environment variables security
  define: {
    // Only expose safe environment variables
    __APP_VERSION__: JSON.stringify(process.env.npm_package_version),
    __BUILD_TIME__: JSON.stringify(new Date().toISOString()),
    // Don't expose sensitive env vars to client
  },
  
  // Dependency optimization
  optimizeDeps: {
    include: [
      'react', 
      'react-dom', 
      'react-router-dom', 
      'lucide-react', 
      'framer-motion'
    ],
    // Exclude potentially unsafe dependencies
    exclude: ['fsevents']
  },
  
  // Preview server security (for production preview)
  preview: {
    port: 4173,
    host: true,
    headers: {
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data: https:",
        "connect-src 'self' https://api.byteguardx.com",
        "frame-src 'none'",
        "object-src 'none'"
      ].join('; ')
    }
  },
  
  // CSS security - simplified for compatibility
  css: {
    postcss: './postcss.config.js'
  }
});
