import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { visualizer } from 'rollup-plugin-visualizer';
import { splitVendorChunkPlugin } from 'vite';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react({
      // Enable React Fast Refresh
      fastRefresh: true,
      // Optimize React imports
      jsxImportSource: '@emotion/react',
      babel: {
        plugins: [
          // Tree shake unused imports
          ['import', { libraryName: 'lodash', libraryDirectory: '', camel2DashComponentName: false }, 'lodash'],
          ['import', { libraryName: 'antd', libraryDirectory: 'es', style: true }, 'antd'],
          // Remove console.log in production
          process.env.NODE_ENV === 'production' && 'transform-remove-console'
        ].filter(Boolean)
      }
    }),
    
    // Split vendor chunks for better caching
    splitVendorChunkPlugin(),
    
    // Bundle analyzer (only in build mode)
    process.env.ANALYZE && visualizer({
      filename: 'dist/stats.html',
      open: true,
      gzipSize: true,
      brotliSize: true
    })
  ],

  // Path resolution
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
      '@components': resolve(__dirname, 'src/components'),
      '@utils': resolve(__dirname, 'src/utils'),
      '@hooks': resolve(__dirname, 'src/hooks'),
      '@services': resolve(__dirname, 'src/services'),
      '@assets': resolve(__dirname, 'src/assets'),
      '@styles': resolve(__dirname, 'src/styles')
    }
  },

  // Development server configuration
  server: {
    port: 3002,
    host: true,
    cors: true,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
        secure: false
      }
    }
  },

  // Build optimization
  build: {
    // Target modern browsers for better optimization
    target: 'es2020',
    
    // Output directory
    outDir: 'dist',
    
    // Generate source maps for debugging
    sourcemap: process.env.NODE_ENV !== 'production',
    
    // Minification
    minify: 'terser',
    terserOptions: {
      compress: {
        // Remove console.log in production
        drop_console: true,
        drop_debugger: true,
        // Remove unused code
        dead_code: true,
        // Optimize conditionals
        conditionals: true,
        // Optimize loops
        loops: true,
        // Remove unused variables
        unused: true
      },
      mangle: {
        // Mangle property names for better compression
        properties: {
          regex: /^_/
        }
      }
    },
    
    // Rollup options for advanced optimization
    rollupOptions: {
      // External dependencies (loaded from CDN in production)
      external: process.env.NODE_ENV === 'production' ? [
        // 'react',
        // 'react-dom'
      ] : [],
      
      output: {
        // Manual chunk splitting for optimal loading
        manualChunks: {
          // Vendor chunks
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'ui-vendor': ['framer-motion', '@headlessui/react'],
          'utils-vendor': ['lodash', 'date-fns', 'axios'],
          'chart-vendor': ['chart.js', 'react-chartjs-2'],
          
          // Feature chunks
          'dashboard': [
            './src/pages/Dashboard.jsx',
            './src/components/Dashboard'
          ],
          'security': [
            './src/pages/Security.jsx',
            './src/components/Security'
          ],
          'reports': [
            './src/pages/Reports.jsx',
            './src/components/Reports'
          ]
        },
        
        // Chunk file naming
        chunkFileNames: (chunkInfo) => {
          const facadeModuleId = chunkInfo.facadeModuleId 
            ? chunkInfo.facadeModuleId.split('/').pop().replace('.jsx', '').replace('.js', '')
            : 'chunk';
          return `js/${facadeModuleId}-[hash].js`;
        },
        
        // Asset file naming
        assetFileNames: (assetInfo) => {
          const info = assetInfo.name.split('.');
          const ext = info[info.length - 1];
          if (/png|jpe?g|svg|gif|tiff|bmp|ico/i.test(ext)) {
            return `images/[name]-[hash][extname]`;
          }
          if (/css/i.test(ext)) {
            return `css/[name]-[hash][extname]`;
          }
          return `assets/[name]-[hash][extname]`;
        }
      }
    },
    
    // Chunk size warnings
    chunkSizeWarningLimit: 1000,
    
    // Asset inlining threshold
    assetsInlineLimit: 4096
  },

  // CSS configuration
  css: {
    // CSS modules
    modules: {
      localsConvention: 'camelCase'
    },
    
    // PostCSS configuration
    postcss: {
      plugins: [
        require('tailwindcss'),
        require('autoprefixer'),
        // Optimize CSS in production
        process.env.NODE_ENV === 'production' && require('cssnano')({
          preset: ['default', {
            discardComments: { removeAll: true },
            normalizeWhitespace: true,
            colormin: true,
            convertValues: true,
            discardDuplicates: true,
            discardEmpty: true,
            mergeRules: true,
            minifyFontValues: true,
            minifyParams: true,
            minifySelectors: true,
            reduceIdents: true,
            svgo: true
          }]
        })
      ].filter(Boolean)
    }
  },

  // Dependency optimization
  optimizeDeps: {
    // Include dependencies that should be pre-bundled
    include: [
      'react',
      'react-dom',
      'react-router-dom',
      'axios',
      'lodash',
      'date-fns'
    ],
    
    // Exclude dependencies from pre-bundling
    exclude: [
      // Large libraries that are better loaded dynamically
      'chart.js'
    ]
  },

  // Define global constants
  define: {
    __APP_VERSION__: JSON.stringify(process.env.npm_package_version),
    __BUILD_TIME__: JSON.stringify(new Date().toISOString()),
    __DEV__: process.env.NODE_ENV === 'development'
  },

  // Environment variables
  envPrefix: 'VITE_',

  // Performance optimizations
  esbuild: {
    // Drop console and debugger in production
    drop: process.env.NODE_ENV === 'production' ? ['console', 'debugger'] : [],
    
    // Optimize for modern browsers
    target: 'es2020',
    
    // Enable tree shaking
    treeShaking: true
  }
});

// Performance monitoring plugin
const performancePlugin = () => {
  return {
    name: 'performance-monitor',
    buildStart() {
      this.startTime = Date.now();
    },
    buildEnd() {
      const buildTime = Date.now() - this.startTime;
      console.log(`🚀 Build completed in ${buildTime}ms`);
    },
    generateBundle(options, bundle) {
      // Analyze bundle size
      let totalSize = 0;
      const chunks = [];
      
      Object.entries(bundle).forEach(([fileName, chunk]) => {
        if (chunk.type === 'chunk') {
          const size = new TextEncoder().encode(chunk.code).length;
          totalSize += size;
          chunks.push({
            name: fileName,
            size: (size / 1024).toFixed(2) + ' KB'
          });
        }
      });
      
      console.log('\n📦 Bundle Analysis:');
      console.log(`Total size: ${(totalSize / 1024).toFixed(2)} KB`);
      
      // Show largest chunks
      chunks
        .sort((a, b) => parseFloat(b.size) - parseFloat(a.size))
        .slice(0, 10)
        .forEach(chunk => {
          console.log(`  ${chunk.name}: ${chunk.size}`);
        });
      
      // Warn about large chunks
      chunks.forEach(chunk => {
        const sizeKB = parseFloat(chunk.size);
        if (sizeKB > 500) {
          console.warn(`⚠️  Large chunk detected: ${chunk.name} (${chunk.size})`);
        }
      });
    }
  };
};

// Add performance plugin in development
if (process.env.NODE_ENV === 'development') {
  export default defineConfig((config) => ({
    ...config,
    plugins: [...config.plugins, performancePlugin()]
  }));
}
