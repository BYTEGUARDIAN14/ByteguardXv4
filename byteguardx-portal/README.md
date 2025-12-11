# ByteGuardX Portal

Official marketing and download portal for ByteGuardX - AI-Powered Vulnerability Scanner.

## 🚀 Features

- **Modern React + TypeScript** - Built with Vite for fast development
- **Responsive Design** - Mobile-first approach with Tailwind CSS
- **Cybersecurity Theme** - Dark mode with cyan accents and professional styling
- **Performance Optimized** - Code splitting, lazy loading, and optimized assets
- **SEO Ready** - Meta tags, Open Graph, and structured data
- **Deployment Ready** - Configured for Vercel with security headers

## 📁 Project Structure

```
byteguardx-portal/
├── public/                 # Static assets
├── src/
│   ├── components/        # Reusable components
│   │   ├── Layout.tsx     # Main layout wrapper
│   │   ├── Navbar.tsx     # Navigation component
│   │   └── Footer.tsx     # Footer component
│   ├── pages/            # Page components
│   │   ├── Home.tsx      # Landing page
│   │   ├── Download.tsx  # Download page with OS detection
│   │   ├── Extensions.tsx # Extensions and integrations
│   │   ├── Compare.tsx   # Competitor comparison
│   │   ├── Docs.tsx      # Documentation hub
│   │   └── Support.tsx   # Support and contact
│   ├── App.tsx           # Main app component
│   ├── main.tsx          # Entry point
│   └── index.css         # Global styles
├── tailwind.config.js    # Tailwind configuration
├── vite.config.ts        # Vite configuration
├── vercel.json           # Deployment configuration
└── package.json          # Dependencies and scripts
```

## 🛠️ Development

### Prerequisites

- Node.js 18+
- npm or yarn

### Setup

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

### Available Scripts

- `npm run dev` - Start development server on port 3001
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint

## 🎨 Design System

### Colors

- **Primary**: Cyan (#0ea5e9) - Main brand color
- **Gray Scale**: Black to white with proper contrast ratios
- **Severity**: Critical (red), High (orange), Medium (yellow), Low (green)

### Typography

- **Font Family**: Inter (sans-serif), JetBrains Mono (monospace)
- **Font Weights**: 300-900 for Inter, 300-700 for JetBrains Mono

### Components

- **Buttons**: Primary, secondary, outline variants
- **Cards**: Hover effects and proper spacing
- **Navigation**: Responsive with mobile menu
- **Forms**: Consistent styling with focus states

## 📱 Pages Overview

### Home (`/`)
- Hero section with key value propositions
- Feature highlights with icons and descriptions
- Platform availability showcase
- Statistics and social proof
- Call-to-action sections

### Download (`/download`)
- OS auto-detection for recommended downloads
- Desktop applications (Windows, macOS, Linux)
- Mobile apps (iOS, Android)
- Browser extensions (Chrome, Firefox)
- Developer tools (CLI, SDKs)
- System requirements

### Extensions (`/extensions`)
- VS Code extension with features and stats
- Browser extensions for Chrome and Firefox
- Git pre-commit hooks
- Python and JavaScript SDKs
- Installation guides and documentation links

### Compare (`/compare`)
- Feature comparison table with competitors
- ByteGuardX vs Snyk, SonarQube, GitLeaks, Veracode
- Key differentiators and advantages
- Pricing comparison

### Docs (`/docs`)
- Documentation hub with organized sections
- Quick links to popular topics
- Code examples for different use cases
- Links to external API documentation

### Support (`/support`)
- Multiple support channels (email, forum, GitHub)
- Comprehensive FAQ section
- Contact form with categorization
- Additional resources and links

## 🚀 Deployment

### Vercel (Recommended)

1. Connect your GitHub repository to Vercel
2. Configure build settings:
   - Build Command: `npm run build`
   - Output Directory: `dist`
3. Deploy automatically on push to main branch

### Manual Deployment

```bash
# Build the project
npm run build

# Deploy the dist/ folder to your hosting provider
```

### Environment Variables

No environment variables required for basic functionality.

## 🔧 Configuration

### Vite Configuration

- React plugin for JSX support
- Path aliases for cleaner imports
- Build optimization with code splitting
- Development server on port 3001

### Tailwind Configuration

- Custom color palette for cybersecurity theme
- Extended animations and keyframes
- Custom utility classes
- Responsive breakpoints

### Vercel Configuration

- SPA routing with fallback to index.html
- Security headers (CSP, HSTS, etc.)
- Performance optimizations

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is part of the ByteGuardX ecosystem and follows the same MIT license.

## 🔗 Links

- **Main Repository**: [ByteGuardX](https://github.com/byteguardx/byteguardx)
- **Documentation**: [docs.byteguardx.com](https://docs.byteguardx.com)
- **Website**: [byteguardx.online](https://byteguardx.online)
- **Support**: [support@byteguardx.com](mailto:support@byteguardx.com)
