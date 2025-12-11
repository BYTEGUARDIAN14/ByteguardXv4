
import React, { useEffect, Suspense } from 'react'
import Lenis from 'lenis'
import { I18nextProvider } from 'react-i18next'
import i18n from './i18n/config'
import { analytics } from './utils/analytics'
import { initializeSecurity } from './utils/security'
import { useGlobalStore } from './store/globalStore'
import Navbar from './components/Navbar'
import Footer from './components/Footer'
import LoadingSpinner from './components/ui/LoadingSpinner'
import SearchModal from './components/ui/SearchModal'

import HeroSection from './components/sections/HeroSection'
import FeaturesSection from './components/sections/FeaturesSection'
import PlatformSection from './components/sections/PlatformSection'
import GallerySection from './components/sections/GallerySection'
import DownloadSection from './components/sections/DownloadSection'
import ComparisonSection from './components/sections/ComparisonSection'
import PricingSection from './components/sections/PricingSection'
import SupportSection from './components/sections/SupportSection'

function App() {
  const { analytics: analyticsEnabled } = useGlobalStore()

  useEffect(() => {
    // Initialize security measures
    initializeSecurity()

    // Initialize analytics if enabled
    analytics.setEnabled(analyticsEnabled)

    // Track page load
    if (analyticsEnabled) {
      analytics.trackPageView('/')
      analytics.trackPerformance()
    }

    // Initialize Lenis smooth scrolling
    const lenis = new Lenis({
      duration: 1.2,
      easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
      gestureDirection: 'vertical',
      smooth: true,
      mouseMultiplier: 1,
      smoothTouch: false,
      touchMultiplier: 2,
      infinite: false,
    })

    function raf(time: number) {
      lenis.raf(time)
      requestAnimationFrame(raf)
    }

    requestAnimationFrame(raf)

    return () => {
      lenis.destroy()
    }
  }, [analyticsEnabled])

  return (
    <I18nextProvider i18n={i18n}>
      <div className="min-h-screen bg-black text-white">
        <Suspense fallback={<LoadingSpinner size="lg" text="Loading ByteGuardX..." />}>
          <Navbar />
          <main>
            <HeroSection />
            <FeaturesSection />
            <PlatformSection />
            <GallerySection />
            <DownloadSection />
            <ComparisonSection />
            <PricingSection />
            <SupportSection />
          </main>
          <Footer />
          <SearchModal />
        </Suspense>
      </div>
    </I18nextProvider>
  )
}

export default App
