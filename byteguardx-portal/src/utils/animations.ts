import { Variants } from 'framer-motion';

// Common animation variants
export const fadeInUp: Variants = {
  hidden: { 
    opacity: 0, 
    y: 60,
    transition: { duration: 0.3 }
  },
  visible: { 
    opacity: 1, 
    y: 0,
    transition: { 
      duration: 0.6,
      ease: [0.25, 0.46, 0.45, 0.94]
    }
  }
};

export const fadeInLeft: Variants = {
  hidden: { opacity: 0, x: -60 },
  visible: { 
    opacity: 1, 
    x: 0,
    transition: { duration: 0.6, ease: 'easeOut' }
  }
};

export const fadeInRight: Variants = {
  hidden: { opacity: 0, x: 60 },
  visible: { 
    opacity: 1, 
    x: 0,
    transition: { duration: 0.6, ease: 'easeOut' }
  }
};

export const scaleIn: Variants = {
  hidden: { opacity: 0, scale: 0.8 },
  visible: { 
    opacity: 1, 
    scale: 1,
    transition: { duration: 0.5, ease: 'easeOut' }
  }
};

export const slideInFromBottom: Variants = {
  hidden: { y: '100%', opacity: 0 },
  visible: { 
    y: 0, 
    opacity: 1,
    transition: { duration: 0.7, ease: [0.25, 0.46, 0.45, 0.94] }
  }
};

// Stagger animations for lists
export const staggerContainer: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
      delayChildren: 0.2
    }
  }
};

export const staggerItem: Variants = {
  hidden: { opacity: 0, y: 20 },
  visible: { 
    opacity: 1, 
    y: 0,
    transition: { duration: 0.5 }
  }
};

// Glassmorphism card hover effect
export const glassCard: Variants = {
  rest: { 
    scale: 1,
    boxShadow: '0 8px 32px rgba(0, 212, 255, 0.1)',
    borderColor: 'rgba(255, 255, 255, 0.2)'
  },
  hover: { 
    scale: 1.02,
    boxShadow: '0 16px 64px rgba(0, 212, 255, 0.2)',
    borderColor: 'rgba(0, 212, 255, 0.4)',
    transition: { duration: 0.3 }
  }
};

// Button animations
export const buttonHover: Variants = {
  rest: { scale: 1 },
  hover: { 
    scale: 1.05,
    transition: { duration: 0.2 }
  },
  tap: { 
    scale: 0.95,
    transition: { duration: 0.1 }
  }
};

// Loading animations
export const loadingSpinner: Variants = {
  animate: {
    rotate: 360,
    transition: {
      duration: 1,
      repeat: Infinity,
      ease: 'linear'
    }
  }
};

export const loadingDots: Variants = {
  animate: {
    scale: [1, 1.2, 1],
    opacity: [0.5, 1, 0.5],
    transition: {
      duration: 1.5,
      repeat: Infinity,
      ease: 'easeInOut'
    }
  }
};

// Page transitions
export const pageTransition: Variants = {
  initial: { opacity: 0, x: -200 },
  animate: { 
    opacity: 1, 
    x: 0,
    transition: { duration: 0.5, ease: 'easeOut' }
  },
  exit: { 
    opacity: 0, 
    x: 200,
    transition: { duration: 0.3 }
  }
};

// Scroll-triggered animations
export const scrollReveal: Variants = {
  hidden: { 
    opacity: 0, 
    y: 100,
    scale: 0.9
  },
  visible: { 
    opacity: 1, 
    y: 0,
    scale: 1,
    transition: { 
      duration: 0.8,
      ease: [0.25, 0.46, 0.45, 0.94]
    }
  }
};

// Floating animation for hero elements
export const floating: Variants = {
  animate: {
    y: [-10, 10, -10],
    transition: {
      duration: 3,
      repeat: Infinity,
      ease: 'easeInOut'
    }
  }
};

// Pulse animation for attention-grabbing elements
export const pulse: Variants = {
  animate: {
    scale: [1, 1.05, 1],
    opacity: [0.8, 1, 0.8],
    transition: {
      duration: 2,
      repeat: Infinity,
      ease: 'easeInOut'
    }
  }
};

// Typing animation for text
export const typewriter = {
  hidden: { width: 0 },
  visible: {
    width: 'auto',
    transition: {
      duration: 2,
      ease: 'easeInOut'
    }
  }
};

// Gradient animation for backgrounds
export const gradientShift: Variants = {
  animate: {
    backgroundPosition: ['0% 50%', '100% 50%', '0% 50%'],
    transition: {
      duration: 5,
      repeat: Infinity,
      ease: 'linear'
    }
  }
};

// Custom easing functions
export const easings = {
  smooth: [0.25, 0.46, 0.45, 0.94],
  bounce: [0.68, -0.55, 0.265, 1.55],
  elastic: [0.175, 0.885, 0.32, 1.275],
  back: [0.68, -0.55, 0.265, 1.55]
};

// Animation presets for different use cases
export const presets = {
  // For hero sections
  hero: {
    container: staggerContainer,
    item: fadeInUp,
    floating: floating
  },
  // For feature cards
  features: {
    container: staggerContainer,
    card: glassCard,
    item: staggerItem
  },
  // For navigation
  navigation: {
    item: fadeInLeft,
    button: buttonHover
  },
  // For modals/overlays
  modal: {
    backdrop: { hidden: { opacity: 0 }, visible: { opacity: 1 } },
    content: scaleIn
  }
};
