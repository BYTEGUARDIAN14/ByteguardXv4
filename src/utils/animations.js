// Advanced Animation Presets for ByteGuardX
import { motion } from 'framer-motion'

// Page Transitions
export const pageVariants = {
  initial: { 
    opacity: 0, 
    x: -50,
    scale: 0.98
  },
  animate: { 
    opacity: 1, 
    x: 0,
    scale: 1,
    transition: { 
      duration: 0.5, 
      ease: [0.25, 0.46, 0.45, 0.94] 
    }
  },
  exit: { 
    opacity: 0, 
    x: 50,
    scale: 0.98,
    transition: { duration: 0.3 }
  }
}

// Stagger Container
export const staggerContainer = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
      delayChildren: 0.2
    }
  }
}

// Stagger Items
export const staggerItem = {
  hidden: { 
    opacity: 0, 
    y: 30,
    scale: 0.95
  },
  visible: { 
    opacity: 1, 
    y: 0,
    scale: 1,
    transition: { 
      duration: 0.6,
      ease: [0.25, 0.46, 0.45, 0.94]
    }
  }
}

// Slide Animations
export const slideUp = {
  hidden: { opacity: 0, y: 60 },
  visible: { 
    opacity: 1, 
    y: 0,
    transition: { duration: 0.6, ease: 'easeOut' }
  }
}

export const slideDown = {
  hidden: { opacity: 0, y: -60 },
  visible: { 
    opacity: 1, 
    y: 0,
    transition: { duration: 0.6, ease: 'easeOut' }
  }
}

export const slideLeft = {
  hidden: { opacity: 0, x: -60 },
  visible: { 
    opacity: 1, 
    x: 0,
    transition: { duration: 0.6, ease: 'easeOut' }
  }
}

export const slideRight = {
  hidden: { opacity: 0, x: 60 },
  visible: { 
    opacity: 1, 
    x: 0,
    transition: { duration: 0.6, ease: 'easeOut' }
  }
}

// Scale Animations
export const scaleIn = {
  hidden: { opacity: 0, scale: 0.8 },
  visible: { 
    opacity: 1, 
    scale: 1,
    transition: { duration: 0.5, ease: 'easeOut' }
  }
}

export const scaleOut = {
  hidden: { opacity: 1, scale: 1 },
  visible: { 
    opacity: 0, 
    scale: 0.8,
    transition: { duration: 0.3 }
  }
}

// Glassmorphism Card Hover
export const glassCardHover = {
  rest: { 
    scale: 1,
    y: 0,
    boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3)',
    borderColor: 'rgba(255, 255, 255, 0.15)'
  },
  hover: { 
    scale: 1.02,
    y: -4,
    boxShadow: '0 16px 64px rgba(0, 212, 255, 0.2)',
    borderColor: 'rgba(0, 212, 255, 0.4)',
    transition: { duration: 0.3, ease: 'easeOut' }
  }
}

// Button Animations
export const buttonPress = {
  whileHover: { scale: 1.02 },
  whileTap: { scale: 0.98 },
  transition: { duration: 0.1 }
}

// Floating Animation
export const floating = {
  animate: {
    y: [-10, 10, -10],
    transition: {
      duration: 3,
      repeat: Infinity,
      ease: 'easeInOut'
    }
  }
}

// Pulse Animation
export const pulse = {
  animate: {
    scale: [1, 1.05, 1],
    opacity: [0.8, 1, 0.8],
    transition: {
      duration: 2,
      repeat: Infinity,
      ease: 'easeInOut'
    }
  }
}

// Scan Progress Animation
export const scanProgress = {
  initial: { width: 0, opacity: 0 },
  animate: { 
    width: '100%', 
    opacity: 1,
    transition: { duration: 2, ease: 'easeInOut' }
  }
}

// Modal Animations
export const modalBackdrop = {
  hidden: { opacity: 0 },
  visible: { opacity: 1 },
  exit: { opacity: 0 }
}

export const modalContent = {
  hidden: { 
    opacity: 0, 
    scale: 0.8,
    y: 50
  },
  visible: { 
    opacity: 1, 
    scale: 1,
    y: 0,
    transition: { 
      duration: 0.3,
      ease: [0.25, 0.46, 0.45, 0.94]
    }
  },
  exit: { 
    opacity: 0, 
    scale: 0.8,
    y: 50,
    transition: { duration: 0.2 }
  }
}

// Notification Animations
export const notificationSlide = {
  initial: { x: 300, opacity: 0 },
  animate: { 
    x: 0, 
    opacity: 1,
    transition: { duration: 0.3, ease: 'easeOut' }
  },
  exit: { 
    x: 300, 
    opacity: 0,
    transition: { duration: 0.2 }
  }
}

// Loading Spinner
export const spinnerRotate = {
  animate: {
    rotate: 360,
    transition: {
      duration: 1,
      repeat: Infinity,
      ease: 'linear'
    }
  }
}

// Typewriter Effect
export const typewriter = {
  hidden: { width: 0 },
  visible: {
    width: 'auto',
    transition: {
      duration: 2,
      ease: 'easeInOut'
    }
  }
}

// Custom Easing Functions
export const easings = {
  smooth: [0.25, 0.46, 0.45, 0.94],
  bounce: [0.68, -0.55, 0.265, 1.55],
  elastic: [0.175, 0.885, 0.32, 1.275],
  back: [0.68, -0.55, 0.265, 1.55]
}

// Utility function to create staggered animations
export const createStagger = (children, delay = 0.1) => ({
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: delay,
      delayChildren: 0.2
    }
  }
})

// Utility function for scroll-triggered animations
export const scrollReveal = (delay = 0) => ({
  hidden: { 
    opacity: 0, 
    y: 50,
    scale: 0.95
  },
  visible: { 
    opacity: 1, 
    y: 0,
    scale: 1,
    transition: { 
      duration: 0.6,
      delay,
      ease: easings.smooth
    }
  }
})
