import React, { useRef } from 'react'
import { motion, useInView } from 'framer-motion'

interface ScrollSectionProps {
  id: string
  children: React.ReactNode
  className?: string
  fullHeight?: boolean
  background?: 'default' | 'gradient' | 'dark'
}

const ScrollSection: React.FC<ScrollSectionProps> = ({
  id,
  children,
  className = '',
  fullHeight = false,
  background = 'default'
}) => {
  const ref = useRef(null)
  const isInView = useInView(ref, { 
    once: false, 
    margin: "-20% 0px -20% 0px" 
  })

  const backgroundClasses = {
    default: 'bg-black',
    gradient: 'bg-gradient-to-b from-black via-gray-900/50 to-black',
    dark: 'bg-gray-950'
  }

  const sectionVariants = {
    hidden: { 
      opacity: 0,
      y: 50
    },
    visible: { 
      opacity: 1,
      y: 0,
      transition: {
        duration: 0.8,
        ease: [0.25, 0.46, 0.45, 0.94],
        staggerChildren: 0.1
      }
    }
  }

  const childVariants = {
    hidden: { 
      opacity: 0,
      y: 30
    },
    visible: { 
      opacity: 1,
      y: 0,
      transition: {
        duration: 0.6,
        ease: [0.25, 0.46, 0.45, 0.94]
      }
    }
  }

  return (
    <motion.section
      id={id}
      ref={ref}
      className={`
        relative w-full
        ${fullHeight ? 'min-h-screen' : 'min-h-[50vh]'}
        ${backgroundClasses[background]}
        ${className}
      `}
      initial="hidden"
      animate={isInView ? "visible" : "hidden"}
      variants={sectionVariants}
    >
      {/* Background Effects */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        {/* Subtle grid pattern */}
        <div 
          className="absolute inset-0 opacity-[0.02]"
          style={{
            backgroundImage: `
              linear-gradient(rgba(14, 165, 233, 0.1) 1px, transparent 1px),
              linear-gradient(90deg, rgba(14, 165, 233, 0.1) 1px, transparent 1px)
            `,
            backgroundSize: '50px 50px'
          }}
        />
        
        {/* Animated gradient orbs */}
        <motion.div
          className="absolute -top-40 -right-40 w-80 h-80 rounded-full opacity-10"
          style={{
            background: 'radial-gradient(circle, rgba(14, 165, 233, 0.3) 0%, transparent 70%)'
          }}
          animate={{
            scale: [1, 1.2, 1],
            opacity: [0.1, 0.15, 0.1]
          }}
          transition={{
            duration: 8,
            repeat: Infinity,
            ease: "easeInOut"
          }}
        />
        
        <motion.div
          className="absolute -bottom-40 -left-40 w-96 h-96 rounded-full opacity-5"
          style={{
            background: 'radial-gradient(circle, rgba(14, 165, 233, 0.2) 0%, transparent 70%)'
          }}
          animate={{
            scale: [1.2, 1, 1.2],
            opacity: [0.05, 0.1, 0.05]
          }}
          transition={{
            duration: 10,
            repeat: Infinity,
            ease: "easeInOut",
            delay: 2
          }}
        />
      </div>

      {/* Content */}
      <motion.div
        className="relative z-10"
        variants={childVariants}
      >
        {children}
      </motion.div>
    </motion.section>
  )
}

export default ScrollSection
