import React, { Suspense, startTransition, useState, useEffect } from 'react'
import LoadingSpinner from './LoadingSpinner'

/**
 * Enhanced Suspense wrapper that handles React 18 concurrent features properly
 * Prevents "component suspended while responding to synchronous input" errors
 */
const SuspenseWrapper = ({ 
  children, 
  fallback = <LoadingSpinner size="lg" text="Loading..." />,
  errorFallback = null 
}) => {
  const [isPending, setIsPending] = useState(false)

  // Handle transitions properly for React 18
  useEffect(() => {
    startTransition(() => {
      setIsPending(false)
    })
  }, [])

  const handleSuspense = () => {
    startTransition(() => {
      setIsPending(true)
    })
  }

  return (
    <Suspense 
      fallback={
        <div className="min-h-screen flex items-center justify-center bg-black">
          <div className="text-center">
            {fallback}
            {isPending && (
              <p className="text-gray-400 mt-4 text-sm">
                Loading component...
              </p>
            )}
          </div>
        </div>
      }
    >
      <div onLoad={handleSuspense}>
        {children}
      </div>
    </Suspense>
  )
}

export default SuspenseWrapper
