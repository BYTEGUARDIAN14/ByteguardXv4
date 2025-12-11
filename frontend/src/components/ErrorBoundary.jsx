import React, { Component } from 'react';
import { ErrorBoundary as ReactErrorBoundary } from 'react-error-boundary';

/**
 * Advanced Error Boundary with Recovery, Logging, and User Feedback
 */
class AdvancedErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: null,
      retryCount: 0,
      isRecovering: false
    };
  }

  static getDerivedStateFromError(error) {
    return {
      hasError: true,
      error,
      errorId: `error_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ errorInfo });
    
    // Log error to monitoring service
    this.logError(error, errorInfo);
    
    // Report to analytics
    this.reportToAnalytics(error, errorInfo);
  }

  logError = (error, errorInfo) => {
    const errorData = {
      id: this.state.errorId,
      message: error.message,
      stack: error.stack,
      componentStack: errorInfo.componentStack,
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent,
      url: window.location.href,
      userId: this.props.userId || 'anonymous',
      retryCount: this.state.retryCount
    };

    // Send to logging service
    if (this.props.onError) {
      this.props.onError(errorData);
    }

    // Log to console in development
    if (process.env.NODE_ENV === 'development') {
      console.group('🚨 Error Boundary Caught Error');
      console.error('Error:', error);
      console.error('Error Info:', errorInfo);
      console.error('Error Data:', errorData);
      console.groupEnd();
    }

    // Store in localStorage for offline reporting
    try {
      const storedErrors = JSON.parse(localStorage.getItem('byteguardx_errors') || '[]');
      storedErrors.push(errorData);
      
      // Keep only last 10 errors
      if (storedErrors.length > 10) {
        storedErrors.splice(0, storedErrors.length - 10);
      }
      
      localStorage.setItem('byteguardx_errors', JSON.stringify(storedErrors));
    } catch (e) {
      console.error('Failed to store error in localStorage:', e);
    }
  };

  reportToAnalytics = (error, errorInfo) => {
    // Report to analytics service (Google Analytics, Mixpanel, etc.)
    if (window.gtag) {
      window.gtag('event', 'exception', {
        description: error.message,
        fatal: false,
        custom_map: {
          error_id: this.state.errorId,
          component_stack: errorInfo.componentStack
        }
      });
    }
  };

  handleRetry = () => {
    this.setState(prevState => ({
      hasError: false,
      error: null,
      errorInfo: null,
      retryCount: prevState.retryCount + 1,
      isRecovering: true
    }));

    // Reset after a short delay to allow re-render
    setTimeout(() => {
      this.setState({ isRecovering: false });
    }, 100);
  };

  handleReload = () => {
    window.location.reload();
  };

  handleReportBug = () => {
    const errorData = {
      id: this.state.errorId,
      message: this.state.error?.message,
      stack: this.state.error?.stack,
      componentStack: this.state.errorInfo?.componentStack,
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent,
      url: window.location.href
    };

    // Open bug report with pre-filled data
    const bugReportUrl = `mailto:support@byteguardx.com?subject=Bug Report - ${this.state.errorId}&body=${encodeURIComponent(
      `Error ID: ${errorData.id}\n\nError Message: ${errorData.message}\n\nTimestamp: ${errorData.timestamp}\n\nURL: ${errorData.url}\n\nUser Agent: ${errorData.userAgent}\n\nPlease describe what you were doing when this error occurred:\n\n`
    )}`;
    
    window.open(bugReportUrl);
  };

  render() {
    if (this.state.hasError) {
      const { error, errorInfo, errorId, retryCount } = this.state;
      const { fallback: CustomFallback, level = 'component' } = this.props;

      // Use custom fallback if provided
      if (CustomFallback) {
        return (
          <CustomFallback
            error={error}
            errorInfo={errorInfo}
            errorId={errorId}
            retryCount={retryCount}
            onRetry={this.handleRetry}
            onReload={this.handleReload}
            onReportBug={this.handleReportBug}
          />
        );
      }

      // Default error UI based on level
      if (level === 'app') {
        return <AppLevelError {...this.state} onRetry={this.handleRetry} onReload={this.handleReload} onReportBug={this.handleReportBug} />;
      }

      return <ComponentLevelError {...this.state} onRetry={this.handleRetry} onReload={this.handleReload} onReportBug={this.handleReportBug} />;
    }

    return this.props.children;
  }
}

// App-level error component
const AppLevelError = ({ error, errorId, retryCount, onRetry, onReload, onReportBug }) => (
  <div className="min-h-screen bg-base-100 flex items-center justify-center p-4">
    <div className="max-w-md w-full">
      <div className="text-center mb-8">
        <div className="w-20 h-20 mx-auto mb-4 bg-error rounded-full flex items-center justify-center">
          <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
          </svg>
        </div>
        <h1 className="text-2xl font-bold text-base-content mb-2">Something went wrong</h1>
        <p className="text-base-content/70 mb-6">
          We're sorry, but something unexpected happened. Our team has been notified.
        </p>
      </div>

      <div className="bg-base-200 rounded-lg p-4 mb-6">
        <div className="text-sm">
          <div className="font-medium mb-1">Error ID: {errorId}</div>
          <div className="text-base-content/70 font-mono text-xs break-all">
            {error?.message}
          </div>
        </div>
      </div>

      <div className="space-y-3">
        <button
          onClick={onRetry}
          className="btn btn-primary w-full"
          disabled={retryCount >= 3}
        >
          {retryCount >= 3 ? 'Max retries reached' : `Try Again ${retryCount > 0 ? `(${retryCount}/3)` : ''}`}
        </button>
        
        <button
          onClick={onReload}
          className="btn btn-outline w-full"
        >
          Reload Page
        </button>
        
        <button
          onClick={onReportBug}
          className="btn btn-ghost w-full"
        >
          Report Bug
        </button>
      </div>

      <div className="text-center mt-6">
        <a href="/" className="link link-primary text-sm">
          Return to Dashboard
        </a>
      </div>
    </div>
  </div>
);

// Component-level error component
const ComponentLevelError = ({ error, errorId, retryCount, onRetry, onReload, onReportBug }) => (
  <div className="bg-error/10 border border-error/20 rounded-lg p-6 m-4">
    <div className="flex items-start space-x-3">
      <div className="flex-shrink-0">
        <svg className="w-6 h-6 text-error" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      </div>
      
      <div className="flex-1">
        <h3 className="text-lg font-medium text-error mb-2">Component Error</h3>
        <p className="text-sm text-base-content/70 mb-4">
          This component encountered an error and couldn't render properly.
        </p>
        
        <details className="mb-4">
          <summary className="cursor-pointer text-sm font-medium text-base-content/80 hover:text-base-content">
            Error Details
          </summary>
          <div className="mt-2 p-3 bg-base-200 rounded text-xs font-mono break-all">
            <div className="mb-2"><strong>ID:</strong> {errorId}</div>
            <div><strong>Message:</strong> {error?.message}</div>
          </div>
        </details>
        
        <div className="flex flex-wrap gap-2">
          <button
            onClick={onRetry}
            className="btn btn-sm btn-primary"
            disabled={retryCount >= 3}
          >
            {retryCount >= 3 ? 'Max retries' : `Retry ${retryCount > 0 ? `(${retryCount}/3)` : ''}`}
          </button>
          
          <button
            onClick={onReportBug}
            className="btn btn-sm btn-ghost"
          >
            Report
          </button>
        </div>
      </div>
    </div>
  </div>
);

// Hook for using error boundary programmatically
export const useErrorHandler = () => {
  const [error, setError] = React.useState(null);

  const resetError = React.useCallback(() => {
    setError(null);
  }, []);

  const captureError = React.useCallback((error, errorInfo = {}) => {
    setError({ error, errorInfo });
  }, []);

  React.useEffect(() => {
    if (error) {
      throw error.error;
    }
  }, [error]);

  return { captureError, resetError };
};

// Higher-order component for wrapping components with error boundary
export const withErrorBoundary = (Component, errorBoundaryProps = {}) => {
  const WrappedComponent = React.forwardRef((props, ref) => (
    <AdvancedErrorBoundary {...errorBoundaryProps}>
      <Component {...props} ref={ref} />
    </AdvancedErrorBoundary>
  ));

  WrappedComponent.displayName = `withErrorBoundary(${Component.displayName || Component.name})`;
  
  return WrappedComponent;
};

// React Error Boundary wrapper for functional components
export const ErrorBoundary = ({ children, onError, fallback, level = 'component' }) => (
  <ReactErrorBoundary
    FallbackComponent={({ error, resetErrorBoundary }) => {
      const errorId = `error_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      
      if (fallback) {
        return fallback({ error, errorId, onRetry: resetErrorBoundary });
      }
      
      return level === 'app' ? (
        <AppLevelError
          error={error}
          errorId={errorId}
          retryCount={0}
          onRetry={resetErrorBoundary}
          onReload={() => window.location.reload()}
          onReportBug={() => {}}
        />
      ) : (
        <ComponentLevelError
          error={error}
          errorId={errorId}
          retryCount={0}
          onRetry={resetErrorBoundary}
          onReload={() => window.location.reload()}
          onReportBug={() => {}}
        />
      );
    }}
    onError={onError}
    onReset={() => {
      // Clear any error state
      window.location.hash = '';
    }}
  >
    {children}
  </ReactErrorBoundary>
);

export default AdvancedErrorBoundary;
