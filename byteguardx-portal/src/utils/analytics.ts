// Privacy-focused analytics for ByteGuardX
interface AnalyticsEvent {
  name: string;
  properties?: Record<string, any>;
  timestamp?: number;
}

interface UserSession {
  sessionId: string;
  startTime: number;
  lastActivity: number;
  pageViews: number;
  events: AnalyticsEvent[];
}

class ByteGuardXAnalytics {
  private session: UserSession | null = null;
  private enabled: boolean = false;
  private queue: AnalyticsEvent[] = [];

  constructor() {
    this.initSession();
  }

  // Initialize analytics session
  private initSession() {
    const sessionId = this.generateSessionId();
    this.session = {
      sessionId,
      startTime: Date.now(),
      lastActivity: Date.now(),
      pageViews: 0,
      events: []
    };
  }

  // Generate unique session ID
  private generateSessionId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  // Enable/disable analytics based on user consent
  setEnabled(enabled: boolean) {
    this.enabled = enabled;
    if (enabled && this.queue.length > 0) {
      // Process queued events
      this.queue.forEach(event => this.track(event.name, event.properties));
      this.queue = [];
    }
  }

  // Track page views
  trackPageView(path: string, title?: string) {
    if (!this.enabled || !this.session) return;

    this.session.pageViews++;
    this.session.lastActivity = Date.now();

    this.track('page_view', {
      path,
      title: title || document.title,
      referrer: document.referrer,
      userAgent: navigator.userAgent,
      timestamp: Date.now()
    });
  }

  // Track custom events
  track(eventName: string, properties?: Record<string, any>) {
    if (!this.enabled || !this.session) {
      // Queue events if analytics not enabled yet
      this.queue.push({ name: eventName, properties, timestamp: Date.now() });
      return;
    }

    const event: AnalyticsEvent = {
      name: eventName,
      properties: {
        ...properties,
        sessionId: this.session.sessionId,
        timestamp: Date.now()
      }
    };

    this.session.events.push(event);
    this.session.lastActivity = Date.now();

    // Send to analytics endpoint (privacy-focused)
    this.sendEvent(event);
  }

  // Track user interactions
  trackInteraction(element: string, action: string, value?: string) {
    this.track('user_interaction', {
      element,
      action,
      value,
      page: window.location.pathname
    });
  }

  // Track performance metrics
  trackPerformance() {
    if (!this.enabled) return;

    const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
    const paint = performance.getEntriesByType('paint');

    this.track('performance', {
      loadTime: navigation.loadEventEnd - navigation.loadEventStart,
      domContentLoaded: navigation.domContentLoadedEventEnd - navigation.domContentLoadedEventStart,
      firstPaint: paint.find(p => p.name === 'first-paint')?.startTime,
      firstContentfulPaint: paint.find(p => p.name === 'first-contentful-paint')?.startTime,
      connectionType: (navigator as any).connection?.effectiveType
    });
  }

  // Track errors
  trackError(error: Error, context?: string) {
    this.track('error', {
      message: error.message,
      stack: error.stack,
      context,
      page: window.location.pathname,
      userAgent: navigator.userAgent
    });
  }

  // Send event to analytics endpoint
  private async sendEvent(event: AnalyticsEvent) {
    try {
      // Only send anonymized data
      const anonymizedEvent = {
        name: event.name,
        properties: this.anonymizeProperties(event.properties || {}),
        timestamp: event.timestamp || Date.now()
      };

      await fetch('/api/analytics', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(anonymizedEvent)
      });
    } catch (error) {
      console.warn('Failed to send analytics event:', error);
    }
  }

  // Remove PII from analytics data
  private anonymizeProperties(properties: Record<string, any>): Record<string, any> {
    const anonymized = { ...properties };
    
    // Remove potential PII
    delete anonymized.email;
    delete anonymized.name;
    delete anonymized.phone;
    delete anonymized.address;
    
    // Hash IP addresses if present
    if (anonymized.ip) {
      anonymized.ip = this.hashString(anonymized.ip);
    }
    
    return anonymized;
  }

  // Simple hash function for anonymization
  private hashString(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString(36);
  }

  // Get session summary
  getSessionSummary() {
    if (!this.session) return null;

    return {
      sessionId: this.session.sessionId,
      duration: Date.now() - this.session.startTime,
      pageViews: this.session.pageViews,
      eventCount: this.session.events.length,
      lastActivity: this.session.lastActivity
    };
  }
}

// Create singleton instance
export const analytics = new ByteGuardXAnalytics();

// React hook for analytics
export const useAnalytics = () => {
  const trackEvent = (name: string, properties?: Record<string, any>) => {
    analytics.track(name, properties);
  };

  const trackPageView = (path?: string) => {
    analytics.trackPageView(path || window.location.pathname);
  };

  const trackInteraction = (element: string, action: string, value?: string) => {
    analytics.trackInteraction(element, action, value);
  };

  return {
    trackEvent,
    trackPageView,
    trackInteraction,
    setEnabled: analytics.setEnabled.bind(analytics),
    getSessionSummary: analytics.getSessionSummary.bind(analytics)
  };
};
