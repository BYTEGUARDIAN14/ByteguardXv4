/**
 * Advanced Animation Optimizer for ByteGuardX
 * Provides smooth 60fps animations with performance monitoring and adaptive quality
 */

class AnimationOptimizer {
  constructor() {
    this.performanceMetrics = {
      frameRate: 60,
      frameDrops: 0,
      averageFrameTime: 16.67, // 60fps = 16.67ms per frame
      lastFrameTime: 0,
      animationQuality: 'high' // high, medium, low
    };
    
    this.activeAnimations = new Map();
    this.animationId = 0;
    this.isMonitoring = false;
    this.performanceObserver = null;
    
    this.initializePerformanceMonitoring();
  }

  initializePerformanceMonitoring() {
    // Use Performance Observer API for accurate frame timing
    if ('PerformanceObserver' in window) {
      this.performanceObserver = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        entries.forEach(entry => {
          if (entry.entryType === 'measure' && entry.name.startsWith('animation-frame')) {
            this.updateFrameMetrics(entry.duration);
          }
        });
      });
      
      this.performanceObserver.observe({ entryTypes: ['measure'] });
    }

    // Fallback frame rate monitoring
    this.startFrameRateMonitoring();
  }

  startFrameRateMonitoring() {
    let frameCount = 0;
    let lastTime = performance.now();
    
    const countFrames = (currentTime) => {
      frameCount++;
      
      if (currentTime - lastTime >= 1000) {
        this.performanceMetrics.frameRate = frameCount;
        
        // Adjust animation quality based on performance
        this.adjustAnimationQuality();
        
        frameCount = 0;
        lastTime = currentTime;
      }
      
      if (this.isMonitoring) {
        requestAnimationFrame(countFrames);
      }
    };
    
    this.isMonitoring = true;
    requestAnimationFrame(countFrames);
  }

  updateFrameMetrics(frameTime) {
    this.performanceMetrics.lastFrameTime = frameTime;
    
    // Calculate running average
    this.performanceMetrics.averageFrameTime = 
      (this.performanceMetrics.averageFrameTime * 0.9) + (frameTime * 0.1);
    
    // Count frame drops (frames taking longer than 16.67ms)
    if (frameTime > 16.67) {
      this.performanceMetrics.frameDrops++;
    }
  }

  adjustAnimationQuality() {
    const { frameRate, averageFrameTime } = this.performanceMetrics;
    
    if (frameRate < 30 || averageFrameTime > 33) {
      this.performanceMetrics.animationQuality = 'low';
    } else if (frameRate < 50 || averageFrameTime > 20) {
      this.performanceMetrics.animationQuality = 'medium';
    } else {
      this.performanceMetrics.animationQuality = 'high';
    }
    
    // Notify active animations of quality change
    this.activeAnimations.forEach(animation => {
      if (animation.onQualityChange) {
        animation.onQualityChange(this.performanceMetrics.animationQuality);
      }
    });
  }

  createOptimizedAnimation(config) {
    const animationId = ++this.animationId;
    
    const animation = {
      id: animationId,
      element: config.element,
      duration: config.duration || 300,
      easing: config.easing || 'ease-out',
      properties: config.properties || {},
      onComplete: config.onComplete,
      onQualityChange: config.onQualityChange,
      startTime: null,
      isRunning: false,
      quality: this.performanceMetrics.animationQuality
    };
    
    this.activeAnimations.set(animationId, animation);
    
    return {
      start: () => this.startAnimation(animationId),
      stop: () => this.stopAnimation(animationId),
      pause: () => this.pauseAnimation(animationId),
      resume: () => this.resumeAnimation(animationId)
    };
  }

  startAnimation(animationId) {
    const animation = this.activeAnimations.get(animationId);
    if (!animation || animation.isRunning) return;
    
    animation.isRunning = true;
    animation.startTime = performance.now();
    
    // Use Web Animations API for better performance
    if ('animate' in animation.element) {
      this.startWebAnimation(animation);
    } else {
      this.startRAFAnimation(animation);
    }
  }

  startWebAnimation(animation) {
    const keyframes = this.generateKeyframes(animation.properties, animation.quality);
    
    const webAnimation = animation.element.animate(keyframes, {
      duration: animation.duration,
      easing: animation.easing,
      fill: 'forwards'
    });
    
    animation.webAnimation = webAnimation;
    
    webAnimation.addEventListener('finish', () => {
      this.completeAnimation(animation.id);
    });
  }

  startRAFAnimation(animation) {
    const animate = (currentTime) => {
      if (!animation.isRunning) return;
      
      performance.mark(`animation-frame-${animation.id}-start`);
      
      const elapsed = currentTime - animation.startTime;
      const progress = Math.min(elapsed / animation.duration, 1);
      
      // Apply easing
      const easedProgress = this.applyEasing(progress, animation.easing);
      
      // Update properties
      this.updateAnimationProperties(animation, easedProgress);
      
      performance.mark(`animation-frame-${animation.id}-end`);
      performance.measure(
        `animation-frame-${animation.id}`,
        `animation-frame-${animation.id}-start`,
        `animation-frame-${animation.id}-end`
      );
      
      if (progress < 1) {
        requestAnimationFrame(animate);
      } else {
        this.completeAnimation(animation.id);
      }
    };
    
    requestAnimationFrame(animate);
  }

  generateKeyframes(properties, quality) {
    const keyframes = [{}];
    
    // Adjust keyframe complexity based on quality
    const steps = quality === 'high' ? 60 : quality === 'medium' ? 30 : 15;
    
    for (let i = 1; i <= steps; i++) {
      const progress = i / steps;
      const frame = {};
      
      Object.entries(properties).forEach(([prop, value]) => {
        if (typeof value === 'object' && value.from !== undefined && value.to !== undefined) {
          frame[prop] = this.interpolateValue(value.from, value.to, progress);
        } else {
          frame[prop] = value;
        }
      });
      
      keyframes.push(frame);
    }
    
    return keyframes;
  }

  updateAnimationProperties(animation, progress) {
    Object.entries(animation.properties).forEach(([prop, value]) => {
      if (typeof value === 'object' && value.from !== undefined && value.to !== undefined) {
        const interpolated = this.interpolateValue(value.from, value.to, progress);
        animation.element.style[prop] = interpolated;
      } else {
        animation.element.style[prop] = value;
      }
    });
  }

  interpolateValue(from, to, progress) {
    if (typeof from === 'number' && typeof to === 'number') {
      return from + (to - from) * progress;
    }
    
    if (typeof from === 'string' && typeof to === 'string') {
      // Handle color interpolation
      if (from.startsWith('#') && to.startsWith('#')) {
        return this.interpolateColor(from, to, progress);
      }
      
      // Handle unit values (px, %, em, etc.)
      const fromMatch = from.match(/^([-\d.]+)(.*)$/);
      const toMatch = to.match(/^([-\d.]+)(.*)$/);
      
      if (fromMatch && toMatch && fromMatch[2] === toMatch[2]) {
        const fromValue = parseFloat(fromMatch[1]);
        const toValue = parseFloat(toMatch[1]);
        const unit = fromMatch[2];
        
        return (fromValue + (toValue - fromValue) * progress) + unit;
      }
    }
    
    return progress < 0.5 ? from : to;
  }

  interpolateColor(from, to, progress) {
    const fromRgb = this.hexToRgb(from);
    const toRgb = this.hexToRgb(to);
    
    const r = Math.round(fromRgb.r + (toRgb.r - fromRgb.r) * progress);
    const g = Math.round(fromRgb.g + (toRgb.g - fromRgb.g) * progress);
    const b = Math.round(fromRgb.b + (toRgb.b - fromRgb.b) * progress);
    
    return `rgb(${r}, ${g}, ${b})`;
  }

  hexToRgb(hex) {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ? {
      r: parseInt(result[1], 16),
      g: parseInt(result[2], 16),
      b: parseInt(result[3], 16)
    } : null;
  }

  applyEasing(progress, easing) {
    switch (easing) {
      case 'ease-in':
        return progress * progress;
      case 'ease-out':
        return 1 - Math.pow(1 - progress, 2);
      case 'ease-in-out':
        return progress < 0.5 
          ? 2 * progress * progress 
          : 1 - Math.pow(-2 * progress + 2, 2) / 2;
      case 'bounce':
        return this.bounceEasing(progress);
      case 'elastic':
        return this.elasticEasing(progress);
      default:
        return progress;
    }
  }

  bounceEasing(t) {
    if (t < 1 / 2.75) {
      return 7.5625 * t * t;
    } else if (t < 2 / 2.75) {
      return 7.5625 * (t -= 1.5 / 2.75) * t + 0.75;
    } else if (t < 2.5 / 2.75) {
      return 7.5625 * (t -= 2.25 / 2.75) * t + 0.9375;
    } else {
      return 7.5625 * (t -= 2.625 / 2.75) * t + 0.984375;
    }
  }

  elasticEasing(t) {
    return t === 0 ? 0 : t === 1 ? 1 : 
      -Math.pow(2, 10 * (t - 1)) * Math.sin((t - 1.1) * 5 * Math.PI);
  }

  completeAnimation(animationId) {
    const animation = this.activeAnimations.get(animationId);
    if (!animation) return;
    
    animation.isRunning = false;
    
    if (animation.onComplete) {
      animation.onComplete();
    }
    
    this.activeAnimations.delete(animationId);
  }

  stopAnimation(animationId) {
    const animation = this.activeAnimations.get(animationId);
    if (!animation) return;
    
    animation.isRunning = false;
    
    if (animation.webAnimation) {
      animation.webAnimation.cancel();
    }
    
    this.activeAnimations.delete(animationId);
  }

  pauseAnimation(animationId) {
    const animation = this.activeAnimations.get(animationId);
    if (!animation) return;
    
    animation.isRunning = false;
    
    if (animation.webAnimation) {
      animation.webAnimation.pause();
    }
  }

  resumeAnimation(animationId) {
    const animation = this.activeAnimations.get(animationId);
    if (!animation) return;
    
    animation.isRunning = true;
    
    if (animation.webAnimation) {
      animation.webAnimation.play();
    }
  }

  getPerformanceMetrics() {
    return { ...this.performanceMetrics };
  }

  destroy() {
    this.isMonitoring = false;
    
    if (this.performanceObserver) {
      this.performanceObserver.disconnect();
    }
    
    this.activeAnimations.forEach((_, id) => {
      this.stopAnimation(id);
    });
    
    this.activeAnimations.clear();
  }
}

// Global animation optimizer instance
export const animationOptimizer = new AnimationOptimizer();

// React hook for optimized animations
export const useOptimizedAnimation = () => {
  const createAnimation = (element, config) => {
    return animationOptimizer.createOptimizedAnimation({
      element,
      ...config
    });
  };

  const getPerformanceMetrics = () => {
    return animationOptimizer.getPerformanceMetrics();
  };

  return {
    createAnimation,
    getPerformanceMetrics
  };
};

export default AnimationOptimizer;
