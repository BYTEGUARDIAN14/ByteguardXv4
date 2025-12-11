import { useEffect } from 'react';

const ForceBlackTheme = () => {
  useEffect(() => {
    // Create and inject aggressive black theme styles
    const style = document.createElement('style');
    style.id = 'force-black-theme';
    style.innerHTML = `
      /* FORCE PURE BLACK THEME - JAVASCRIPT INJECTION */
      *, *::before, *::after {
        background-color: #000000 !important;
        background-image: none !important;
        background: #000000 !important;
        color: #ffffff !important;
      }
      
      /* Hover effects - only cyan */
      *:hover {
        color: #00bcd4 !important;
        border-color: #00bcd4 !important;
        background-color: #000000 !important;
      }
      
      /* SVG exceptions */
      svg, svg * {
        background-color: transparent !important;
        color: inherit !important;
        fill: currentColor !important;
      }
      
      /* Body and root */
      html, body, #root {
        background-color: #000000 !important;
        background: #000000 !important;
        color: #ffffff !important;
      }
      
      /* All containers */
      div, section, main, article, aside, header, footer, nav {
        background-color: #000000 !important;
        background: #000000 !important;
      }
      
      /* Remove any remaining gradients */
      [class*="gradient"], [style*="gradient"] {
        background: #000000 !important;
        background-image: none !important;
      }
    `;
    
    // Add to head
    document.head.appendChild(style);
    
    // Also force styles directly on elements
    const forceBlackOnElement = (element) => {
      if (element && element.style) {
        element.style.backgroundColor = '#000000';
        element.style.background = '#000000';
        element.style.backgroundImage = 'none';
        element.style.color = '#ffffff';
      }
    };
    
    // Force on body and root
    forceBlackOnElement(document.body);
    forceBlackOnElement(document.documentElement);
    forceBlackOnElement(document.getElementById('root'));
    
    // Observer to force black on new elements
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === 1) { // Element node
            forceBlackOnElement(node);
            // Force on all children too
            const children = node.querySelectorAll('*');
            children.forEach(forceBlackOnElement);
          }
        });
      });
    });
    
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
    
    // Cleanup
    return () => {
      const existingStyle = document.getElementById('force-black-theme');
      if (existingStyle) {
        existingStyle.remove();
      }
      observer.disconnect();
    };
  }, []);

  return null; // This component doesn't render anything
};

export default ForceBlackTheme;
