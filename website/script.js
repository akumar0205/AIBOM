/**
 * AIBOM Website Scripts
 * =====================
 * Minimal, focused JavaScript for:
 * - Copy to clipboard functionality
 * - Smooth scroll navigation
 * - Toast notifications
 */

(function() {
  'use strict';

  // ==========================================================================
  // Toast Notification System
  // ==========================================================================
  
  const toast = document.getElementById('toast');
  let toastTimeout = null;

  /**
   * Show a toast notification
   * @param {string} message - The message to display
   * @param {number} duration - How long to show the toast (ms)
   */
  function showToast(message, duration = 2000) {
    if (!toast) return;

    // Clear existing timeout
    if (toastTimeout) {
      clearTimeout(toastTimeout);
    }

    // Update message
    const messageEl = toast.querySelector('.toast-message');
    if (messageEl) {
      messageEl.textContent = message;
    }

    // Show toast
    toast.classList.add('show');

    // Hide after duration
    toastTimeout = setTimeout(() => {
      toast.classList.remove('show');
    }, duration);
  }

  // ==========================================================================
  // Copy to Clipboard
  // ==========================================================================

  /**
   * Copy text to clipboard
   * @param {string} text - The text to copy
   * @returns {Promise<boolean>} - Whether the copy succeeded
   */
  async function copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (err) {
      // Fallback for older browsers
      try {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.left = '-9999px';
        textarea.style.top = '0';
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        
        const success = document.execCommand('copy');
        document.body.removeChild(textarea);
        return success;
      } catch (fallbackErr) {
        console.error('Failed to copy:', fallbackErr);
        return false;
      }
    }
  }

  /**
   * Get text content from a target element
   * @param {string} targetId - The ID of the target element
   * @returns {string|null} - The text content or null
   */
  function getTargetText(targetId) {
    const target = document.getElementById(targetId);
    if (!target) return null;
    return target.textContent.trim();
  }

  /**
   * Initialize copy buttons
   */
  function initCopyButtons() {
    const copyButtons = document.querySelectorAll('[data-copy-target]');

    copyButtons.forEach(button => {
      button.addEventListener('click', async function(e) {
        e.preventDefault();
        
        const targetId = this.getAttribute('data-copy-target');
        const text = getTargetText(targetId);

        if (!text) {
          console.error('Copy target not found:', targetId);
          return;
        }

        const success = await copyToClipboard(text);
        
        if (success) {
          showToast('Copied to clipboard');
          
          // Visual feedback on button
          const originalContent = this.innerHTML;
          this.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
              <polyline points="20 6 9 17 4 12"/>
            </svg>
          `;
          
          setTimeout(() => {
            this.innerHTML = originalContent;
          }, 1500);
        } else {
          showToast('Failed to copy');
        }
      });
    });
  }

  // ==========================================================================
  // Smooth Scroll Navigation
  // ==========================================================================

  /**
   * Smooth scroll to anchor links
   */
  function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
      anchor.addEventListener('click', function(e) {
        const href = this.getAttribute('href');
        
        // Skip if it's just "#"
        if (href === '#') return;

        const target = document.querySelector(href);
        if (!target) return;

        e.preventDefault();

        // Get the target position
        const navHeight = document.querySelector('.nav')?.offsetHeight || 64;
        const targetPosition = target.getBoundingClientRect().top + window.pageYOffset - navHeight - 20;

        // Smooth scroll
        window.scrollTo({
          top: targetPosition,
          behavior: 'smooth'
        });

        // Update URL hash without jumping
        history.pushState(null, null, href);
      });
    });
  }

  // ==========================================================================
  // Active Nav Link
  // ==========================================================================

  /**
   * Update active nav link based on scroll position
   */
  function initActiveNavLink() {
    const sections = document.querySelectorAll('section[id]');
    const navLinks = document.querySelectorAll('.nav-link[href^="#"]');

    if (!sections.length || !navLinks.length) return;

    function updateActiveLink() {
      const scrollPos = window.scrollY + 100;
      let activeSection = null;

      sections.forEach(section => {
        const sectionTop = section.offsetTop;
        const sectionHeight = section.offsetHeight;

        if (scrollPos >= sectionTop && scrollPos < sectionTop + sectionHeight) {
          activeSection = section.getAttribute('id');
        }
      });

      navLinks.forEach(link => {
        link.classList.remove('active');
        const href = link.getAttribute('href');
        if (href === `#${activeSection}`) {
          link.classList.add('active');
        }
      });
    }

    // Throttled scroll listener
    let ticking = false;
    window.addEventListener('scroll', () => {
      if (!ticking) {
        window.requestAnimationFrame(() => {
          updateActiveLink();
          ticking = false;
        });
        ticking = true;
      }
    }, { passive: true });

    // Initial check
    updateActiveLink();
  }

  // ==========================================================================
  // Intersection Observer for Animations
  // ==========================================================================

  /**
   * Initialize scroll-triggered animations
   */
  function initScrollAnimations() {
    // Check for reduced motion preference
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      return;
    }

    const observerOptions = {
      root: null,
      rootMargin: '0px',
      threshold: 0.1
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('in-view');
          observer.unobserve(entry.target);
        }
      });
    }, observerOptions);

    // Observe elements that should animate
    document.querySelectorAll('.feature-card, .why-card, .step').forEach(el => {
      el.style.opacity = '0';
      el.style.transform = 'translateY(20px)';
      el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
      observer.observe(el);
    });

    // Add CSS for animated elements
    const style = document.createElement('style');
    style.textContent = `
      .in-view {
        opacity: 1 !important;
        transform: translateY(0) !important;
      }
    `;
    document.head.appendChild(style);
  }

  // ==========================================================================
  // Keyboard Navigation
  // ==========================================================================

  /**
   * Add keyboard support for interactive elements
   */
  function initKeyboardNavigation() {
    // Make copy buttons focusable and keyboard accessible
    document.querySelectorAll('[data-copy-target]').forEach(button => {
      if (!button.hasAttribute('tabindex')) {
        button.setAttribute('tabindex', '0');
      }

      button.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          button.click();
        }
      });
    });
  }

  // ==========================================================================
  // Initialize Everything
  // ==========================================================================

  function init() {
    initCopyButtons();
    initSmoothScroll();
    initActiveNavLink();
    initScrollAnimations();
    initKeyboardNavigation();

    // Console greeting
    console.log('%c AIBOM ', 'background: #4F8CFF; color: #0B0F17; font-weight: bold; padding: 4px 8px; border-radius: 4px;', 'AI Bill of Materials Generator');
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
