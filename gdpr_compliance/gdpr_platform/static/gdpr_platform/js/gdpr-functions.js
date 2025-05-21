// GDPR Platform JavaScript Functions

// Cache DOM elements for better performance
const domCache = {};

/**
 * Get DOM element with caching for better performance
 * @param {string} selector - CSS selector
 * @returns {HTMLElement} - DOM element
 */
function getElement(selector) {
    if (!domCache[selector]) {
        domCache[selector] = document.querySelector(selector);
    }
    return domCache[selector];
}

/**
 * Get all DOM elements matching selector with caching
 * @param {string} selector - CSS selector
 * @returns {NodeList} - DOM elements
 */
function getElements(selector) {
    if (!domCache[selector]) {
        domCache[selector] = document.querySelectorAll(selector);
    }
    return domCache[selector];
}

/**
 * Initialize the application
 */
function initApp() {
    setupEventListeners();
    setupResponsiveChecks();
    setupDarkMode();
    setupAccessibility();
    initializeTooltips();
    setupFormValidation();
    setupDataTables();
}

/**
 * Set up event listeners
 */
function setupEventListeners() {
    // Toggle sidenav on mobile
    const sidenavToggle = getElement('.sidenav-toggler');
    if (sidenavToggle) {
        sidenavToggle.addEventListener('click', toggleSidenav);
    }

    // Close sidenav on mobile
    const closeSidenav = getElement('#closeSidenav');
    if (closeSidenav) {
        closeSidenav.addEventListener('click', closeSidenavOnMobile);
    }

    // Session timeout warning
    setupSessionTimeout();

    // Consent form handling
    setupConsentForms();

    // Data request handling
    setupDataRequestForms();
}

/**
 * Toggle sidenav on mobile
 */
function toggleSidenav() {
    document.body.classList.toggle('g-sidenav-pinned');
    document.body.classList.toggle('g-sidenav-hidden');
    const backdrop = getElement('.sidenav-backdrop');
    if (backdrop) {
        backdrop.classList.toggle('d-none');
    }
}

/**
 * Close sidenav on mobile
 */
function closeSidenavOnMobile() {
    document.body.classList.remove('g-sidenav-pinned');
    document.body.classList.add('g-sidenav-hidden');
    const backdrop = getElement('.sidenav-backdrop');
    if (backdrop) {
        backdrop.classList.add('d-none');
    }
}

/**
 * Set up responsive design checks
 */
function setupResponsiveChecks() {
    const checkResponsive = () => {
        const isMobile = window.innerWidth < 992;
        if (isMobile) {
            document.body.classList.add('g-sidenav-hidden');
            document.body.classList.remove('g-sidenav-pinned');
        } else {
            document.body.classList.remove('g-sidenav-hidden');
            document.body.classList.add('g-sidenav-pinned');
        }
    };

    // Run on page load
    checkResponsive();

    // Run on window resize with debounce
    let resizeTimer;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(checkResponsive, 250);
    });
}

/**
 * Set up dark mode toggle
 */
function setupDarkMode() {
    const darkModeToggle = getElement('#darkModeToggle');
    if (darkModeToggle) {
        // Check for saved preference
        const darkModeEnabled = localStorage.getItem('darkMode') === 'true';
        if (darkModeEnabled) {
            document.body.classList.add('dark-mode');
            darkModeToggle.checked = true;
        }

        // Toggle dark mode
        darkModeToggle.addEventListener('change', () => {
            document.body.classList.toggle('dark-mode');
            localStorage.setItem('darkMode', darkModeToggle.checked);
        });
    }

    // Check system preference if no saved preference
    if (!localStorage.getItem('darkMode')) {
        const prefersDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
        if (prefersDarkMode) {
            document.body.classList.add('dark-mode');
            if (darkModeToggle) {
                darkModeToggle.checked = true;
            }
        }
    }
}

/**
 * Set up accessibility features
 */
function setupAccessibility() {
    // Add focus styles
    const focusableElements = getElements('a, button, input, select, textarea, [tabindex]:not([tabindex="-1"])');
    focusableElements.forEach(element => {
        element.addEventListener('focus', () => {
            element.classList.add('focus-visible');
        });
        element.addEventListener('blur', () => {
            element.classList.remove('focus-visible');
        });
    });
}

/**
 * Initialize Bootstrap tooltips
 */
function initializeTooltips() {
    // Check if Bootstrap's tooltip is available
    if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
        const tooltips = getElements('[data-bs-toggle="tooltip"]');
        tooltips.forEach(tooltip => {
            new bootstrap.Tooltip(tooltip);
        });
    }
}

/**
 * Set up form validation
 */
function setupFormValidation() {
    const forms = getElements('.needs-validation');
    forms.forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });
}

/**
 * Set up DataTables if available
 */
function setupDataTables() {
    if (typeof $.fn.DataTable !== 'undefined') {
        $('.datatable').each(function() {
            $(this).DataTable({
                responsive: true,
                language: {
                    search: "",
                    searchPlaceholder: "Search...",
                    lengthMenu: "_MENU_ records per page",
                },
                dom: '<"top"lf>rt<"bottom"ip><"clear">',
                pageLength: 10
            });
        });
    }
}

/**
 * Set up session timeout warning
 */
function setupSessionTimeout() {
    // Session timeout warning 5 minutes before expiry
    const sessionTimeout = 3600; // 1 hour in seconds
    const warningTime = 300; // 5 minutes in seconds
    
    let sessionTimer;
    
    const resetSessionTimer = () => {
        clearTimeout(sessionTimer);
        sessionTimer = setTimeout(showSessionWarning, (sessionTimeout - warningTime) * 1000);
    };
    
    const showSessionWarning = () => {
        // Create warning modal if it doesn't exist
        let warningModal = getElement('#sessionWarningModal');
        if (!warningModal) {
            warningModal = document.createElement('div');
            warningModal.id = 'sessionWarningModal';
            warningModal.className = 'modal fade';
            warningModal.setAttribute('tabindex', '-1');
            warningModal.innerHTML = `
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Session Timeout Warning</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <p>Your session will expire in 5 minutes. Would you like to continue?</p>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Logout</button>
                            <button type="button" class="btn btn-primary" id="extendSessionBtn">Continue Session</button>
                        </div>
                    </div>
                </div>
            `;
            document.body.appendChild(warningModal);
            
            // Add event listener to extend session button
            const extendSessionBtn = getElement('#extendSessionBtn');
            extendSessionBtn.addEventListener('click', extendSession);
        }
        
        // Show warning modal
        const modal = new bootstrap.Modal(warningModal);
        modal.show();
        
        // Set timeout to logout after warning time
        setTimeout(() => {
            window.location.href = '/gdpr/logout/';
        }, warningTime * 1000);
    };
    
    const extendSession = () => {
        // Hide modal
        const warningModal = getElement('#sessionWarningModal');
        const modal = bootstrap.Modal.getInstance(warningModal);
        if (modal) {
            modal.hide();
        }
        
        // Make AJAX request to extend session
        fetch('/gdpr/extend-session/', {
            method: 'POST',
            headers: {
                'X-CSRFToken': getCsrfToken(),
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                resetSessionTimer();
            }
        })
        .catch(error => {
            console.error('Error extending session:', error);
        });
    };
    
    // Reset timer on user activity
    ['click', 'mousemove', 'keypress', 'scroll', 'touchstart'].forEach(event => {
        document.addEventListener(event, resetSessionTimer, { passive: true });
    });
    
    // Start timer on page load
    resetSessionTimer();
}

/**
 * Set up consent forms
 */
function setupConsentForms() {
    const consentForms = getElements('.consent-form');
    consentForms.forEach(form => {
        form.addEventListener('submit', event => {
            const submitButton = form.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Saving...';
            }
        });
    });
}

/**
 * Set up data request forms with loading states
 */
function setupDataRequestForms() {
    const dataForms = getElements('.data-request-form');
    dataForms.forEach(form => {
        form.addEventListener('submit', event => {
            addLoadingOverlay(form);
        });
    });
}

/**
 * Add loading overlay to an element
 * @param {HTMLElement} element - Element to add loading overlay to
 */
function addLoadingOverlay(element) {
    const overlay = document.createElement('div');
    overlay.className = 'loading-overlay';
    overlay.innerHTML = '<div class="loading-spinner"></div>';
    element.style.position = 'relative';
    element.appendChild(overlay);
}

/**
 * Remove loading overlay from an element
 * @param {HTMLElement} element - Element to remove loading overlay from
 */
function removeLoadingOverlay(element) {
    const overlay = element.querySelector('.loading-overlay');
    if (overlay) {
        overlay.remove();
    }
}

/**
 * Get CSRF token from cookies
 * @returns {string} - CSRF token
 */
function getCsrfToken() {
    let csrfToken = '';
    const cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i].trim();
        if (cookie.startsWith('csrftoken=')) {
            csrfToken = cookie.substring('csrftoken='.length);
            break;
        }
    }
    return csrfToken;
}

/**
 * Debounce function to limit function calls
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @returns {Function} - Debounced function
 */
function debounce(func, wait) {
    let timeout;
    return function(...args) {
        const context = this;
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(context, args), wait);
    };
}

/**
 * Format date in locale format
 * @param {string} dateString - Date string
 * @returns {string} - Formatted date
 */
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString();
}

/**
 * Format datetime in locale format
 * @param {string} dateString - Date string
 * @returns {string} - Formatted datetime
 */
function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', initApp);