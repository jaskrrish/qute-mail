// Email Client JavaScript

class EmailClient {
    constructor() {
        this.init();
    }

    init() {
        // Initialize event listeners
        this.setupFormHandlers();
        this.setupKeyboardShortcuts();
        this.startAutoRefresh();
    }

    setupFormHandlers() {
        // Handle compose form submission
        const composeForm = document.getElementById('composeForm');
        if (composeForm) {
            composeForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.sendEmail();
            });
        }

        // Handle login form submission
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                this.showLoadingButton(e.target.querySelector('button[type="submit"]'));
            });
        }
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl/Cmd + Enter to send email
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                const composeModal = document.getElementById('composeModal');
                if (composeModal.classList.contains('show')) {
                    this.sendEmail();
                }
            }

            // 'c' key to compose new email
            if (e.key === 'c' && !this.isTyping()) {
                const composeButton = document.querySelector('[data-bs-target="#composeModal"]');
                if (composeButton) {
                    composeButton.click();
                }
            }

            // 'r' key to refresh inbox
            if (e.key === 'r' && !this.isTyping()) {
                this.refreshInbox();
            }
        });
    }

    isTyping() {
        const activeElement = document.activeElement;
        return activeElement.tagName === 'INPUT' || 
               activeElement.tagName === 'TEXTAREA' || 
               activeElement.contentEditable === 'true';
    }

    async sendEmail() {
        const form = document.getElementById('composeForm');
        const submitBtn = form.querySelector('button[type="submit"]');
        const formData = new FormData(form);

        try {
            this.showLoadingButton(submitBtn);
            
            const response = await fetch(form.action, {
                method: 'POST',
                body: formData,
                headers: {
                    'X-CSRFToken': formData.get('csrfmiddlewaretoken')
                }
            });

            if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    this.showToast('Email sent successfully!', 'success');
                    this.resetComposeForm();
                    bootstrap.Modal.getInstance(document.getElementById('composeModal')).hide();
                } else {
                    this.showToast(result.error || 'Failed to send email', 'error');
                }
            } else {
                this.showToast('Failed to send email', 'error');
            }
        } catch (error) {
            console.error('Error sending email:', error);
            this.showToast('Network error occurred', 'error');
        } finally {
            this.hideLoadingButton(submitBtn);
        }
    }

    resetComposeForm() {
        const form = document.getElementById('composeForm');
        if (form) {
            form.reset();
        }
    }

    showLoadingButton(button) {
        if (button) {
            button.disabled = true;
            const originalText = button.innerHTML;
            button.setAttribute('data-original-text', originalText);
            button.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Sending...';
        }
    }

    hideLoadingButton(button) {
        if (button) {
            button.disabled = false;
            const originalText = button.getAttribute('data-original-text');
            if (originalText) {
                button.innerHTML = originalText;
            }
        }
    }

    refreshInbox() {
        const refreshBtn = document.querySelector('[onclick="refreshInbox()"]');
        if (refreshBtn) {
            refreshBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Refreshing...';
            setTimeout(() => {
                location.reload();
            }, 500);
        }
    }

    startAutoRefresh() {
        // Only auto-refresh on inbox page
        if (window.location.pathname.includes('inbox')) {
            setInterval(() => {
                this.checkForNewEmails();
            }, 15000); // Check every 15 seconds
        }
    }

    async checkForNewEmails() {
        try {
            const response = await fetch('/client/api/inbox/count/');
            if (response.ok) {
                const data = await response.json();
                const currentCount = document.querySelectorAll('.email-item').length;
                
                if (data.count > currentCount) {
                    // New emails available
                    this.showToast(`${data.count - currentCount} new email(s) received!`, 'info');
                    setTimeout(() => {
                        location.reload();
                    }, 2000);
                }
            }
        } catch (error) {
            console.error('Error checking for new emails:', error);
        }
    }

    showToast(message, type = 'info') {
        // Create toast element
        const toastId = 'toast-' + Date.now();
        const toastHtml = `
            <div id="${toastId}" class="toast" role="alert" aria-live="assertive" aria-atomic="true">
                <div class="toast-header">
                    <i class="fas fa-${this.getToastIcon(type)} me-2 text-${this.getToastColor(type)}"></i>
                    <strong class="me-auto">Qute-Mail</strong>
                    <small class="text-muted">just now</small>
                    <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
                </div>
                <div class="toast-body">
                    ${message}
                </div>
            </div>
        `;

        // Add toast to page
        let toastContainer = document.getElementById('toast-container');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.id = 'toast-container';
            toastContainer.className = 'position-fixed top-0 end-0 p-3';
            toastContainer.style.zIndex = '1050';
            document.body.appendChild(toastContainer);
        }

        toastContainer.insertAdjacentHTML('beforeend', toastHtml);

        // Show toast
        const toastElement = document.getElementById(toastId);
        const toast = new bootstrap.Toast(toastElement);
        toast.show();

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (toastElement) {
                toastElement.remove();
            }
        }, 5000);
    }

    getToastIcon(type) {
        const icons = {
            'success': 'check-circle',
            'error': 'exclamation-circle',
            'info': 'info-circle',
            'warning': 'exclamation-triangle'
        };
        return icons[type] || 'info-circle';
    }

    getToastColor(type) {
        const colors = {
            'success': 'success',
            'error': 'danger',
            'info': 'primary',
            'warning': 'warning'
        };
        return colors[type] || 'primary';
    }
}

// Initialize email client when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new EmailClient();
});

// Global functions for template compatibility
function openEmail(emailId) {
    // Implementation moved to inbox template for now
}

function refreshInbox() {
    new EmailClient().refreshInbox();
}