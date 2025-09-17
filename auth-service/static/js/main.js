// Main JavaScript file for auth-service
document.addEventListener('DOMContentLoaded', function() {
    console.log('Auth service main.js loaded');
    
    // Initialize any global functionality here
    initializeServiceManagement();
});

function initializeServiceManagement() {
    // Handle service-related UI interactions
    const serviceItems = document.querySelectorAll('.service-item, .service-card');
    
    serviceItems.forEach(item => {
        // Add click handlers for service items if needed
        const link = item.querySelector('a');
        if (link) {
            link.addEventListener('click', function(e) {
                // Could add loading states or other UX improvements here
            });
        }
    });
    
    // Handle form submissions
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Обработка...';
            }
        });
    });
}

// Utility function for showing notifications
function showNotification(message, type = 'info') {
    // Simple notification system
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    // Add to page
    document.body.appendChild(notification);
    
    // Auto-remove after 3 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
        }
    }, 3000);
}

// Make functions globally available
window.showNotification = showNotification;
