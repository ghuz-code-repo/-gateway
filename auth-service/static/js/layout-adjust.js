// Layout adjust for single-page architecture
function adjustContainerPadding() {
    // For single-page architecture, we use CSS .header-spacer instead of JS padding adjustment
    // This function is kept for compatibility with other pages that might use the old approach
    
    const adminPageContainer = document.querySelector('.admin-page-container');
    if (adminPageContainer) {
        // This is the new single-page admin interface - no JS adjustment needed
        return;
    }
    
    // Fallback for other pages using the old approach
    const header = document.querySelector('.header-container');
    const containers = document.querySelectorAll('.container');

    if (header && containers.length > 0) {
        const headerHeight = header.offsetHeight;
        containers.forEach(container => {
            // Only adjust if it's not part of the single-page admin interface
            if (!container.closest('.admin-page-container')) {
                container.style.paddingTop = headerHeight + 20 + 'px';
            }
        });
    }
}

// Adjust padding on DOMContentLoaded
document.addEventListener('DOMContentLoaded', adjustContainerPadding);

// Adjust padding on window resize
let resizeTimeout;
window.addEventListener('resize', () => {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(adjustContainerPadding, 100); // Debounce resize event
});
