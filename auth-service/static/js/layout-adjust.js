function adjustContainerPadding() {
    const header = document.querySelector('.header-container');
    const containers = document.querySelectorAll('.container'); // Select all containers

    if (header && containers.length > 0) {
        const headerHeight = header.offsetHeight;
        containers.forEach(container => {
            container.style.paddingTop = headerHeight + 20 + 'px'; // Add 20px extra spacing
        });
    } else if (containers.length > 0) {
        // Fallback if header isn't found, ensure some default padding
        // This might be useful for pages like login.html that don't have the .header-container
        // but still use .container (though login.html uses .login-container)
        // For now, let's assume pages with .container will have .header-container
        // or their specific styling (like login-container) handles spacing.
        // If a .container exists without a .header-container, it might need its own margin/padding.
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
