document.addEventListener('DOMContentLoaded', () => {
    const themeSwitcherButton = document.getElementById('theme-switcher');
    const htmlElement = document.documentElement;
    const bodyElement = document.body;
    const logo = document.getElementById('dynamic-logo');

    // Theme-specific values
    const darkThemeClass = 'dark-theme';
    const lightThemeClass = 'light-theme'; // Optional: if you have specific light-theme only styles
    const darkThemeBgColor = '#121212'; // From your CSS
    const lightThemeBgColor = '#f5f5f5'; // From your CSS
    const darkLogoSrc = '/auth/static/img/logo-dark.svg'; // Default logo
    const lightLogoSrc = '/auth/static/img/logo-light.svg'; // Assumed logo for dark theme

    const moonIconClass = 'fa-moon';
    const sunIconClass = 'fa-sun';

    function applyTheme(theme) {
        localStorage.setItem('theme', theme);
        const iconElement = themeSwitcherButton ? themeSwitcherButton.querySelector('i') : null;

        if (theme === 'dark') {
            htmlElement.classList.add(darkThemeClass);
            htmlElement.classList.remove(lightThemeClass); // Remove light if it exists
            bodyElement.style.backgroundColor = darkThemeBgColor;
            if (logo) {
                logo.src = lightLogoSrc;
            }
            if (iconElement) {
                iconElement.classList.remove(moonIconClass);
                iconElement.classList.add(sunIconClass);
            }
        } else { // Light theme
            htmlElement.classList.remove(darkThemeClass);
            htmlElement.classList.add(lightThemeClass); // Add light if you use it
            bodyElement.style.backgroundColor = lightThemeBgColor;
            if (logo) {
                logo.src = darkLogoSrc;
            }
            if (iconElement) {
                iconElement.classList.remove(sunIconClass);
                iconElement.classList.add(moonIconClass);
            }
        }
    }

    // Set initial state of the button icon and logo.
    // The inline script in <head> already handles the class on <html> and body background for FOUC.
    // This part ensures the button icon and logo are correct on load.
    const currentTheme = localStorage.getItem('theme') || 'light'; // Default to light if nothing set
    const initialIconElement = themeSwitcherButton ? themeSwitcherButton.querySelector('i') : null;

    if (currentTheme === 'dark') {
        // Ensure class and bg are set if somehow missed by inline script (defensive)
        htmlElement.classList.add(darkThemeClass);
        bodyElement.style.backgroundColor = darkThemeBgColor;
        if (logo) logo.src = lightLogoSrc;
        if (initialIconElement) {
            initialIconElement.classList.remove(moonIconClass);
            initialIconElement.classList.add(sunIconClass);
        }
    } else {
        htmlElement.classList.remove(darkThemeClass); // Ensure dark is removed
        bodyElement.style.backgroundColor = lightThemeBgColor;
        if (logo) logo.src = darkLogoSrc;
        if (initialIconElement) {
            initialIconElement.classList.remove(sunIconClass);
            initialIconElement.classList.add(moonIconClass);
        }
    }

    // Event listener for the theme switcher button
    if (themeSwitcherButton) {
        themeSwitcherButton.addEventListener('click', () => {
            const newTheme = htmlElement.classList.contains(darkThemeClass) ? 'light' : 'dark';
            applyTheme(newTheme);
        });
    }
});
