document.addEventListener('DOMContentLoaded', () => {
    const themeSwitcherButton = document.getElementById('theme-switcher');
    const htmlElement = document.documentElement;
    const logo = document.getElementById('dynamic-logo');

    // Theme-specific values
    const darkThemeClass = 'dark-theme';
    const lightThemeClass = 'light-theme';
    const darkLogoSrc = '/auth/static/img/logo-dark.svg';
    const lightLogoSrc = '/auth/static/img/logo-light.svg';

    const moonIconClass = 'fa-moon';
    const sunIconClass = 'fa-sun';

    // Cookie functions
    function setCookie(name, value, days) {
        const expires = new Date();
        expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
        document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/;SameSite=Lax`;
    }

    function getCookie(name) {
        const nameEQ = name + "=";
        const ca = document.cookie.split(';');
        for(let i = 0; i < ca.length; i++) {
            let c = ca[i];
            while (c.charAt(0) === ' ') c = c.substring(1, c.length);
            if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
        }
        return null;
    }

    function applyTheme(theme) {
        localStorage.setItem('theme', theme);
        setCookie('gh_theme', theme, 365); // Сохраняем в cookie на год
        
        const iconElement = themeSwitcherButton ? themeSwitcherButton.querySelector('i') : null;

        if (theme === 'dark') {
            htmlElement.classList.add(darkThemeClass);
            htmlElement.classList.remove(lightThemeClass);
            if (logo) {
                logo.src = lightLogoSrc;
            }
            if (iconElement) {
                iconElement.classList.remove(moonIconClass);
                iconElement.classList.add(sunIconClass);
            }
        } else {
            htmlElement.classList.remove(darkThemeClass);
            htmlElement.classList.add(lightThemeClass);
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
    const cookieTheme = getCookie('gh_theme');
    const currentTheme = cookieTheme || localStorage.getItem('theme') || 'light';
    
    // Sync localStorage with cookie if different
    if (cookieTheme && cookieTheme !== localStorage.getItem('theme')) {
        localStorage.setItem('theme', cookieTheme);
    }
    
    const initialIconElement = themeSwitcherButton ? themeSwitcherButton.querySelector('i') : null;

    if (currentTheme === 'dark') {
        // Ensure class and bg are set if somehow missed by inline script (defensive)
        htmlElement.classList.add(darkThemeClass);
        if (logo) logo.src = lightLogoSrc;
        if (initialIconElement) {
            initialIconElement.classList.remove(moonIconClass);
            initialIconElement.classList.add(sunIconClass);
        }
    } else {
        htmlElement.classList.remove(darkThemeClass); // Ensure dark is removed
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
