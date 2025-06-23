document.addEventListener('DOMContentLoaded', () => {
    const burgerMenuToggle = document.getElementById('burger-menu-toggle');
    const mobileMenuModal = document.getElementById('mobile-menu-modal');
    const mobileMenuClose = document.getElementById('mobile-menu-close');
    const modalBackdrop = document.getElementById('modal-backdrop');
    const themeSwitcherMobile = document.getElementById('theme-switcher-mobile'); // Mobile theme switcher
    const htmlElement = document.documentElement;

    function openMenu() {
        if (mobileMenuModal && modalBackdrop) {
            mobileMenuModal.classList.add('open');
            modalBackdrop.classList.add('open');
            document.body.style.overflowY = 'hidden'; // Prevent body scroll when menu is open
        }
    }

    function closeMenu() {
        if (mobileMenuModal && modalBackdrop) {
            mobileMenuModal.classList.remove('open');
            modalBackdrop.classList.remove('open');
            document.body.style.overflowY = ''; // Restore body scroll
        }
    }

    if (burgerMenuToggle) {
        burgerMenuToggle.addEventListener('click', openMenu);
    }

    if (mobileMenuClose) {
        mobileMenuClose.addEventListener('click', closeMenu);
    }

    if (modalBackdrop) {
        modalBackdrop.addEventListener('click', closeMenu);
    }

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

    // Handle theme switching from the mobile menu
    if (themeSwitcherMobile) {
        // Initialize mobile theme switcher icon based on current theme
        const cookieTheme = getCookie('gh_theme');
        const currentTheme = cookieTheme || localStorage.getItem('theme') || 'light';
        const mobileIconElement = themeSwitcherMobile.querySelector('i');

        if (currentTheme === 'dark') {
            if (mobileIconElement) {
                mobileIconElement.classList.remove('fa-moon');
                mobileIconElement.classList.add('fa-sun');
                themeSwitcherMobile.childNodes[1].nodeValue = " Светлая тема"; // Assuming icon is first child
            }
        } else {
            if (mobileIconElement) {
                mobileIconElement.classList.remove('fa-sun');
                mobileIconElement.classList.add('fa-moon');
                themeSwitcherMobile.childNodes[1].nodeValue = " Тёмная тема";
            }
        }
        
        themeSwitcherMobile.addEventListener('click', () => {
            const isDark = htmlElement.classList.contains('dark-theme');
            const newTheme = isDark ? 'light' : 'dark';
            
            localStorage.setItem('theme', newTheme);
            setCookie('gh_theme', newTheme, 365); // Сохраняем в cookie
            
            const mainLogo = document.getElementById('dynamic-logo'); // The main logo in the header
            const darkLogoSrc = '/auth/static/img/logo-dark.svg'; 
            const lightLogoSrc = '/auth/static/img/logo-light.svg';

            if (newTheme === 'dark') {
                htmlElement.classList.add('dark-theme');
                htmlElement.classList.remove('light-theme');
                if (mainLogo) mainLogo.src = lightLogoSrc;
                if (mobileIconElement) {
                    mobileIconElement.classList.remove('fa-moon');
                    mobileIconElement.classList.add('fa-sun');
                    themeSwitcherMobile.childNodes[1].nodeValue = " Светлая тема";
                }
                // Also update the main theme switcher icon if it exists
                const mainThemeSwitcherIcon = document.querySelector('#theme-switcher i');
                if (mainThemeSwitcherIcon) {
                    mainThemeSwitcherIcon.classList.remove('fa-moon');
                    mainThemeSwitcherIcon.classList.add('fa-sun');
                }
            } else {
                htmlElement.classList.remove('dark-theme');
                htmlElement.classList.add('light-theme');
                if (mainLogo) mainLogo.src = darkLogoSrc;
                if (mobileIconElement) {
                    mobileIconElement.classList.remove('fa-sun');
                    mobileIconElement.classList.add('fa-moon');
                    themeSwitcherMobile.childNodes[1].nodeValue = " Тёмная тема";
                }
                // Also update the main theme switcher icon if it exists
                const mainThemeSwitcherIcon = document.querySelector('#theme-switcher i');
                if (mainThemeSwitcherIcon) {
                    mainThemeSwitcherIcon.classList.remove('fa-sun');
                    mainThemeSwitcherIcon.classList.add('fa-moon');
                }
            }
            // closeMenu(); // Optionally close menu after theme change
        });
    }
});
