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

    // Handle theme switching from the mobile menu
    if (themeSwitcherMobile) {
        // Initialize mobile theme switcher icon based on current theme
        const currentTheme = localStorage.getItem('theme') || 'light';
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
            
            // This reuses the logic from your main theme-switcher.js,
            // but applies it specifically for the mobile button's context.
            // Ideally, the core theme application logic would be a shared function.
            localStorage.setItem('theme', newTheme);
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
