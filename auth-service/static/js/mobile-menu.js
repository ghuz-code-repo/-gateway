document.addEventListener('DOMContentLoaded', () => {
    const burgerMenuToggle = document.getElementById('burger-menu-toggle');
    const mobileMenuModal = document.getElementById('mobile-menu-modal');
    const mobileMenuClose = document.getElementById('mobile-menu-close');
    const modalBackdrop = document.getElementById('modal-backdrop');
    const themeSwitcherMobile = document.getElementById('theme-switcher-mobile'); // Mobile theme switcher
    const htmlElement = document.documentElement;

    // Блокировка скролла страницы делается классом через ghScrollLock
    // (mobile-ux.js): инлайновый style.overflowY проигрывал !important-правилам
    // легаси, и страница под открытым меню продолжала скроллиться.
    function lockPageScroll() {
        if (window.ghScrollLock) {
            window.ghScrollLock.lock();
        } else {
            document.documentElement.classList.add('gh-scroll-lock');
            document.body.classList.add('gh-scroll-lock');
        }
    }

    function unlockPageScroll() {
        if (window.ghScrollLock) {
            window.ghScrollLock.reset();
        } else {
            document.documentElement.classList.remove('gh-scroll-lock');
            document.body.classList.remove('gh-scroll-lock');
        }
    }

    function isMenuOpen() {
        return !!(mobileMenuModal && mobileMenuModal.classList.contains('open'));
    }

    function openMenu() {
        if (mobileMenuModal && modalBackdrop) {
            mobileMenuModal.classList.add('open');
            modalBackdrop.classList.add('open');
            lockPageScroll();
            if (burgerMenuToggle) {
                burgerMenuToggle.classList.add('active');
                burgerMenuToggle.setAttribute('aria-expanded', 'true');
            }
            if (mobileMenuClose) {
                mobileMenuClose.focus();
            }
        }
    }

    function closeMenu() {
        if (mobileMenuModal && modalBackdrop) {
            mobileMenuModal.classList.remove('open');
            modalBackdrop.classList.remove('open');
            unlockPageScroll();
            if (burgerMenuToggle) {
                burgerMenuToggle.classList.remove('active');
                burgerMenuToggle.setAttribute('aria-expanded', 'false');
            }
        }
    }

    if (burgerMenuToggle) {
        // Тап по бургеру при открытом меню должен его закрывать: иконка
        // превращается в крестик, и другого поведения от неё не ждут.
        burgerMenuToggle.addEventListener('click', function () {
            if (isMenuOpen()) {
                closeMenu();
            } else {
                openMenu();
            }
        });
    }

    if (mobileMenuClose) {
        mobileMenuClose.addEventListener('click', closeMenu);
    }

    if (modalBackdrop) {
        modalBackdrop.addEventListener('click', closeMenu);
    }

    document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape' && isMenuOpen()) {
            closeMenu();
        }
    });

    // При повороте экрана или переходе на планшетную ширину меню теряет
    // смысл: десктопные контролы возвращаются, а скролл остался бы заблокирован.
    window.addEventListener('resize', function () {
        if (isMenuOpen() && window.innerWidth > 768) {
            closeMenu();
        }
    });

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
            const darkLogoSrc = '/static/img/logo-dark.svg'; 
            const lightLogoSrc = '/static/img/logo-light.svg';

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
