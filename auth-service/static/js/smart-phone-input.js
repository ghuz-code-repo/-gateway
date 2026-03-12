/**
 * Умный класс для работы с полем ввода телефона
 * Адаптировано из React компонента SmartPhoneInput
 * 
 * Функции:
 * - Автоматическое форматирование номера по маске страны
 * - Определение страны по коду телефона
 * - Геолокация для автоопределения страны пользователя
 * - Валидация номеров
 * - Уведомления о неподдерживаемых номерах
 */
class SmartPhoneInput {
    constructor(inputElement, options = {}) {
        if (!inputElement) {
            throw new Error('SmartPhoneInput: input element is required');
        }
        
        this.inputElement = inputElement;
        this.notificationElement = null;
        this.isProcessing = false;
        this.isFocused = false;
        this.lastValue = '';
        
        // Конфигурация по умолчанию
        this.config = {
            allowedCountryCodes: window.PhoneConfig.allowedCountryCodes,
            defaultCountryCode: window.PhoneConfig.defaultCountryCode,
            enableGeolocation: true,
            showUnsupportedNotification: true,
            ...options
        };
        
        // Инициализируем компонент
        this.init();
    }
    
    /**
     * Инициализация компонента
     */
    init() {
        console.log('SmartPhoneInput: Инициализация компонента');
        
        // Устанавливаем начальный placeholder
        this.inputElement.placeholder = `+${this.config.defaultCountryCode}`;
        
        // Добавляем обработчики событий
        this.attachEventListeners();
        
        // Создаем элемент для уведомлений
        this.createNotificationElement();
        
        // Геолокация отключена - используем код страны по умолчанию
        console.log('SmartPhoneInput: Geolocation disabled - using default country code');
    }
    
    /**
     * Добавляет обработчики событий к полю ввода
     */
    attachEventListeners() {
        this.inputElement.addEventListener('input', (e) => this.handleInput(e));
        this.inputElement.addEventListener('focus', (e) => this.handleFocus(e));
        this.inputElement.addEventListener('blur', (e) => this.handleBlur(e));
        this.inputElement.addEventListener('keydown', (e) => this.handleKeydown(e));
    }
    
    /**
     * Обработчик события ввода
     */
    handleInput(event) {
        if (this.isProcessing) return;
        
        this.isProcessing = true;
        
        // Сохраняем позицию курсора
        const cursorPosition = event.target.selectionStart;
        const rawValue = event.target.value;
        const oldValue = this.lastValue || '';
        
        // Определяем, что произошло: добавление или удаление
        const isAddition = rawValue.length > oldValue.length;
        
        console.log('Input event:', {
            rawValue,
            oldValue,
            isAddition,
            cursorPosition
        });
        
        const formattedValue = this.formatPhoneNumber(rawValue, cursorPosition, isAddition);
        
        // Обновляем значение поля
        this.inputElement.value = formattedValue;
        this.lastValue = formattedValue;
        
        // Анализируем введенный код страны
        this.analyzeAndShowNotifications(formattedValue);
        
        // Обновляем placeholder
        this.updatePlaceholder(formattedValue);
        
        console.log('SmartPhoneInput: Formatted value:', formattedValue);
        
        this.isProcessing = false;
    }
    
    /**
     * Обработчик фокуса
     */
    handleFocus(event) {
        this.isFocused = true;
        console.log('SmartPhoneInput: Input focused');
    }
    
    /**
     * Обработчик потери фокуса
     */
    handleBlur(event) {
        this.isFocused = false;
        // Скрываем уведомления при потере фокуса
        setTimeout(() => {
            if (!this.isFocused) {
                this.hideNotification();
            }
        }, 200);
        console.log('SmartPhoneInput: Input blurred');
    }
    
    /**
     * Обработчик нажатий клавиш
     */
    handleKeydown(event) {
        // Разрешаем только цифры, +, пробелы, backspace, delete, стрелки
        const allowedKeys = [
            'Backspace', 'Delete', 'ArrowLeft', 'ArrowRight', 
            'ArrowUp', 'ArrowDown', 'Tab', 'Enter', 'Escape'
        ];
        
        const isNumber = /[0-9]/.test(event.key);
        const isPlus = event.key === '+';
        const isSpace = event.key === ' ';
        const isAllowedKey = allowedKeys.includes(event.key);
        const isCtrlCmd = event.ctrlKey || event.metaKey;
        
        if (!isNumber && !isPlus && !isSpace && !isAllowedKey && !isCtrlCmd) {
            event.preventDefault();
        }
        
        // Разрешаем + только в начале
        if (isPlus && this.inputElement.selectionStart !== 0) {
            event.preventDefault();
        }
        
        // Специальная обработка Backspace для "умного" удаления
        if (event.key === 'Backspace') {
            this.handleBackspace(event);
        }
    }
    
    /**
     * Обработчик "умного" Backspace
     */
    handleBackspace(event) {
        const input = this.inputElement;
        const cursorPosition = input.selectionStart;
        const value = input.value;
        
        // Если выделен текст, пусть браузер обрабатывает как обычно
        if (input.selectionStart !== input.selectionEnd) {
            return;
        }
        
        // Если курсор в начале, ничего не делаем
        if (cursorPosition === 0) {
            event.preventDefault();
            return;
        }
        
        // Если символ перед курсором - не цифра (пробел, +), ищем предыдущую цифру
        const charBefore = value[cursorPosition - 1];
        if (!/\d/.test(charBefore)) {
            event.preventDefault();
            
            // Ищем предыдущую цифру
            let newPosition = cursorPosition - 1;
            while (newPosition > 0 && !/\d/.test(value[newPosition - 1])) {
                newPosition--;
            }
            
            if (newPosition > 0) {
                // Удаляем найденную цифру
                const newValue = value.slice(0, newPosition - 1) + value.slice(newPosition);
                input.value = newValue;
                
                // Форматируем заново
                const formattedValue = this.formatPhoneNumber(newValue);
                input.value = formattedValue;
                
                // Устанавливаем курсор в правильную позицию
                setTimeout(() => {
                    const newCursorPos = Math.max(0, newPosition - 1);
                    input.setSelectionRange(newCursorPos, newCursorPos);
                }, 0);
            }
        }
        // Если символ перед курсором - цифра, пусть браузер обрабатывает как обычно
    }
    
    /**
     * Форматирует номер телефона по маске страны
     */
    formatPhoneNumber(phoneNumber, cursorPosition = 0, isAddition = true) {
        if (!phoneNumber) return '';
        
        console.log('formatPhoneNumber called with:', { phoneNumber, cursorPosition, isAddition });
        
        // Извлекаем только цифры из входного номера
        let digits = phoneNumber.replace(/[^\d]/g, '');
        
        console.log('Extracted digits:', digits);
        
        // Если нет цифр, возвращаем пустую строку
        if (!digits) return '';
        
        // Определяем код страны
        const detectedCode = this.detectCountryCode(digits);
        
        console.log('Detected country code:', detectedCode);
        
        if (detectedCode && window.PhoneConfig.countryPhoneConfig[detectedCode]) {
            const config = window.PhoneConfig.countryPhoneConfig[detectedCode];
            
            // Разделяем код страны и номер телефона
            const countryCodeLength = detectedCode.length;
            let phoneDigits = digits.substring(countryCodeLength);
            
            // Ограничиваем длину номера согласно максимальной длине для страны
            const maxPhoneDigits = config.maxLength - countryCodeLength - 1; // -1 для знака +
            if (phoneDigits.length > maxPhoneDigits) {
                phoneDigits = phoneDigits.substring(0, maxPhoneDigits);
                console.log(`Phone digits truncated to ${maxPhoneDigits} digits:`, phoneDigits);
            }
            
            console.log('Formatting with code:', {
                detectedCode,
                phoneDigits,
                totalDigits: digits,
                maxPhoneDigits,
                format: config.format
            });
            
            // Применяем форматирование: код уже в формате, передаем только цифры номера
            return this.applyFormatWithCode(detectedCode, phoneDigits, config.format);
        }
        
        // Если код не определен, возвращаем с + и ограничиваем длину
        return '+' + digits.substring(0, 15); // Максимальная длина
    }
    
    /**
     * Применяет форматирование по маске
     */
    applyFormat(digits, format) {
        console.log('applyFormat called with:', { digits, format });
        
        let formatted = '';
        let digitIndex = 0;
        
        // Проходим по всем символам в формате
        for (let i = 0; i < format.length; i++) {
            if (format[i] === '9') {
                // Это позиция для цифры
                if (digitIndex < digits.length) {
                    formatted += digits[digitIndex];
                    digitIndex++;
                } else {
                    // Цифр больше нет, прекращаем форматирование
                    break;
                }
            } else {
                // Это символ форматирования (+ или пробел)
                formatted += format[i];
            }
        }
        
        console.log('applyFormat result:', formatted);
        return formatted;
    }
    
    /**
     * Применяет форматирование с учетом кода страны
     */
    applyFormatWithCode(countryCode, phoneDigits, format) {
        console.log('applyFormatWithCode called with:', { countryCode, phoneDigits, format });
        
        // Простая логика: если нет цифр номера, возвращаем только код с +
        if (!phoneDigits || phoneDigits.length === 0) {
            console.log('No phone digits, returning country code only');
            return '+' + countryCode;
        }
        
        // Если есть цифры номера, применяем полное форматирование
        let formatted = '';
        let countryCodeIndex = 0;
        let phoneDigitsIndex = 0;
        
        console.log('Formatting separately:', { countryCode, phoneDigits });
        
        // Проходим по всем символам в формате
        for (let i = 0; i < format.length; i++) {
            if (format[i] === 'X') {
                // Это позиция для цифры номера телефона
                if (phoneDigitsIndex < phoneDigits.length) {
                    formatted += phoneDigits[phoneDigitsIndex];
                    phoneDigitsIndex++;
                } else {
                    // Цифр номера больше нет, прекращаем
                    break;
                }
            } else {
                // Это константный символ (код страны, +, пробелы)
                formatted += format[i];
            }
        }
        
        console.log('applyFormatWithCode result:', formatted);
        return formatted;
    }
    
    /**
     * Определяет код страны из номера телефона
     */
    detectCountryCode(phoneDigits) {
        if (!phoneDigits) return null;
        
        const allCodes = Object.keys(window.PhoneConfig.countryPhoneConfig);
        
        // Ищем точное совпадение (начинается с кода)
        const exactMatches = allCodes.filter(code => phoneDigits.startsWith(code));
        
        if (exactMatches.length > 0) {
            // Возвращаем самый длинный код (приоритет более специфичным)
            return exactMatches.sort((a, b) => b.length - a.length)[0];
        }
        
        return null;
    }
    
    /**
     * Анализирует код страны для показа уведомлений
     */
    analyzeCountryCode(phoneNumber) {
        if (!phoneNumber) {
            return { status: 'empty', code: null, possibleCodes: [] };
        }
        
        const cleanNumber = phoneNumber.replace(/[^\d]/g, '');
        
        if (!cleanNumber) {
            return { status: 'empty', code: null, possibleCodes: [] };
        }
        
        const allCodes = Object.keys(window.PhoneConfig.countryPhoneConfig);
        
        // Ищем точные совпадения
        const exactMatches = allCodes.filter(code => 
            cleanNumber.startsWith(code) && cleanNumber.length >= code.length
        );
        
        if (exactMatches.length > 0) {
            const foundCode = exactMatches.sort((a, b) => b.length - a.length)[0];
            return {
                status: 'found',
                code: foundCode,
                possibleCodes: exactMatches,
                isAllowed: this.config.allowedCountryCodes.includes(foundCode)
            };
        }
        
        // Ищем частичные совпадения
        const partialMatches = allCodes.filter(code => code.startsWith(cleanNumber));
        
        if (partialMatches.length > 0) {
            return {
                status: 'partial',
                code: null,
                possibleCodes: partialMatches
            };
        }
        
        // Нет совпадений
        return {
            status: 'impossible',
            code: cleanNumber,
            possibleCodes: []
        };
    }
    
    /**
     * Анализирует номер и показывает уведомления
     */
    analyzeAndShowNotifications(phoneNumber) {
        if (!this.isFocused || !this.config.showUnsupportedNotification) {
            return;
        }
        
        const analysis = this.analyzeCountryCode(phoneNumber);
        
        if (analysis.status === 'found' && !analysis.isAllowed) {
            // Код найден, но не разрешен
            const countryName = window.PhoneConfig.countryPhoneConfig[analysis.code].name;
            this.showNotification(
                `Мы не сможем с вами связаться по номеру из страны: ${countryName}`,
                'warning'
            );
        } else if (analysis.status === 'impossible') {
            // Невозможный код
            this.showNotification(
                'Неизвестный код страны. Проверьте правильность ввода номера.',
                'error'
            );
        } else {
            // Все в порядке или частичный ввод
            this.hideNotification();
        }
    }
    
    /**
     * Обновляет placeholder в зависимости от введенного значения
     */
    updatePlaceholder(phoneNumber) {
        const detectedCode = this.detectCountryCode(phoneNumber.replace(/[^\d]/g, ''));
        
        if (detectedCode && window.PhoneConfig.countryPhoneConfig[detectedCode]) {
            const config = window.PhoneConfig.countryPhoneConfig[detectedCode];
            this.inputElement.placeholder = config.format;
        } else {
            this.inputElement.placeholder = `+${this.config.defaultCountryCode}`;
        }
    }
    
    /**
     * Создает элемент для уведомлений
     */
    createNotificationElement() {
        this.notificationElement = document.createElement('div');
        this.notificationElement.className = 'smart-phone-notification';
        this.notificationElement.style.display = 'none';
        
        // Вставляем после поля ввода
        this.inputElement.parentNode.insertBefore(
            this.notificationElement, 
            this.inputElement.nextSibling
        );
    }
    
    /**
     * Показывает уведомление
     */
    showNotification(message, type = 'info') {
        if (!this.notificationElement) return;
        
        this.notificationElement.textContent = message;
        this.notificationElement.className = `smart-phone-notification ${type}`;
        this.notificationElement.style.display = 'block';
        
        console.log('SmartPhoneInput: Showing notification:', message, type);
    }
    
    /**
     * Скрывает уведомление
     */
    hideNotification() {
        if (!this.notificationElement) return;
        
        this.notificationElement.style.display = 'none';
        console.log('SmartPhoneInput: Hiding notification');
    }
    
    /**
     * Определяет страну по геолокации
     */
    async detectCountryByGeolocation() {
        try {
            console.log('SmartPhoneInput: Определение страны по IP...');
            
            // Используем бесплатный API для определения страны
            const response = await fetch('https://ipapi.co/json/');
            const data = await response.json();
            
            if (data.country_code && window.PhoneConfig.countryIsoToPhoneCode[data.country_code]) {
                const countryCode = window.PhoneConfig.countryIsoToPhoneCode[data.country_code];
                
                console.log('SmartPhoneInput: Определена страна:', data.country_name, 'Код:', countryCode);
                
                // Обновляем placeholder
                if (window.PhoneConfig.countryPhoneConfig[countryCode]) {
                    const config = window.PhoneConfig.countryPhoneConfig[countryCode];
                    this.inputElement.placeholder = config.format;
                }
                
                // Если поле пустое, можно предустановить код страны
                if (!this.inputElement.value.trim()) {
                    // Не автоматически заполняем, только обновляем placeholder
                    // this.inputElement.value = `+${countryCode}`;
                }
            }
        } catch (error) {
            console.warn('SmartPhoneInput: Не удалось определить страну по геолокации:', error);
        }
    }
    
    /**
     * Валидирует номер телефона
     */
    isValid(phoneNumber = null) {
        const number = phoneNumber || this.inputElement.value;
        const cleanDigits = number.replace(/[^\d]/g, '');
        const detectedCode = this.detectCountryCode(cleanDigits);
        
        if (!detectedCode || !window.PhoneConfig.countryPhoneConfig[detectedCode]) {
            return false;
        }
        
        const config = window.PhoneConfig.countryPhoneConfig[detectedCode];
        return config.pattern.test(cleanDigits);
    }
    
    /**
     * Возвращает чистый номер без форматирования
     */
    getCleanValue() {
        return this.inputElement.value.replace(/[^\d]/g, '');
    }
    
    /**
     * Устанавливает значение с форматированием
     */
    setValue(phoneNumber) {
        const formatted = this.formatPhoneNumber(phoneNumber);
        this.inputElement.value = formatted;
        this.updatePlaceholder(formatted);
    }
    
    /**
     * Уничтожает экземпляр компонента
     */
    destroy() {
        // Удаляем обработчики событий
        this.inputElement.removeEventListener('input', this.handleInput);
        this.inputElement.removeEventListener('focus', this.handleFocus);
        this.inputElement.removeEventListener('blur', this.handleBlur);
        this.inputElement.removeEventListener('keydown', this.handleKeydown);
        
        // Удаляем элемент уведомлений
        if (this.notificationElement && this.notificationElement.parentNode) {
            this.notificationElement.parentNode.removeChild(this.notificationElement);
        }
        
        console.log('SmartPhoneInput: Компонент уничтожен');
    }
}

// Экспортируем класс в глобальную область видимости
window.SmartPhoneInput = SmartPhoneInput;