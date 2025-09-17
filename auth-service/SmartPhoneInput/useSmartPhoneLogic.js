import { useCallback } from 'react';
import phoneConfigData from './phoneConfig.json';

// Конфигурация из JSON файла
const PHONE_CONFIG = phoneConfigData;
const COUNTRY_PHONE_CONFIG = phoneConfigData.countryPhoneConfig;
const COUNTRY_ISO_TO_PHONE_CODE = phoneConfigData.countryIsoToPhoneCode;
const DEFAULT_ALLOWED_CODES = phoneConfigData.allowedCountryCodes;
const DEFAULT_COUNTRY_CODE = phoneConfigData.defaultCountryCode;

// Преобразуем строковые паттерны в RegExp объекты
Object.keys(COUNTRY_PHONE_CONFIG).forEach(code => {
  COUNTRY_PHONE_CONFIG[code].pattern = new RegExp(COUNTRY_PHONE_CONFIG[code].pattern);
});

// Экспорт конфигурации для внешнего использования
export { PHONE_CONFIG, COUNTRY_PHONE_CONFIG, COUNTRY_ISO_TO_PHONE_CODE, DEFAULT_ALLOWED_CODES, DEFAULT_COUNTRY_CODE };

/**
 * Прогрессивная проверка кода страны
 * @param {string} phoneNumber - номер телефона для проверки
 * @returns {Object} результат проверки
 */
function analyzeCountryCode(phoneNumber) {
  // console.log('🔍 analyzeCountryCode called with:', phoneNumber);
  
  if (!phoneNumber) {
    return { status: 'empty', code: null, possibleCodes: [] };
  }
  
  const cleanNumber = phoneNumber.replace(/[^\d]/g, '');
  // console.log('🔍 analyzeCountryCode: cleanNumber =', cleanNumber);
  
  if (!cleanNumber) {
    return { status: 'empty', code: null, possibleCodes: [] };
  }
  
  const allCodes = Object.keys(COUNTRY_PHONE_CONFIG);
  // console.log('🔍 analyzeCountryCode: all available codes =', allCodes);
  
  // Ищем точные совпадения (полные коды)
  const exactMatches = allCodes.filter(code => cleanNumber.startsWith(code) && cleanNumber.length >= code.length);
  // console.log('🔍 analyzeCountryCode: exact matches =', exactMatches);
  
  if (exactMatches.length > 0) {
    // Найден точный код - выбираем самый длинный (приоритет у более специфичных кодов)
    const foundCode = exactMatches.sort((a, b) => b.length - a.length)[0];
    // console.log('🔍 analyzeCountryCode: EXACT CODE FOUND:', foundCode);
    return { 
      status: 'found', 
      code: foundCode, 
      possibleCodes: exactMatches,
      isAllowed: DEFAULT_ALLOWED_CODES.includes(foundCode)
    };
  }
  
  // Ищем частичные совпадения (коды, которые начинаются с введённых цифр)
  const partialMatches = allCodes.filter(code => code.startsWith(cleanNumber));
  // console.log('🔍 analyzeCountryCode: partial matches =', partialMatches);
  
  if (partialMatches.length > 0) {
    // console.log('🔍 analyzeCountryCode: PARTIAL MATCHES FOUND:', partialMatches);
    return { 
      status: 'partial', 
      code: null, 
      possibleCodes: partialMatches 
    };
  }
  
  // Нет ни точных, ни частичных совпадений - код невозможен
  // console.log('🔍 analyzeCountryCode: NO POSSIBLE CODES - IMPOSSIBLE');
  return { 
    status: 'impossible', 
    code: cleanNumber, 
    possibleCodes: [] 
  };
}

/**
 * Определяет код страны из номера телефона
 */
function detectCountryCode(phoneNumber) {
  // console.log('🔍 detectCountryCode called with:', phoneNumber);
  
  if (!phoneNumber) {
    // console.log('🔍 detectCountryCode: phoneNumber is empty, returning null');
    return null;
  }
  
  const analysis = analyzeCountryCode(phoneNumber);
  
  if (analysis.status === 'found') {
    // console.log('🔍 detectCountryCode: returning found code:', analysis.code);
    return analysis.code;
  }
  
  // console.log('🔍 detectCountryCode: no exact code found, returning null');
  return null;
}

/**
 * Универсальная функция форматирования номера на основе маски из конфигурации
 * @param {string} countryCode - код страны
 * @param {string} digits - цифры номера (без кода страны)
 * @returns {string} отформатированный номер
 */
function formatByMask(countryCode, digits) {
  const config = COUNTRY_PHONE_CONFIG[countryCode];
  if (!config || !config.format) {
    return `+${countryCode}${digits}`;
  }
  
  const format = config.format;
  // console.log(`📞 Formatting ${countryCode} with digits: "${digits}" using format: "${format}"`);
  
  // Извлекаем маску после кода страны
  const maskParts = format.split(' ').slice(1); // убираем "+код"
  // console.log(`📞 Mask parts:`, maskParts);
  
  let result = `+${countryCode}`;
  let digitIndex = 0;
  
  for (const part of maskParts) {
    if (digitIndex >= digits.length) break;
    
    const partLength = part.length;
    const digitsPart = digits.substring(digitIndex, digitIndex + partLength);
    
    if (digitsPart) {
      result += ` ${digitsPart}`;
      digitIndex += partLength;
    }
  }
  
  // console.log(`📞 Result: "${result}"`);
  return result;
}

/**
 * Форматирует номер телефона
 * @param {string} inputValue - введенное значение
 * @returns {string} отформатированный номер
 */
export function formatPhoneNumber(inputValue) {
  if (!inputValue) return '';
  
  // Удаляем все символы кроме цифр и +
  let cleaned = inputValue.replace(/[^\d+]/g, '');
  
  // Если пустая строка
  if (!cleaned) {
    return '';
  }
  
  // Если не начинается с +, добавляем
  if (!cleaned.startsWith('+')) {
    cleaned = '+' + cleaned;
  }
  
  // Определяем код страны
  const countryCode = detectCountryCode(cleaned);
  if (!countryCode) {
    return cleaned; // Возвращаем как есть, если код не определен
  }

  const config = COUNTRY_PHONE_CONFIG[countryCode];
  if (!config) {
    return cleaned;
  }

  // Извлекаем цифры после кода страны
  const digits = cleaned.substring(1); // убираем +
  const countryDigits = digits.substring(countryCode.length); // убираем код страны
  
  // Обрезаем по максимальной длине
  const maxDigits = config.maxLength - countryCode.length - 1; // -1 для +
  const truncatedDigits = countryDigits.substring(0, maxDigits);
  
  // Используем универсальное форматирование по маске
  return formatByMask(countryCode, truncatedDigits);
}

/**
 * Проверяет, разрешен ли код страны
 */
export function isCountryCodeAllowed(phoneNumber, allowedCodes = DEFAULT_ALLOWED_CODES) {
  const countryCode = detectCountryCode(phoneNumber);
  return countryCode ? allowedCodes.includes(countryCode) : false;
}

/**
 * Валидирует номер телефона
 */
export function validatePhoneNumber(phoneNumber, allowedCodes = DEFAULT_ALLOWED_CODES) {
  const formattedValue = formatPhoneNumber(phoneNumber);
  const detectedCode = detectCountryCode(formattedValue);
  const isValid = formattedValue ? isCountryCodeAllowed(formattedValue, allowedCodes) : false;
  const isComplete = formattedValue.length > (detectedCode?.length || 0) + 1;
  
  return {
    isValid,
    countryCode: detectedCode,
    value: formattedValue,
    isComplete
  };
}

/**
 * Получает оптимальный код страны для пользователя
 * Логика: если введенный код не разрешен, пытаемся определить страну пользователя по IP,
 * если не получилось или страна не разрешена - берем первый код из списка разрешенных
 * 
 * @param {string} currentCode - текущий введенный код страны
 * @param {string[]} allowedCodes - список разрешенных кодов стран
 * @param {boolean} enableGeolocation - включить геолокацию
 * @returns {Promise<string>} оптимальный код страны
 */
export async function getOptimalCountryCode(currentCode = '', allowedCodes = DEFAULT_ALLOWED_CODES, enableGeolocation = true) {
  // Если текущий код разрешен - возвращаем его
  if (currentCode && allowedCodes.includes(currentCode)) {
    return currentCode;
  }

  // Пытаемся получить страну пользователя через геолокацию
  if (enableGeolocation) {
    try {
      const userCountryCode = await getUserCountryByGeolocation();
      if (userCountryCode && allowedCodes.includes(userCountryCode)) {
        return userCountryCode;
      }
    } catch (error) {
      console.warn('Не удалось определить страну пользователя:', error);
    }
  }

  // Возвращаем первый разрешенный код
  return allowedCodes[0] || DEFAULT_COUNTRY_CODE;
}

/**
 * Получает страну пользователя через геолокацию по IP
 * @returns {Promise<string|null>} код страны или null
 */
async function getUserCountryByGeolocation() {
  // Попытка получить страну через IP
  try {
    const response = await fetch('https://ipapi.co/json/');
    if (response.ok) {
      const data = await response.json();
      const phoneCode = COUNTRY_ISO_TO_PHONE_CODE[data.country_code];
      if (phoneCode) {
        return phoneCode;
      }
    }
  } catch (error) {
    console.warn('IP геолокация недоступна:', error);
  }

  // Попытка получить координаты через браузер (если IP не сработал)
  if (navigator.geolocation) {
    try {
      const position = await new Promise((resolve, reject) => {
        navigator.geolocation.getCurrentPosition(resolve, reject, {
          timeout: 5000,
          enableHighAccuracy: false
        });
      });

      const { latitude, longitude } = position.coords;

      // Обратное геокодирование через несколько сервисов
      const geocodeServices = [
        `https://api.bigdatacloud.net/data/reverse-geocode-client?latitude=${latitude}&longitude=${longitude}&localityLanguage=en`,
        `https://geocode.xyz/${latitude},${longitude}?json=1`
      ];

      for (const serviceUrl of geocodeServices) {
        try {
          const response = await fetch(serviceUrl);
          if (response.ok) {
            const data = await response.json();
            const countryCode = data.countryCode || data.country;
            const phoneCode = COUNTRY_ISO_TO_PHONE_CODE[countryCode];
            if (phoneCode) {
              return phoneCode;
            }
          }
        } catch (error) {
          console.warn(`Ошибка геокодирования ${serviceUrl}:`, error);
        }
      }
    } catch (error) {
      console.warn('Геолокация браузера недоступна:', error);
    }
  }

  return null;
}

/**
 * Хук с умной логикой для обработки номеров телефонов
 * 
 * @param {Object} config - конфигурация
 * @param {string[]} config.allowedCountryCodes - разрешенные коды стран для отправки
 * @param {string} config.defaultCountryCode - код страны по умолчанию  
 * @param {boolean} config.enableGeolocation - включить геолокацию
 * @param {boolean} config.showFullMaskPlaceholder - показывать полную маску в placeholder (по умолчанию false)
 * @returns {Object} методы для работы с телефонными номерами
 */
export function useSmartPhoneLogic(config = {}) {
  const {
    allowedCountryCodes = DEFAULT_ALLOWED_CODES,
    defaultCountryCode = DEFAULT_COUNTRY_CODE,
    enableGeolocation = true,
    showFullMaskPlaceholder = false
  } = config;

  /**
   * Проверяет, разрешен ли код страны для отправки
   * @param {string} phone - номер телефона
   * @returns {boolean} true если код страны разрешен
   */
  const isCountryCodeAllowedCallback = useCallback((phone) => {
    return isCountryCodeAllowed(phone, allowedCountryCodes);
  }, [allowedCountryCodes]);

  /**
   * Проверяет, содержит ли значение только код страны
   * @param {string} value - значение поля
   * @returns {boolean} true если только код страны
   */
  const isOnlyCountryCode = useCallback((value) => {
    if (!value || value.trim() === '') return false;
    
    const cleaned = value.replace(/\s/g, ''); // убираем пробелы
    const numbers = cleaned.replace(/[^\d+]/g, ''); // оставляем только + и цифры
    
    if (!numbers.startsWith('+')) return false;
    
    const digits = numbers.substring(1);
    
    // Проверяем, является ли это только кодом страны
    const detectedCode = detectCountryCode(numbers);
    
    if (detectedCode) {
      // Если код определен - проверяем точное совпадение длины
      return digits.length === detectedCode.length;
    } else {
      // Если код не определен нашей системой, считаем что это код страны
      // если цифр от 1 до 4 (стандартные коды стран 1-4 цифры)
      return digits.length >= 1 && digits.length <= 4;
    }
  }, []);

  /**
   * Получает оптимальный placeholder на основе геолокации
   * @returns {Promise<string>} оптимальный placeholder
   */
  const getOptimalPlaceholder = useCallback(async () => {
    const optimalCode = await getOptimalCountryCode('', allowedCountryCodes, enableGeolocation);
    
    return showFullMaskPlaceholder 
      ? (COUNTRY_PHONE_CONFIG[optimalCode]?.format || `+${optimalCode}`)
      : `+${optimalCode}`;
  }, [allowedCountryCodes, enableGeolocation, showFullMaskPlaceholder]);

  /**
   * Валидирует номер телефона и возвращает результат
   * @param {string} phoneNumber - номер для валидации
   * @returns {Object} результат валидации
   */
  const validatePhoneNumberCallback = useCallback((phoneNumber) => {
    return validatePhoneNumber(phoneNumber, allowedCountryCodes);
  }, [allowedCountryCodes]);

  return {
    formatPhoneNumber,
    detectCountryCode,
    analyzeCountryCode,
    isCountryCodeAllowed: isCountryCodeAllowedCallback,
    isOnlyCountryCode,
    getOptimalPlaceholder,
    getOptimalCountryCode: (currentCode) => getOptimalCountryCode(currentCode, allowedCountryCodes, enableGeolocation),
    validatePhoneNumber: validatePhoneNumberCallback,
    COUNTRY_PHONE_CONFIG,
    COUNTRY_ISO_TO_PHONE_CODE,
    PHONE_CONFIG
  };
}
