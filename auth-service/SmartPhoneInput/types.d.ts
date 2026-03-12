/**
 * Типы для компонента SmartPhoneInput
 * Используется для TypeScript проектов
 */

/**
 * Конфигурация поведения компонента
 */
export interface SmartPhoneConfig {
  /** Разрешенные коды стран для отправки формы */
  allowedCountryCodes?: string[];
  /** Код страны по умолчанию */
  defaultCountryCode?: string;
  /** Включить определение геолокации */
  enableGeolocation?: boolean;
}

/**
 * Данные о статусе валидации
 */
export interface ValidationStatus {
  /** Является ли значение валидным для отправки */
  isValid: boolean;
  /** Определенный код страны */
  countryCode: string | null;
  /** Текущее значение поля */
  value: string;
  /** Введен ли полный номер */
  isComplete: boolean;
}

/**
 * Данные об определенной стране
 */
export interface DetectedCountry {
  /** Код страны */
  countryCode: string;
  /** Разрешен ли этот код для отправки */
  isAllowed: boolean;
}

/**
 * Свойства компонента SmartPhoneInput
 */
export interface SmartPhoneInputProps {
  /** Текущее значение поля */
  value?: string;
  /** Обработчик изменения значения */
  onChange?: (event: React.ChangeEvent<HTMLInputElement>) => void;
  /** Начальный placeholder */
  placeholder?: string;
  /** CSS класс для стилизации */
  className?: string;
  /** Конфигурация поведения */
  config?: SmartPhoneConfig;
  /** Обработчик изменения статуса валидации */
  onValidationChange?: (status: ValidationStatus) => void;
  /** Обработчик определения страны */
  onCountryDetected?: (country: DetectedCountry) => void;
  /** Дополнительные свойства для input элемента */
  inputProps?: React.InputHTMLAttributes<HTMLInputElement>;
}

/**
 * Возвращаемые методы хука useSmartPhoneLogic
 */
export interface SmartPhoneLogicReturn {
  /** Форматирует номер телефона */
  formatPhoneNumber: (value: string) => string;
  /** Определяет код страны из номера */
  detectCountryCode: (phone: string) => string | null;
  /** Проверяет разрешенность кода страны */
  isCountryCodeAllowed: (phone: string) => boolean;
  /** Проверяет, содержит ли только код страны */
  isOnlyCountryCode: (value: string) => boolean;
  /** Получает оптимальный placeholder */
  getOptimalPlaceholder: (geolocationFn?: (() => Promise<string | null>) | null, fallbackCountryCode?: string) => Promise<string>;
  /** Определяет страну по геолокации */
  getCountryByGeolocation: () => Promise<string | null>;
  /** Конфигурация стран */
  COUNTRY_PHONE_CONFIG: Record<string, any>;
  /** Маппинг ISO кодов на телефонные коды */
  COUNTRY_ISO_TO_PHONE_CODE: Record<string, string>;
}
