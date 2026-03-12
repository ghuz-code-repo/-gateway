import React from 'react';
import './UnsupportedCountryNotification.css';

/**
 * Компонент уведомления о неподдерживаемом коде страны
 * @param {string} unsupportedCode - неподдерживаемый код страны
 * @param {string} unsupportedType - тип проблемы: 'forbidden' или 'unknown'
 * @param {string[]} allowedCountryCodes - список разрешенных кодов
 * @param {function} onUseGeolocation - обработчик подстановки кода по геолокации (заменяет всё поле)
 * @param {function} onKeepCurrentCode - обработчик очистки поля
 * @param {boolean} isProcessing - флаг процесса определения геолокации
 */
export const UnsupportedCountryNotification = ({
  unsupportedCode,
  unsupportedType,
  allowedCountryCodes,
  onUseGeolocation,
  onKeepCurrentCode,
  isProcessing = false
}) => {
  // console.log('🔴 UnsupportedCountryNotification rendered with:', { unsupportedCode, unsupportedType, allowedCountryCodes, isProcessing });
  
  // Определяем сообщение в зависимости от типа проблемы
  const getNotificationMessage = () => {
    if (unsupportedType === 'forbidden') {
      return {
        title: `Мы не можем связаться по телефону с таким кодом страны (+${unsupportedCode})`,
        message: `Пожалуйста, используйте: ${allowedCountryCodes.map(code => `+${code}`).join(', ')}`
      };
    } else {
      return {
        title: `Данный код страны (+${unsupportedCode}) не поддерживается.`,
        message: `Поддерживаемые коды: ${allowedCountryCodes.map(code => `+${code}`).join(', ')}`
      };
    }
  };
  
  const notification = getNotificationMessage();
  
  return (
    <div className="unsupported-country-notification">
      <div className="unsupported-country-notification__title">
        {notification.title}
      </div>
      <div className="unsupported-country-notification__message">
        {notification.message}
      </div>
      <div className="unsupported-country-notification__actions">
        <button
          type="button"
          onClick={onUseGeolocation}
          onMouseDown={(e) => e.preventDefault()} // Предотвращаем blur поля
          disabled={isProcessing}
          className="unsupported-country-notification__button unsupported-country-notification__button--primary"
        >
          {isProcessing ? 'Определение...' : 'Подставить код по геолокации'}
        </button>
        <button
          type="button"
          onClick={onKeepCurrentCode}
          onMouseDown={(e) => e.preventDefault()} // Предотвращаем blur поля
          className="unsupported-country-notification__button unsupported-country-notification__button--secondary"
        >
          Очистить поле
        </button>
      </div>
    </div>
  );
};

export default UnsupportedCountryNotification;
