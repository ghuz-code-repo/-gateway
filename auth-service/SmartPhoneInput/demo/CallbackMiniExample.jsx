import React, { useState } from 'react';
import { SmartPhoneInput } from '../SmartPhoneInput';
import { sendLeadToMacroCRM, showFlashMessage } from '../../utils/macroCRM';

/**
 * Пример интеграции SmartPhoneInput в форму обратного звонка
 * Демонстрирует базовое использование компонента
 */
const CallbackMiniExample = () => {
  const [formData, setFormData] = useState({
    name: '',
    phone: ''
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isPhoneValid, setIsPhoneValid] = useState(false);

  /**
   * Обработчик изменения телефона
   */
  const handlePhoneChange = (event) => {
    setFormData(prev => ({
      ...prev,
      phone: event.target.value
    }));
  };

  /**
   * Обработчик валидации телефона
   */
  const handlePhoneValidation = (status) => {
    setIsPhoneValid(status.isValid);
    console.log('Phone validation:', status);
  };

  /**
   * Обработчик определения страны
   */
  const handleCountryDetected = (country) => {
    console.log('Country detected:', country);
  };

  /**
   * Обработчик изменения имени
   */
  const handleNameChange = (event) => {
    setFormData(prev => ({
      ...prev,
      name: event.target.value
    }));
  };

  /**
   * Обработчик отправки формы
   */
  const handleSubmit = async (event) => {
    event.preventDefault();
    
    if (!formData.name.trim()) {
      showFlashMessage('Введите имя', 'error');
      return;
    }

    if (!isPhoneValid) {
      showFlashMessage('Введите корректный номер телефона', 'error');
      return;
    }

    setIsSubmitting(true);

    try {
      const leadData = {
        name: formData.name.trim(),
        phone: formData.phone,
        source: 'Callback Mini Example'
      };

      await sendLeadToMacroCRM(leadData);
      showFlashMessage('Заявка отправлена! Мы свяжемся с вами в ближайшее время.', 'success');
      
      // Сброс формы
      setFormData({ name: '', phone: '' });
      setIsPhoneValid(false);
      
    } catch (error) {
      console.error('Ошибка отправки:', error);
      showFlashMessage('Ошибка отправки. Попробуйте позже.', 'error');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="callback-mini-example">
      <h3>Обратный звонок</h3>
      <p>Оставьте заявку и мы свяжемся с вами</p>
      
      <form onSubmit={handleSubmit} className="callback-form">
        <div className="form-group">
          <input
            type="text"
            value={formData.name}
            onChange={handleNameChange}
            placeholder="Ваше имя"
            className="form-input"
            required
          />
        </div>

        <div className="form-group">
          <SmartPhoneInput
            value={formData.phone}
            onChange={handlePhoneChange}
            onValidationChange={handlePhoneValidation}
            onCountryDetected={handleCountryDetected}
            className={`form-input ${isPhoneValid ? 'valid' : ''}`}
            config={{
              allowedCountryCodes: ['998'], // Только Узбекистан
              defaultCountryCode: '998',
              enableGeolocation: true
            }}
            inputProps={{
              required: true,
              'aria-label': 'Номер телефона'
            }}
          />
        </div>

        <button 
          type="submit" 
          disabled={isSubmitting || !isPhoneValid || !formData.name.trim()}
          className={`submit-button ${isSubmitting ? 'loading' : ''}`}
        >
          {isSubmitting ? 'Отправка...' : 'Заказать звонок'}
        </button>
      </form>

      {/* Индикатор валидности */}
      {formData.phone && (
        <div className={`validation-indicator ${isPhoneValid ? 'valid' : 'invalid'}`}>
          {isPhoneValid ? '✓ Номер корректен' : '⚠ Проверьте номер'}
        </div>
      )}

      <style jsx>{`
        .callback-mini-example {
          max-width: 400px;
          margin: 0 auto;
          padding: 20px;
          background: #f8f9fa;
          border-radius: 8px;
        }

        .callback-form {
          display: flex;
          flex-direction: column;
          gap: 15px;
        }

        .form-group {
          display: flex;
          flex-direction: column;
        }

        .form-input {
          padding: 12px;
          border: 1px solid #ddd;
          border-radius: 4px;
          font-size: 16px;
          transition: border-color 0.2s;
        }

        .form-input:focus {
          outline: none;
          border-color: #007bff;
          box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
        }

        .form-input.valid {
          border-color: #28a745;
        }

        .submit-button {
          padding: 12px 24px;
          background: #007bff;
          color: white;
          border: none;
          border-radius: 4px;
          font-size: 16px;
          cursor: pointer;
          transition: background-color 0.2s;
        }

        .submit-button:hover:not(:disabled) {
          background: #0056b3;
        }

        .submit-button:disabled {
          background: #6c757d;
          cursor: not-allowed;
        }

        .submit-button.loading {
          position: relative;
        }

        .validation-indicator {
          padding: 8px 12px;
          border-radius: 4px;
          font-size: 14px;
          margin-top: 10px;
        }

        .validation-indicator.valid {
          background: #d4edda;
          color: #155724;
          border: 1px solid #c3e6cb;
        }

        .validation-indicator.invalid {
          background: #f8d7da;
          color: #721c24;
          border: 1px solid #f5c6cb;
        }
      `}</style>
    </div>
  );
};

export default CallbackMiniExample;
