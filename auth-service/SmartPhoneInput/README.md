# SmartPhoneInput - Умное поле ввода телефона

Переиспользуемый React компонент для ввода номеров телефонов с автоформатированием, валидацией и умным определением страны через геолокацию.

## � Структура компонента

```
SmartPhoneInput/
├── SmartPhoneInput.jsx      # Основной компонент
├── useSmartPhoneLogic.js    # Хук с логикой
├── index.js                 # Экспорты
├── types.d.ts              # TypeScript типы
├── README.md               # Документация (этот файл)
└── demo/                   # 📂 Демо и примеры
    ├── README.md           # Описание демо-материалов
    ├── CHEATSHEET.md       # Шпаргалка по использованию
    ├── QUICK_START.md      # Быстрый старт
    ├── CallbackMiniExample.jsx    # Пример интеграции
    ├── smart-phone-input-demo.html # Интерактивное демо
    └── cheatsheet-demo.html       # Демо шпаргалки
```

## 🎯 Демо и примеры

Все демонстрационные материалы находятся в папке [`demo/`](./demo/):
- **HTML демо** - интерактивное тестирование компонента
- **React примеры** - готовые решения для интеграции  
- **Документация** - шпаргалки и быстрый старт

## �🚀 Быстрый старт

### Базовое использование

```jsx
import { SmartPhoneInput } from './components/SmartPhoneInput';

function MyForm() {
  const [phone, setPhone] = useState('');

  const handlePhoneChange = (event) => {
    setPhone(event.target.value);
  };

  return (
    <SmartPhoneInput
      value={phone}
      onChange={handlePhoneChange}
      className="my-phone-input"
    />
  );
}
```

### Расширенное использование с обработчиками

```jsx
import { SmartPhoneInput } from './components/SmartPhoneInput';

function AdvancedForm() {
  const [phone, setPhone] = useState('');
  const [isValid, setIsValid] = useState(false);
  const [detectedCountry, setDetectedCountry] = useState(null);

  // Обработчик изменения номера телефона
  const handlePhoneChange = (event) => {
    setPhone(event.target.value);
  };

  // Обработчик валидации (вызывается при каждом изменении)
  const handleValidationChange = (status) => {
    setIsValid(status.isValid);
    console.log('Статус валидации:', {
      isValid: status.isValid,        // true/false - можно ли отправлять
      countryCode: status.countryCode, // '998', '7', etc.
      isComplete: status.isComplete    // введен ли полный номер
    });
  };

  // Обработчик определения страны (вызывается при смене кода страны)
  const handleCountryDetected = (country) => {
    setDetectedCountry(country);
    console.log('Определена страна:', {
      countryCode: country.countryCode, // '998', '7', etc.
      isAllowed: country.isAllowed      // разрешен ли для отправки
    });
  };

  return (
    <div>
      <SmartPhoneInput
        value={phone}
        onChange={handlePhoneChange}
        onValidationChange={handleValidationChange}
        onCountryDetected={handleCountryDetected}
        config={{
          allowedCountryCodes: ['998', '7'], // Только Узбекистан и Россия
          defaultCountryCode: '998',         // При фокусе покажет +998
          enableGeolocation: true            // Определять страну автоматически
        }}
        className="form-input"
        inputProps={{
          id: 'phone-field',
          'aria-label': 'Номер телефона',
          required: true
        }}
      />
      
      {/* Индикаторы состояния */}
      {isValid && <span className="valid">✓ Номер корректен для отправки</span>}
      {detectedCountry && (
        <span>
          Страна: {detectedCountry.countryCode} 
          {detectedCountry.isAllowed ? ' ✅' : ' ❌ (не разрешена)'}
        </span>
      )}
    </div>
  );
}
```

## 📋 API Reference

### Props компонента SmartPhoneInput

| Prop | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `value` | `string` | `''` | Текущее значение поля |
| `onChange` | `function` | - | **Обязательный.** Вызывается при изменении значения |
| `placeholder` | `string` | `'+998 99 999 99 99'` | Начальный placeholder |
| `className` | `string` | `''` | CSS класс для стилизации |
| `config` | `object` | `{}` | Конфигурация поведения (см. ниже) |
| `onValidationChange` | `function` | - | Вызывается при изменении статуса валидации |
| `onCountryDetected` | `function` | - | Вызывается при определении страны |
| `inputProps` | `object` | `{}` | Дополнительные props для input элемента |

### Конфигурация (config)

```javascript
const config = {
  // Какие коды стран разрешены для отправки формы
  allowedCountryCodes: ['998', '7', '996'], // По умолчанию: ['998']
  
  // Какой код показывать при фокусе на пустое поле
  defaultCountryCode: '998', // По умолчанию: '998'
  
  // Пытаться ли определить страну автоматически
  enableGeolocation: true, // По умолчанию: true
  
  // Показывать полную маску в placeholder (например: "+998 99 999 99 99")
  showFullMaskPlaceholder: false // По умолчанию: false (показывает только "+998")
};
```

### Что делает каждая настройка:

**`allowedCountryCodes`** - контролирует валидацию:
- Если введен номер с кодом из этого списка → `isValid = true`
- Если код не в списке → `isValid = false` (форму нельзя отправлять)

**`defaultCountryCode`** - что показывать по умолчанию:
- При клике на пустое поле появится этот код
- Пример: если `'7'`, то покажет `+7`

**`enableGeolocation`** - умное определение страны:
- `true` - пытается определить страну пользователя и показать соответствующий placeholder
- `false` - всегда использует `defaultCountryCode`

**`showFullMaskPlaceholder`** - тип placeholder:
- `false` (по умолчанию) - показывает только код страны: `+998`
- `true` - показывает полную маску: `+998 99 999 99 99`

### Обработчик валидации (onValidationChange)

```javascript
const handleValidationChange = (status) => {
  // status - объект с информацией о валидации:
  console.log({
    isValid: status.isValid,      // true/false - можно ли отправлять форму
    countryCode: status.countryCode, // '998', '7', null - определенный код
    value: status.value,          // '+998 90 123 45 67' - текущее значение
    isComplete: status.isComplete // true/false - введен ли полный номер
  });
  
  // Используйте для управления кнопкой отправки:
  setCanSubmit(status.isValid && status.isComplete);
};
```

### Обработчик определения страны (onCountryDetected)

```javascript
const handleCountryDetected = (country) => {
  // country - объект с информацией о стране:
  console.log({
    countryCode: country.countryCode, // '998', '7', '996' etc.
    isAllowed: country.isAllowed      // разрешен ли этот код для отправки
  });
  
  // Используйте для показа сообщений:
  if (!country.isAllowed) {
    showMessage('Этот код страны не поддерживается');
  }
};
```

## 🌍 Поддерживаемые страны

Компонент поддерживает форматирование для следующих стран:

| Страна | Код | Формат | Пример |
|--------|-----|--------|--------|
| Россия/Казахстан | +7 | +7 999 999 99 99| +7 999 123 45 67 |
| Узбекистан | +998 | +998 99 999 99 99| +998 90 123 45 67 |
| Кыргызстан | +996 | +996 999 999 999 | +996 555 123 456 |
| Таджикистан | +992 | +992 99 999 9999 | +992 93 123 4567 |
| Туркменистан | +993 | +993 99 999 999 | +993 65 123 456 |

## 🎨 Стилизация

Компонент не содержит встроенных стилей, что позволяет полностью кастомизировать внешний вид:

```css
/* Базовые стили */
.my-phone-input {
  width: 100%;
  padding: 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 16px;
}

/* Стили при фокусе */
.my-phone-input:focus {
  outline: none;
  border-color: #007bff;
  box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
}

/* Валидный номер */
.my-phone-input.valid {
  border-color: #28a745;
}

/* Невалидный номер */
.my-phone-input.invalid {
  border-color: #dc3545;
}
```

## 🔧 Использование хука отдельно

Если нужна только логика без компонента:

```jsx
import { useSmartPhoneLogic } from './components/SmartPhoneInput';

function CustomPhoneComponent() {
  const {
    formatPhoneNumber,
    isCountryCodeAllowed,
    detectCountryCode
  } = useSmartPhoneLogic({
    allowedCountryCodes: ['998'],
    enableGeolocation: true
  });

  const handleInput = (value) => {
    const formatted = formatPhoneNumber(value);
    const isValid = isCountryCodeAllowed(formatted);
    const country = detectCountryCode(formatted);
    
    // Ваша логика
  };

  return (
    <input
      type="tel"
      onChange={(e) => handleInput(e.target.value)}
    />
  );
}
```

## 🚀 Установка в новый проект

### 1. Скопируйте файлы

Скопируйте папку `SmartPhoneInput` в ваш проект:

```
src/
  components/
    SmartPhoneInput/
      ├── SmartPhoneInput.jsx
      ├── useSmartPhoneLogic.js
      ├── index.js
      └── types.d.ts (для TypeScript)
```

### 2. Импортируйте компонент

```jsx
import { SmartPhoneInput } from './components/SmartPhoneInput';
// или
import SmartPhoneInput from './components/SmartPhoneInput';
```

### 3. Используйте в форме

```jsx
function ContactForm() {
  const [formData, setFormData] = useState({
    name: '',
    phone: '',
    email: ''
  });

  const handlePhoneChange = (event) => {
    setFormData(prev => ({
      ...prev,
      phone: event.target.value
    }));
  };

  const handleSubmit = (event) => {
    event.preventDefault();
    // Отправка формы
    console.log('Отправка:', formData);
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        value={formData.name}
        onChange={(e) => setFormData(prev => ({...prev, name: e.target.value}))}
        placeholder="Имя"
      />
      
      <SmartPhoneInput
        value={formData.phone}
        onChange={handlePhoneChange}
        className="form-control"
      />
      
      <input
        type="email"
        value={formData.email}
        onChange={(e) => setFormData(prev => ({...prev, email: e.target.value}))}
        placeholder="Email"
      />
      
      <button type="submit">Отправить</button>
    </form>
  );
}
```

## 🔍 Примеры интеграции

### Пример 1: Простая форма обратного звонка

```jsx
import { SmartPhoneInput } from './components/SmartPhoneInput';

function CallbackForm() {
  const [formData, setFormData] = useState({
    name: '',
    phone: ''
  });
  const [canSubmit, setCanSubmit] = useState(false);

  const handlePhoneChange = (event) => {
    setFormData(prev => ({
      ...prev,
      phone: event.target.value
    }));
  };

  const handleValidation = (status) => {
    // Кнопка активна только если номер валиден и полный
    setCanSubmit(status.isValid && status.isComplete && formData.name.trim());
  };

  const handleSubmit = (event) => {
    event.preventDefault();
    if (canSubmit) {
      console.log('Отправка:', formData);
      // Здесь ваша логика отправки
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        value={formData.name}
        onChange={(e) => setFormData(prev => ({...prev, name: e.target.value}))}
        placeholder="Ваше имя"
        required
      />
      
      <SmartPhoneInput
        value={formData.phone}
        onChange={handlePhoneChange}
        onValidationChange={handleValidation}
        className="phone-input"
      />
      
      <button type="submit" disabled={!canSubmit}>
        Заказать звонок
      </button>
    </form>
  );
}
```

### Пример 2: Форма с ограничениями по странам

```jsx
// Разрешить только Узбекистан и Россию
function RestrictedForm() {
  const [phone, setPhone] = useState('');
  const [error, setError] = useState('');

  const handleValidation = (status) => {
    if (status.value && !status.isValid) {
      setError('Поддерживаются только номера Узбекистана (+998) и России (+7)');
    } else {
      setError('');
    }
  };

  return (
    <div>
      <SmartPhoneInput
        value={phone}
        onChange={(e) => setPhone(e.target.value)}
        onValidationChange={handleValidation}
        config={{
          allowedCountryCodes: ['998', '7'], // Только эти коды
          defaultCountryCode: '998'
        }}
      />
      {error && <div className="error">{error}</div>}
    </div>
  );
}
```

### Пример 3: Отключение геолокации

```jsx
// Всегда показывать +998, не определять страну автоматически
function SimpleForm() {
  const [phone, setPhone] = useState('');

  return (
    <SmartPhoneInput
      value={phone}
      onChange={(e) => setPhone(e.target.value)}
      config={{
        enableGeolocation: false, // Отключить автоопределение
        defaultCountryCode: '998'
      }}
    />
  );
}
```

### Пример 4: Многострановая поддержка

```jsx
// Поддержка всех доступных стран
function InternationalForm() {
  const [phone, setPhone] = useState('');
  const [countryInfo, setCountryInfo] = useState('');

  const handleCountryDetected = (country) => {
    const countryNames = {
      '7': 'Россия/Казахстан',
      '998': 'Узбекистан',
      '996': 'Кыргызстан',
      '992': 'Таджикистан',
      '993': 'Туркменистан'
    };
    
    setCountryInfo(countryNames[country.countryCode] || 'Неизвестная страна');
  };

  return (
    <div>
      <SmartPhoneInput
        value={phone}
        onChange={(e) => setPhone(e.target.value)}
        onCountryDetected={handleCountryDetected}
        config={{
          allowedCountryCodes: ['7', '998', '996', '992', '993'], // Все страны
          defaultCountryCode: '998'
        }}
      />
      {countryInfo && <small>Определена страна: {countryInfo}</small>}
    </div>
  );
}

### С React Hook Form

```jsx
import { useForm, Controller } from 'react-hook-form';
import { SmartPhoneInput } from './components/SmartPhoneInput';

function FormWithValidation() {
  const { control, handleSubmit, formState: { errors } } = useForm();

  const onSubmit = (data) => {
    console.log('Данные формы:', data);
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <Controller
        name="phone"
        control={control}
        rules={{ required: 'Номер телефона обязателен' }}
        render={({ field }) => (
          <SmartPhoneInput
            {...field}
            className={errors.phone ? 'error' : ''}
          />
        )}
      />
      {errors.phone && <span className="error">{errors.phone.message}</span>}
      
      <button type="submit">Отправить</button>
    </form>
  );
}
```

### С Formik

```jsx
import { Formik, Field } from 'formik';
import { SmartPhoneInput } from './components/SmartPhoneInput';

function FormikForm() {
  return (
    <Formik
      initialValues={{ phone: '' }}
      onSubmit={(values) => console.log(values)}
    >
      {({ setFieldValue, values }) => (
        <Form>
          <SmartPhoneInput
            value={values.phone}
            onChange={(e) => setFieldValue('phone', e.target.value)}
          />
          <button type="submit">Отправить</button>
        </Form>
      )}
    </Formik>
  );
}
```

## 🌐 Геолокация

Компонент использует многоуровневую систему определения страны:

1. **IP-геолокация** (ipapi.co)
2. **GPS браузера** (navigator.geolocation)
3. **Обратное геокодирование** (bigdatacloud.net, geocode.xyz)
4. **Fallback** на страну по умолчанию

Для отключения геолокации:

```jsx
<SmartPhoneInput
  config={{ enableGeolocation: false }}
  // ...остальные props
/>
```

## 📱 Мобильная оптимизация

Компонент автоматически устанавливает `type="tel"`, что включает числовую клавиатуру на мобильных устройствах.

## 🔐 Безопасность

- Все внешние API запросы обрабатывают ошибки
- Геолокация запрашивается с тайм-аутом
- Нет сохранения персональных данных
- Валидация происходит только на клиенте

## 🤝 Совместимость

- React 16.8+ (для хуков)
- Современные браузеры с поддержкой fetch API
- TypeScript (опционально, типы включены)

## 📋 TODO / Будущие улучшения

- [ ] Добавить поддержку больше стран
- [ ] Кэширование результатов геолокации
- [ ] Offline режим
- [ ] Анимации переходов placeholder
- [ ] A11y улучшения
