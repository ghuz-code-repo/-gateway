/**
 * Конфигурация для умного поля ввода телефонных номеров
 * Адаптировано из React компонента SmartPhoneInput
 */

window.PhoneConfig = {
    defaultCountryCode: "998",
    allowedCountryCodes: [
        "998"  // Только Узбекистан полностью поддерживается
    ],
    countryPhoneConfig: {
        "993": {
            name: "Туркменистан",
            format: "+993 XX XX XX XX",
            maxLength: 13,
            pattern: /^993\d{8}$/
        },
        "380": {
            name: "Украина",
            format: "+380 XX XXX XX XX",
            maxLength: 13,
            pattern: /^380\d{9}$/
        },
        "375": {
            name: "Беларусь",
            format: "+375 XX XXX XX XX",
            maxLength: 13,
            pattern: /^375\d{9}$/
        },
        "49": {
            name: "Германия",
            format: "+49 XXX XXXXXXX",
            maxLength: 15,
            pattern: /^49\d{10,11}$/
        },
        "33": {
            name: "Франция",
            format: "+33 X XX XX XX XX",
            maxLength: 13,
            pattern: /^33\d{9}$/
        },
        "44": {
            name: "Великобритания",
            format: "+44 XX XXXX XXXX",
            maxLength: 13,
            pattern: /^44\d{10}$/
        },
        "1": {
            name: "США/Канада",
            format: "+1 XXX XXX XXXX",
            maxLength: 12,
            pattern: /^1\d{10}$/
        },
        "7": {
            name: "Россия/Казахстан",
            format: "+7 XXX XXX XX XX",
            maxLength: 12,
            pattern: /^7\d{10}$/
        },
        "998": {
            name: "Узбекистан", 
            format: "+998 XX XXX XX XX",
            displayFormat: "+998 99 999 99 99",
            maxLength: 13,
            pattern: /^998\d{9}$/
        },
        "996": {
            name: "Кыргызстан",
            format: "+996 XXX XX XX XX",
            maxLength: 13,
            pattern: /^996\d{9}$/
        },
        "992": {
            name: "Таджикистан",
            format: "+992 XX XXX XX XX",
            maxLength: 13,
            pattern: /^992\d{9}$/
        }
    },
    countryIsoToPhoneCode: {
        "UZ": "998",
        "RU": "7",
        "KZ": "7",
        "KG": "996",
        "TJ": "992",
        "TM": "993",
        "UA": "380",
        "BY": "375",
        "DE": "49",
        "US": "1",
        "CN": "86",
        "FR": "33",
        "GB": "44"
    }
};