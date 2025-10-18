#!/usr/bin/env python3
"""
Скрипт для получения Telegram Chat ID
Использование:
1. Напишите боту /start в Telegram
2. Запустите этот скрипт с токеном бота
3. Скопируйте Chat ID и используйте его в настройках
"""

import sys
import requests

def get_updates(bot_token):
    """Получить последние обновления от бота"""
    url = f"https://api.telegram.org/bot{bot_token}/getUpdates"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        if not data.get('ok'):
            print(f"❌ Ошибка API: {data.get('description', 'Unknown error')}")
            return
        
        updates = data.get('result', [])
        
        if not updates:
            print("⚠️  Нет новых сообщений. Пожалуйста:")
            print("   1. Откройте Telegram")
            print("   2. Найдите своего бота")
            print("   3. Напишите /start")
            print("   4. Запустите этот скрипт снова")
            return
        
        print("📱 Найденные чаты:\n")
        seen_chats = set()
        
        for update in updates:
            message = update.get('message', {})
            chat = message.get('chat', {})
            
            if not chat:
                continue
            
            chat_id = chat.get('id')
            if chat_id in seen_chats:
                continue
            
            seen_chats.add(chat_id)
            
            chat_type = chat.get('type', 'unknown')
            first_name = chat.get('first_name', '')
            last_name = chat.get('last_name', '')
            username = chat.get('username', '')
            title = chat.get('title', '')
            
            print(f"Chat ID: {chat_id}")
            print(f"  Тип: {chat_type}")
            
            if chat_type == 'private':
                name = f"{first_name} {last_name}".strip()
                print(f"  Имя: {name}")
                if username:
                    print(f"  Username: @{username}")
            elif title:
                print(f"  Название: {title}")
            
            print()
        
        print("\n✅ Используйте Chat ID (число) в настройках вместо username!")
        print("   Например: system_telegram_username = '12345678' (без @)")
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Ошибка при запросе к API: {e}")
    except Exception as e:
        print(f"❌ Неожиданная ошибка: {e}")

def main():
    print("🤖 Telegram Chat ID Finder\n")
    
    if len(sys.argv) > 1:
        bot_token = sys.argv[1]
    else:
        bot_token = input("Введите токен бота: ").strip()
    
    if not bot_token:
        print("❌ Токен бота не может быть пустым")
        sys.exit(1)
    
    get_updates(bot_token)

if __name__ == "__main__":
    main()
