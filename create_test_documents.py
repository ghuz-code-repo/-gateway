#!/usr/bin/env python3
"""
Скрипт для создания тестовых документов в auth-service
"""
import requests
import json

def create_test_documents():
    """Создает тестовые документы для пользователя"""
    
    # URL для создания документов (требует авторизации)
    base_url = "http://localhost"
    
    # Данные для создания документов
    test_documents = [
        {
            "document_type": "ПИНФЛ",
            "title": "Справка ПИНФЛ",
            "fields": {
                "pinfl": "12345678901234",
                "full_name": "Продгарай Тестовый",
                "birth_date": "1990-01-01"
            }
        },
        {
            "document_type": "Паспорт",
            "title": "Паспортные данные",
            "fields": {
                "series": "AA",
                "number": "1234567",
                "issued_by": "Тестовое ОАЭП",
                "issued_date": "2020-01-01"
            }
        },
        {
            "document_type": "Банковские данные",
            "title": "Банковские реквизиты",
            "fields": {
                "bank_name": "Тестовый Банк",
                "account": "12345678901234567890",
                "mfo": "00999"
            }
        }
    ]
    
    print("Создание тестовых документов...")
    
    for doc_data in test_documents:
        try:
            # Создание документа
            response = requests.post(
                f"{base_url}/profile/documents",
                json=doc_data,
                cookies={"token": "your_token_here"},  # Замените на реальный токен
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 201:
                result = response.json()
                doc_id = result.get('document_id')
                print(f"✅ Документ '{doc_data['title']}' создан с ID: {doc_id}")
                
                # Здесь можно добавить загрузку файлов, если нужно
                # upload_test_file(doc_id, doc_data['document_type'])
                
            else:
                print(f"❌ Ошибка создания документа '{doc_data['title']}': {response.status_code}")
                print(f"Response: {response.text}")
                
        except Exception as e:
            print(f"❌ Исключение при создании '{doc_data['title']}': {e}")

def upload_test_file(doc_id, doc_type):
    """Загружает тестовый файл к документу"""
    # Создаем тестовый файл в памяти
    test_content = f"""Тестовый документ: {doc_type}
Это содержимое тестового файла для демонстрации функциональности загрузки документов.
Дата создания: 2024-09-29
"""
    
    files = {'file': (f'{doc_type.lower()}.txt', test_content, 'text/plain')}
    
    try:
        response = requests.post(
            f"http://localhost/profile/documents/{doc_id}/attachments",
            files=files,
            cookies={"token": "your_token_here"}  # Замените на реальный токен
        )
        
        if response.status_code == 200:
            print(f"✅ Файл для документа {doc_type} загружен")
        else:
            print(f"❌ Ошибка загрузки файла для {doc_type}: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Исключение при загрузке файла: {e}")

if __name__ == "__main__":
    print("Тестовый скрипт для создания документов")
    print("ВНИМАНИЕ: Требует действительный токен авторизации!")
    print("Для запуска нужно:")
    print("1. Войти в систему через браузер")
    print("2. Скопировать токен из cookie")
    print("3. Заменить 'your_token_here' на реальный токен")
    print()
    
    # create_test_documents()  # Раскомментируйте когда будет готов токен