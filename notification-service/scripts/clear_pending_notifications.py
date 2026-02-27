#!/usr/bin/env python3
"""
Скрипт для очистки ожидающих уведомлений в notification-service
Удаляет все pending и failed уведомления из PostgreSQL
"""

import argparse
import subprocess

# Цвета для вывода
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    NC = '\033[0m'


def clear_notifications(ssh_host: str, postgres_container: str, db_name: str, dry_run: bool = False):
    """Очистить pending уведомления через SSH"""
    
    print(f"{Colors.GREEN}========================================{Colors.NC}")
    print(f"{Colors.GREEN}Очистка ожидающих уведомлений{Colors.NC}")
    print(f"{Colors.GREEN}========================================{Colors.NC}")
    print()
    print(f"SSH: {ssh_host}")
    print(f"PostgreSQL контейнер: {postgres_container}")
    print(f"База данных: {db_name}")
    
    if dry_run:
        print(f"{Colors.YELLOW}Режим: DRY RUN (только показать статистику){Colors.NC}")
    print()
    
    # SQL для показа статистики
    stats_sql = """
    SELECT 
        status, 
        COUNT(*) as count,
        TO_TIMESTAMP(MIN(created_at)) as oldest,
        TO_TIMESTAMP(MAX(created_at)) as newest
    FROM notifications 
    GROUP BY status
    ORDER BY count DESC;
    """
    
    print(f"{Colors.YELLOW}📊 Получение статистики...{Colors.NC}")
    
    ssh_cmd = ['ssh', ssh_host, 
               f"docker exec -i {postgres_container} psql -U postgres -d {db_name} -c \"{stats_sql}\""]
    
    try:
        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            check=True
        )
        print(result.stdout)
        
    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}❌ Ошибка подключения к PostgreSQL: {e}{Colors.NC}")
        print(f"Stderr: {e.stderr}")
        return False
    
    if dry_run:
        print(f"{Colors.YELLOW}🔍 DRY RUN: Уведомления НЕ будут удалены{Colors.NC}")
        return True
    
    # Подтверждение
    confirm = input(f"\n❓ Удалить все pending и failed уведомления? (yes/no): ")
    if confirm.lower() != 'yes':
        print(f"{Colors.YELLOW}⚠️  Отменено пользователем{Colors.NC}")
        return False
    
    # SQL для удаления
    delete_sql = """
    DELETE FROM notifications 
    WHERE status IN ('pending', 'failed');
    """
    
    print(f"\n{Colors.GREEN}🗑️  Удаление pending и failed уведомлений...{Colors.NC}")
    
    ssh_cmd = ['ssh', ssh_host,
               f"docker exec -i {postgres_container} psql -U postgres -d {db_name} -c \"{delete_sql}\""]
    
    try:
        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            check=True
        )
        print(result.stdout)
        
        # Показать результат
        print(f"\n{Colors.YELLOW}📊 Статистика после удаления:{Colors.NC}")
        result = subprocess.run(
            ['ssh', ssh_host, 
             f"docker exec -i {postgres_container} psql -U postgres -d {db_name} -c \"{stats_sql}\""],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            check=True
        )
        print(result.stdout)
        
        print(f"{Colors.GREEN}✅ Очистка завершена!{Colors.NC}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}❌ Ошибка удаления: {e}{Colors.NC}")
        print(f"Stderr: {e.stderr}")
        return False


def main():
    parser = argparse.ArgumentParser(description='Очистка ожидающих уведомлений')
    parser.add_argument('--ssh-host', type=str, default='gh_prod', help='SSH host/алиас (по умолчанию gh_prod)')
    parser.add_argument('--postgres-container', type=str, default='gateway-postgres-1', help='Имя PostgreSQL контейнера (по умолчанию gateway-postgres-1)')
    parser.add_argument('--db-name', type=str, default='notification_db', help='Имя базы данных (по умолчанию notification_db)')
    parser.add_argument('--dry-run', action='store_true', help='Только показать статистику')
    
    args = parser.parse_args()
    
    clear_notifications(args.ssh_host, args.postgres_container, args.db_name, args.dry_run)


if __name__ == '__main__':
    main()
