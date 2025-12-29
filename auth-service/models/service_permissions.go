package models

import (
	"strings"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Service management permissions - для управления сервисами через auth-service
const (
	// User management permissions
	PermServiceUsersAdd    = "service.users.add"    // Добавление пользователей в сервис
	PermServiceUsersRemove = "service.users.remove" // Удаление пользователей из сервиса
	PermServiceUsersView   = "service.users.view"   // Просмотр списка пользователей
	PermServiceUsersExport = "service.users.export" // Экспорт списка пользователей
	PermServiceUsersImport = "service.users.import" // Импорт пользователей

	// Role assignment permissions
	PermServiceRolesAssign   = "service.roles.assign"   // Назначение ролей пользователям
	PermServiceRolesUnassign = "service.roles.unassign" // Снятие ролей с пользователей

	// Role management permissions
	PermServiceRolesCreate = "service.roles.create" // Создание новых ролей
	PermServiceRolesEdit   = "service.roles.edit"   // Редактирование ролей
	PermServiceRolesDelete = "service.roles.delete" // Удаление ролей
	PermServiceRolesView   = "service.roles.view"   // Просмотр ролей

	// Permission management
	PermServicePermissionsManage = "service.permissions.manage" // Управление разрешениями сервиса
	PermServicePermissionsSync   = "service.permissions.sync"   // Синхронизация разрешений с сервисом

	// Service settings
	PermServiceSettingsEdit = "service.settings.edit" // Изменение настроек сервиса
	PermServiceSettingsView = "service.settings.view" // Просмотр настроек сервиса

	// Full access (для обратной совместимости)
	PermServiceManageFull = "service.manage.full" // Полный доступ к управлению сервисом
)

// ServiceManagementPermissions - список всех разрешений для управления сервисами
var ServiceManagementPermissions = []string{
	PermServiceUsersAdd,
	PermServiceUsersRemove,
	PermServiceUsersView,
	PermServiceUsersExport,
	PermServiceUsersImport,
	PermServiceRolesAssign,
	PermServiceRolesUnassign,
	PermServiceRolesCreate,
	PermServiceRolesEdit,
	PermServiceRolesDelete,
	PermServiceRolesView,
	PermServicePermissionsManage,
	PermServicePermissionsSync,
	PermServiceSettingsEdit,
	PermServiceSettingsView,
	PermServiceManageFull,
}

// HasServicePermission проверяет, есть ли у пользователя конкретное разрешение в сервисе
func HasServicePermission(userID primitive.ObjectID, serviceKey string, permission string) bool {
	// Получаем роли пользователя в сервисе
	userServiceRoles, err := GetUserServiceRolesByUserID(userID)
	if err != nil {
		return false
	}

	// Проверяем каждую роль пользователя в этом сервисе
	for _, userRole := range userServiceRoles {
		if userRole.ServiceKey != serviceKey || !userRole.IsActive {
			continue
		}

		// Получаем детали роли
		role, err := GetRoleByServiceAndName(serviceKey, userRole.RoleName)
		if err != nil || role == nil {
			continue
		}

		// Проверяем разрешения роли
		for _, perm := range role.Permissions {
			// Точное совпадение
			if perm == permission {
				return true
			}

			// Полный доступ
			if perm == PermServiceManageFull {
				return true
			}

			// Wildcard разрешения (например, "service.users.*" покрывает "service.users.add")
			if strings.HasSuffix(perm, ".*") {
				prefix := strings.TrimSuffix(perm, "*")
				if strings.HasPrefix(permission, prefix) {
					return true
				}
			}
		}
	}

	return false
}

// GetUserServiceManagementPermissions возвращает разрешения на управление сервисом (через auth-service)
func GetUserServiceManagementPermissions(userID primitive.ObjectID, serviceKey string) []string {
	permissionsMap := make(map[string]bool)

	// Получаем роли пользователя в сервисе
	userServiceRoles, err := GetUserServiceRolesByUserID(userID)
	if err != nil {
		return []string{}
	}

	// Собираем все разрешения из всех ролей
	for _, userRole := range userServiceRoles {
		if userRole.ServiceKey != serviceKey || !userRole.IsActive {
			continue
		}

		role, err := GetRoleByServiceAndName(serviceKey, userRole.RoleName)
		if err != nil || role == nil {
			continue
		}

		for _, perm := range role.Permissions {
			permissionsMap[perm] = true
		}
	}

	// Преобразуем map в slice
	permissions := make([]string, 0, len(permissionsMap))
	for perm := range permissionsMap {
		permissions = append(permissions, perm)
	}

	return permissions
}
