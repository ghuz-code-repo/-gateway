package routes

import (
	"auth-service/models"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User API structures
type CreateUserRequest struct {
	Username  string   `json:"username" binding:"required"`
	Password  string   `json:"password" binding:"required"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	IsActive  bool     `json:"is_active"`
	FullName  string   `json:"full_name"`
}

type UpdateUserRequest struct {
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
	IsActive *bool    `json:"is_active"`
	FullName string   `json:"full_name"`
}

type UserResponse struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
	IsActive bool     `json:"is_active"`
	FullName string   `json:"full_name"`
}

// ListUsersAPI возвращает список пользователей
func ListUsersAPI(c *gin.Context) {
	users, err := models.GetAllUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve users",
			"details": err.Error(),
		})
		return
	}

	var response []UserResponse
	for _, user := range users {
		response = append(response, UserResponse{
			ID:       user.ID.Hex(),
			Username: user.Username,
			Email:    user.Email,
			Roles:    user.Roles,
			IsActive: user.IsActive,
			FullName: user.FullName,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"users": response,
	})
}

// CreateUserAPI создает нового пользователя
func CreateUserAPI(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	// Проверяем, существует ли пользователь
	existingUser, _ := models.GetUserByUsername(req.Username)
	if existingUser != nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "User with this username already exists",
		})
		return
	}

	// Создаем пользователя
	userID, err := models.CreateUser(req.Username, req.Email, req.Password, req.FullName, req.Roles)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create user",
			"details": err.Error(),
		})
		return
	}

	response := UserResponse{
		ID:       userID.Hex(),
		Username: req.Username,
		Email:    req.Email,
		Roles:    req.Roles,
		IsActive: req.IsActive,
		FullName: req.FullName,
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User created successfully",
		"user":    response,
	})
}

// GetUserAPI возвращает информацию о пользователе по ID
func GetUserAPI(c *gin.Context) {
	userID := c.Param("id")
	
	_, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID format",
		})
		return
	}

	user, err := models.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
		})
		return
	}

	response := UserResponse{
		ID:       user.ID.Hex(),
		Username: user.Username,
		Email:    user.Email,
		Roles:    user.Roles,
		IsActive: user.IsActive,
		FullName: user.FullName,
	}

	c.JSON(http.StatusOK, gin.H{
		"user": response,
	})
}

// UpdateUserAPI обновляет информацию о пользователе
func UpdateUserAPI(c *gin.Context) {
	userID := c.Param("id")
	
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID format",
		})
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	// Получаем существующего пользователя
	user, err := models.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
		})
		return
	}

	// Обновляем поля
	email := user.Email
	roles := user.Roles
	isActive := user.IsActive
	fullName := user.FullName

	if req.Email != "" {
		email = req.Email
	}
	if req.Roles != nil {
		roles = req.Roles
	}
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	if req.FullName != "" {
		fullName = req.FullName
	}

	err = models.UpdateUser(objectID, user.Username, email, "", fullName, roles)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update user",
			"details": err.Error(),
		})
		return
	}

	response := UserResponse{
		ID:       user.ID.Hex(),
		Username: user.Username,
		Email:    email,
		Roles:    roles,
		IsActive: isActive,
		FullName: fullName,
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User updated successfully",
		"user":    response,
	})
}

// DeleteUserAPI удаляет пользователя
func DeleteUserAPI(c *gin.Context) {
	userID := c.Param("id")
	
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID format",
		})
		return
	}

	err = models.DeleteUser(objectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete user",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User deleted successfully",
	})
}
