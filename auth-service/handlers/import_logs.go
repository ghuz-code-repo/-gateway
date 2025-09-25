package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"auth-service/models"
)

// ShowImportLogsPage displays the import logs page
func ShowImportLogsPage(c *gin.Context) {
	// Get pagination parameters
	page := 1
	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	limit := 20
	skip := (page - 1) * limit

	// Get logs
	logs, err := models.GetImportLogs(limit, skip)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"title": "Ошибка",
			"error": "Не удалось загрузить логи импорта",
		})
		return
	}

	// Render page
	c.HTML(http.StatusOK, "import_logs.html", gin.H{
		"title":       "Логи импорта пользователей",
		"logs":        logs,
		"currentPage": page,
		"nextPage":    page + 1,
		"prevPage":    page - 1,
		"hasPrev":     page > 1,
		"hasNext":     len(logs) == limit,
	})
}

// ShowImportLogDetails displays detailed information about a specific import log
func ShowImportLogDetails(c *gin.Context) {
	// Get log ID from URL
	idStr := c.Param("id")
	logID, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"title": "Ошибка",
			"error": "Неверный ID лога",
		})
		return
	}

	// Get log details
	log, err := models.GetImportLogByID(logID.Hex())
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"title": "Ошибка",
			"error": "Лог не найден",
		})
		return
	}

	// Render details page
	c.HTML(http.StatusOK, "import_log_details.html", gin.H{
		"title": "Детали импорта",
		"log":   log,
	})
}