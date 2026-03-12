package handlers

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/xuri/excelize/v2"

	"auth-service/models"
)

// ExportUsersToExcel creates an Excel file with users and services data
func ExportUsersToExcel(c *gin.Context) {
	// Get current user for logging
	currentUser, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	user := currentUser.(*models.User)
	log.Printf("User %s requested Excel export", user.Username)

	// Get users data
	users, err := models.GetUsersForExport()
	if err != nil {
		log.Printf("Error getting users for export: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get users data"})
		return
	}

	// Get services data
	services, err := models.GetServicesForExport()
	if err != nil {
		log.Printf("Error getting services for export: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get services data"})
		return
	}

	// Create Excel file
	file := excelize.NewFile()
	defer file.Close()

	// Create Users sheet
	err = createUsersSheet(file, users, services)
	if err != nil {
		log.Printf("Error creating users sheet: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create users sheet"})
		return
	}

	// Create Services sheet
	err = createServicesSheet(file, services)
	if err != nil {
		log.Printf("Error creating services sheet: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create services sheet"})
		return
	}

	// Reference sheets removed - using Services sheet only

	// Set active sheet to Users
	file.SetActiveSheet(0)

	// Generate file content
	var buffer bytes.Buffer
	err = file.Write(&buffer)
	if err != nil {
		log.Printf("Error writing Excel file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate Excel file"})
		return
	}

	// Set response headers
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("users_export_%s.xlsx", timestamp)

	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	c.Data(http.StatusOK, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", buffer.Bytes())

	log.Printf("Excel export completed for user %s, file: %s", user.Username, filename)
}

// createUsersSheet creates the Users sheet with user data and service roles
func createUsersSheet(file *excelize.File, users []models.UserImportExport, services []models.ServiceInfo) error {
	sheetName := "Users"

	// Rename default sheet
	file.SetSheetName("Sheet1", sheetName)

	// Create headers
	baseHeaders := []string{
		"ID", "Имя пользователя", "Email", "Фамилия", "Имя", "Отчество", "Частица",
		"Телефон", "Отдел", "Должность", "Пароль", "Забанен", "Удалить",
	}

	// Add service headers
	serviceHeaders := make([]string, len(services))
	serviceMap := make(map[string]int)          // service key -> column index
	serviceKeyToName := make(map[string]string) // service key -> service name

	for i, service := range services {
		serviceHeaders[i] = service.Key // Use Key for headers to match import logic
		serviceMap[service.Key] = len(baseHeaders) + i
		serviceKeyToName[service.Key] = service.Name
	}

	allHeaders := append(baseHeaders, serviceHeaders...)

	// Set headers
	for i, header := range allHeaders {
		cell := fmt.Sprintf("%s1", getColumnName(i+1))
		file.SetCellValue(sheetName, cell, header)
	}

	// Style headers
	headerStyle, _ := file.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"CCCCCC"}, Pattern: 1},
	})

	file.SetCellStyle(sheetName, "A1", fmt.Sprintf("%s1", getColumnName(len(allHeaders))), headerStyle)

	// Fill user data
	for i, user := range users {
		row := i + 2

		// Basic user data
		file.SetCellValue(sheetName, fmt.Sprintf("A%d", row), user.ID)
		file.SetCellValue(sheetName, fmt.Sprintf("B%d", row), user.Username)
		file.SetCellValue(sheetName, fmt.Sprintf("C%d", row), user.Email)
		file.SetCellValue(sheetName, fmt.Sprintf("D%d", row), user.LastName)
		file.SetCellValue(sheetName, fmt.Sprintf("E%d", row), user.FirstName)
		file.SetCellValue(sheetName, fmt.Sprintf("F%d", row), user.MiddleName)
		file.SetCellValue(sheetName, fmt.Sprintf("G%d", row), user.Suffix)
		file.SetCellValue(sheetName, fmt.Sprintf("H%d", row), user.Phone)
		file.SetCellValue(sheetName, fmt.Sprintf("I%d", row), user.Department)
		file.SetCellValue(sheetName, fmt.Sprintf("J%d", row), user.Position)
		file.SetCellValue(sheetName, fmt.Sprintf("K%d", row), "") // Пароль - пустое поле

		file.SetCellValue(sheetName, fmt.Sprintf("L%d", row), user.Banned)     // Забанен
		file.SetCellValue(sheetName, fmt.Sprintf("M%d", row), user.DeleteUser) // Удалить

		// Service roles
		for serviceKey, roles := range user.ServiceRoles {
			if colIndex, exists := serviceMap[serviceKey]; exists {
				cell := fmt.Sprintf("%s%d", getColumnName(colIndex+1), row)
				file.SetCellValue(sheetName, cell, roles)
			}
		}
	}

	// Auto-fit columns
	for i := range allHeaders {
		colName := getColumnName(i + 1)
		file.SetColWidth(sheetName, colName, colName, 15)
	}

	return nil
}

// createServicesSheet creates the Services sheet with services and their roles
func createServicesSheet(file *excelize.File, services []models.ServiceInfo) error {
	sheetName := "Services"
	file.NewSheet(sheetName)

	// Headers
	file.SetCellValue(sheetName, "A1", "Название сервиса")
	file.SetCellValue(sheetName, "B1", "Ключ сервиса")
	file.SetCellValue(sheetName, "C1", "Описание")
	file.SetCellValue(sheetName, "D1", "Доступные роли")

	// Style headers
	headerStyle, _ := file.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"CCCCCC"}, Pattern: 1},
	})
	file.SetCellStyle(sheetName, "A1", "D1", headerStyle)

	// Fill services data
	for i, service := range services {
		row := i + 2
		file.SetCellValue(sheetName, fmt.Sprintf("A%d", row), service.Name)
		file.SetCellValue(sheetName, fmt.Sprintf("B%d", row), service.Key)
		file.SetCellValue(sheetName, fmt.Sprintf("C%d", row), service.Description)
		file.SetCellValue(sheetName, fmt.Sprintf("D%d", row), strings.Join(service.Roles, ", "))
	}

	// Auto-fit columns
	file.SetColWidth(sheetName, "A", "A", 20)
	file.SetColWidth(sheetName, "B", "B", 15)
	file.SetColWidth(sheetName, "C", "C", 30)
	file.SetColWidth(sheetName, "D", "D", 40)

	return nil
}

// getColumnName converts column index to Excel column name (1->A, 2->B, 27->AA, etc.)
func getColumnName(colIndex int) string {
	result := ""
	for colIndex > 0 {
		colIndex--
		result = string(rune('A'+colIndex%26)) + result
		colIndex /= 26
	}
	return result
}

// DownloadUsersTemplate creates and downloads an empty template for user import
func DownloadUsersTemplate(c *gin.Context) {
	// Get services for template
	services, err := models.GetServicesForExport()
	if err != nil {
		log.Printf("Error getting services for template: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get services data"})
		return
	}

	// Create Excel file
	file := excelize.NewFile()
	defer file.Close()

	// Create empty users sheet with headers only
	err = createUsersSheet(file, []models.UserImportExport{}, services)
	if err != nil {
		log.Printf("Error creating template users sheet: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create template"})
		return
	}

	// Create services sheet
	err = createServicesSheet(file, services)
	if err != nil {
		log.Printf("Error creating template services sheet: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create services sheet"})
		return
	}

	// Reference sheets removed - using Services sheet only

	// Add example user
	file.SetCellValue("Users", "A2", "")
	file.SetCellValue("Users", "B2", "new_user")
	file.SetCellValue("Users", "C2", "new_user@example.com")
	file.SetCellValue("Users", "D2", "Иванов")
	file.SetCellValue("Users", "E2", "Иван")
	file.SetCellValue("Users", "F2", "Иванович")
	file.SetCellValue("Users", "G2", "Jr.")
	file.SetCellValue("Users", "H2", "+7 (999) 123-45-67")
	file.SetCellValue("Users", "I2", "IT отдел")
	file.SetCellValue("Users", "J2", "Разработчик")
	file.SetCellValue("Users", "K2", "")      // Пароль - пустое поле (будет сгенерирован автоматически)
	file.SetCellValue("Users", "L2", "false") // Забанен - false по умолчанию
	file.SetCellValue("Users", "M2", "false") // Удалить - false по умолчанию

	// Add example roles for services (if any)
	if len(services) > 0 {
		file.SetCellValue("Users", "N2", "admin,editor") // Example for first service (now column N)
	}

	// Set active sheet to Users
	file.SetActiveSheet(0)

	// Generate file content
	var buffer bytes.Buffer
	err = file.Write(&buffer)
	if err != nil {
		log.Printf("Error writing template file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate template"})
		return
	}

	// Set response headers
	filename := "users_template.xlsx"

	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	c.Data(http.StatusOK, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", buffer.Bytes())

	log.Printf("Template download completed")
}
