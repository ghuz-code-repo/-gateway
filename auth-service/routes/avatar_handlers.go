package routes

import (
	"auth-service/models"
	"fmt"
	"image"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/disintegration/imaging"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// uploadAvatarHandler handles avatar upload
func uploadAvatarHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	// Parse multipart form with 10MB limit
	err := c.Request.ParseMultipartForm(10 << 20) // 10MB
	if err != nil {
		log.Printf("Failed to parse multipart form: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse form data"})
		return
	}

	// Check if this is a crop update or new file upload FIRST
	cropUpdateValue := c.PostForm("crop_update")
	isCropUpdate := cropUpdateValue == "true"

	// If this is a crop update, handle it differently
	if isCropUpdate {
		// Handle crop update logic here
		handleCropUpdate(c, user)
		return
	}

	// Continue with original file upload logic

	var originalPath, croppedPath string
	var ext string
	userDataDir := fmt.Sprintf("./data/%s", user.ID.Hex())

	if isCropUpdate {
		// This is a crop update of existing image
		log.Printf("Processing crop update for existing avatar")

		// Check if user has an original avatar file
		if user.OriginalAvatarPath == "" {
			log.Printf("No original avatar found for crop update")
			c.JSON(http.StatusBadRequest, gin.H{"error": "No original avatar found for cropping"})
			return
		}

		// Use existing original file
		originalPath = "." + user.OriginalAvatarPath
		if _, err := os.Stat(originalPath); os.IsNotExist(err) {
			log.Printf("Original avatar file not found: %s", originalPath)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Original avatar file not found"})
			return
		}

		// Determine extension and cropped path from existing avatar
		ext = strings.ToLower(filepath.Ext(user.OriginalAvatarPath))
		croppedFilename := "avatar" + ext
		croppedPath = filepath.Join(userDataDir, croppedFilename)
	} else {
		// This is a new file upload
		log.Printf("Processing new file upload")

		file, fileHeader, err := c.Request.FormFile("avatar")
		if err != nil {
			log.Printf("Failed to get avatar file: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "MODIFIED VERSION: No avatar file provided"})
			return
		}
		defer file.Close()

		// Validate file size (10MB max)
		if fileHeader.Size > 10*1024*1024 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "File size exceeds 10MB limit"})
			return
		}

		// Validate file type
		filename := fileHeader.Filename
		ext = strings.ToLower(filepath.Ext(filename))
		if ext != ".jpg" && ext != ".jpeg" && ext != ".png" && ext != ".gif" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Only JPG, JPEG, PNG, and GIF files are allowed"})
			return
		}

		// Create user data directory if it doesn't exist
		if err := os.MkdirAll(userDataDir, 0755); err != nil {
			log.Printf("Failed to create user data directory: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create upload directory"})
			return
		}

		// Use fixed filenames: original.jpg and avatar.jpg
		originalFilename := "original" + ext
		croppedFilename := "avatar" + ext

		originalPath = filepath.Join(userDataDir, originalFilename)
		croppedPath = filepath.Join(userDataDir, croppedFilename)

		// Save original file
		outFile, err := os.Create(originalPath)
		if err != nil {
			log.Printf("Failed to create avatar file: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save avatar"})
			return
		}
		defer outFile.Close()

		_, err = io.Copy(outFile, file)
		if err != nil {
			log.Printf("Failed to save avatar file: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save avatar"})
			return
		}
	}

	// Parse crop coordinates if provided
	var cropCoords *models.CropCoords
	log.Printf("DEBUG: Checking for crop coordinates in POST form data")
	log.Printf("DEBUG: crop_x='%s', crop_y='%s', crop_width='%s', crop_height='%s'",
		c.PostForm("crop_x"), c.PostForm("crop_y"), c.PostForm("crop_width"), c.PostForm("crop_height"))

	if cropX := c.PostForm("crop_x"); cropX != "" {
		x, _ := strconv.ParseFloat(cropX, 64)
		y, _ := strconv.ParseFloat(c.PostForm("crop_y"), 64)
		width, _ := strconv.ParseFloat(c.PostForm("crop_width"), 64)
		height, _ := strconv.ParseFloat(c.PostForm("crop_height"), 64)

		log.Printf("DEBUG: Parsed coordinates: x=%f, y=%f, width=%f, height=%f", x, y, width, height)

		// Validate coordinates are reasonable
		if x >= 0 && y >= 0 && width > 0 && height > 0 && x <= 1 && y <= 1 && width <= 1 && height <= 1 {
			cropCoords = &models.CropCoords{
				X:      x,
				Y:      y,
				Width:  width,
				Height: height,
			}

			if isCropUpdate {
				log.Printf("DEBUG: Crop coordinates received for crop update: x=%f, y=%f, width=%f, height=%f", x, y, width, height)
			} else {
				log.Printf("DEBUG: Crop coordinates received for new file upload: x=%f, y=%f, width=%f, height=%f", x, y, width, height)
			}
		} else {
			log.Printf("DEBUG: Invalid crop coordinates received: x=%f, y=%f, width=%f, height=%f", x, y, width, height)
		}
	} else {
		log.Printf("DEBUG: No crop_x parameter found in form data")
	}

	if !isCropUpdate && cropCoords == nil {
		// For new file upload without coordinates, reset to default
		log.Printf("DEBUG: New file upload without crop coordinates - will use default center crop")
	}

	// Process image: create resized avatar from original
	err = processAvatar(originalPath, croppedPath, cropCoords)
	if err != nil {
		log.Printf("Failed to process avatar: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process avatar"})
		return
	}

	// Prepare database paths
	var relativeCroppedPath, relativeOriginalPath string
	if isCropUpdate {
		// For crop update, keep the same paths but update crop coordinates
		relativeCroppedPath = user.AvatarPath
		relativeOriginalPath = user.OriginalAvatarPath
	} else {
		// For new upload, create new paths using new avatar endpoint
		originalFilename := "original" + ext
		relativeCroppedPath = fmt.Sprintf("/avatar/%s", user.ID.Hex()) // New endpoint path
		relativeOriginalPath = fmt.Sprintf("/data/%s/%s", user.ID.Hex(), originalFilename)
	}

	log.Printf("DEBUG: About to update avatar in database:")
	log.Printf("DEBUG: User ID: %s", user.ID.Hex())
	log.Printf("DEBUG: relativeCroppedPath: '%s'", relativeCroppedPath)
	log.Printf("DEBUG: relativeOriginalPath: '%s'", relativeOriginalPath)
	log.Printf("DEBUG: cropCoords: %+v", cropCoords)
	log.Printf("DEBUG: isCropUpdate: %v", isCropUpdate)
	log.Printf("DEBUG: Current user avatar path before update: '%s'", user.AvatarPath)
	log.Printf("DEBUG: Current user crop coordinates before update: %+v", user.CropCoordinates)

	err = models.UpdateUserAvatarWithCrop(user.ID, relativeCroppedPath, relativeOriginalPath, cropCoords)
	if err != nil {
		log.Printf("Failed to update user avatar in database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update avatar in database"})
		return
	}

	log.Printf("DEBUG: Successfully updated avatar in database")

	// Fetch updated user to verify changes
	updatedUser, err := models.GetUserByID(user.ID.Hex())
	if err != nil {
		log.Printf("Warning: Could not fetch updated user for verification: %v", err)
	} else {
		log.Printf("DEBUG: After update - user avatar path: '%s'", updatedUser.AvatarPath)
		log.Printf("DEBUG: After update - user crop coordinates: %+v", updatedUser.CropCoordinates)
	}

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"message":       "Avatar uploaded successfully",
		"avatar_path":   relativeCroppedPath,
		"original_path": relativeOriginalPath,
	})
}

// removeAvatarHandler handles avatar removal
func removeAvatarHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	// Remove avatar files if they exist
	if user.AvatarPath != "" {
		avatarFile := "." + user.AvatarPath
		if err := os.Remove(avatarFile); err != nil {
			log.Printf("Warning: Failed to remove avatar file %s: %v", avatarFile, err)
		}
	}

	if user.OriginalAvatarPath != "" {
		originalFile := "." + user.OriginalAvatarPath
		if err := os.Remove(originalFile); err != nil {
			log.Printf("Warning: Failed to remove original avatar file %s: %v", originalFile, err)
		}
	}

	// Clear avatar paths in database
	err := models.UpdateUserAvatar(user.ID, "")
	if err != nil {
		log.Printf("Failed to clear user avatar in database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove avatar from database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Avatar removed successfully",
	})
}

// getOriginalAvatarHandler returns original avatar info for cropping
func getOriginalAvatarHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	log.Printf("DEBUG: getOriginalAvatarHandler called for user %s", user.ID.Hex())
	log.Printf("DEBUG: User original avatar path: '%s'", user.OriginalAvatarPath)
	log.Printf("DEBUG: User current avatar path: '%s'", user.AvatarPath)
	log.Printf("DEBUG: User crop coordinates: %+v", user.CropCoordinates)

	if user.OriginalAvatarPath == "" {
		log.Printf("DEBUG: No original avatar path found for user")
		c.JSON(http.StatusNotFound, gin.H{"error": "No original avatar found"})
		return
	}

	// Check if original avatar file exists
	avatarFile := "." + user.OriginalAvatarPath
	if _, err := os.Stat(avatarFile); os.IsNotExist(err) {
		log.Printf("DEBUG: Original avatar file not found: %s", avatarFile)
		c.JSON(http.StatusNotFound, gin.H{"error": "Original avatar file not found"})
		return
	}

	log.Printf("DEBUG: Original avatar file exists: %s", avatarFile)

	// Return info about original avatar and current crop coordinates
	response := gin.H{
		"success":             true,
		"original_path":       user.OriginalAvatarPath,
		"current_avatar_path": user.AvatarPath,
	}

	// Add crop coordinates if available
	if user.CropCoordinates != nil {
		response["crop_coordinates"] = gin.H{
			"x":      user.CropCoordinates.X,
			"y":      user.CropCoordinates.Y,
			"width":  user.CropCoordinates.Width,
			"height": user.CropCoordinates.Height,
		}
		log.Printf("DEBUG: Added crop coordinates to response: %+v", user.CropCoordinates)
	} else {
		log.Printf("DEBUG: No crop coordinates found for user")
	}

	log.Printf("DEBUG: Returning response: %+v", response)
	c.JSON(http.StatusOK, response)
}

// getOriginalAvatarFileHandler serves the original avatar file
func getOriginalAvatarFileHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	if user.OriginalAvatarPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "No original avatar found"})
		return
	}

	// Serve the original avatar file
	avatarFile := "." + user.OriginalAvatarPath
	if _, err := os.Stat(avatarFile); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Original avatar file not found"})
		return
	}

	c.File(avatarFile)
}

// processAvatar creates a resized and optionally cropped avatar from the original image
func processAvatar(originalPath, avatarPath string, cropCoords *models.CropCoords) error {
	log.Printf("DEBUG: processAvatar called - originalPath: %s, avatarPath: %s, cropCoords: %+v", originalPath, avatarPath, cropCoords)

	// Open the original image
	src, err := imaging.Open(originalPath)
	if err != nil {
		return fmt.Errorf("failed to open original image: %v", err)
	}

	// Get original dimensions
	bounds := src.Bounds()
	originalWidth := bounds.Dx()
	originalHeight := bounds.Dy()
	log.Printf("DEBUG: Original image dimensions: %dx%d", originalWidth, originalHeight)

	var processed image.Image = src

	// Apply cropping if coordinates are provided
	if cropCoords != nil && cropCoords.Width > 0 && cropCoords.Height > 0 {
		// Convert relative coordinates to absolute pixels
		x := int(cropCoords.X * float64(originalWidth))
		y := int(cropCoords.Y * float64(originalHeight))
		width := int(cropCoords.Width * float64(originalWidth))
		height := int(cropCoords.Height * float64(originalHeight))

		log.Printf("DEBUG: Crop coordinates (absolute): x=%d, y=%d, width=%d, height=%d", x, y, width, height)

		// Ensure crop coordinates are within image bounds
		if x < 0 {
			x = 0
		}
		if y < 0 {
			y = 0
		}
		if x+width > originalWidth {
			width = originalWidth - x
		}
		if y+height > originalHeight {
			height = originalHeight - y
		}

		log.Printf("DEBUG: Adjusted crop coordinates: x=%d, y=%d, width=%d, height=%d", x, y, width, height)

		// Crop the image to user's selection
		cropRect := image.Rect(x, y, x+width, y+height)
		processed = imaging.Crop(src, cropRect)

		// Get dimensions after crop
		bounds = processed.Bounds()
		croppedWidth := bounds.Dx()
		croppedHeight := bounds.Dy()
		log.Printf("DEBUG: Dimensions after crop: %dx%d", croppedWidth, croppedHeight)

		// For user-defined crop, resize maintaining aspect ratio up to 200px max
		avatarSize := 200
		var finalImage image.Image

		if croppedWidth >= croppedHeight {
			// Landscape or square - resize by width
			finalImage = imaging.Resize(processed, avatarSize, 0, imaging.Lanczos)
		} else {
			// Portrait - resize by height
			finalImage = imaging.Resize(processed, 0, avatarSize, imaging.Lanczos)
		}

		processed = finalImage
		finalBounds := processed.Bounds()
		log.Printf("DEBUG: Final dimensions: %dx%d (maintaining user crop aspect ratio)", finalBounds.Dx(), finalBounds.Dy())
	} else {
		log.Printf("DEBUG: No crop coordinates provided, using automatic center crop")

		// No crop coordinates - make the image square by cropping from center, then resize
		bounds = processed.Bounds()
		width := bounds.Dx()
		height := bounds.Dy()

		// Make it square by cropping from center
		var squareSize int
		if width > height {
			squareSize = height
			// Crop horizontally from center
			x := (width - height) / 2
			cropRect := image.Rect(x, 0, x+height, height)
			processed = imaging.Crop(processed, cropRect)
		} else if height > width {
			squareSize = width
			// Crop vertically from center
			y := (height - width) / 2
			cropRect := image.Rect(0, y, width, y+width)
			processed = imaging.Crop(processed, cropRect)
		} else {
			squareSize = width // Already square
		}

		log.Printf("DEBUG: Made square with size: %d", squareSize)

		// Now resize to final avatar size
		avatarSize := 200
		processed = imaging.Resize(processed, avatarSize, avatarSize, imaging.Lanczos)
		log.Printf("DEBUG: Final resize to: %dx%d (auto crop)", avatarSize, avatarSize)
	}

	// Save the processed avatar
	err = imaging.Save(processed, avatarPath)
	if err != nil {
		return fmt.Errorf("failed to save processed avatar: %v", err)
	}

	log.Printf("Avatar processed successfully: %s (crop coords: %+v)", avatarPath, cropCoords)
	return nil
}

// handleCropUpdate handles crop update for existing avatar
func handleCropUpdate(c *gin.Context, user *models.User) {
	log.Printf("DEBUG: handleCropUpdate called for user %s", user.ID.Hex())

	// Check if user has an original avatar file
	if user.OriginalAvatarPath == "" {
		log.Printf("No original avatar found for crop update")
		c.JSON(http.StatusBadRequest, gin.H{"error": "No original avatar found for cropping"})
		return
	}

	// Use existing original file
	originalPath := "." + user.OriginalAvatarPath
	if _, err := os.Stat(originalPath); os.IsNotExist(err) {
		log.Printf("Original avatar file not found: %s", originalPath)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Original avatar file not found"})
		return
	}

	// Determine extension and cropped path from existing avatar
	ext := strings.ToLower(filepath.Ext(user.OriginalAvatarPath))
	userDataDir := fmt.Sprintf("./data/%s", user.ID.Hex())
	croppedFilename := "avatar" + ext
	croppedPath := filepath.Join(userDataDir, croppedFilename)

	// Parse crop coordinates
	var cropCoords *models.CropCoords
	if cropX := c.PostForm("crop_x"); cropX != "" {
		x, _ := strconv.ParseFloat(cropX, 64)
		y, _ := strconv.ParseFloat(c.PostForm("crop_y"), 64)
		width, _ := strconv.ParseFloat(c.PostForm("crop_width"), 64)
		height, _ := strconv.ParseFloat(c.PostForm("crop_height"), 64)

		log.Printf("Crop coordinates received: x=%f, y=%f, width=%f, height=%f", x, y, width, height)

		cropCoords = &models.CropCoords{
			X:      x,
			Y:      y,
			Width:  width,
			Height: height,
		}
	}

	// Process image: create resized avatar from original
	err := processAvatar(originalPath, croppedPath, cropCoords)
	if err != nil {
		log.Printf("Failed to process avatar: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process avatar"})
		return
	}

	// For crop update, use new avatar endpoint path
	relativeCroppedPath := fmt.Sprintf("/avatar/%s", user.ID.Hex()) // Always use new endpoint
	relativeOriginalPath := user.OriginalAvatarPath

	log.Printf("DEBUG: About to update avatar in database:")
	log.Printf("DEBUG: User ID: %s", user.ID.Hex())
	log.Printf("DEBUG: relativeCroppedPath: '%s'", relativeCroppedPath)
	log.Printf("DEBUG: relativeOriginalPath: '%s'", relativeOriginalPath)
	log.Printf("DEBUG: cropCoords: %+v", cropCoords)
	log.Printf("DEBUG: isCropUpdate: true")

	err = models.UpdateUserAvatarWithCrop(user.ID, relativeCroppedPath, relativeOriginalPath, cropCoords)
	if err != nil {
		log.Printf("Failed to update user avatar in database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update avatar in database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"message":       "Avatar updated successfully",
		"avatar_path":   relativeCroppedPath,
		"original_path": relativeOriginalPath,
	})
}

// Admin handlers for managing user avatars

// adminUploadAvatarHandler handles avatar upload for specific user (admin access)
func adminUploadAvatarHandler(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Не указан ID пользователя"})
		return
	}

	// Get target user
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID пользователя"})
		return
	}

	targetUser, err := models.GetUserByID(objID.Hex())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
		return
	}

	log.Printf("DEBUG: adminUploadAvatarHandler called for user %s", targetUser.ID.Hex())
	log.Printf("DEBUG: Request method: %s", c.Request.Method)
	log.Printf("DEBUG: Content-Type: %s", c.Request.Header.Get("Content-Type"))

	// Parse multipart form with 99MB limit
	err = c.Request.ParseMultipartForm(99 << 20) // 99MB
	if err != nil {
		log.Printf("Failed to parse multipart form: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка обработки формы"})
		return
	}

	// Check if this is a crop update
	cropUpdate := c.Request.FormValue("crop_update")
	log.Printf("DEBUG: crop_update value: '%s'", cropUpdate)

	if cropUpdate == "true" {
		log.Printf("DEBUG: Processing crop update for existing avatar")
		adminHandleCropUpdate(c, targetUser)
		return
	}

	// Handle new file upload
	log.Printf("DEBUG: Processing new file upload")
	file, header, err := c.Request.FormFile("avatar")
	if err != nil {
		log.Printf("No file found in request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Файл не найден"})
		return
	}
	defer file.Close()

	log.Printf("DEBUG: File received - Name: %s, Size: %d", header.Filename, header.Size)

	// Validate file size (99MB)
	if header.Size > 99*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Файл слишком большой (максимум 99MB)"})
		return
	}

	// Create user directory
	userDir := fmt.Sprintf("./data/%s", targetUser.ID.Hex())
	if err := os.MkdirAll(userDir, 0755); err != nil {
		log.Printf("Failed to create user directory: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка создания директории"})
		return
	}

	// Save original file
	ext := filepath.Ext(header.Filename)
	originalPath := filepath.Join(userDir, "original"+ext)

	out, err := os.Create(originalPath)
	if err != nil {
		log.Printf("Failed to create original file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения файла"})
		return
	}
	defer out.Close()

	_, err = io.Copy(out, file)
	if err != nil {
		log.Printf("Failed to copy file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка копирования файла"})
		return
	}

	log.Printf("DEBUG: Original file saved to: %s", originalPath)

	// Parse crop coordinates
	var cropCoords *models.CropCoords
	x := c.PostForm("crop_x") // Use the same parameter names as in the regular handler
	y := c.PostForm("crop_y")
	width := c.PostForm("crop_width")
	height := c.PostForm("crop_height")

	log.Printf("DEBUG: Crop coordinates - crop_x: %s, crop_y: %s, crop_width: %s, crop_height: %s", x, y, width, height)

	if x != "" && y != "" && width != "" && height != "" {
		cropCoords = &models.CropCoords{}
		if cropCoords.X, err = strconv.ParseFloat(x, 64); err != nil {
			log.Printf("Invalid crop x coordinate: %v", err)
		}
		if cropCoords.Y, err = strconv.ParseFloat(y, 64); err != nil {
			log.Printf("Invalid crop y coordinate: %v", err)
		}
		if cropCoords.Width, err = strconv.ParseFloat(width, 64); err != nil {
			log.Printf("Invalid crop width: %v", err)
		}
		if cropCoords.Height, err = strconv.ParseFloat(height, 64); err != nil {
			log.Printf("Invalid crop height: %v", err)
		}
		log.Printf("DEBUG: Parsed crop coordinates: %+v", cropCoords)
	}

	// Process and save cropped avatar
	avatarPath := filepath.Join(userDir, "avatar.jpg")
	if err := processAvatar(originalPath, avatarPath, cropCoords); err != nil {
		log.Printf("Failed to process avatar: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки изображения"})
		return
	}

	log.Printf("DEBUG: Avatar processed and saved to: %s", avatarPath)

	// Update user's avatar path in database using new endpoint
	relativeAvatarPath := fmt.Sprintf("/avatar/%s", targetUser.ID.Hex())
	if err := models.UpdateUserAvatar(targetUser.ID, relativeAvatarPath); err != nil {
		log.Printf("Failed to update user avatar path: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления профиля"})
		return
	}

	log.Printf("DEBUG: Avatar path updated in database: %s", relativeAvatarPath)

	// Return success response
	relativeCroppedPath := fmt.Sprintf("/avatar/%s", targetUser.ID.Hex())
	relativeOriginalPath := fmt.Sprintf("/data/%s/original%s", targetUser.ID.Hex(), ext)

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"message":       "Аватар успешно загружен",
		"avatar_path":   relativeCroppedPath,
		"original_path": relativeOriginalPath,
	})
}

// adminHandleCropUpdate handles crop update for existing avatar (admin access)
func adminHandleCropUpdate(c *gin.Context, user *models.User) {
	log.Printf("DEBUG: adminHandleCropUpdate called for user %s", user.ID.Hex())

	// Parse crop coordinates
	x := c.Request.FormValue("crop_x")
	y := c.Request.FormValue("crop_y")
	width := c.Request.FormValue("crop_width")
	height := c.Request.FormValue("crop_height")

	log.Printf("DEBUG: Crop coordinates - x: %s, y: %s, width: %s, height: %s", x, y, width, height)

	if x == "" || y == "" || width == "" || height == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Отсутствуют координаты обрезки"})
		return
	}

	cropCoords := &models.CropCoords{}
	var err error

	if cropCoords.X, err = strconv.ParseFloat(x, 64); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверная координата X"})
		return
	}
	if cropCoords.Y, err = strconv.ParseFloat(y, 64); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверная координата Y"})
		return
	}
	if cropCoords.Width, err = strconv.ParseFloat(width, 64); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверная ширина"})
		return
	}
	if cropCoords.Height, err = strconv.ParseFloat(height, 64); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверная высота"})
		return
	}

	log.Printf("DEBUG: Parsed crop coordinates: %+v", cropCoords)

	// Find original file
	userDir := fmt.Sprintf("./data/%s", user.ID.Hex())
	originalPath := ""

	// Try different extensions
	extensions := []string{".jpg", ".jpeg", ".png", ".gif"}
	for _, ext := range extensions {
		testPath := filepath.Join(userDir, "original"+ext)
		if _, err := os.Stat(testPath); err == nil {
			originalPath = testPath
			break
		}
	}

	if originalPath == "" {
		log.Printf("DEBUG: No original file found in %s", userDir)
		c.JSON(http.StatusNotFound, gin.H{"error": "Оригинальный файл не найден"})
		return
	}

	log.Printf("DEBUG: Found original file: %s", originalPath)

	// Process and save cropped avatar directly
	avatarPath := filepath.Join(userDir, "avatar.jpg")
	if err := processAvatar(originalPath, avatarPath, cropCoords); err != nil {
		log.Printf("Failed to process avatar: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки изображения"})
		return
	}

	log.Printf("DEBUG: Avatar reprocessed and saved to: %s", avatarPath)

	// Update the database with crop coordinates and avatar path using new endpoint
	user.CropCoordinates = cropCoords
	relativeAvatarPath := fmt.Sprintf("/avatar/%s", user.ID.Hex())

	// Find original file extension for response
	ext := filepath.Ext(originalPath)
	relativeOriginalPath := fmt.Sprintf("/data/%s/original%s", user.ID.Hex(), ext)

	if err := models.UpdateUserAvatarWithCrop(user.ID, relativeAvatarPath, relativeOriginalPath, cropCoords); err != nil {
		log.Printf("Failed to save crop coordinates and avatar path: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения изменений аватара"})
		return
	}

	log.Printf("DEBUG: Avatar path and crop coordinates saved to database")

	// Return success response with updated avatar path and timestamp
	relativeCroppedPathForResponse := fmt.Sprintf("/avatar/%s?t=%d", user.ID.Hex(), time.Now().Unix())
	relativeOriginalPathForResponse := fmt.Sprintf("/data/%s/original%s", user.ID.Hex(), ext)

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"message":       "Обрезка аватара обновлена",
		"avatar_path":   relativeCroppedPathForResponse,
		"original_path": relativeOriginalPathForResponse,
	})
}

// adminRemoveAvatarHandler removes avatar for specific user (admin access)
func adminRemoveAvatarHandler(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Не указан ID пользователя"})
		return
	}

	// Get target user
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID пользователя"})
		return
	}

	targetUser, err := models.GetUserByID(objID.Hex())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
		return
	}

	// Remove avatar files
	userDir := fmt.Sprintf("./data/%s", targetUser.ID.Hex())

	// Remove avatar file
	avatarPath := filepath.Join(userDir, "avatar.jpg")
	if err := os.Remove(avatarPath); err != nil && !os.IsNotExist(err) {
		log.Printf("Failed to remove avatar file: %v", err)
	}

	// Remove original files
	extensions := []string{".jpg", ".jpeg", ".png", ".gif"}
	for _, ext := range extensions {
		originalPath := filepath.Join(userDir, "original"+ext)
		if err := os.Remove(originalPath); err != nil && !os.IsNotExist(err) {
			log.Printf("Failed to remove original file %s: %v", originalPath, err)
		}
	}

	// Update user's avatar path in database
	if err := models.UpdateUserAvatar(targetUser.ID, ""); err != nil {
		log.Printf("Failed to update user avatar path: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления профиля"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Аватар удален",
	})
}

// adminGetOriginalAvatarHandler returns original avatar info for specific user (admin access)
func adminGetOriginalAvatarHandler(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Не указан ID пользователя"})
		return
	}

	log.Printf("DEBUG: adminGetOriginalAvatarHandler called for user ID: %s", userID)

	// Get target user - fetch fresh data from database
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID пользователя"})
		return
	}

	targetUser, err := models.GetUserByID(objID.Hex())
	if err != nil {
		log.Printf("DEBUG: User not found: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
		return
	}

	log.Printf("DEBUG: Target user loaded - avatar path: '%s', original path: '%s'", targetUser.AvatarPath, targetUser.OriginalAvatarPath)
	log.Printf("DEBUG: Target user crop coordinates: %+v", targetUser.CropCoordinates)

	// Find original file
	userDir := fmt.Sprintf("./data/%s", targetUser.ID.Hex())
	log.Printf("DEBUG: Looking for original files in: %s", userDir)

	extensions := []string{".jpg", ".jpeg", ".png", ".gif"}
	for _, ext := range extensions {
		originalPath := filepath.Join(userDir, "original"+ext)
		log.Printf("DEBUG: Checking for original file: %s", originalPath)

		if _, err := os.Stat(originalPath); err == nil {
			log.Printf("DEBUG: Found original file: %s", originalPath)

			// Get image dimensions
			file, err := os.Open(originalPath)
			if err != nil {
				log.Printf("DEBUG: Failed to open original file for dimensions: %v", err)
				continue
			}
			defer file.Close()

			config, _, err := image.DecodeConfig(file)
			if err != nil {
				log.Printf("DEBUG: Failed to decode image config: %v", err)
				continue
			}

			relativeOriginalPath := fmt.Sprintf("/data/%s/original%s", targetUser.ID.Hex(), ext)

			// Prepare response with crop coordinates if available
			response := gin.H{
				"original_path": relativeOriginalPath,
				"width":         config.Width,
				"height":        config.Height,
			}

			// Add crop coordinates if available
			if targetUser.CropCoordinates != nil {
				response["crop_coordinates"] = gin.H{
					"x":      targetUser.CropCoordinates.X,
					"y":      targetUser.CropCoordinates.Y,
					"width":  targetUser.CropCoordinates.Width,
					"height": targetUser.CropCoordinates.Height,
				}
				log.Printf("DEBUG: Added crop coordinates to admin response: %+v", targetUser.CropCoordinates)
			} else {
				log.Printf("DEBUG: No crop coordinates found for user")
			}

			log.Printf("DEBUG: Returning admin response: %+v", response)
			c.JSON(http.StatusOK, response)
			return
		}
	}

	log.Printf("DEBUG: No original files found in any format")
	c.JSON(http.StatusNotFound, gin.H{"error": "Оригинальный файл не найден"})
}

// adminGetOriginalAvatarFileHandler serves original avatar file for specific user (admin access)
func adminGetOriginalAvatarFileHandler(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Не указан ID пользователя"})
		return
	}

	// Get target user
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID пользователя"})
		return
	}

	targetUser, err := models.GetUserByID(objID.Hex())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
		return
	}

	// Check if user has avatar
	if targetUser.AvatarPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "У пользователя нет аватара"})
		return
	}

	// Find and serve original file
	userDir := fmt.Sprintf("./data/%s", targetUser.ID.Hex())

	extensions := []string{".jpg", ".jpeg", ".png", ".gif"}
	for _, ext := range extensions {
		originalPath := filepath.Join(userDir, "original"+ext)
		if _, err := os.Stat(originalPath); err == nil {
			c.File(originalPath)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Оригинальный файл не найден"})
}
