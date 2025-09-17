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

	"github.com/disintegration/imaging"
	"github.com/gin-gonic/gin"
)

// uploadAvatarHandler handles avatar upload
func uploadAvatarHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	
	// Parse multipart form with 99MB limit
	err := c.Request.ParseMultipartForm(99 << 20) // 99MB
	if err != nil {
		log.Printf("Failed to parse multipart form: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse form data"})
		return
	}

	file, fileHeader, err := c.Request.FormFile("avatar")
	if err != nil {
		log.Printf("Failed to get avatar file: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "No avatar file provided"})
		return
	}
	defer file.Close()

	// Validate file size (99MB max)
	if fileHeader.Size > 99*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File size exceeds 99MB limit"})
		return
	}

	// Validate file type
	filename := fileHeader.Filename
	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".jpg" && ext != ".jpeg" && ext != ".png" && ext != ".gif" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only JPG, JPEG, PNG, and GIF files are allowed"})
		return
	}

	// Create user data directory if it doesn't exist
	userDataDir := fmt.Sprintf("./data/%s", user.ID.Hex())
	if err := os.MkdirAll(userDataDir, 0755); err != nil {
		log.Printf("Failed to create user data directory: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create upload directory"})
		return
	}

	// Use fixed filenames: original.jpg and avatar.jpg
	originalFilename := "original" + ext
	croppedFilename := "avatar" + ext

	originalPath := filepath.Join(userDataDir, originalFilename)
	croppedPath := filepath.Join(userDataDir, croppedFilename)

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

	// Parse crop coordinates if provided
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
	err = processAvatar(originalPath, croppedPath, cropCoords)
	if err != nil {
		log.Printf("Failed to process avatar: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process avatar"})
		return
	}

	// Update user avatar in database
	relativeCroppedPath := fmt.Sprintf("/data/%s/%s", user.ID.Hex(), croppedFilename)
	relativeOriginalPath := fmt.Sprintf("/data/%s/%s", user.ID.Hex(), originalFilename)
	
	log.Printf("DEBUG: About to update avatar in database:")
	log.Printf("DEBUG: User ID: %s", user.ID.Hex())
	log.Printf("DEBUG: relativeCroppedPath: '%s'", relativeCroppedPath)
	log.Printf("DEBUG: relativeOriginalPath: '%s'", relativeOriginalPath)
	log.Printf("DEBUG: cropCoords: %+v", cropCoords)
	
	err = models.UpdateUserAvatarWithCrop(user.ID, relativeCroppedPath, relativeOriginalPath, cropCoords)
	if err != nil {
		log.Printf("Failed to update user avatar in database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update avatar in database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Avatar uploaded successfully",
		"avatar_path": relativeCroppedPath,
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
	
	if user.OriginalAvatarPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "No original avatar found"})
		return
	}

	// Check if original avatar file exists
	avatarFile := "." + user.OriginalAvatarPath
	if _, err := os.Stat(avatarFile); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Original avatar file not found"})
		return
	}

	// Return info about original avatar and current crop coordinates
	response := gin.H{
		"success": true,
		"original_avatar_path": user.OriginalAvatarPath,
		"current_avatar_path": user.AvatarPath,
	}

	// Add crop coordinates if available
	if user.CropCoordinates != nil {
		response["crop_coordinates"] = gin.H{
			"x": user.CropCoordinates.X,
			"y": user.CropCoordinates.Y,
			"width": user.CropCoordinates.Width,
			"height": user.CropCoordinates.Height,
		}
	}

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
	// Open the original image
	src, err := imaging.Open(originalPath)
	if err != nil {
		return fmt.Errorf("failed to open original image: %v", err)
	}

	// Get original dimensions
	bounds := src.Bounds()
	originalWidth := bounds.Dx()
	originalHeight := bounds.Dy()

	var processed image.Image = src

	// Apply cropping if coordinates are provided
	if cropCoords != nil && cropCoords.Width > 0 && cropCoords.Height > 0 {
		// Convert relative coordinates to absolute pixels
		x := int(cropCoords.X * float64(originalWidth))
		y := int(cropCoords.Y * float64(originalHeight))
		width := int(cropCoords.Width * float64(originalWidth))
		height := int(cropCoords.Height * float64(originalHeight))

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

		// Crop the image
		cropRect := image.Rect(x, y, x+width, y+height)
		processed = imaging.Crop(src, cropRect)
	}

	// Resize to avatar size (200x200 pixels)
	avatarSize := 200
	processed = imaging.Resize(processed, avatarSize, avatarSize, imaging.Lanczos)

	// Save the processed avatar
	err = imaging.Save(processed, avatarPath)
	if err != nil {
		return fmt.Errorf("failed to save processed avatar: %v", err)
	}

	log.Printf("Avatar processed successfully: %s (crop coords: %+v)", avatarPath, cropCoords)
	return nil
}


