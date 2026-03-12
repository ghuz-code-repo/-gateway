package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

// SafeServeFile serves a file safely with path traversal protection
// basePath: the base directory where files are stored (e.g., "./data")
// requestedPath: the requested file path relative to basePath
func SafeServeFile(c *gin.Context, basePath, requestedPath string) error {
	// Clean the requested path to remove any ".." or other malicious components
	cleanPath := filepath.Clean(requestedPath)
	
	// Get absolute path of base directory
	absBasePath, err := filepath.Abs(basePath)
	if err != nil {
		return fmt.Errorf("invalid base path: %v", err)
	}
	
	// Construct absolute requested path
	absRequestPath := filepath.Join(absBasePath, cleanPath)
	absRequestPath, err = filepath.Abs(absRequestPath)
	if err != nil {
		return fmt.Errorf("invalid requested path: %v", err)
	}
	
	// Security check: ensure the requested path is within the base path
	if !strings.HasPrefix(absRequestPath, absBasePath) {
		return fmt.Errorf("path traversal attack detected")
	}
	
	// Check if file exists
	fileInfo, err := os.Stat(absRequestPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("file not found")
	}
	if err != nil {
		return fmt.Errorf("error accessing file: %v", err)
	}
	
	// Don't serve directories
	if fileInfo.IsDir() {
		return fmt.Errorf("cannot serve directory")
	}
	
	// Serve the file
	c.File(absRequestPath)
	return nil
}

// ValidateFilePath validates a file path for security
func ValidateFilePath(basePath, requestedPath string) (string, error) {
	// Clean the requested path
	cleanPath := filepath.Clean(requestedPath)
	
	// Get absolute path of base directory
	absBasePath, err := filepath.Abs(basePath)
	if err != nil {
		return "", fmt.Errorf("invalid base path: %v", err)
	}
	
	// Construct absolute requested path
	absRequestPath := filepath.Join(absBasePath, cleanPath)
	absRequestPath, err = filepath.Abs(absRequestPath)
	if err != nil {
		return "", fmt.Errorf("invalid requested path: %v", err)
	}
	
	// Security check: ensure the requested path is within the base path
	if !strings.HasPrefix(absRequestPath, absBasePath) {
		return "", fmt.Errorf("path traversal detected")
	}
	
	return absRequestPath, nil
}
