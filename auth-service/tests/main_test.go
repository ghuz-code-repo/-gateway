package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"auth-service/models"
	"auth-service/routes"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// Global test variables
var (
	testRouter *gin.Engine
	testDB     *mongo.Database
)

const (
	testMongoURI  = "mongodb://mongoadmin:Ur1Ci0T2D4bOoLbWH36ZwGzRWPaZV1@localhost:27017/authdb_test?authSource=admin"
	testDBName    = "authdb_test"
	testJWTSecret = "test_jwt_secret_for_integration_tests"
	testAPIKey    = "test_internal_api_key_12345"
)

func TestMain(m *testing.M) {
	// Set environment variables BEFORE any init
	os.Setenv("JWT_SECRET", testJWTSecret)
	os.Setenv("INTERNAL_API_KEY", testAPIKey)
	os.Setenv("ENVIRONMENT", "test")
	os.Setenv("MONGO_URI", testMongoURI)
	os.Setenv("MONGO_DB", testDBName)

	// Change working directory to auth-service root (for templates)
	authServiceRoot := filepath.Join("..")
	if err := os.Chdir(authServiceRoot); err != nil {
		log.Fatalf("Failed to chdir to auth-service root: %v", err)
	}

	// Initialize MongoDB with test database
	if err := models.InitDB(testMongoURI, testDBName); err != nil {
		log.Fatalf("Failed to connect to test MongoDB: %v", err)
	}

	testDB = models.GetDatabase()

	// Clean test database before all tests
	cleanAllCollections()

	// Setup Gin router in test mode
	gin.SetMode(gin.TestMode)
	testRouter = setupTestRouter()

	// Run tests
	code := m.Run()

	// Cleanup after all tests
	cleanAllCollections()

	os.Exit(code)
}

func setupTestRouter() *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())

	// Template functions (same as main.go)
	router.SetFuncMap(template.FuncMap{
		"join": strings.Join,
		"jsonify": func(v interface{}) (string, error) {
			b, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			return string(b), nil
		},
		"div": func(a, b float64) float64 {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"subtract": func(a, b int) int {
			return a - b
		},
		"hasAdminRole": func(serviceRoles []models.UserServiceRole) bool {
			for _, sr := range serviceRoles {
				if sr.IsActive && sr.ServiceKey == "system" && sr.RoleName == "admin" {
					return true
				}
			}
			return false
		},
	})

	// Load templates
	rootTemplates, err := filepath.Glob("templates/*.html")
	if err != nil {
		log.Fatalf("Failed to glob root templates: %v", err)
	}
	roleManagementTemplates, err := filepath.Glob("templates/role_management/*.html")
	if err != nil {
		log.Fatalf("Failed to glob role_management templates: %v", err)
	}
	allTemplates := append(rootTemplates, roleManagementTemplates...)
	if len(allTemplates) > 0 {
		router.LoadHTMLFiles(allTemplates...)
	}

	// Setup all routes
	routes.SetupAllRoutes(router)

	return router
}

// cleanAllCollections drops all data from test collections
func cleanAllCollections() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collections := []string{
		"users",
		"roles",
		"service_roles",
		"permissions",
		"services",
		"user_service_roles",
		"document_types",
		"blacklisted_tokens",
		"password_reset_tokens",
		"import_logs",
		"service_import_logs",
		"activity_logs",
		"user_sessions",
		"service_instances",
	}

	for _, col := range collections {
		testDB.Collection(col).DeleteMany(ctx, bson.M{})
	}
}

// performRequest executes an HTTP request against the test router
func performRequest(method, path string, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var reqBody *strings.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	} else {
		reqBody = strings.NewReader("")
	}

	req := httptest.NewRequest(method, path, reqBody)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)
	return w
}

// performFormRequest executes an HTTP request with form-encoded body
func performFormRequest(method, path string, formData string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)
	return w
}

// performRequestWithAPIKey executes an HTTP request with the internal API key
func performRequestWithAPIKey(method, path string, body string) *httptest.ResponseRecorder {
	var reqBody *strings.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	} else {
		reqBody = strings.NewReader("")
	}

	req := httptest.NewRequest(method, path, reqBody)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-API-Key", testAPIKey)

	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)
	return w
}

// parseJSONResponse parses the response body as JSON
func parseJSONResponse(w *httptest.ResponseRecorder) map[string]interface{} {
	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		return nil
	}
	return result
}

// assertStatus checks that the response has the expected status code
func assertStatus(t *testing.T, w *httptest.ResponseRecorder, expected int) {
	t.Helper()
	if w.Code != expected {
		t.Errorf("Expected status %d, got %d. Body: %s", expected, w.Code, w.Body.String()[:min(500, w.Body.Len())])
	}
}

// isRedirectToLogin checks if the response is a redirect to the login page
func isRedirectToLogin(w *httptest.ResponseRecorder) bool {
	if w.Code == http.StatusFound || w.Code == http.StatusSeeOther || w.Code == http.StatusTemporaryRedirect {
		location := w.Header().Get("Location")
		return strings.Contains(location, "/login")
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func debugResponse(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	body := w.Body.String()
	if len(body) > 1000 {
		body = body[:1000] + "..."
	}
	t.Logf("Response: status=%d, body=%s", w.Code, body)
	for k, v := range w.Header() {
		t.Logf("Header: %s = %s", k, v)
	}
}

// formatJSON creates a JSON string for request bodies
func formatJSON(data map[string]interface{}) string {
	b, _ := json.Marshal(data)
	return string(b)
}

// formatJSONString creates a JSON string from a Go struct-like value
func toJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Test placeholder to verify test infrastructure works
func TestInfrastructure_DatabaseConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := testDB.Client().Ping(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to ping test database: %v", err)
	}
}

func TestInfrastructure_RouterSetup(t *testing.T) {
	w := performRequest("GET", "/health", "")
	if w.Code != http.StatusOK {
		t.Fatalf("Health endpoint returned %d, expected 200", w.Code)
	}
}

func TestInfrastructure_TestDBIsolation(t *testing.T) {
	// Verify we're using the test database, not production
	dbName := testDB.Name()
	if dbName != testDBName {
		t.Fatalf("Test database name is '%s', expected '%s'", dbName, testDBName)
	}

	// Verify we can write and read
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	col := testDB.Collection("_test_probe")
	_, err := col.InsertOne(ctx, bson.M{"probe": true})
	if err != nil {
		t.Fatalf("Failed to write to test database: %v", err)
	}
	col.Drop(ctx)
	_ = fmt.Sprintf("Test database isolation verified")
}
