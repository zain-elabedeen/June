package auth_test

import (
	"api/internal/auth"
	"api/internal/config"
	"api/internal/models"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/google/uuid"
)

var testDB *sql.DB
var testRouter *gin.Engine
var testCfg config.Config

// TestMain sets up the test environment (DB, router) and tears it down.
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	// Load test configuration (consider a separate .env.test or environment variables)
	// For simplicity, we'll use some defaults here or try to load from existing config logic
	cfg, err := config.LoadConfig("../../.env") // Adjust path if your .env is elsewhere or use test-specific config
	if err != nil {
		log.Fatalf("Failed to load test config: %v", err)
	}
	testCfg = cfg
	// Override DB settings for test database if necessary
	// e.g., testCfg.DBName = "test_june_db"

	// Connect to test database
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		testCfg.DBHost, testCfg.DBPort, testCfg.DBUser, testCfg.DBPassword, testCfg.DBName, testCfg.DBSslMode)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to test database: %v", err)
	}
	testDB = db

	// Optional: Run migrations - This requires your migration tool/logic to be callable.
	// For now, we assume the schema is managed or migrations are run manually for the test DB.
	// If you have a migration function: migrations.Run(testDB, "../../db/migrations")

	// Setup router
	testRouter = gin.New()
	authHandler := auth.NewAuthHandler(testDB, testCfg)
	authRoutes := testRouter.Group("/api/v1/auth")
	{
		authRoutes.POST("/register", authHandler.Register)
		authRoutes.POST("/login", authHandler.Login)
		authRoutes.POST("/refresh", authHandler.RefreshToken)
		authRoutes.POST("/logout", authHandler.Logout)
		// GET /me and PUT /change-password would need middleware setup for tests
	}

	// Run tests
	code := m.Run()

	// Teardown: Close DB connection, clean up test data if necessary
	clearRefreshTokensTable() // Example cleanup
	clearUsersTable()         // Example cleanup
	testDB.Close()
	os.Exit(code)
}

func clearUsersTable() {
	_, err := testDB.Exec("DELETE FROM users")
	if err != nil {
		log.Printf("Failed to clear users table: %v", err)
	}
	// Reset sequence if you have auto-incrementing IDs managed by sequences and want fresh counts for each run
	// _, err = testDB.Exec("ALTER SEQUENCE users_id_seq RESTART WITH 1")
}

func clearRefreshTokensTable() {
	_, err := testDB.Exec("DELETE FROM refresh_tokens")
	if err != nil {
		log.Printf("Failed to clear refresh_tokens table: %v", err)
	}
}

func makeRequest(method, url string, body interface{}) *httptest.ResponseRecorder {
	var reqBody *bytes.Buffer
	if body != nil {
		jsonBody, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(jsonBody)
	} else {
		reqBody = bytes.NewBuffer([]byte{})
	}

	req, _ := http.NewRequest(method, url, reqBody)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	testRouter.ServeHTTP(rr, req)
	return rr
}

func TestUserRegistration_Success(t *testing.T) {
	// Ensure tables are clean before this specific test if needed, or rely on TestMain
	clearUsersTable()
	clearRefreshTokensTable()

	registrationData := models.RegistrationRequest{
		FullName: "Test User Reg Success",
		Email:    "testuser_reg_succ@example.com",
		Password: "Password123!",
		// Phone: optional, can add if needed for test coverage
	}

	rr := makeRequest("POST", "/api/v1/auth/register", registrationData)

	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
		t.Logf("Response body: %s", rr.Body.String())
		return
	}

	var responseUser models.User
	if err := json.Unmarshal(rr.Body.Bytes(), &responseUser); err != nil {
		t.Fatalf("Failed to unmarshal response body: %v", err)
	}

	if responseUser.ID == uuid.Nil {
		t.Errorf("Expected user ID to be set, got nil")
	}
	if responseUser.FullName != registrationData.FullName {
		t.Errorf("Expected FullName %s, got %s", registrationData.FullName, responseUser.FullName)
	}
	if responseUser.Email != registrationData.Email {
		t.Errorf("Expected email %s, got %s", registrationData.Email, responseUser.Email)
	}
	if responseUser.PasswordHash != "" {
		t.Errorf("Expected password_hash to be empty in response, got '%s'", responseUser.PasswordHash)
	}
	if responseUser.CreatedAt.IsZero() {
		t.Errorf("Expected CreatedAt to be set")
	}
	if responseUser.UpdatedAt.IsZero() {
		t.Errorf("Expected UpdatedAt to be set")
	}
	// Default role should be 'user'
	if responseUser.Role != models.RoleUser {
		t.Errorf("Expected default role to be '%s', got '%s'", models.RoleUser, responseUser.Role)
	}

	// Optionally, verify in DB
	var dbPasswordHash, dbFullName, dbEmail string
	var dbRole models.UserRole
	err := testDB.QueryRow("SELECT email, full_name, password_hash, role FROM users WHERE id = $1", responseUser.ID).Scan(&dbEmail, &dbFullName, &dbPasswordHash, &dbRole)
	if err != nil {
		t.Fatalf("Failed to query user from DB: %v", err)
	}
	if dbEmail != registrationData.Email {
		t.Errorf("User email in DB is incorrect: got %s want %s", dbEmail, registrationData.Email)
	}
	if dbFullName != registrationData.FullName {
		t.Errorf("User FullName in DB is incorrect: got %s want %s", dbFullName, registrationData.FullName)
	}
	if dbPasswordHash == "" {
		t.Errorf("Password hash in DB is empty, expected it to be set")
	}
	if dbRole != models.RoleUser {
		t.Errorf("User role in DB is incorrect: got %s want %s", dbRole, models.RoleUser)
	}
	// We can't easily check the password directly, but we know it should be hashed.
}

func TestUserRegistration_Failure_DuplicateEmail(t *testing.T) {
	clearUsersTable()
	clearRefreshTokensTable()

	// First registration (should succeed)
	user1Data := models.RegistrationRequest{
		FullName: "Test User One",
		Email:    "duplicate@example.com",
		Password: "Password123!",
	}
	rr1 := makeRequest("POST", "/api/v1/auth/register", user1Data)
	if status := rr1.Code; status != http.StatusCreated {
		t.Fatalf("First registration failed: got status %v, want %v. Body: %s", status, http.StatusCreated, rr1.Body.String())
	}

	// Second registration with the same email (should fail)
	user2Data := models.RegistrationRequest{
		FullName: "Test User Two",
		Email:    "duplicate@example.com", // Same email
		Password: "Password456!",
	}
	rr2 := makeRequest("POST", "/api/v1/auth/register", user2Data)

	if status := rr2.Code; status != http.StatusConflict {
		t.Errorf("handler returned wrong status code for duplicate email: got %v want %v", status, http.StatusConflict)
		t.Logf("Response body: %s", rr2.Body.String())
		return
	}

	var errorResponse map[string]string
	if err := json.Unmarshal(rr2.Body.Bytes(), &errorResponse); err != nil {
		t.Fatalf("Failed to unmarshal error response body: %v", err)
	}

	expectedError := "email_exists"
	if msg, ok := errorResponse["error"]; !ok || msg != expectedError {
		t.Errorf("Expected error message '%s', got '%s' or not found", expectedError, msg)
	}
}

func TestUserRegistration_Failure_ShortPassword(t *testing.T) {
	clearUsersTable()
	clearRefreshTokensTable()

	registrationData := models.RegistrationRequest{
		FullName: "Test User ShortPass",
		Email:    "shortpass@example.com",
		Password: "short", // Password less than 8 characters
	}

	rr := makeRequest("POST", "/api/v1/auth/register", registrationData)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code for short password: got %v want %v", status, http.StatusBadRequest)
		t.Logf("Response body: %s", rr.Body.String())
		return
	}

	var errorResponse map[string]interface{} // Gin's default validation errors can be more complex
	if err := json.Unmarshal(rr.Body.Bytes(), &errorResponse); err != nil {
		t.Fatalf("Failed to unmarshal error response body: %v. Body: %s", err, rr.Body.String())
	}

	// Gin's validation error messages for binding often include field names and validation tags.
	// For example: { "error": "Key: 'RegistrationRequest.Password' Error:Field validation for 'Password' failed on the 'min' tag" }
	// We'll check if the error message string contains relevant parts.
	if errMessage, ok := errorResponse["message"].(string); ok {
		if !strings.Contains(errMessage, "Password") || !strings.Contains(errMessage, "min") {
			t.Errorf("Expected error message to contain 'Password' and 'min', got: %s", errMessage)
		}
	} else if errMessage, ok := errorResponse["error"].(string); ok { // Fallback for simpler error structure
		if !strings.Contains(errMessage, "Password") || !strings.Contains(errMessage, "min") {
			t.Errorf("Expected error message to contain 'Password' and 'min', got: %s", errMessage)
		}
	} else {
		t.Errorf("Expected error message in response, but got: %v", rr.Body.String())
	}
}

func TestUserRegistration_Failure_InvalidEmail(t *testing.T) {
	clearUsersTable()
	clearRefreshTokensTable()

	registrationData := models.RegistrationRequest{
		FullName: "Test User InvalidEmail",
		Email:    "invalid-email-format", // Invalid email
		Password: "Password123!",
	}

	rr := makeRequest("POST", "/api/v1/auth/register", registrationData)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code for invalid email: got %v want %v", status, http.StatusBadRequest)
		t.Logf("Response body: %s", rr.Body.String())
		return
	}

	var errorResponse map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &errorResponse); err != nil {
		t.Fatalf("Failed to unmarshal error response body: %v. Body: %s", err, rr.Body.String())
	}

	// Check for error message related to email validation
	if errMessage, ok := errorResponse["message"].(string); ok {
		if !strings.Contains(errMessage, "Email") || !strings.Contains(errMessage, "email") { // Gin's validator usually mentions field and tag
			t.Errorf("Expected error message to contain 'Email' and 'email' tag, got: %s", errMessage)
		}
	} else if errMessage, ok := errorResponse["error"].(string); ok { // Fallback
		if !strings.Contains(errMessage, "Email") || !strings.Contains(errMessage, "email") {
			t.Errorf("Expected error message to contain 'Email' and 'email' tag, got: %s", errMessage)
		}
	} else {
		t.Errorf("Expected error message in response, but got: %v", rr.Body.String())
	}
}

func TestUserLogin_Success(t *testing.T) {
	clearUsersTable()
	clearRefreshTokensTable()

	// 1. Register a user first
	registrationData := models.RegistrationRequest{
		FullName: "Test Login User",
		Email:    "login_succ@example.com",
		Password: "Password123!",
	}
	rrReg := makeRequest("POST", "/api/v1/auth/register", registrationData)
	if status := rrReg.Code; status != http.StatusCreated {
		t.Fatalf("Registration prerequisite for login test failed: got status %v, want %v. Body: %s", status, http.StatusCreated, rrReg.Body.String())
	}
	var registeredUser models.User
	if err := json.Unmarshal(rrReg.Body.Bytes(), &registeredUser); err != nil {
		t.Fatalf("Failed to unmarshal registration response: %v", err)
	}

	// 2. Attempt to log in
	loginData := models.LoginRequest{
		Email:    registrationData.Email,
		Password: registrationData.Password,
	}
	rrLogin := makeRequest("POST", "/api/v1/auth/login", loginData)

	if status := rrLogin.Code; status != http.StatusOK {
		t.Errorf("Login handler returned wrong status code: got %v want %v", status, http.StatusOK)
		t.Logf("Response body: %s", rrLogin.Body.String())
		return
	}

	var tokenResponse models.TokenResponse
	if err := json.Unmarshal(rrLogin.Body.Bytes(), &tokenResponse); err != nil {
		t.Fatalf("Failed to unmarshal login response body: %v. Body: %s", err, rrLogin.Body.String())
	}

	if tokenResponse.AccessToken == "" {
		t.Errorf("Expected access_token in response, got empty string")
	}
	if tokenResponse.RefreshToken == "" {
		t.Errorf("Expected refresh_token in response, got empty string")
	}

	// 3. Verify refresh token was stored in DB
	var storedTokenID string
	var storedUserID uuid.UUID
	err := testDB.QueryRow("SELECT id, user_id FROM refresh_tokens WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1", registeredUser.ID).Scan(&storedTokenID, &storedUserID)
	if err != nil {
		t.Fatalf("Failed to query refresh_token from DB: %v", err)
	}
	if storedUserID != registeredUser.ID {
		t.Errorf("Stored refresh token has incorrect user_id: got %v, want %v", storedUserID, registeredUser.ID)
	}
	if storedTokenID == "" {
		t.Errorf("Stored refresh token ID is empty")
	}
}

func TestUserLogin_Failure_InvalidCredentials(t *testing.T) {
	clearUsersTable()
	clearRefreshTokensTable()

	// 1. Register a user first
	registrationData := models.RegistrationRequest{
		FullName: "Test InvalidCreds User",
		Email:    "invalidcreds@example.com",
		Password: "Password123!",
	}
	rrReg := makeRequest("POST", "/api/v1/auth/register", registrationData)
	if status := rrReg.Code; status != http.StatusCreated {
		t.Fatalf("Registration prerequisite for login test failed: got status %v, want %v. Body: %s", status, http.StatusCreated, rrReg.Body.String())
	}

	// 2. Attempt to log in with invalid password
	loginData := models.LoginRequest{
		Email:    registrationData.Email,
		Password: "WrongPassword!",
	}
	rrLogin := makeRequest("POST", "/api/v1/auth/login", loginData)

	if status := rrLogin.Code; status != http.StatusUnauthorized {
		t.Errorf("Login handler returned wrong status code for invalid credentials: got %v want %v", status, http.StatusUnauthorized)
		t.Logf("Response body: %s", rrLogin.Body.String())
		return
	}

	var errorResponse map[string]interface{}
	if err := json.Unmarshal(rrLogin.Body.Bytes(), &errorResponse); err != nil {
		t.Fatalf("Failed to unmarshal error response body: %v. Body: %s", err, rrLogin.Body.String())
	}

	if message, ok := errorResponse["message"].(string); ok {
		if !strings.Contains(strings.ToLower(message), "invalid credentials") {
			t.Errorf("Expected error message to indicate invalid credentials, got: %s", message)
		}
	} else if errVal, ok := errorResponse["error"].(string); ok {
		if !strings.Contains(strings.ToLower(errVal), "invalid credentials") {
			t.Errorf("Expected error message to indicate invalid credentials, got: %s", errVal)
		}
	} else {
		t.Errorf("Expected error message in response, but got: %v", rrLogin.Body.String())
	}
}

func TestUserLogin_Failure_UserNotFound(t *testing.T) {
	clearUsersTable()
	clearRefreshTokensTable()

	// Attempt to log in with a non-existent email
	loginData := models.LoginRequest{
		Email:    "nonexistentuser@example.com",
		Password: "Password123!",
	}
	rrLogin := makeRequest("POST", "/api/v1/auth/login", loginData)

	if status := rrLogin.Code; status != http.StatusUnauthorized { // Or http.StatusNotFound, depending on desired behavior
		t.Errorf("Login handler returned wrong status code for non-existent user: got %v want %v", status, http.StatusUnauthorized)
		t.Logf("Response body: %s", rrLogin.Body.String())
		return
	}

	var errorResponse map[string]interface{}
	if err := json.Unmarshal(rrLogin.Body.Bytes(), &errorResponse); err != nil {
		t.Fatalf("Failed to unmarshal error response body: %v. Body: %s", err, rrLogin.Body.String())
	}

	// General message for non-existent user or bad creds to avoid user enumeration
	if message, ok := errorResponse["message"].(string); ok {
		if !strings.Contains(strings.ToLower(message), "invalid credentials") {
			t.Errorf("Expected error message to indicate invalid credentials (for non-existent user), got: %s", message)
		}
	} else if errVal, ok := errorResponse["error"].(string); ok {
		if !strings.Contains(strings.ToLower(errVal), "invalid credentials") {
			t.Errorf("Expected error message to indicate invalid credentials (for non-existent user), got: %s", errVal)
		}
	} else {
		t.Errorf("Expected error message in response, but got: %v", rrLogin.Body.String())
	}
}

func TestUserLogin_Failure_MissingEmail(t *testing.T) {
	clearUsersTable()
	clearRefreshTokensTable()

	// Attempt to log in with missing email
	loginData := models.LoginRequest{
		// Email is intentionally omitted
		Password: "Password123!",
	}
	rrLogin := makeRequest("POST", "/api/v1/auth/login", loginData)

	if status := rrLogin.Code; status != http.StatusBadRequest {
		t.Errorf("Login handler returned wrong status code for missing email: got %v want %v", status, http.StatusBadRequest)
		t.Logf("Response body: %s", rrLogin.Body.String())
		return
	}

	var errorResponse map[string]interface{}
	if err := json.Unmarshal(rrLogin.Body.Bytes(), &errorResponse); err != nil {
		t.Fatalf("Failed to unmarshal error response body: %v. Body: %s", err, rrLogin.Body.String())
	}

	if message, ok := errorResponse["message"].(string); ok {
		if !strings.Contains(strings.ToLower(message), "email is required") && !strings.Contains(strings.ToLower(message), "validation for 'email' failed on the 'required' tag") {
			t.Errorf("Expected error message to indicate missing email, got: %s", message)
		}
	} else if errVal, ok := errorResponse["error"].(string); ok {
		if !strings.Contains(strings.ToLower(errVal), "email is required") && !strings.Contains(strings.ToLower(errVal), "validation for 'email' failed on the 'required' tag") {
			t.Errorf("Expected error message to indicate missing email, got: %s", errVal)
		}
	} else {
		t.Errorf("Expected error message in response, but got: %v", rrLogin.Body.String())
	}
}

func TestUserLogin_Failure_MissingPassword(t *testing.T) {
	clearUsersTable()
	clearRefreshTokensTable()

	// Attempt to log in with missing password
	loginData := models.LoginRequest{
		Email: "missingpassword@example.com",
		// Password is intentionally omitted
	}
	rrLogin := makeRequest("POST", "/api/v1/auth/login", loginData)

	if status := rrLogin.Code; status != http.StatusBadRequest {
		t.Errorf("Login handler returned wrong status code for missing password: got %v want %v", status, http.StatusBadRequest)
		t.Logf("Response body: %s", rrLogin.Body.String())
		return
	}

	var errorResponse map[string]interface{}
	if err := json.Unmarshal(rrLogin.Body.Bytes(), &errorResponse); err != nil {
		t.Fatalf("Failed to unmarshal error response body: %v. Body: %s", err, rrLogin.Body.String())
	}

	if message, ok := errorResponse["message"].(string); ok {
		if !strings.Contains(strings.ToLower(message), "password is required") && !strings.Contains(strings.ToLower(message), "validation for 'password' failed on the 'required' tag") {
			t.Errorf("Expected error message to indicate missing password, got: %s", message)
		}
	} else if errVal, ok := errorResponse["error"].(string); ok {
		if !strings.Contains(strings.ToLower(errVal), "password is required") && !strings.Contains(strings.ToLower(errVal), "validation for 'password' failed on the 'required' tag") {
			t.Errorf("Expected error message to indicate missing password, got: %s", errVal)
		}
	} else {
		t.Errorf("Expected error message in response, but got: %v", rrLogin.Body.String())
	}
}
