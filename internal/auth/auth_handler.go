package auth

import (
	"api/internal/config"
	"api/internal/models"
	"api/pkg/utils"
	"database/sql"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq" // For handling PostgreSQL specific errors
)

// AuthHandler holds dependencies for authentication handlers.
// This approach allows us to inject dependencies like DB and Config into handlers.
type AuthHandler struct {
	DB  *sql.DB
	Cfg config.Config
}

// NewAuthHandler creates a new AuthHandler with given dependencies.
func NewAuthHandler(db *sql.DB, cfg config.Config) *AuthHandler {
	return &AuthHandler{DB: db, Cfg: cfg}
}

// Register handles new user registration.
// POST /auth/register
func (h *AuthHandler) Register(c *gin.Context) {
	var req models.RegistrationRequest

	// Bind JSON request to the RegistrationRequest struct
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": err.Error()})
		return
	}

	// Hash the password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "message": "Failed to hash password"})
		return
	}

	// Create a new user model
	newUser := models.User{
		ID:           uuid.New(), // Generate a new UUID
		Email:        strings.ToLower(req.Email), // Store email in lowercase
		PasswordHash: hashedPassword,
		FullName:     req.FullName,
		Phone:        req.Phone, // Will be nil if not provided
		Role:         models.RoleUser, // Default role
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Insert user into the database
	query := `INSERT INTO users (id, email, password_hash, full_name, phone, role, created_at, updated_at) 
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`

	_, err = h.DB.Exec(query,
		newUser.ID,
		newUser.Email,
		newUser.PasswordHash,
		newUser.FullName,
		newUser.Phone, // pq driver handles nil pointers for nullable columns
		newUser.Role,
		newUser.CreatedAt,
		newUser.UpdatedAt,
	)

	if err != nil {
		// Check for unique constraint violation (e.g., email already exists)
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23505" { // Unique violation
				c.JSON(http.StatusConflict, gin.H{"error": "email_exists", "message": "User with this email already exists"})
				return
			}
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database_error", "message": "Failed to register user: " + err.Error()})
		return
	}

	// Return success response (omitting sensitive info like password)
	// The newUser struct already has PasswordHash and TwoFactorSecret omitted by json:"-"
	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully. Please verify your email.",
		"user": gin.H{
			"id":        newUser.ID,
			"email":     newUser.Email,
			"full_name": newUser.FullName,
			"role":      newUser.Role,
		},
	})

	// TODO: Implement email verification sending logic here
}

// Login handles user login and token generation.
// POST /auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest

	// Bind JSON request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": err.Error()})
		return
	}

	// Fetch user by email
	user := models.User{}
	query := `SELECT id, email, password_hash, role, is_email_verified FROM users WHERE email = $1 AND deleted_at IS NULL`
	err := h.DB.QueryRow(query, strings.ToLower(req.Email)).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Role, &user.IsEmailVerified)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials", "message": "Invalid email or password"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database_error", "message": "Failed to fetch user: " + err.Error()})
		return
	}

	// Check password
	if !utils.CheckPasswordHash(req.Password, user.PasswordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials", "message": "Invalid email or password"})
		return
	}

	// TODO: Check if email is verified, if required by application logic
	// if !user.IsEmailVerified {
	// 	c.JSON(http.StatusForbidden, gin.H{"error": "email_not_verified", "message": "Please verify your email before logging in."})
	// 	return
	// }

	// Generate JWT tokens
	// TODO: Make token expiration times configurable
	accessTokenExpMinutes := 15  // e.g., 15 minutes
	refreshTokenExpDays := 7     // e.g., 7 days

	accessToken, refreshToken, refreshTokenClaims, err := utils.GenerateTokens(user.ID, user.Email, string(user.Role), h.Cfg.JWTAccessSecret, h.Cfg.JWTRefreshSecret, accessTokenExpMinutes, refreshTokenExpDays)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token_generation_failed", "message": err.Error()})
		return
	}

	// Store refresh token in DB
	refreshTokenID, err := uuid.Parse(refreshTokenClaims.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "message": "Failed to parse refresh token ID: " + err.Error()})
		return
	}
	storeQuery := `INSERT INTO refresh_tokens (id, user_id, expires_at) VALUES ($1, $2, $3)`
	_, err = h.DB.Exec(storeQuery, refreshTokenID, user.ID, refreshTokenClaims.ExpiresAt.Time)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database_error", "message": "Failed to store refresh token: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// RefreshToken handles generating a new access token from a refresh token.
// POST /auth/refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req models.RefreshTokenRequest

	// Bind JSON request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": err.Error()})
		return
	}

	// Validate the refresh token
	claims, err := utils.ValidateToken(req.RefreshToken, h.Cfg.JWTRefreshSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_refresh_token", "message": "Invalid or expired refresh token: " + err.Error()})
		return
	}

	// Check if the refresh token exists in the database and hasn't been revoked
	var dbTokenID string
	checkQuery := `SELECT id FROM refresh_tokens WHERE id = $1 AND user_id = $2 AND expires_at > NOW()`
	err = h.DB.QueryRow(checkQuery, claims.ID, claims.UserID).Scan(&dbTokenID)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_refresh_token", "message": "Refresh token not found, already used, or expired"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database_error", "message": "Failed to verify refresh token: " + err.Error()})
		return
	}

	// Fetch user from DB to ensure they are still valid
	var user models.User
	query := `SELECT id, email, role, is_email_verified FROM users WHERE id = $1 AND deleted_at IS NULL`
	dbErr := h.DB.QueryRow(query, claims.UserID).Scan(&user.ID, &user.Email, &user.Role, &user.IsEmailVerified)
	if dbErr != nil {
		if dbErr == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user_not_found", "message": "User associated with token not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database_error", "message": "Failed to fetch user: " + dbErr.Error()})
		return
	}

	// Invalidate the used refresh token in the DB
	deleteQuery := `DELETE FROM refresh_tokens WHERE id = $1`
	_, err = h.DB.Exec(deleteQuery, claims.ID) // claims.ID is the JTI of the used refresh token
	if err != nil {
		// Log error, but proceed to issue new tokens if user is valid, as the old token might have expired naturally.
		// However, if it's a critical DB error, we might reconsider.
		log.Printf("Failed to delete old refresh token %s: %v", claims.ID, err) 
		// For now, we continue even if deletion fails, as the token might have already been removed or expired.
	}

	// Generate new access and refresh tokens
	accessTokenExpMinutes := 15  // e.g., 15 minutes
	refreshTokenExpDays := 7     // e.g., 7 days

	newAccessToken, newRefreshToken, newRefreshTokenClaims, err := utils.GenerateTokens(user.ID, user.Email, string(user.Role), h.Cfg.JWTAccessSecret, h.Cfg.JWTRefreshSecret, accessTokenExpMinutes, refreshTokenExpDays)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token_generation_failed", "message": "Failed to generate new tokens: " + err.Error()})
		return
	}

	// Store the new refresh token in DB
	newRefreshTokenID, err := uuid.Parse(newRefreshTokenClaims.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "message": "Failed to parse new refresh token ID: " + err.Error()})
		return
	}
	storeNewQuery := `INSERT INTO refresh_tokens (id, user_id, expires_at) VALUES ($1, $2, $3)`
	_, err = h.DB.Exec(storeNewQuery, newRefreshTokenID, user.ID, newRefreshTokenClaims.ExpiresAt.Time)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database_error", "message": "Failed to store new refresh token: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.TokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	})
}

// Logout handles user logout by invalidating the provided refresh token.
// POST /auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	var req models.RefreshTokenRequest // Expecting { "refresh_token": "..." }
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "Refresh token required: " + err.Error()})
		return
	}

	// Validate the token to get its JTI (ID)
	claims, err := utils.ValidateToken(req.RefreshToken, h.Cfg.JWTRefreshSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_refresh_token", "message": "Invalid refresh token provided: " + err.Error()})
		return
	}

	// Invalidate the refresh token in the DB using its JTI (claims.ID)
	deleteQuery := `DELETE FROM refresh_tokens WHERE id = $1`
	result, err := h.DB.Exec(deleteQuery, claims.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database_error", "message": "Failed to invalidate refresh token: " + err.Error()})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusOK, gin.H{"message": "Refresh token not found or already invalidated. Logged out successfully."})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully. Refresh token invalidated."})
}

// GetMe retrieves the details of the currently authenticated user.
// GET /auth/me
// This handler relies on AuthMiddleware to set user details in the context.
func (h *AuthHandler) GetMe(c *gin.Context) {
	userIDUntyped, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "context_error", "message": "User ID not found in context. Ensure AuthMiddleware is used."})
		return
	}

	userIDString, ok := userIDUntyped.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "context_error", "message": "User ID in context is not a string."})
		return
	}

	userID, err := uuid.Parse(userIDString)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_user_id_format", "message": "User ID in token is not a valid UUID."})
		return
	}

	// Fetch user details from the database
	// We select specific fields to avoid exposing sensitive data like password_hash
	var user models.User
	query := `SELECT id, email, phone, full_name, role, is_email_verified, is_phone_verified, two_factor_enabled, created_at, updated_at 
	          FROM users WHERE id = $1 AND deleted_at IS NULL`

	err = h.DB.QueryRow(query, userID).Scan(
		&user.ID, &user.Email, &user.Phone, &user.FullName, &user.Role,
		&user.IsEmailVerified, &user.IsPhoneVerified, &user.TwoFactorEnabled,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "user_not_found", "message": "Authenticated user not found in database."})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database_error", "message": "Failed to fetch user details: " + err.Error()})
		return
	}

	// Return user details (User struct is already configured to omit PasswordHash and TwoFactorSecret via json:"-")
	c.JSON(http.StatusOK, user)
}

// ChangePassword handles changing the password for an authenticated user.
// PUT /auth/change-password
// This handler relies on AuthMiddleware.
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	userIDUntyped, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "context_error", "message": "User ID not found in context"})
		return
	}
	userIDString := userIDUntyped.(string) // Assumes AuthMiddleware sets it as string

	var req models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": err.Error()})
		return
	}

	// Fetch current password hash from DB
	var currentPasswordHash string
	query := `SELECT password_hash FROM users WHERE id = $1 AND deleted_at IS NULL`
	err := h.DB.QueryRow(query, userIDString).Scan(&currentPasswordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "user_not_found", "message": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database_error", "message": "Failed to fetch user password: " + err.Error()})
		return
	}

	// Verify current password
	if !utils.CheckPasswordHash(req.CurrentPassword, currentPasswordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_current_password", "message": "Incorrect current password"})
		return
	}

	// Hash new password
	newPasswordHash, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "message": "Failed to hash new password"})
		return
	}

	// Update password in DB
	updateQuery := `UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3`
	_, err = h.DB.Exec(updateQuery, newPasswordHash, time.Now(), userIDString)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database_error", "message": "Failed to update password: " + err.Error()})
		return
	}

	// Invalidate all active refresh tokens for this user from the database
	invalidateTokensQuery := `DELETE FROM refresh_tokens WHERE user_id = $1`
	_, err = h.DB.Exec(invalidateTokensQuery, userIDString)
	if err != nil {
		// Log this error, but the password change itself was successful.
		// The user might need to log in again on other devices.
		log.Printf("Failed to invalidate refresh tokens for user %s after password change: %v", userIDString, err)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully. All active sessions have been logged out."})
}
