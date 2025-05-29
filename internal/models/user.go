package models

import (
	"time"

	"github.com/google/uuid"
)

// UserRole defines the type for user roles.
// Corresponds to the 'user_role' ENUM in PostgreSQL.
// We define it here as a string type for simplicity in Go code,
// but it will be validated against the ENUM constraints at the DB level.
type UserRole string

const (
	RoleUser  UserRole = "user"
	RoleAdmin UserRole = "admin"
)

// User represents a user in the system.
// Corresponds to the 'users' table in PostgreSQL.
// Note: We use sql.NullString, sql.NullBool, etc. for nullable fields if needed,
// or pointers to basic types. For TIMESTAMPTZ, *time.Time can be used for nullability.
// For gen_random_uuid() default, we expect the DB to handle it on INSERT if ID is not provided or is zero UUID.
type User struct {
	ID                uuid.UUID `json:"id" db:"id"`
	Email             string    `json:"email" db:"email"`
	Phone             *string   `json:"phone,omitempty" db:"phone"` // Pointer for nullability
	PasswordHash      string    `json:"-" db:"password_hash"`      // Omit from JSON responses
	FullName          string    `json:"full_name" db:"full_name"`
	Role              UserRole  `json:"role" db:"role"`
	IsEmailVerified   bool      `json:"is_email_verified" db:"is_email_verified"`
	IsPhoneVerified   bool      `json:"is_phone_verified" db:"is_phone_verified"`
	TwoFactorEnabled  bool      `json:"two_factor_enabled" db:"two_factor_enabled"`
	TwoFactorSecret   *string   `json:"-" db:"two_factor_secret"` // Omit from JSON responses, pointer for nullability
	DeletedAt         *time.Time `json:"deleted_at,omitempty" db:"deleted_at"` // Pointer for nullability
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time `json:"updated_at" db:"updated_at"`
}

// RegistrationRequest defines the expected structure for user registration.
// We'll use this for binding JSON in the registration handler.
type RegistrationRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"` // Example: min 8 chars
	FullName string `json:"full_name" binding:"required"`
	Phone    *string `json:"phone,omitempty"` // Optional phone number
}

// LoginRequest defines the expected structure for user login.
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// TokenResponse defines the structure for returning JWT tokens.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	// Optionally, you can include token expiry times or user details here
}

// RefreshTokenRequest defines the structure for the refresh token request.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// ChangePasswordRequest defines the structure for changing a user's password.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=8"` // Example: min 8 chars
}
