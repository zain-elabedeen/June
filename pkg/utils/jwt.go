package utils

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims defines the JWT claims structure.
type Claims struct {
	UserID uuid.UUID `json:"user_id"`
	Email  string    `json:"email"`
	Role   string    `json:"role"` // Assuming role is a string, adjust if it's a custom type
	jwt.RegisteredClaims
}

// GenerateToken generates a JWT token.
func GenerateToken(userID uuid.UUID, secretKey string, expirationTime time.Duration) (string, *Claims, error) {
	tokenID := uuid.New()
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expirationTime)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        tokenID.String(), // JTI (JWT ID)
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", nil, err
	}
	return signedToken, claims, nil
}

// GenerateTokens generates both access and refresh JWT tokens.
// It now returns the refresh token's claims as well, which includes the JTI.
func GenerateTokens(userID uuid.UUID, email, role string, accessSecret, refreshSecret string, accessExpMinutes, refreshExpDays int) (accessToken string, refreshToken string, refreshTokenClaims *Claims, err error) {
	accessToken, _, err = GenerateToken(userID, accessSecret, time.Duration(accessExpMinutes)*time.Minute)
	if err != nil {
		return
	}
	refreshToken, refreshTokenClaims, err = GenerateToken(userID, refreshSecret, time.Duration(refreshExpDays*24)*time.Hour)
	refreshTokenClaims.Email = email
	refreshTokenClaims.Role = role
	return
}

// ValidateToken validates a JWT token and returns the claims if valid.
func ValidateToken(tokenString string, secretKey string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{},
		func(token *jwt.Token) (interface{}, error) {
			// Check the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(secretKey), nil
		},
		// Optional: Add validation options like leeway for clock skew
		// jwt.WithLeeway(5*time.Second),
	)

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("token is invalid or claims type assertion failed")
	}

	return claims, nil
}
