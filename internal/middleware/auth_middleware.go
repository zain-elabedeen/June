package middleware

import (
	"api/internal/config"
	"api/pkg/utils"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware creates a Gin middleware for JWT authentication.
func AuthMiddleware(cfg config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization_header_missing", "message": "Authorization header is required"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_authorization_header", "message": "Authorization header must be in 'Bearer {token}' format"})
			return
		}

		tokenString := parts[1]
		claims, err := utils.ValidateToken(tokenString, cfg.JWTAccessSecret)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "message": "Invalid or expired access token: " + err.Error()})
			return
		}

		// Set user information in the context for downstream handlers
		c.Set("userID", claims.UserID.String()) // Store as string for easier retrieval
		c.Set("userEmail", claims.Email)
		c.Set("userRole", claims.Role)

		c.Next()
	}
}
