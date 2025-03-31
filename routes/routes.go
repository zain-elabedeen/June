package routes

import (
	"api/handlers"
	"api/middleware"

	"github.com/gin-gonic/gin"
)

// SetupRouter initializes all routes
func SetupRouter() *gin.Engine {
	router := gin.Default()

	// Add middleware
	router.Use(middleware.Logger())

	// Health check
	router.GET("/health", handlers.HealthCheck)

	// API v1 group
	v1 := router.Group("/api/v1")
	{
		v1.GET("/", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"message": "Welcome to API v1",
			})
		})
	}

	return router
}
