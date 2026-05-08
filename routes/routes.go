package routes

import (
	"api/handlers"
	"api/internal/auth"
	"api/internal/config"
	internalmiddleware "api/internal/middleware" // Alias for middleware package
	"api/internal/simulation"

	// "api/middleware" // Removing this, as Logger is now in internalmiddleware
	"database/sql"

	"github.com/gin-gonic/gin"
)

// SetupRouter initializes all routes and sets up dependencies for handlers.
func SetupRouter(db *sql.DB, cfg config.Config) *gin.Engine {
	simRuntime := simulation.New(cfg)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(simulation.StructuredLogger(cfg.ServiceName))
	router.Use(simRuntime.Middleware())

	// Add middleware
	// router.Use(internalmiddleware.Logger())

	// Health check
	// TODO: If HealthCheck needs db or cfg, refactor handlers.HealthCheck to accept them.
	// Example: router.GET("/health", handlers.HealthCheck(db, cfg))
	router.GET("/health", handlers.HealthCheck)
	router.GET("/ready", simRuntime.ReadyHandler())

	// API v1 group
	v1 := router.Group("/api/v1")
	{
		v1.GET("/", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"message": "Welcome to API v1",
			})
		})
		v1.GET("/sim", simRuntime.InfoHandler())
		v1.GET("/sim/work", simRuntime.WorkHandler())

		// Authentication routes
		authHandler := auth.NewAuthHandler(db, cfg) // Create AuthHandler instance
		authRoutes := v1.Group("/auth")
		{
			authRoutes.POST("/register", authHandler.Register)
			authRoutes.POST("/login", authHandler.Login)
			authRoutes.POST("/refresh", authHandler.RefreshToken)
			authRoutes.POST("/logout", authHandler.Logout)
			authRoutes.GET("/me", internalmiddleware.AuthMiddleware(cfg), authHandler.GetMe)
			authRoutes.PUT("/change-password", internalmiddleware.AuthMiddleware(cfg), authHandler.ChangePassword) // Apply AuthMiddleware here
			// TODO: Add other auth routes: /2fa/enable etc.
		}
	}

	return router
}
