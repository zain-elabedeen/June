package main

import (
	"api/internal/config"
	"api/internal/database"
	"api/routes"
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	// Load application configuration
	// We pass an empty string for path, relying on environment variables primarily.
	// If you have an app.env file in the root, you could pass "." as the path.
	cfg, err := config.LoadConfig("")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize database connection
	if err := database.ConnectDB(cfg); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.CloseDB() // Ensure DB connection is closed when main exits

	// Set Gin mode
	gin.SetMode(cfg.GinMode)

	// Pass database connection and config to the router setup
	router := routes.SetupRouter(database.DB, cfg)

	serverAddr := fmt.Sprintf(":%s", cfg.ServerPort)
	log.Printf("Starting server on %s in %s mode", serverAddr, cfg.GinMode)
	if err := router.Run(serverAddr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
