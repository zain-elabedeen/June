package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"api/internal/config" // Assuming your module is 'api'

	_ "github.com/lib/pq" // PostgreSQL driver
)

// DB is a global variable to hold the database connection pool.
var DB *sql.DB

// ConnectDB initializes the database connection using the provided configuration.
func ConnectDB(cfg config.Config) error {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.DBHost,
		cfg.DBPort,
		cfg.DBUser,
		cfg.DBPassword,
		cfg.DBName,
		cfg.DBSslMode,
	)

	var err error
	DB, err = sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool settings
	DB.SetMaxOpenConns(25) // Example value, adjust as needed
	DB.SetMaxIdleConns(25) // Example value, adjust as needed
	DB.SetConnMaxLifetime(5 * time.Minute) // Example value, adjust as needed

	// Test the connection
	err = DB.Ping()
	if err != nil {
		DB.Close() // Close the connection if ping fails
		return fmt.Errorf("failed to ping database: %w", err)
	}

	log.Println("Successfully connected to the database!")
	return nil
}

// CloseDB closes the database connection.
// It's good practice to call this when the application is shutting down.
func CloseDB() {
	if DB != nil {
		err := DB.Close()
		if err != nil {
			log.Printf("Error closing database connection: %v", err)
		} else {
			log.Println("Database connection closed.")
		}
	}
}
