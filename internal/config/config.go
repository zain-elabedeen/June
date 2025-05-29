package config

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Config stores all configuration of the application.
// The values are read by viper from a config file or environment variables.
type Config struct {
	GinMode               string `mapstructure:"GIN_MODE"`
	ServerPort            string `mapstructure:"SERVER_PORT"`
	DBHost                string `mapstructure:"DB_HOST"`
	DBPort                string `mapstructure:"DB_PORT"`
	DBUser                string `mapstructure:"DB_USER"`
	DBPassword            string `mapstructure:"DB_PASSWORD"`
	DBName                string `mapstructure:"DB_NAME"`
	DBSslMode             string `mapstructure:"DB_SSLMODE"`
	JWTAccessSecret       string `mapstructure:"JWT_ACCESS_SECRET"`
	JWTRefreshSecret      string `mapstructure:"JWT_REFRESH_SECRET"`
	JWTAccessTokenExpiry  int    `mapstructure:"JWT_ACCESS_EXP_MINUTES"` // Added for access token expiry
	JWTRefreshTokenExpiry int    `mapstructure:"JWT_REFRESH_EXP_DAYS"`   // Added for refresh token expiry
	APIBaseURL            string `mapstructure:"API_BASE_URL"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(paths ...string) (config Config, err error) {
	// Set default values
	viper.SetDefault("GIN_MODE", "debug")
	viper.SetDefault("SERVER_PORT", "8080")
	viper.SetDefault("DB_SSLMODE", "disable")
	viper.SetDefault("JWT_ACCESS_EXP_MINUTES", 15)
	viper.SetDefault("JWT_REFRESH_EXP_DAYS", 7)

	vp := viper.New()
	// Explicitly bind environment variables
	vp.BindEnv("GIN_MODE")
	vp.BindEnv("SERVER_PORT")
	vp.BindEnv("DB_HOST")
	vp.BindEnv("DB_PORT")
	vp.BindEnv("DB_USER")
	vp.BindEnv("DB_PASSWORD")
	vp.BindEnv("DB_NAME")
	vp.BindEnv("DB_SSLMODE")
	vp.BindEnv("JWT_ACCESS_SECRET")
	vp.BindEnv("JWT_REFRESH_SECRET")
	vp.BindEnv("JWT_ACCESS_EXP_MINUTES")
	vp.BindEnv("JWT_REFRESH_EXP_DAYS")
	vp.BindEnv("API_BASE_URL")

	// If a config file path is provided, try to read it
	if len(paths) > 0 && paths[0] != "" {
		for _, path := range paths {
			vp.AddConfigPath(path)
		}
		vp.SetConfigName("app") // Name of config file (without extension)
		vp.SetConfigType("env") // Look for .env file
		// Example: /path/to/config/app.env

		if err = vp.ReadInConfig(); err != nil {
			// Ignore error if file not found, continue to load environment variables
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				// Config file was found but another error was produced
				return Config{}, fmt.Errorf("failed to read config file: %w", err)
			}
		}
	}

	// Override with environment variables
	vp.AutomaticEnv()
	vp.SetEnvKeyReplacer(strings.NewReplacer(".", "_")) // Replace dots with underscores for nested keys if any

	err = vp.Unmarshal(&config)
	if err != nil {
		return Config{}, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Fallback for SERVER_PORT if Viper didn't load it (e.g., from env var)
	if config.ServerPort == "" {
		config.ServerPort = os.Getenv("SERVER_PORT")
	}

	// Basic validation (can be expanded)
	log.Printf("Config DB: Host=%s, Port=%s, User=%s, Name=%s, ServerPort=%s", config.DBHost, config.DBPort, config.DBUser, config.DBName, config.ServerPort)
	if config.DBHost == "" || config.DBUser == "" || config.DBPassword == "" || config.DBName == "" {
		return Config{}, fmt.Errorf("database configuration is incomplete")
	}
	if config.JWTAccessSecret == "" {
		return Config{}, fmt.Errorf("JWT_ACCESS_SECRET is required")
	}
	if config.JWTRefreshSecret == "" {
		return Config{}, fmt.Errorf("JWT_REFRESH_SECRET is required")
	}

	return
}
