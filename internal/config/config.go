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
	ServiceName           string `mapstructure:"JUNE_SERVICE_NAME"`
	SimEnabled            bool   `mapstructure:"JUNE_SIM_ENABLED"`
	SimProfile            string `mapstructure:"JUNE_SIM_PROFILE"`
	SimErrorEvery         int    `mapstructure:"JUNE_SIM_ERROR_EVERY"`
	SimLatencyMs          int    `mapstructure:"JUNE_SIM_LATENCY_MS"`
	SimTimeoutEvery       int    `mapstructure:"JUNE_SIM_TIMEOUT_EVERY"`
	SimDependencyEvery    int    `mapstructure:"JUNE_SIM_DEPENDENCY_ERROR_EVERY"`
	SimCPUBurnMs          int    `mapstructure:"JUNE_SIM_CPU_BURN_MS"`
	SimMemoryMB           int    `mapstructure:"JUNE_SIM_MEMORY_MB"`
	SimCrashAfterRequests int    `mapstructure:"JUNE_SIM_CRASH_AFTER_REQUESTS"`
	SimProbeFailureEvery  int    `mapstructure:"JUNE_SIM_PROBE_FAILURE_EVERY"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(paths ...string) (config Config, err error) {
	vp := viper.New()

	// Set default values
	vp.SetDefault("GIN_MODE", "debug")
	vp.SetDefault("SERVER_PORT", "8080")
	vp.SetDefault("DB_SSLMODE", "disable")
	vp.SetDefault("JWT_ACCESS_EXP_MINUTES", 15)
	vp.SetDefault("JWT_REFRESH_EXP_DAYS", 7)
	vp.SetDefault("JUNE_SERVICE_NAME", "june-api")
	vp.SetDefault("JUNE_SIM_ENABLED", false)
	vp.SetDefault("JUNE_SIM_PROFILE", "baseline")

	for _, key := range []string{
		"GIN_MODE",
		"SERVER_PORT",
		"DB_HOST",
		"DB_PORT",
		"DB_USER",
		"DB_PASSWORD",
		"DB_NAME",
		"DB_SSLMODE",
		"JWT_ACCESS_SECRET",
		"JWT_REFRESH_SECRET",
		"JWT_ACCESS_EXP_MINUTES",
		"JWT_REFRESH_EXP_DAYS",
		"API_BASE_URL",
		"JUNE_SERVICE_NAME",
		"JUNE_SIM_ENABLED",
		"JUNE_SIM_PROFILE",
		"JUNE_SIM_ERROR_EVERY",
		"JUNE_SIM_LATENCY_MS",
		"JUNE_SIM_TIMEOUT_EVERY",
		"JUNE_SIM_DEPENDENCY_ERROR_EVERY",
		"JUNE_SIM_CPU_BURN_MS",
		"JUNE_SIM_MEMORY_MB",
		"JUNE_SIM_CRASH_AFTER_REQUESTS",
		"JUNE_SIM_PROBE_FAILURE_EVERY",
	} {
		if bindErr := vp.BindEnv(key); bindErr != nil {
			return Config{}, fmt.Errorf("failed to bind env %s: %w", key, bindErr)
		}
	}

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
