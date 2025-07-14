package config

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// TrinoConfig holds Trino connection parameters
type TrinoConfig struct {
	Host                   string
	Port                   int
	User                   string
	Password               string
	Catalog                string
	Schema                 string
	Scheme                 string
	SSL                    bool
	SSLInsecure            bool
	ExternalAuthentication bool
	AccessToken            string
	AllowWriteQueries      bool          // Controls whether non-read-only SQL queries are allowed
	QueryTimeout           time.Duration // Query execution timeout
}

// NewTrinoConfig creates a new TrinoConfig with values from environment variables or defaults
func NewTrinoConfig() *TrinoConfig {
	port, _ := strconv.Atoi(getEnv("TRINO_PORT", "8080"))
	ssl, _ := strconv.ParseBool(getEnv("TRINO_SSL", "true"))
	sslInsecure, _ := strconv.ParseBool(getEnv("TRINO_SSL_INSECURE", "true"))
	scheme := getEnv("TRINO_SCHEME", "https")
	externalAuthentication, _ := strconv.ParseBool(getEnv("TRINO_EXTERNAL_AUTHENTICATION", "false"))
	accessToken := getEnv("TRINO_ACCESS_TOKEN", "")
	allowWriteQueries, _ := strconv.ParseBool(getEnv("TRINO_ALLOW_WRITE_QUERIES", "false"))

	// Parse query timeout from environment variable
	const defaultTimeout = 30
	timeoutStr := getEnv("TRINO_QUERY_TIMEOUT", strconv.Itoa(defaultTimeout))
	timeoutInt, err := strconv.Atoi(timeoutStr)

	// Validate timeout value
	switch {
	case err != nil:
		log.Printf("WARNING: Invalid TRINO_QUERY_TIMEOUT '%s': not an integer. Using default of %d seconds", timeoutStr, defaultTimeout)
		timeoutInt = defaultTimeout
	case timeoutInt <= 0:
		log.Printf("WARNING: Invalid TRINO_QUERY_TIMEOUT '%d': must be positive. Using default of %d seconds", timeoutInt, defaultTimeout)
		timeoutInt = defaultTimeout
	}

	queryTimeout := time.Duration(timeoutInt) * time.Second

	// If using HTTPS, force SSL to true
	if strings.EqualFold(scheme, "https") {
		ssl = true
	}

	// Log a warning if write queries are allowed
	if allowWriteQueries {
		log.Println("WARNING: Write queries are enabled (TRINO_ALLOW_WRITE_QUERIES=true). SQL injection protection is bypassed.")
	}

	return &TrinoConfig{
		Host:                   getEnv("TRINO_HOST", "localhost"),
		Port:                   port,
		User:                   getEnv("TRINO_USER", "trino"),
		Password:               getEnv("TRINO_PASSWORD", ""),
		Catalog:                getEnv("TRINO_CATALOG", "memory"),
		Schema:                 getEnv("TRINO_SCHEMA", "default"),
		Scheme:                 scheme,
		SSL:                    ssl,
		SSLInsecure:            sslInsecure,
		ExternalAuthentication: externalAuthentication,
		AccessToken:            accessToken,
		AllowWriteQueries:      allowWriteQueries,
		QueryTimeout:           queryTimeout,
	}
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
