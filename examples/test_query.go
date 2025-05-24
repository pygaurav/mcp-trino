// Package main executes test queries against the Trino server
// and demonstrates basic client functionality.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

const (
	host = "localhost"
	port = "9097"
)

func main() {
	// Test a simple query
	result, err := executeQuery("SELECT 1 AS test")
	if err != nil {
		log.Fatalf("Query execution failed: %v", err)
	}
	fmt.Println("Query result:")
	fmt.Println(result)

	// Test listing catalogs
	catalogs, err := listCatalogs()
	if err != nil {
		log.Fatalf("Failed to list catalogs: %v", err)
	}
	fmt.Println("\nAvailable catalogs:")
	for _, catalog := range catalogs {
		fmt.Printf("- %s\n", catalog)
	}

	// If memory catalog is available, list schemas
	if contains(catalogs, "memory") {
		schemas, err := listSchemas("memory")
		if err != nil {
			log.Fatalf("Failed to list schemas: %v", err)
		}
		fmt.Println("\nAvailable schemas in memory catalog:")
		for _, schema := range schemas {
			fmt.Printf("- %s\n", schema)
		}
	}
}

// executeQuery executes a SQL query against the Trino server
func executeQuery(query string) (string, error) {
	url := fmt.Sprintf("http://%s:%s/api/query", host, port)
	payload := fmt.Sprintf(`{"query": "%s"}`, escapeQuery(query))

	resp, err := http.Post(url, "application/json", strings.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Error closing response body: %v\n", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("server error: %s", string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, body, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to format JSON: %v", err)
	}

	return prettyJSON.String(), nil
}

// listCatalogs lists all available catalogs
func listCatalogs() ([]string, error) {
	query := "SHOW CATALOGS"
	result, err := executeQuery(query)
	if err != nil {
		return nil, err
	}

	var data []map[string]interface{}
	err = json.Unmarshal([]byte(result), &data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse catalog result: %v", err)
	}

	catalogs := make([]string, 0, len(data))
	for _, row := range data {
		if catalog, ok := row["Catalog"].(string); ok {
			catalogs = append(catalogs, catalog)
		}
	}

	return catalogs, nil
}

// listSchemas lists all schemas in a catalog
func listSchemas(catalog string) ([]string, error) {
	query := fmt.Sprintf("SHOW SCHEMAS FROM %s", catalog)
	result, err := executeQuery(query)
	if err != nil {
		return nil, err
	}

	var data []map[string]interface{}
	err = json.Unmarshal([]byte(result), &data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse schema result: %v", err)
	}

	schemas := make([]string, 0, len(data))
	for _, row := range data {
		if schema, ok := row["Schema"].(string); ok {
			schemas = append(schemas, schema)
		}
	}

	return schemas, nil
}

// escapeQuery escapes quotes in a SQL query
func escapeQuery(query string) string {
	return strings.ReplaceAll(query, `"`, `\"`)
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
