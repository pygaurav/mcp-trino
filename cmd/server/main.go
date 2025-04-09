package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/tuannvm/mcp-trino/internal/config"
	"github.com/tuannvm/mcp-trino/internal/handlers"
	"github.com/tuannvm/mcp-trino/internal/trino"
)

const (
	// Version is the server version
	Version = "0.1.0"
)

func main() {
	log.Println("Starting Trino MCP Server...")

	// Initialize Trino configuration
	log.Println("Loading Trino configuration...")
	trinoConfig := config.NewTrinoConfig()

	// Initialize Trino client
	log.Println("Connecting to Trino server...")
	trinoClient, err := trino.NewClient(trinoConfig)
	if err != nil {
		log.Fatalf("Failed to initialize Trino client: %v", err)
	}
	defer trinoClient.Close()

	// Test connection by listing catalogs
	log.Println("Testing Trino connection...")
	catalogs, err := trinoClient.ListCatalogs()
	if err != nil {
		log.Fatalf("Failed to connect to Trino: %v", err)
	}
	log.Printf("Connected to Trino server. Available catalogs: %s", strings.Join(catalogs, ", "))

	// Create and initialize MCP server
	log.Println("Initializing MCP server...")
	mcpServer := server.NewMCPServer("Trino MCP Server", Version)

	// Initialize tool handlers
	trinoHandlers := handlers.NewTrinoHandlers(trinoClient)

	// Register Trino tools
	registerTrinoTools(mcpServer, trinoHandlers)

	// Choose server mode based on environment
	transport := getEnv("MCP_TRANSPORT", "stdio")

	// Setup graceful shutdown
	done := make(chan bool, 1)
	go handleSignals(done)

	// Start the server
	log.Printf("Starting Trino MCP Server with %s transport...", transport)
	switch transport {
	case "stdio":
		if err := server.ServeStdio(mcpServer); err != nil {
			log.Fatalf("STDIO server error: %v", err)
		}
	case "http":
		// HTTP server implementation
		port := getEnv("MCP_PORT", "8080")
		addr := fmt.Sprintf(":%s", port)

		// Create an HTTP server
		log.Printf("Starting HTTP server on %s", addr)
		httpServer := &http.Server{
			Addr: addr,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/api/query" {
					handleTrinoQuery(w, r, trinoClient)
					return
				}

				http.Error(w, "Not found", http.StatusNotFound)
			}),
		}

		// Start HTTP server in goroutine
		go func() {
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTP server error: %v", err)
			}
		}()

		// Wait for shutdown signal
		<-done
		log.Println("Shutting down HTTP server...")
		if err := httpServer.Close(); err != nil {
			log.Printf("Error closing HTTP server: %v", err)
		}
	default:
		log.Fatalf("Unsupported transport: %s", transport)
	}

	log.Println("Server shutdown complete")
}

// handleTrinoQuery handles HTTP requests for Trino queries
func handleTrinoQuery(w http.ResponseWriter, r *http.Request, client *trino.Client) {
	// Parse request
	var request struct {
		Query string `json:"query"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	// Execute query
	results, err := client.ExecuteQuery(request.Query)
	if err != nil {
		http.Error(w, fmt.Sprintf("Query execution failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Return results as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		http.Error(w, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

// registerTrinoTools registers all Trino-related tools with the MCP server
func registerTrinoTools(mcpServer *server.MCPServer, h *handlers.TrinoHandlers) {
	// Register ExecuteQuery tool
	executeQueryTool := mcp.NewTool("execute_query",
		mcp.WithDescription("Execute a SQL query against the Trino server"),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("The SQL query to execute"),
		),
	)
	mcpServer.AddTool(executeQueryTool, h.ExecuteQuery)

	// Register ListCatalogs tool
	listCatalogsTool := mcp.NewTool("list_catalogs",
		mcp.WithDescription("List all available catalogs in the Trino server"),
	)
	mcpServer.AddTool(listCatalogsTool, h.ListCatalogs)

	// Register ListSchemas tool
	listSchemasTool := mcp.NewTool("list_schemas",
		mcp.WithDescription("List all schemas in a catalog"),
		mcp.WithString("catalog",
			mcp.Description("The catalog to list schemas from (optional)"),
		),
	)
	mcpServer.AddTool(listSchemasTool, h.ListSchemas)

	// Register ListTables tool
	listTablesTool := mcp.NewTool("list_tables",
		mcp.WithDescription("List all tables in a schema"),
		mcp.WithString("catalog",
			mcp.Description("The catalog containing the schema (optional)"),
		),
		mcp.WithString("schema",
			mcp.Description("The schema to list tables from (optional)"),
		),
	)
	mcpServer.AddTool(listTablesTool, h.ListTables)

	// Register GetTableSchema tool
	getTableSchemaTool := mcp.NewTool("get_table_schema",
		mcp.WithDescription("Get the schema of a table"),
		mcp.WithString("catalog",
			mcp.Description("The catalog containing the table (optional)"),
		),
		mcp.WithString("schema",
			mcp.Description("The schema containing the table (optional)"),
		),
		mcp.WithString("table",
			mcp.Required(),
			mcp.Description("The table to get the schema for"),
		),
	)
	mcpServer.AddTool(getTableSchemaTool, h.GetTableSchema)
}

// handleSignals handles OS signals for graceful shutdown
func handleSignals(done chan<- bool) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
	log.Println("Received shutdown signal, shutting down...")
	done <- true
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
