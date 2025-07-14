package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/tuannvm/mcp-trino/internal/auth"
	"github.com/tuannvm/mcp-trino/internal/config"
	"github.com/tuannvm/mcp-trino/internal/handlers"
	"github.com/tuannvm/mcp-trino/internal/trino"
)

// These variables will be set during the build via ldflags
var (
	// Version is the server version, set by the build process
	Version = "dev"
)

// Context keys are now imported from auth package

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
	defer func() {
		if err := trinoClient.Close(); err != nil {
			log.Printf("Error closing Trino client: %v", err)
		}
	}()

	// Test connection by listing catalogs
	log.Println("Testing Trino connection...")
	catalogs, err := trinoClient.ListCatalogs()
	if err != nil {
		log.Fatalf("Failed to connect to Trino: %v", err)
	}
	log.Printf("Connected to Trino server. Available catalogs: %s", strings.Join(catalogs, ", "))

	// Create OAuth token injection context function
	contextFunc := func(ctx context.Context, r *http.Request) context.Context {
		// Extract Bearer token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			// Clean any whitespace
			token = strings.TrimSpace(token)
			ctx = auth.WithOAuthToken(ctx, token)
			log.Printf("OAuth: Token extracted from request (length: %d)", len(token))
		} else if authHeader != "" {
			preview := authHeader
			if len(authHeader) > 30 {
				preview = authHeader[:30] + "..."
			}
			log.Printf("OAuth: Invalid Authorization header format: %s", preview)
		}
		return ctx
	}

	// Create MCP server with OAuth middleware
	log.Println("Initializing MCP server...")
	
	// Create hooks for server-level authentication
	hooks := &server.Hooks{}
	if trinoConfig.OAuthEnabled {
		hooks.AddOnRequestInitialization(auth.CreateRequestAuthHook())
	}
	
	mcpServer := server.NewMCPServer("Trino MCP Server", Version,
		server.WithToolCapabilities(true),
		server.WithHooks(hooks),
	)

	// Initialize tool handlers
	trinoHandlers := handlers.NewTrinoHandlers(trinoClient)
	registerTrinoTools(mcpServer, trinoHandlers)

	// Choose server mode
	transport := getEnv("MCP_TRANSPORT", "stdio")

	// Graceful shutdown
	done := make(chan bool, 1)
	go handleSignals(done)

	log.Printf("Starting MCP server with %s transport...", transport)
	switch transport {
	case "stdio":
		if err := server.ServeStdio(mcpServer); err != nil {
			log.Fatalf("STDIO server error: %v", err)
		}
	case "http":
		port := getEnv("MCP_PORT", "9097")
		addr := fmt.Sprintf(":%s", port)

		// Create StreamableHTTP server (modern approach)
		log.Println("Setting up StreamableHTTP server...")
		
		// Create StreamableHTTP server instance
		streamableServer := server.NewStreamableHTTPServer(
			mcpServer,
			server.WithEndpointPath("/mcp"),
			server.WithHTTPContextFunc(contextFunc),
			server.WithStateLess(false), // Enable session management
		)
		
		// Create HTTP mux for routing
		mux := http.NewServeMux()
		
		// Add status endpoint
		mux.HandleFunc("/", handleStatus)
		
		// Add MCP endpoint with StreamableHTTP
		mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
			// Add CORS headers
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			
			log.Printf("MCP %s %s", r.Method, r.URL.Path)
			
			// Handle MCP request using StreamableHTTP server
			streamableServer.ServeHTTP(w, r)
		})

		httpServer := &http.Server{
			Addr:    addr,
			Handler: mux,
		}

		go func() {
			if trinoConfig.OAuthEnabled {
				certFile := getEnv("HTTPS_CERT_FILE", "")
				keyFile := getEnv("HTTPS_KEY_FILE", "")
				
				if certFile != "" && keyFile != "" {
					log.Printf("Starting HTTPS server on %s/mcp (OAuth enabled)", addr)
					if err := httpServer.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
						log.Fatalf("HTTPS server error: %v", err)
					}
				} else {
					log.Printf("WARNING: OAuth is enabled but HTTPS certificates not provided. Running HTTP server (not recommended for production)")
					log.Printf("Starting HTTP server on %s/mcp", addr)
					if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
						log.Fatalf("HTTP server error: %v", err)
					}
				}
			} else {
				log.Printf("Starting HTTP server on %s/mcp", addr)
				if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Fatalf("HTTP server error: %v", err)
				}
			}
		}()

		<-done
		log.Println("Shutting down HTTP server...")
		_ = httpServer.Close()
	default:
		log.Fatalf("Unsupported transport: %s", transport)
	}

	log.Println("Server shutdown complete")
}

func registerTrinoTools(m *server.MCPServer, h *handlers.TrinoHandlers) {
	m.AddTool(mcp.NewTool("execute_query",
		mcp.WithDescription("Execute a SQL query"),
		mcp.WithString("query", mcp.Required(), mcp.Description("SQL query")),
	), h.ExecuteQuery)
	m.AddTool(mcp.NewTool("list_catalogs", mcp.WithDescription("List catalogs")), h.ListCatalogs)
	m.AddTool(mcp.NewTool("list_schemas",
		mcp.WithDescription("List schemas"),
		mcp.WithString("catalog", mcp.Description("Catalog"))), h.ListSchemas)
	m.AddTool(mcp.NewTool("list_tables",
		mcp.WithDescription("List tables"),
		mcp.WithString("catalog", mcp.Description("Catalog")),
		mcp.WithString("schema", mcp.Description("Schema"))), h.ListTables)
	m.AddTool(mcp.NewTool("get_table_schema",
		mcp.WithDescription("Get table schema"),
		mcp.WithString("catalog", mcp.Description("Catalog")),
		mcp.WithString("schema", mcp.Description("Schema")),
		mcp.WithString("table", mcp.Required(), mcp.Description("Table"))), h.GetTableSchema)
}

func handleSignals(done chan<- bool) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	done <- true
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"status":"ok","version":"%s"}`, Version)
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}