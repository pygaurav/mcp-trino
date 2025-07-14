package main

import (
	"context"
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
	"github.com/tuannvm/mcp-trino/internal/auth"
	"github.com/tuannvm/mcp-trino/internal/config"
	"github.com/tuannvm/mcp-trino/internal/handlers"
	"github.com/tuannvm/mcp-trino/internal/middleware"
	"github.com/tuannvm/mcp-trino/internal/oauth"
	"github.com/tuannvm/mcp-trino/internal/trino"
)

// These variables will be set during the build via ldflags
var (
	// Version is the server version, set by the build process
	Version = "dev"
)

func main() {
	log.Println("Starting Trino MCP Server...")

	// Initialize Trino configuration
	log.Println("Loading Trino configuration...")
	trinoConfig := config.NewTrinoConfig()

	// Initialize OAuth configuration if enabled
	var bearerValidator *auth.BearerTokenValidator
	var authMiddleware *middleware.AuthMiddleware
	
	if trinoConfig.OAuthEnabled {
		log.Println("Setting up OAuth authentication...")
		
		// Setup OAuth configuration
		providerURL := getEnv("OAUTH_PROVIDER_URL", "")
		if providerURL == "" {
			log.Fatal("OAUTH_PROVIDER_URL is required when OAuth is enabled")
		}
		
		ctx := context.Background()
		oauthConfig, err := oauth.SetupOAuthConfiguration(ctx, providerURL)
		if err != nil {
			log.Fatalf("Failed to setup OAuth configuration: %v", err)
		}
		
		// Fetch JWKS for token validation
		client := oauth.NewOAuthDiscoveryClient()
		jwks, err := client.FetchJWKS(ctx, oauthConfig.JWKSURL)
		if err != nil {
			log.Fatalf("Failed to fetch JWKS: %v", err)
		}
		
		// Get the first RSA key (simplified)
		if len(jwks.Keys) == 0 {
			log.Fatal("No keys found in JWKS")
		}
		
		publicKey, err := jwks.Keys[0].GetPublicKey()
		if err != nil {
			log.Fatalf("Failed to parse public key: %v", err)
		}
		
		// Create Bearer token validator
		bearerValidator = auth.NewBearerTokenValidator(publicKey, oauthConfig.Issuer, oauthConfig.ClientID)
		
		// Create authentication middleware
		authMiddleware = middleware.NewAuthMiddleware(trinoConfig, bearerValidator)
		
		log.Println("OAuth authentication setup complete")
	}

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

	// Create and initialize MCP server
	log.Println("Initializing MCP server...")
	mcpServer := server.NewMCPServer("Trino MCP Server", Version)

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
		host := getEnv("MCP_HOST", "localhost")
		addr := fmt.Sprintf(":%s", port)

		// Create SSE server
		log.Println("Setting up SSE server...")
		baseURL := fmt.Sprintf("http://%s:%s", host, port)
		sseServer := server.NewSSEServer(
			mcpServer,
			server.WithSSEEndpoint("/sse"),
			server.WithMessageEndpoint("/api/v1"),
			server.WithKeepAlive(true),
			server.WithBaseURL(baseURL),
			server.WithUseFullURLForMessageEndpoint(true),
		)
		log.Printf("SSE path: %s", sseServer.CompleteSsePath())
		log.Printf("Message path: %s", sseServer.CompleteMessagePath())

		// Create HTTP handler with authentication
		var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("HTTP %s %s", r.Method, r.URL.Path)
			
			switch {
			case r.URL.Path == "/sse":
				w.Header().Set("Content-Type", "text/event-stream")
				sseServer.ServeHTTP(w, r)
			case r.Method == http.MethodPost && r.URL.Path == "/api/query":
				handleTrinoQuery(w, r, trinoClient)
			case r.Method == http.MethodGet && r.URL.Path == "/":
				handleStatus(w, r)
			default:
				sseServer.ServeHTTP(w, r)
			}
		})

		// Apply middleware stack
		handler = middleware.LoggingMiddleware(handler)
		handler = middleware.SecurityHeadersMiddleware(handler)
		handler = middleware.CORSMiddleware(handler)
		
		// Apply authentication middleware if OAuth is enabled
		if trinoConfig.OAuthEnabled && authMiddleware != nil {
			handler = authMiddleware.AuthenticateRequest(handler)
		}

		httpServer := &http.Server{
			Addr:    addr,
			Handler: handler,
		}

		go func() {
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTP server error: %v", err)
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

func handleTrinoQuery(w http.ResponseWriter, r *http.Request, client *trino.Client) {
	if client == nil {
		http.Error(w, "Trino client not available", http.StatusServiceUnavailable)
		return
	}

	// Log authentication info
	middleware.LogAuthenticationInfo(r.Context(), "direct query execution")
	
	var req struct {
		Query string `json:"query"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	res, err := client.ExecuteQuery(req.Query)
	if err != nil {
		http.Error(w, fmt.Sprintf("Query failed: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
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
	status := map[string]string{"status": "ok", "version": Version}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}
