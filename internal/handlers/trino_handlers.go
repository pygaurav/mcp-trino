package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/tuannvm/mcp-trino/internal/middleware"
	"github.com/tuannvm/mcp-trino/internal/trino"
)

// TrinoHandlers contains all handlers for Trino-related tools
type TrinoHandlers struct {
	TrinoClient *trino.Client
}

// NewTrinoHandlers creates a new set of Trino handlers
func NewTrinoHandlers(client *trino.Client) *TrinoHandlers {
	return &TrinoHandlers{
		TrinoClient: client,
	}
}

// ExecuteQuery handles query execution
func (h *TrinoHandlers) ExecuteQuery(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Log authentication info
	middleware.LogAuthenticationInfo(ctx, "execute_query")
	
	// Type assert Arguments to map[string]interface{}
	args, ok := request.Params.Arguments.(map[string]interface{})
	if !ok {
		mcpErr := fmt.Errorf("invalid arguments format")
		return mcp.NewToolResultErrorFromErr(mcpErr.Error(), mcpErr), nil
	}
	
	// Extract the query parameter
	query, ok := args["query"].(string)
	if !ok {
		mcpErr := fmt.Errorf("query parameter must be a string")
		return mcp.NewToolResultErrorFromErr(mcpErr.Error(), mcpErr), nil
	}

	// Execute the query - SQL injection protection is handled within the client
	results, err := h.TrinoClient.ExecuteQuery(query)
	if err != nil {
		log.Printf("Error executing query: %v", err)
		mcpErr := fmt.Errorf("query execution failed: %w", err)
		return mcp.NewToolResultErrorFromErr(mcpErr.Error(), mcpErr), nil
	}

	// Convert results to JSON string for display
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		mcpErr := fmt.Errorf("failed to marshal results to JSON: %w", err)
		return mcp.NewToolResultErrorFromErr(mcpErr.Error(), mcpErr), nil
	}

	// Return the results as formatted JSON text
	return mcp.NewToolResultText(string(jsonData)), nil
}

// ListCatalogs handles catalog listing
func (h *TrinoHandlers) ListCatalogs(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Log authentication info
	middleware.LogAuthenticationInfo(ctx, "list_catalogs")
	
	catalogs, err := h.TrinoClient.ListCatalogs()
	if err != nil {
		log.Printf("Error listing catalogs: %v", err)
		mcpErr := fmt.Errorf("failed to list catalogs: %w", err)
		return mcp.NewToolResultErrorFromErr(mcpErr.Error(), mcpErr), nil
	}

	// Convert catalogs to JSON string for display
	jsonData, err := json.MarshalIndent(catalogs, "", "  ")
	if err != nil {
		mcpErr := fmt.Errorf("failed to marshal catalogs to JSON: %w", err)
		return mcp.NewToolResultErrorFromErr(mcpErr.Error(), mcpErr), nil
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}

// ListSchemas handles schema listing
func (h *TrinoHandlers) ListSchemas(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Log authentication info
	middleware.LogAuthenticationInfo(ctx, "list_schemas")
	
	// Type assert Arguments to map[string]interface{}
	args, ok := request.Params.Arguments.(map[string]interface{})
	if !ok {
		mcpErr := fmt.Errorf("invalid arguments format")
		return mcp.NewToolResultErrorFromErr(mcpErr.Error(), mcpErr), nil
	}
	
	// Extract catalog parameter (optional)
	var catalog string
	if catalogParam, ok := args["catalog"].(string); ok {
		catalog = catalogParam
	}

	schemas, err := h.TrinoClient.ListSchemas(catalog)
	if err != nil {
		log.Printf("Error listing schemas: %v", err)
		mcpErr := fmt.Errorf("failed to list schemas: %w", err)
		return mcp.NewToolResultErrorFromErr(mcpErr.Error(), mcpErr), nil
	}

	// Convert schemas to JSON string for display
	jsonData, err := json.MarshalIndent(schemas, "", "  ")
	if err != nil {
		mcpErr := fmt.Errorf("failed to marshal schemas to JSON: %w", err)
		return mcp.NewToolResultErrorFromErr(mcpErr.Error(), mcpErr), nil
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}

// ListTables handles table listing
func (h *TrinoHandlers) ListTables(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Log authentication info
	middleware.LogAuthenticationInfo(ctx, "list_tables")
	
	// Type assert Arguments to map[string]interface{}
	args, ok := request.Params.Arguments.(map[string]interface{})
	if !ok {
		mcpErr := fmt.Errorf("invalid arguments format")
		return mcp.NewToolResultErrorFromErr(mcpErr.Error(), mcpErr), nil
	}
	
	// Extract catalog and schema parameters (optional)
	var catalog, schema string
	if catalogParam, ok := args["catalog"].(string); ok {
		catalog = catalogParam
	}
	if schemaParam, ok := args["schema"].(string); ok {
		schema = schemaParam
	}

	tables, err := h.TrinoClient.ListTables(catalog, schema)
	if err != nil {
		log.Printf("Error listing tables: %v", err)
		mcpErr := fmt.Errorf("failed to list tables: %w", err)
		return mcp.NewToolResultErrorFromErr(mcpErr.Error(), mcpErr), nil
	}

	// Convert tables to JSON string for display
	jsonData, err := json.MarshalIndent(tables, "", "  ")
	if err != nil {
		mcpErr := fmt.Errorf("failed to marshal tables to JSON: %w", err)
		return mcp.NewToolResultErrorFromErr(mcpErr.Error(), mcpErr), nil
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}

// GetTableSchema handles table schema retrieval
func (h *TrinoHandlers) GetTableSchema(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Log authentication info
	middleware.LogAuthenticationInfo(ctx, "get_table_schema")
	
	// Type assert Arguments to map[string]interface{}
	args, ok := request.Params.Arguments.(map[string]interface{})
	if !ok {
		mcpErr := fmt.Errorf("invalid arguments format")
		return mcp.NewToolResultErrorFromErr(mcpErr.Error(), mcpErr), nil
	}
	
	// Extract parameters
	var catalog, schema string
	var table string

	if catalogParam, ok := args["catalog"].(string); ok {
		catalog = catalogParam
	}
	if schemaParam, ok := args["schema"].(string); ok {
		schema = schemaParam
	}

	// Table parameter is required
	tableParam, ok := args["table"].(string)
	if !ok {
		mcpErr := fmt.Errorf("table parameter is required")
		return mcp.NewToolResultErrorFromErr(mcpErr.Error(), mcpErr), nil
	}
	table = tableParam

	tableSchema, err := h.TrinoClient.GetTableSchema(catalog, schema, table)
	if err != nil {
		log.Printf("Error getting table schema: %v", err)
		mcpErr := fmt.Errorf("failed to get table schema: %w", err)
		return mcp.NewToolResultErrorFromErr(mcpErr.Error(), mcpErr), nil
	}

	// Convert table schema to JSON string for display
	jsonData, err := json.MarshalIndent(tableSchema, "", "  ")
	if err != nil {
		mcpErr := fmt.Errorf("failed to marshal table schema to JSON: %w", err)
		return mcp.NewToolResultErrorFromErr(mcpErr.Error(), mcpErr), nil
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}
