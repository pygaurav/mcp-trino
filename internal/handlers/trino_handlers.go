package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/mark3labs/mcp-go/mcp"
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
	// Extract the query parameter
	query, ok := request.Params.Arguments["query"].(string)
	if !ok {
		return nil, fmt.Errorf("query parameter must be a string")
	}

	// Execute the query
	results, err := h.TrinoClient.ExecuteQuery(query)
	if err != nil {
		log.Printf("Error executing query: %v", err)
		return nil, fmt.Errorf("query execution failed: %v", err)
	}

	// Convert results to JSON string for display
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal results to JSON: %v", err)
	}

	// Return the results as formatted JSON text
	return mcp.NewToolResultText(string(jsonData)), nil
}

// ListCatalogs handles catalog listing
func (h *TrinoHandlers) ListCatalogs(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	catalogs, err := h.TrinoClient.ListCatalogs()
	if err != nil {
		log.Printf("Error listing catalogs: %v", err)
		return nil, fmt.Errorf("failed to list catalogs: %v", err)
	}

	// Convert catalogs to JSON string for display
	jsonData, err := json.MarshalIndent(catalogs, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal catalogs to JSON: %v", err)
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}

// ListSchemas handles schema listing
func (h *TrinoHandlers) ListSchemas(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Extract catalog parameter (optional)
	var catalog string
	if catalogParam, ok := request.Params.Arguments["catalog"].(string); ok {
		catalog = catalogParam
	}

	schemas, err := h.TrinoClient.ListSchemas(catalog)
	if err != nil {
		log.Printf("Error listing schemas: %v", err)
		return nil, fmt.Errorf("failed to list schemas: %v", err)
	}

	// Convert schemas to JSON string for display
	jsonData, err := json.MarshalIndent(schemas, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal schemas to JSON: %v", err)
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}

// ListTables handles table listing
func (h *TrinoHandlers) ListTables(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Extract catalog and schema parameters (optional)
	var catalog, schema string
	if catalogParam, ok := request.Params.Arguments["catalog"].(string); ok {
		catalog = catalogParam
	}
	if schemaParam, ok := request.Params.Arguments["schema"].(string); ok {
		schema = schemaParam
	}

	tables, err := h.TrinoClient.ListTables(catalog, schema)
	if err != nil {
		log.Printf("Error listing tables: %v", err)
		return nil, fmt.Errorf("failed to list tables: %v", err)
	}

	// Convert tables to JSON string for display
	jsonData, err := json.MarshalIndent(tables, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tables to JSON: %v", err)
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}

// GetTableSchema handles table schema retrieval
func (h *TrinoHandlers) GetTableSchema(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Extract parameters
	var catalog, schema string
	var table string

	if catalogParam, ok := request.Params.Arguments["catalog"].(string); ok {
		catalog = catalogParam
	}
	if schemaParam, ok := request.Params.Arguments["schema"].(string); ok {
		schema = schemaParam
	}

	// Table parameter is required
	tableParam, ok := request.Params.Arguments["table"].(string)
	if !ok {
		return nil, fmt.Errorf("table parameter is required")
	}
	table = tableParam

	tableSchema, err := h.TrinoClient.GetTableSchema(catalog, schema, table)
	if err != nil {
		log.Printf("Error getting table schema: %v", err)
		return nil, fmt.Errorf("failed to get table schema: %v", err)
	}

	// Convert table schema to JSON string for display
	jsonData, err := json.MarshalIndent(tableSchema, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal table schema to JSON: %v", err)
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}
