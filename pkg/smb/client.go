// Package smb provides SMB2/SMB3 client functionality.
//
// This package implements the core SMB protocol operations including:
//   - Connection establishment with dialect negotiation
//   - NTLM/NTLMv2 authentication (password and pass-the-hash)
//   - Share (tree) connection and disconnection
//   - File and directory operations (Phase 4)
//   - Named pipe operations (Phase 5)
//
// Basic usage:
//
//	client := smb.NewClient()
//	if err := client.Connect(ctx, "192.168.1.100", 445); err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	creds := auth.NewPasswordCredentials("DOMAIN", "user", "password")
//	if err := client.Authenticate(ctx, creds); err != nil {
//	    log.Fatal(err)
//	}
//
//	tree, err := client.TreeConnect(ctx, "C$")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.TreeDisconnect(ctx, tree)
package smb

import (
	"context"
	"fmt"
	"time"

	"github.com/ineffectivecoder/SMBGooser/pkg/auth"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb/smb1"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

// Client represents an SMB2/SMB3 client (with SMB1 fallback support)
type Client struct {
	config     ClientConfig
	transport  *Transport
	session    *Session
	negResult  *NegotiateResult
	ipcTree    *Tree        // Cached IPC$ tree for RPC operations
	smb1Client *smb1.Client // SMB1 client (nil if using SMB2/3)
	usingSmb1  bool         // True if connected via SMB1
}

// ClientConfig configures client behavior
type ClientConfig struct {
	Timeout          time.Duration
	PreferredDialect types.Dialect
	RequireSigning   bool
	MaxCredits       uint16
	Socks5URL        string // SOCKS5 proxy URL (e.g., "socks5://127.0.0.1:1080")
	ForceSMB1        bool   // Force SMB1 mode for legacy systems
}

// DefaultClientConfig returns default client configuration
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Timeout:          30 * time.Second,
		PreferredDialect: types.DialectSMB3_1_1,
		MaxCredits:       128,
	}
}

// NewClient creates a new SMB client with default configuration
func NewClient() *Client {
	return NewClientWithConfig(DefaultClientConfig())
}

// NewClientWithConfig creates a new SMB client with custom configuration
func NewClientWithConfig(config ClientConfig) *Client {
	return &Client{
		config: config,
	}
}

// Connect establishes a connection to an SMB server
func (c *Client) Connect(ctx context.Context, host string, port int) error {
	// Establish transport
	transport, err := DialWithConfig(ctx, host, port, TransportConfig{
		Timeout:   c.config.Timeout,
		Socks5URL: c.config.Socks5URL,
	})
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	c.transport = transport

	// Perform dialect negotiation
	negotiator := NewNegotiator(transport)
	negResult, err := negotiator.Negotiate(ctx)
	if err != nil {
		c.transport.Close()
		c.transport = nil
		return fmt.Errorf("negotiation failed: %w", err)
	}
	c.negResult = negResult

	return nil
}

// Authenticate performs NTLM authentication
func (c *Client) Authenticate(ctx context.Context, creds auth.Credentials) error {
	if c.transport == nil || c.negResult == nil {
		return ErrNotConnected
	}

	// Create session
	c.session = NewSession(c.transport, c.negResult)

	// Authenticate
	if err := c.session.Authenticate(ctx, creds, c.negResult); err != nil {
		return err
	}

	return nil
}

// TreeConnect connects to a share
func (c *Client) TreeConnect(ctx context.Context, shareName string) (*Tree, error) {
	if c.session == nil || !c.session.IsAuthenticated() {
		return nil, ErrNotConnected
	}

	return c.session.TreeConnect(ctx, shareName)
}

// TreeDisconnect disconnects from a share
func (c *Client) TreeDisconnect(ctx context.Context, tree *Tree) error {
	if c.session == nil {
		return nil
	}

	// Don't disconnect the cached IPC$ tree
	if tree == c.ipcTree {
		return nil
	}

	return c.session.TreeDisconnect(ctx, tree)
}

// GetIPCTree returns an IPC$ tree connection for RPC operations
// Each call creates a new tree to avoid state corruption issues
func (c *Client) GetIPCTree(ctx context.Context) (*Tree, error) {
	if c.session == nil || !c.session.IsAuthenticated() {
		return nil, ErrNotConnected
	}

	// Create new IPC$ tree connection each time
	// This avoids state corruption when reusing trees across pipe operations
	tree, err := c.session.TreeConnect(ctx, "IPC$")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to IPC$: %w", err)
	}

	return tree, nil
}

// Close closes the client connection
func (c *Client) Close() error {
	// Disconnect IPC$ tree first
	if c.ipcTree != nil && c.session != nil {
		c.session.TreeDisconnect(context.Background(), c.ipcTree)
		c.ipcTree = nil
	}

	if c.session != nil {
		c.session.Close()
		c.session = nil
	}

	if c.transport != nil {
		err := c.transport.Close()
		c.transport = nil
		return err
	}

	return nil
}

// Session returns the current session
func (c *Client) Session() *Session {
	return c.session
}

// NegotiateResult returns the negotiation result
func (c *Client) NegotiateResult() *NegotiateResult {
	return c.negResult
}

// IsConnected returns true if connected and authenticated
func (c *Client) IsConnected() bool {
	if c.usingSmb1 {
		return c.smb1Client != nil
	}
	return c.session != nil && c.session.IsAuthenticated()
}

// IsSMB1 returns true if using SMB1 protocol
func (c *Client) IsSMB1() bool {
	return c.usingSmb1
}

// Dialect returns the negotiated dialect
func (c *Client) Dialect() types.Dialect {
	if c.usingSmb1 {
		return 0 // SMB1 has no types.Dialect equivalent
	}
	if c.negResult != nil {
		return c.negResult.Dialect
	}
	return 0
}

// DialectName returns the negotiated dialect as a string
func (c *Client) DialectName() string {
	if c.usingSmb1 {
		return "SMB 1.0 (NT LM 0.12)"
	}
	return DialectName(c.Dialect())
}

// SMB1Client returns the SMB1 client if in SMB1 mode, nil otherwise
func (c *Client) SMB1Client() *smb1.Client {
	return c.smb1Client
}
