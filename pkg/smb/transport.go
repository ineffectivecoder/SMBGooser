// Package smb provides SMB2/SMB3 protocol implementation.
package smb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
	"golang.org/x/net/proxy"
)

// Default SMB port
const DefaultPort = 445

// Transport handles TCP connection with NetBIOS session framing
type Transport struct {
	conn       net.Conn
	mu         sync.Mutex
	timeout    time.Duration
	remoteHost string
}

// TransportConfig configures transport behavior
type TransportConfig struct {
	Timeout   time.Duration
	Socks5URL string // SOCKS5 proxy URL (e.g., "socks5://127.0.0.1:1080" or "socks5://user:pass@host:port")
}

// DefaultTransportConfig returns default transport configuration
func DefaultTransportConfig() TransportConfig {
	return TransportConfig{
		Timeout: 30 * time.Second,
	}
}

// Dial establishes a TCP connection to an SMB server
func Dial(ctx context.Context, host string, port int) (*Transport, error) {
	return DialWithConfig(ctx, host, port, DefaultTransportConfig())
}

// DialWithConfig establishes a TCP connection with custom configuration
func DialWithConfig(ctx context.Context, host string, port int, config TransportConfig) (*Transport, error) {
	if port <= 0 {
		port = DefaultPort
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	var conn net.Conn
	var err error

	if config.Socks5URL != "" {
		// Use SOCKS5 proxy
		conn, err = dialSocks5(ctx, config.Socks5URL, addr, config.Timeout)
	} else {
		// Direct connection
		dialer := &net.Dialer{
			Timeout: config.Timeout,
		}
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
	}

	return &Transport{
		conn:       conn,
		timeout:    config.Timeout,
		remoteHost: host,
	}, nil
}

// dialSocks5 establishes a connection through a SOCKS5 proxy
func dialSocks5(ctx context.Context, proxyURL, target string, timeout time.Duration) (net.Conn, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid SOCKS5 URL: %w", err)
	}

	var auth *proxy.Auth
	if u.User != nil {
		pass, _ := u.User.Password()
		auth = &proxy.Auth{
			User:     u.User.Username(),
			Password: pass,
		}
	}

	dialer, err := proxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: timeout})
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	// proxy.Dialer doesn't support context, so we use a channel for timeout
	type dialResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan dialResult, 1)

	go func() {
		conn, err := dialer.Dial("tcp", target)
		resultCh <- dialResult{conn, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-resultCh:
		return result.conn, result.err
	}
}

// Send sends an SMB2 message with NetBIOS session header
func (t *Transport) Send(msg []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		return errors.New("transport not connected")
	}

	// Set write deadline
	if t.timeout > 0 {
		t.conn.SetWriteDeadline(time.Now().Add(t.timeout))
	}

	// Build NetBIOS session message
	// Format: 1 byte type (0x00 = session message) + 3 bytes length (big-endian)
	msgLen := len(msg)
	if msgLen > 0x00FFFFFF {
		return errors.New("message too large for NetBIOS framing")
	}

	// NetBIOS header (4 bytes): type (0x00) + length (3 bytes, big-endian)
	header := make([]byte, 4)
	header[0] = 0x00 // Session message type
	header[1] = byte(msgLen >> 16)
	header[2] = byte(msgLen >> 8)
	header[3] = byte(msgLen)

	// Write header
	if _, err := t.conn.Write(header); err != nil {
		return fmt.Errorf("failed to write NetBIOS header: %w", err)
	}

	// Write message
	if _, err := t.conn.Write(msg); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}

// Recv receives an SMB2 message with NetBIOS session header
func (t *Transport) Recv() ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		return nil, errors.New("transport not connected")
	}

	// Set read deadline
	if t.timeout > 0 {
		t.conn.SetReadDeadline(time.Now().Add(t.timeout))
	}

	// Read NetBIOS header (4 bytes)
	header := make([]byte, 4)
	if _, err := io.ReadFull(t.conn, header); err != nil {
		return nil, fmt.Errorf("failed to read NetBIOS header: %w", err)
	}

	// Parse length (3 bytes, big-endian)
	// Note: header[0] is type (0x00 for session message)
	msgLen := int(header[1])<<16 | int(header[2])<<8 | int(header[3])

	if msgLen == 0 {
		return nil, errors.New("received empty message")
	}

	if msgLen > 16*1024*1024 { // 16MB sanity limit
		return nil, fmt.Errorf("message too large: %d bytes", msgLen)
	}

	// Read message body
	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(t.conn, msg); err != nil {
		return nil, fmt.Errorf("failed to read message body: %w", err)
	}

	return msg, nil
}

// Close closes the transport connection
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		return nil
	}

	err := t.conn.Close()
	t.conn = nil
	return err
}

// LocalAddr returns the local network address
func (t *Transport) LocalAddr() net.Addr {
	if t.conn == nil {
		return nil
	}
	return t.conn.LocalAddr()
}

// RemoteAddr returns the remote network address
func (t *Transport) RemoteAddr() net.Addr {
	if t.conn == nil {
		return nil
	}
	return t.conn.RemoteAddr()
}

// RemoteHost returns the hostname of the remote server
func (t *Transport) RemoteHost() string {
	return t.remoteHost
}

// SetTimeout sets the read/write timeout
func (t *Transport) SetTimeout(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.timeout = d
}

// SendRecv sends a message and waits for a response (convenience method)
func (t *Transport) SendRecv(msg []byte) ([]byte, error) {
	if err := t.Send(msg); err != nil {
		return nil, err
	}
	return t.Recv()
}

// RawMessage represents a raw SMB message with header and payload
type RawMessage struct {
	Header  []byte
	Payload []byte
}

// ParseRawMessage splits a received message into header and payload
func ParseRawMessage(msg []byte) (*RawMessage, error) {
	if len(msg) < 64 { // SMB2 header is 64 bytes
		return nil, errors.New("message too small for SMB2 header")
	}

	// Verify SMB2 protocol ID
	if msg[0] != 0xFE || msg[1] != 'S' || msg[2] != 'M' || msg[3] != 'B' {
		return nil, errors.New("invalid SMB2 protocol ID")
	}

	// Get structure size from header to determine header end
	structSize := encoding.Uint16LE(msg[4:6])
	if structSize != 64 {
		return nil, fmt.Errorf("invalid SMB2 header structure size: %d", structSize)
	}

	return &RawMessage{
		Header:  msg[:64],
		Payload: msg[64:],
	}, nil
}
