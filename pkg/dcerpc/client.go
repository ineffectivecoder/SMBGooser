package dcerpc

import (
	"fmt"

	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
)

// Client represents a DCE/RPC client over a named pipe
type Client struct {
	pipe           *pipe.Pipe
	callID         uint32
	boundInterface UUID
	maxXmitFrag    uint16
	maxRecvFrag    uint16
	isBound        bool
}

// NewClient creates a new RPC client over a named pipe
func NewClient(p *pipe.Pipe) *Client {
	return &Client{
		pipe:        p,
		callID:      1,
		maxXmitFrag: 4280,
		maxRecvFrag: 4280,
	}
}

// Bind binds to an RPC interface
func (c *Client) Bind(interfaceUUID UUID, version uint32) error {
	// Create bind request
	bindReq := NewBindRequest(interfaceUUID, version, c.nextCallID())

	// Send bind request
	response, err := c.pipe.Transact(bindReq.Marshal())
	if err != nil {
		return fmt.Errorf("bind transact failed: %w", err)
	}

	// Parse response header first to check packet type
	var header CommonHeader
	if err := header.Unmarshal(response); err != nil {
		return fmt.Errorf("failed to parse response header: %w", err)
	}

	if header.PacketType == PacketTypeBindNak {
		return ErrBindFailed
	}

	if header.PacketType != PacketTypeBindAck {
		return fmt.Errorf("unexpected packet type: %d", header.PacketType)
	}

	// Parse bind ack
	var bindAck BindAck
	if err := bindAck.Unmarshal(response); err != nil {
		return fmt.Errorf("failed to parse bind ack: %w", err)
	}

	if !bindAck.IsAccepted() {
		return ErrBindFailed
	}

	c.boundInterface = interfaceUUID
	c.maxXmitFrag = bindAck.MaxXmitFrag
	c.maxRecvFrag = bindAck.MaxRecvFrag
	c.isBound = true

	return nil
}

// Call makes an RPC call
func (c *Client) Call(opnum uint16, stubData []byte) ([]byte, error) {
	if !c.isBound {
		return nil, ErrNotBound
	}

	// Create request
	req := NewRequest(opnum, stubData, c.nextCallID())

	// Send request
	response, err := c.pipe.Transact(req.Marshal())
	if err != nil {
		return nil, fmt.Errorf("call transact failed: %w", err)
	}

	// Parse response header
	var header CommonHeader
	if err := header.Unmarshal(response); err != nil {
		return nil, fmt.Errorf("failed to parse response header: %w", err)
	}

	if header.PacketType == PacketTypeFault {
		var fault Fault
		if err := fault.Unmarshal(response); err != nil {
			return nil, fmt.Errorf("RPC fault (parse error: %w)", err)
		}
		return nil, fmt.Errorf("RPC fault: status 0x%08X", fault.Status)
	}

	if header.PacketType != PacketTypeResponse {
		return nil, fmt.Errorf("unexpected packet type: %d", header.PacketType)
	}

	// Parse response
	var resp Response
	if err := resp.Unmarshal(response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.StubData, nil
}

// CallRaw makes an RPC call and returns the raw response including header
func (c *Client) CallRaw(opnum uint16, stubData []byte) ([]byte, error) {
	if !c.isBound {
		return nil, ErrNotBound
	}

	req := NewRequest(opnum, stubData, c.nextCallID())
	return c.pipe.Transact(req.Marshal())
}

// nextCallID returns the next call ID
func (c *Client) nextCallID() uint32 {
	id := c.callID
	c.callID++
	return id
}

// IsBound returns true if bound to an interface
func (c *Client) IsBound() bool {
	return c.isBound
}

// BoundInterface returns the bound interface UUID
func (c *Client) BoundInterface() UUID {
	return c.boundInterface
}

// Close closes the RPC client
func (c *Client) Close() error {
	c.isBound = false
	return nil
}

// Pipe returns the underlying pipe
func (c *Client) Pipe() *pipe.Pipe {
	return c.pipe
}
