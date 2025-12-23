package svcctl

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
)

// Client represents an SCMR RPC client
type Client struct {
	rpc       *dcerpc.Client
	pipe      *pipe.Pipe
	tree      *smb.Tree
	smbClient *smb.Client
	scmHandle Handle // Handle to Service Control Manager
}

// NewClient creates a new SCMR client
func NewClient(ctx context.Context, smbClient *smb.Client) (*Client, error) {
	// Get cached IPC$ tree
	tree, err := smbClient.GetIPCTree(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get IPC$ tree: %w", err)
	}

	// Open svcctl pipe
	p, err := pipe.Open(ctx, tree, "svcctl")
	if err != nil {
		smbClient.TreeDisconnect(ctx, tree)
		return nil, fmt.Errorf("failed to open svcctl pipe: %w", err)
	}

	// Create RPC client
	rpc := dcerpc.NewClient(p)

	// Bind to SVCCTL interface
	if err := rpc.Bind(SVCCTL_UUID, 2); err != nil {
		p.Close()
		smbClient.TreeDisconnect(ctx, tree)
		return nil, fmt.Errorf("failed to bind to SVCCTL: %w", err)
	}

	return &Client{
		rpc:       rpc,
		pipe:      p,
		tree:      tree,
		smbClient: smbClient,
	}, nil
}

// OpenSCManager opens the Service Control Manager
func (c *Client) OpenSCManager(machineName string, access SCMAccessMask) error {
	stub := encodeOpenSCManager(machineName, access)

	resp, err := c.rpc.Call(OpROpenSCManagerW, stub)
	if err != nil {
		return fmt.Errorf("ROpenSCManagerW failed: %w", err)
	}

	if len(resp) < 24 {
		return fmt.Errorf("invalid response size: %d", len(resp))
	}

	copy(c.scmHandle[:], resp[:20])

	retCode := uint32(resp[20]) | uint32(resp[21])<<8 | uint32(resp[22])<<16 | uint32(resp[23])<<24
	if retCode != 0 {
		return fmt.Errorf("ROpenSCManagerW returned error: 0x%08X", retCode)
	}

	return nil
}

// CreateService creates a new service
func (c *Client) CreateService(serviceName, displayName, binPath string) (Handle, error) {
	stub := encodeCreateService(c.scmHandle, serviceName, displayName, binPath)

	resp, err := c.rpc.Call(OpRCreateServiceW, stub)
	if err != nil {
		return Handle{}, fmt.Errorf("RCreateServiceW failed: %w", err)
	}

	if len(resp) < 24 {
		return Handle{}, fmt.Errorf("invalid response size: %d", len(resp))
	}

	var handle Handle
	copy(handle[:], resp[:20])

	retCode := uint32(resp[20]) | uint32(resp[21])<<8 | uint32(resp[22])<<16 | uint32(resp[23])<<24
	if retCode != 0 {
		return Handle{}, fmt.Errorf("RCreateServiceW returned error: 0x%08X", retCode)
	}

	return handle, nil
}

// OpenService opens an existing service
func (c *Client) OpenService(serviceName string, access ServiceAccessMask) (Handle, error) {
	stub := encodeOpenService(c.scmHandle, serviceName, access)

	resp, err := c.rpc.Call(OpROpenServiceW, stub)
	if err != nil {
		return Handle{}, fmt.Errorf("ROpenServiceW failed: %w", err)
	}

	if len(resp) < 24 {
		return Handle{}, fmt.Errorf("invalid response size: %d", len(resp))
	}

	var handle Handle
	copy(handle[:], resp[:20])

	retCode := uint32(resp[20]) | uint32(resp[21])<<8 | uint32(resp[22])<<16 | uint32(resp[23])<<24
	if retCode != 0 {
		return Handle{}, fmt.Errorf("ROpenServiceW returned error: 0x%08X", retCode)
	}

	return handle, nil
}

// StartService starts a service
func (c *Client) StartService(serviceHandle Handle) error {
	stub := encodeStartService(serviceHandle)

	resp, err := c.rpc.Call(OpRStartServiceW, stub)
	if err != nil {
		// Error 1053 = service didn't respond in time (expected for short-lived commands)
		if resp != nil && len(resp) >= 4 {
			retCode := uint32(resp[0]) | uint32(resp[1])<<8 | uint32(resp[2])<<16 | uint32(resp[3])<<24
			if retCode == 1053 {
				return nil
			}
		}
		return fmt.Errorf("RStartServiceW failed: %w", err)
	}

	if len(resp) < 4 {
		return nil
	}

	retCode := uint32(resp[0]) | uint32(resp[1])<<8 | uint32(resp[2])<<16 | uint32(resp[3])<<24
	if retCode != 0 && retCode != 1053 {
		return fmt.Errorf("RStartServiceW returned error: 0x%08X", retCode)
	}

	return nil
}

// DeleteService deletes a service
func (c *Client) DeleteService(serviceHandle Handle) error {
	stub := encodeDeleteService(serviceHandle)

	resp, err := c.rpc.Call(OpRDeleteService, stub)
	if err != nil {
		return fmt.Errorf("RDeleteService failed: %w", err)
	}

	if len(resp) >= 4 {
		retCode := uint32(resp[0]) | uint32(resp[1])<<8 | uint32(resp[2])<<16 | uint32(resp[3])<<24
		if retCode != 0 {
			return fmt.Errorf("RDeleteService returned error: 0x%08X", retCode)
		}
	}

	return nil
}

// CloseHandle closes a service or SCM handle
func (c *Client) CloseHandle(handle Handle) error {
	stub := make([]byte, 20)
	copy(stub, handle[:])

	_, err := c.rpc.Call(OpRCloseServiceHandle, stub)
	return err
}

// ControlService sends a control code to a service
func (c *Client) ControlService(serviceHandle Handle, control uint32) (*ServiceStatus, error) {
	stub := encodeControlService(serviceHandle, control)

	resp, err := c.rpc.Call(OpRControlService, stub)
	if err != nil {
		return nil, fmt.Errorf("RControlService failed: %w", err)
	}

	if len(resp) < 32 {
		return nil, fmt.Errorf("invalid response size")
	}

	// Parse SERVICE_STATUS
	status := &ServiceStatus{
		ServiceType:      ServiceType(binary.LittleEndian.Uint32(resp[0:4])),
		CurrentState:     ServiceState(binary.LittleEndian.Uint32(resp[4:8])),
		ControlsAccepted: binary.LittleEndian.Uint32(resp[8:12]),
		Win32ExitCode:    binary.LittleEndian.Uint32(resp[12:16]),
		ServiceExitCode:  binary.LittleEndian.Uint32(resp[16:20]),
		CheckPoint:       binary.LittleEndian.Uint32(resp[20:24]),
		WaitHint:         binary.LittleEndian.Uint32(resp[24:28]),
	}

	retCode := binary.LittleEndian.Uint32(resp[28:32])
	if retCode != 0 {
		return status, fmt.Errorf("error: 0x%08X", retCode)
	}

	return status, nil
}

// StopService stops a running service
func (c *Client) StopService(serviceHandle Handle) (*ServiceStatus, error) {
	return c.ControlService(serviceHandle, 1) // SERVICE_CONTROL_STOP = 1
}

// EnumServices enumerates all services
func (c *Client) EnumServices(serviceType ServiceType, serviceState uint32) ([]ServiceInfo, error) {
	// Two-phase call like Impacket:
	// 1. First call with cbBufSize=0 to get pcbBytesNeeded
	// 2. Second call with the correct buffer size

	// Phase 1: Query needed buffer size
	stub := encodeEnumServicesStatus(c.scmHandle, serviceType, serviceState, 0)
	resp, err := c.rpc.Call(OpREnumServicesStatusW, stub)
	if err != nil {
		// We expect this to fail with ERROR_MORE_DATA (234)
		if resp == nil {
			return nil, fmt.Errorf("REnumServicesStatusW failed: %w", err)
		}
	}

	// Parse the response to get pcbBytesNeeded
	// Response format: MaxCount(4) + buffer(0) + pcbBytesNeeded(4) + lpServicesReturned(4) + resumePtr(4) + resumeVal(4) + errcode(4)
	// With 0-byte buffer, response should be about 24 bytes
	if len(resp) < 20 {
		return nil, fmt.Errorf("invalid phase 1 response size: %d", len(resp))
	}

	if Debug {
		fmt.Printf("[DEBUG] Phase 1 response: %d bytes, hex: %x\n", len(resp), resp)
	}

	// Read pcbBytesNeeded from response (after MaxCount and empty buffer)
	// Structure: MaxCount(4) + pcbBytesNeeded(4) + lpServicesReturned(4) + resumePtr(4) + resumeVal?(4) + retcode(4)
	pcbBytesNeeded := binary.LittleEndian.Uint32(resp[4:8])
	retCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])

	if Debug {
		fmt.Printf("[DEBUG] Phase 1: pcbBytesNeeded=%d, retCode=0x%08X\n", pcbBytesNeeded, retCode)
	}

	// 234 = ERROR_MORE_DATA, expected when buffer is 0
	if retCode != 234 && retCode != 0 {
		return nil, fmt.Errorf("phase 1 enumeration failed with error: 0x%08X", retCode)
	}

	if pcbBytesNeeded == 0 {
		return nil, nil // No services
	}

	// Phase 2: Query with correct buffer size
	stub = encodeEnumServicesStatus(c.scmHandle, serviceType, serviceState, pcbBytesNeeded)
	resp, err = c.rpc.Call(OpREnumServicesStatusW, stub)
	if err != nil {
		return nil, fmt.Errorf("REnumServicesStatusW phase 2 failed: %w", err)
	}

	if Debug {
		fmt.Printf("[DEBUG] Phase 2 response: %d bytes\n", len(resp))
		if len(resp) >= 32 {
			fmt.Printf("[DEBUG] First 32 bytes: %x\n", resp[:32])
			fmt.Printf("[DEBUG] Last 32 bytes: %x\n", resp[len(resp)-32:])
		}
	}

	return parseEnumServicesResponse(resp, pcbBytesNeeded)
}

// QueryServiceStatus queries the status of a service
func (c *Client) QueryServiceStatus(serviceHandle Handle) (*ServiceStatus, error) {
	stub := make([]byte, 20)
	copy(stub, serviceHandle[:])

	resp, err := c.rpc.Call(OpRQueryServiceStatus, stub)
	if err != nil {
		return nil, fmt.Errorf("RQueryServiceStatus failed: %w", err)
	}

	if len(resp) < 32 {
		return nil, fmt.Errorf("invalid response size: %d", len(resp))
	}

	// Parse SERVICE_STATUS structure (28 bytes) + return code (4 bytes)
	status := &ServiceStatus{
		ServiceType:      ServiceType(uint32(resp[0]) | uint32(resp[1])<<8 | uint32(resp[2])<<16 | uint32(resp[3])<<24),
		CurrentState:     ServiceState(uint32(resp[4]) | uint32(resp[5])<<8 | uint32(resp[6])<<16 | uint32(resp[7])<<24),
		ControlsAccepted: uint32(resp[8]) | uint32(resp[9])<<8 | uint32(resp[10])<<16 | uint32(resp[11])<<24,
		Win32ExitCode:    uint32(resp[12]) | uint32(resp[13])<<8 | uint32(resp[14])<<16 | uint32(resp[15])<<24,
		ServiceExitCode:  uint32(resp[16]) | uint32(resp[17])<<8 | uint32(resp[18])<<16 | uint32(resp[19])<<24,
		CheckPoint:       uint32(resp[20]) | uint32(resp[21])<<8 | uint32(resp[22])<<16 | uint32(resp[23])<<24,
		WaitHint:         uint32(resp[24]) | uint32(resp[25])<<8 | uint32(resp[26])<<16 | uint32(resp[27])<<24,
	}

	retCode := uint32(resp[28]) | uint32(resp[29])<<8 | uint32(resp[30])<<16 | uint32(resp[31])<<24
	if retCode != 0 {
		return nil, fmt.Errorf("RQueryServiceStatus returned error: 0x%08X", retCode)
	}

	return status, nil
}

// Close closes the SCMR client
func (c *Client) Close() error {
	if c.scmHandle != (Handle{}) {
		c.CloseHandle(c.scmHandle)
	}
	if c.rpc != nil {
		c.rpc.Close()
	}
	if c.pipe != nil {
		c.pipe.Close()
	}
	if c.tree != nil && c.smbClient != nil {
		c.smbClient.TreeDisconnect(context.Background(), c.tree)
	}
	return nil
}

// Execute runs a command by creating a temporary service
func (c *Client) Execute(command string) error {
	serviceName := fmt.Sprintf("smbg%d", time.Now().UnixNano()%100000)

	// Use cmd.exe /c to run the command
	binPath := fmt.Sprintf("%%COMSPEC%% /C %s", command)

	serviceHandle, err := c.CreateService(serviceName, serviceName, binPath)
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}

	// Start the service (executes the command)
	startErr := c.StartService(serviceHandle)

	// Always try to delete the service
	deleteErr := c.DeleteService(serviceHandle)
	c.CloseHandle(serviceHandle)

	if startErr != nil {
		return fmt.Errorf("failed to start service: %w", startErr)
	}

	if deleteErr != nil {
		return fmt.Errorf("command executed but failed to delete service: %w", deleteErr)
	}

	return nil
}
