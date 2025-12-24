package tsch

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
)

// Client represents a Task Scheduler RPC client with authenticated RPC
type Client struct {
	auth      *dcerpc.NTLMAuth
	pipe      *pipe.Pipe
	tree      *smb.Tree
	smbClient *smb.Client
	callID    uint32
}

// Credentials holds authentication credentials for RPC
type Credentials struct {
	Username string
	Password string
	Hash     []byte // NT hash for pass-the-hash
	Domain   string
}

// NewClient creates a new Task Scheduler client with authenticated RPC
// Task Scheduler requires PKT_PRIVACY (auth level 6) for RPC calls
func NewClient(ctx context.Context, smbClient *smb.Client, creds Credentials) (*Client, error) {
	// Get cached IPC$ tree
	tree, err := smbClient.GetIPCTree(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get IPC$ tree: %w", err)
	}

	// Open atsvc pipe using RPC-compatible method (matches Impacket)
	p, err := pipe.OpenForRPC(ctx, tree, "atsvc")
	if err != nil {
		smbClient.TreeDisconnect(ctx, tree)
		return nil, fmt.Errorf("failed to open atsvc pipe: %w", err)
	}

	// Create NTLM auth context
	auth := &dcerpc.NTLMAuth{
		User:     creds.Username,
		Password: creds.Password,
		Hash:     creds.Hash,
		Domain:   creds.Domain,
	}

	// Perform authenticated bind (3-way handshake)
	if err := performAuthenticatedBind(p, auth); err != nil {
		p.Close()
		smbClient.TreeDisconnect(ctx, tree)
		return nil, fmt.Errorf("failed to bind to TSCH: %w", err)
	}

	return &Client{
		auth:      auth,
		pipe:      p,
		tree:      tree,
		smbClient: smbClient,
		callID:    2, // Start at 2 after auth binding
	}, nil
}

// performAuthenticatedBind performs a 3-way DCERPC auth handshake
func performAuthenticatedBind(p *pipe.Pipe, auth *dcerpc.NTLMAuth) error {
	// Step 1: Send Bind with NTLM Negotiate
	bindReq := auth.CreateBindWithAuth(TSCH_UUID, 1)

	if _, err := p.Write(bindReq); err != nil {
		return fmt.Errorf("bind write failed: %w", err)
	}

	// Read BindAck
	bindAck := make([]byte, 4096)
	n, err := p.Read(bindAck)
	if err != nil {
		return fmt.Errorf("bind read failed: %w", err)
	}
	bindAck = bindAck[:n]

	if len(bindAck) < 24 {
		return fmt.Errorf("BindAck too short: %d bytes", len(bindAck))
	}

	// Check packet type (offset 2)
	if bindAck[2] == 13 { // BindNak
		return fmt.Errorf("bind rejected (BindNak)")
	}
	if bindAck[2] != 12 { // BindAck
		return fmt.Errorf("unexpected bind response: type=%d", bindAck[2])
	}

	// Extract auth data from BindAck
	authLen := binary.LittleEndian.Uint16(bindAck[10:12])
	if authLen == 0 {
		return fmt.Errorf("no auth data in BindAck")
	}

	fragLen := binary.LittleEndian.Uint16(bindAck[8:10])
	authTrailerStart := int(fragLen) - int(authLen) - 8

	if authTrailerStart < 24 || authTrailerStart+int(authLen)+8 > int(fragLen) {
		return fmt.Errorf("invalid auth trailer position")
	}

	// Extract auth_context_id from auth trailer
	serverAuthContextID := binary.LittleEndian.Uint32(bindAck[authTrailerStart+4 : authTrailerStart+8])
	auth.SetAuthContextID(serverAuthContextID)

	// Extract NTLM Challenge
	challengeMsg := bindAck[authTrailerStart+8 : authTrailerStart+8+int(authLen)]

	// Step 2: Process challenge and create Authenticate message
	authenticateMsg, err := auth.ProcessChallenge(challengeMsg)
	if err != nil {
		return fmt.Errorf("failed to process challenge: %w", err)
	}

	// Step 3: Send Auth3
	auth3Req := auth.CreateAuth3(authenticateMsg)
	if _, err := p.Write(auth3Req); err != nil {
		return fmt.Errorf("Auth3 write failed: %w", err)
	}

	// Auth3 has no response - success!
	return nil
}

// Close closes the client
func (c *Client) Close() error {
	if c.pipe != nil {
		c.pipe.Close()
	}
	if c.tree != nil && c.smbClient != nil {
		c.smbClient.TreeDisconnect(context.Background(), c.tree)
	}
	return nil
}

// call sends an authenticated RPC call and returns the response
func (c *Client) call(opnum uint16, stub []byte) ([]byte, error) {
	// Create authenticated request
	req := c.auth.CreateAuthenticatedRequest(opnum, stub, c.callID)
	c.callID++

	// Send request
	if _, err := c.pipe.Write(req); err != nil {
		return nil, fmt.Errorf("request write failed: %w", err)
	}

	// Read response
	resp := make([]byte, 65536)
	n, err := c.pipe.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("request read failed: %w", err)
	}
	resp = resp[:n]

	// Check for DCERPC fault (type 3)
	if len(resp) >= 24 && resp[2] == 3 {
		status := binary.LittleEndian.Uint32(resp[24:28])
		return nil, fmt.Errorf("DCERPC fault: 0x%08X", status)
	}

	// Decrypt the authenticated response
	decryptedStub, err := c.auth.ProcessAuthenticatedResponse(resp)
	if err != nil {
		// Fall back to skipping header (for responses without encrypted data)
		if len(resp) > 24 {
			return resp[24:], nil
		}
		return resp, nil
	}

	return decryptedStub, nil
}

// Execute runs a command by creating and running a scheduled task
func (c *Client) Execute(command string) error {
	// Generate unique task name
	taskName := fmt.Sprintf("\\smbg%d", time.Now().UnixNano()%1000000)

	// Create XML task definition
	taskXML := buildTaskXML(command)

	// Register the task
	if err := c.registerTask(taskName, taskXML); err != nil {
		return fmt.Errorf("failed to register task: %w", err)
	}

	// Run the task immediately
	if err := c.runTask(taskName); err != nil {
		// Still try to delete
		c.deleteTask(taskName)
		return fmt.Errorf("failed to run task: %w", err)
	}

	// Small delay to let task start
	time.Sleep(100 * time.Millisecond)

	// Delete the task
	if err := c.deleteTask(taskName); err != nil {
		return fmt.Errorf("task executed but cleanup failed: %w", err)
	}

	return nil
}

// registerTask registers a new scheduled task
func (c *Client) registerTask(taskPath, taskXML string) error {
	stub := encodeRegisterTask(taskPath, taskXML)

	resp, err := c.call(OpSchRpcRegisterTask, stub)
	if err != nil {
		return err
	}

	// Check return code (at end of response)
	if len(resp) >= 4 {
		retCode := uint32(resp[len(resp)-4]) | uint32(resp[len(resp)-3])<<8 |
			uint32(resp[len(resp)-2])<<16 | uint32(resp[len(resp)-1])<<24
		if retCode != 0 {
			return fmt.Errorf("SchRpcRegisterTask returned error: 0x%08X", retCode)
		}
	}

	return nil
}

// runTask runs a registered task
func (c *Client) runTask(taskPath string) error {
	stub := encodeRunTask(taskPath)

	_, err := c.call(OpSchRpcRun, stub)
	if err != nil {
		return err
	}

	// Note: Impacket doesn't check SchRpcRun return code, just proceeds
	// The response contains GUID + ErrorCode but parsing is complex due to auth trailer
	return nil
}

// deleteTask deletes a scheduled task
func (c *Client) deleteTask(taskPath string) error {
	stub := encodeDeleteTask(taskPath)

	_, err := c.call(OpSchRpcDelete, stub)
	if err != nil {
		return err
	}

	// Note: Skip return code check - parsing is complex due to auth trailer
	// Impacket also doesn't do detailed error checking here
	return nil
}

// EnumTasks enumerates scheduled tasks in the given path
// path should be like "\\" for root or "\\Microsoft\\Windows" for subfolders
func (c *Client) EnumTasks(path string) ([]string, error) {
	stub := encodeEnumTasks(path, TaskEnumHidden, 0, 0xffffffff)

	resp, err := c.call(OpSchRpcEnumTasks, stub)
	if err != nil {
		return nil, fmt.Errorf("SchRpcEnumTasks failed: %w", err)
	}

	names, errCode, _ := parseEnumResponse(resp)
	if errCode != 0 && errCode != 0x00000001 { // 0x1 = S_FALSE (more data available)
		return names, fmt.Errorf("SchRpcEnumTasks returned: 0x%08X", errCode)
	}

	return names, nil
}

// EnumFolders enumerates task scheduler folders in the given path
// path should be like "\\" for root
func (c *Client) EnumFolders(path string) ([]string, error) {
	stub := encodeEnumFolders(path, TaskEnumHidden, 0, 0xffffffff)

	resp, err := c.call(OpSchRpcEnumFolders, stub)
	if err != nil {
		return nil, fmt.Errorf("SchRpcEnumFolders failed: %w", err)
	}

	names, errCode, _ := parseEnumResponse(resp)
	if errCode != 0 && errCode != 0x00000001 { // 0x1 = S_FALSE
		return names, fmt.Errorf("SchRpcEnumFolders returned: 0x%08X", errCode)
	}

	return names, nil
}

// buildTaskXML creates an XML task definition for command execution
// Format matches Impacket's atexec.py for compatibility
func buildTaskXML(command string) string {
	// Escape XML special characters
	command = strings.ReplaceAll(command, "&", "&amp;")
	command = strings.ReplaceAll(command, "<", "&lt;")
	command = strings.ReplaceAll(command, ">", "&gt;")
	command = strings.ReplaceAll(command, "\"", "&quot;")

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/C %s</Arguments>
    </Exec>
  </Actions>
</Task>`, command)
}
