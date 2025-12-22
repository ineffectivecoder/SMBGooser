package tsch

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
)

// Client represents a Task Scheduler RPC client
type Client struct {
	rpc       *dcerpc.Client
	pipe      *pipe.Pipe
	tree      *smb.Tree
	smbClient *smb.Client
}

// NewClient creates a new Task Scheduler client
func NewClient(ctx context.Context, smbClient *smb.Client) (*Client, error) {
	// Get cached IPC$ tree
	tree, err := smbClient.GetIPCTree(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get IPC$ tree: %w", err)
	}

	// Open atsvc pipe (Task Scheduler)
	p, err := pipe.Open(ctx, tree, "atsvc")
	if err != nil {
		smbClient.TreeDisconnect(ctx, tree)
		return nil, fmt.Errorf("failed to open atsvc pipe: %w", err)
	}

	// Create RPC client
	rpc := dcerpc.NewClient(p)

	// Bind to ITaskSchedulerService interface
	if err := rpc.Bind(TSCH_UUID, 1); err != nil {
		p.Close()
		smbClient.TreeDisconnect(ctx, tree)
		return nil, fmt.Errorf("failed to bind to TSCH: %w", err)
	}

	return &Client{
		rpc:       rpc,
		pipe:      p,
		tree:      tree,
		smbClient: smbClient,
	}, nil
}

// Execute runs a command by creating and running a scheduled task
func (c *Client) Execute(command string) error {
	// Generate unique task name
	taskName := fmt.Sprintf("\\smbg%d", time.Now().UnixNano()%1000000)

	// Create XML task definition
	// Use cmd.exe /c to run the command
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

	resp, err := c.rpc.Call(OpSchRpcRegisterTask, stub)
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

	resp, err := c.rpc.Call(OpSchRpcRun, stub)
	if err != nil {
		return err
	}

	// Check return code
	if len(resp) >= 4 {
		retCode := uint32(resp[len(resp)-4]) | uint32(resp[len(resp)-3])<<8 |
			uint32(resp[len(resp)-2])<<16 | uint32(resp[len(resp)-1])<<24
		if retCode != 0 {
			return fmt.Errorf("SchRpcRun returned error: 0x%08X", retCode)
		}
	}

	return nil
}

// deleteTask deletes a scheduled task
func (c *Client) deleteTask(taskPath string) error {
	stub := encodeDeleteTask(taskPath)

	resp, err := c.rpc.Call(OpSchRpcDelete, stub)
	if err != nil {
		return err
	}

	// Check return code
	if len(resp) >= 4 {
		retCode := uint32(resp[len(resp)-4]) | uint32(resp[len(resp)-3])<<8 |
			uint32(resp[len(resp)-2])<<16 | uint32(resp[len(resp)-1])<<24
		if retCode != 0 {
			return fmt.Errorf("SchRpcDelete returned error: 0x%08X", retCode)
		}
	}

	return nil
}

// Close closes the client
func (c *Client) Close() error {
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

// buildTaskXML creates an XML task definition for command execution
func buildTaskXML(command string) string {
	// Escape XML special characters
	command = strings.ReplaceAll(command, "&", "&amp;")
	command = strings.ReplaceAll(command, "<", "&lt;")
	command = strings.ReplaceAll(command, ">", "&gt;")
	command = strings.ReplaceAll(command, "\"", "&quot;")

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>SMBGooser Task</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2099-01-01T00:00:00</StartBoundary>
      <Enabled>false</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
    <DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/C %s</Arguments>
    </Exec>
  </Actions>
</Task>`, command)
}
