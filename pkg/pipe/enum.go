package pipe

import (
	"context"
	"errors"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
)

// Well-known named pipes for common services
const (
	PipeSrvsvc   = "srvsvc"      // Server Service
	PipeSamr     = "samr"        // SAM Remote
	PipeLsarpc   = "lsarpc"      // LSA Remote
	PipeNetlogon = "netlogon"    // Netlogon
	PipeEfsrpc   = "efsrpc"      // EFS Remote (PetitPotam)
	PipeSpoolss  = "spoolss"     // Print Spooler (PrinterBug)
	PipeNetdfs   = "netdfs"      // DFS (DFSCoerce)
	PipeWkssvc   = "wkssvc"      // Workstation Service
	PipeBrowser  = "browser"     // Browser Service
	PipeSvcctl   = "svcctl"      // Service Control
	PipeAtsvc    = "atsvc"       // Task Scheduler
	PipeEpmapper = "epmapper"    // Endpoint Mapper
	PipeFssagent = "FssagentRpc" // VSS Agent (ShadowCoerce)
)

// CommonPipes returns a list of common named pipes to check
func CommonPipes() []string {
	return []string{
		PipeSrvsvc,
		PipeSamr,
		PipeLsarpc,
		PipeNetlogon,
		PipeEfsrpc,
		PipeSpoolss,
		PipeNetdfs,
		PipeWkssvc,
		PipeBrowser,
		PipeSvcctl,
		PipeAtsvc,
		PipeEpmapper,
		PipeFssagent,
	}
}

// Enumerate lists available named pipes on the IPC$ share
func Enumerate(ctx context.Context, tree *smb.Tree) ([]string, error) {
	// List the root of IPC$ share to get pipe names
	files, err := tree.ListDirectory(ctx, "")
	if err != nil {
		return nil, err
	}

	var pipes []string
	for _, f := range files {
		pipes = append(pipes, f.Name)
	}

	return pipes, nil
}

// PipeStatus represents the result of checking a pipe
type PipeStatus struct {
	Name   string
	Status string // "available", "access_denied", "not_found", "error"
	Error  error
}

// CheckPipe checks if a specific pipe is available
func CheckPipe(ctx context.Context, tree *smb.Tree, pipeName string) bool {
	status := CheckPipeWithStatus(ctx, tree, pipeName)
	return status.Status == "available"
}

// CheckPipeWithStatus checks a pipe and returns detailed status
func CheckPipeWithStatus(ctx context.Context, tree *smb.Tree, pipeName string) PipeStatus {
	pipe, err := Open(ctx, tree, pipeName)
	if err != nil {
		errStr := strings.ToLower(err.Error())
		status := PipeStatus{Name: pipeName, Error: err}

		// Check for access denied errors
		if strings.Contains(errStr, "access denied") ||
			strings.Contains(errStr, "access_denied") ||
			errors.Is(err, smb.ErrAccessDenied) {
			status.Status = "access_denied"
			// Check for not found errors
		} else if strings.Contains(errStr, "not found") ||
			strings.Contains(errStr, "object_name_not_found") ||
			strings.Contains(errStr, "bad network name") {
			status.Status = "not_found"
		} else {
			// Store the actual error message for debugging
			status.Status = "error"
		}
		return status
	}
	pipe.Close()
	return PipeStatus{Name: pipeName, Status: "available"}
}

// EnumerateCommon checks which common pipes are available
func EnumerateCommon(ctx context.Context, tree *smb.Tree) []string {
	var available []string
	for _, pipeName := range CommonPipes() {
		if CheckPipe(ctx, tree, pipeName) {
			available = append(available, pipeName)
		}
	}
	return available
}

// EnumerateCommonWithStatus checks common pipes and returns detailed status for each
func EnumerateCommonWithStatus(ctx context.Context, tree *smb.Tree) []PipeStatus {
	var statuses []PipeStatus
	for _, pipeName := range CommonPipes() {
		statuses = append(statuses, CheckPipeWithStatus(ctx, tree, pipeName))
	}
	return statuses
}
