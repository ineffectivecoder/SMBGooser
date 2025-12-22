// Package tsch implements MS-TSCH (Task Scheduler Service Remoting Protocol)
// for remote command execution via scheduled tasks.
package tsch

import (
	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
)

// ITaskSchedulerService UUID: 86D35949-83C9-4044-B424-DB363231FD0C
var TSCH_UUID = dcerpc.MustParseUUID("86d35949-83c9-4044-b424-db363231fd0c")

// TSCH Opnums (ITaskSchedulerService)
const (
	OpSchRpcHighestVersion    = 0
	OpSchRpcRegisterTask      = 1
	OpSchRpcRetrieveTask      = 2
	OpSchRpcCreateFolder      = 3
	OpSchRpcSetSecurity       = 4
	OpSchRpcGetSecurity       = 5
	OpSchRpcEnumFolders       = 6
	OpSchRpcEnumTasks         = 7
	OpSchRpcEnumInstances     = 8
	OpSchRpcGetInstanceInfo   = 9
	OpSchRpcStopInstance      = 10
	OpSchRpcStop              = 11
	OpSchRpcRun               = 12
	OpSchRpcDelete            = 13
	OpSchRpcRename            = 14
	OpSchRpcScheduledRuntimes = 15
	OpSchRpcGetLastRunInfo    = 16
	OpSchRpcGetTaskInfo       = 17
	OpSchRpcGetNumberOfMissed = 18
	OpSchRpcEnableTask        = 19
)

// Task registration flags
const (
	TaskCreate                     = 2
	TaskUpdate                     = 4
	TaskCreateOrUpdate             = 6
	TaskDisable                    = 8
	TaskDontAddPrincipalAce        = 16
	TaskIgnoreRegistrationTriggers = 32
)

// Task logon types
const (
	TaskLogonNone                  = 0
	TaskLogonPassword              = 1
	TaskLogonS4U                   = 2
	TaskLogonInteractiveToken      = 3
	TaskLogonGroup                 = 4
	TaskLogonServiceAccount        = 5
	TaskLogonInteractiveOrPassword = 6
)

// Task run flags
const (
	TaskRunNoFlags           = 0
	TaskRunAsSelf            = 1
	TaskRunIgnoreConstraints = 2
	TaskRunUseSessionId      = 4
	TaskRunUserSid           = 8
)
