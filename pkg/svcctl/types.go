// Package svcctl implements MS-SCMR (Service Control Manager Remote Protocol)
// for remote service management and command execution.
package svcctl

import (
	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
)

// SVCCTL interface UUID: 367abb81-9844-35f1-ad32-98f038001003
var SVCCTL_UUID = dcerpc.MustParseUUID("367abb81-9844-35f1-ad32-98f038001003")

// SCMR Opnums
const (
	OpRCloseServiceHandle   = 0
	OpRControlService       = 1
	OpRDeleteService        = 2
	OpRQueryServiceStatus   = 6
	OpRChangeServiceConfigW = 11
	OpRCreateServiceW       = 12
	OpROpenSCManagerW       = 15
	OpROpenServiceW         = 16
	OpRStartServiceW        = 19
	OpRQueryServiceConfigW  = 17
	OpREnumServicesStatusW  = 14
)

// Access Masks for SCManager
type SCMAccessMask uint32

const (
	SCManagerConnect          SCMAccessMask = 0x0001
	SCManagerCreateService    SCMAccessMask = 0x0002
	SCManagerEnumerateService SCMAccessMask = 0x0004
	SCManagerLock             SCMAccessMask = 0x0008
	SCManagerQueryLockStatus  SCMAccessMask = 0x0010
	SCManagerModifyBootConfig SCMAccessMask = 0x0020
	SCManagerAllAccess        SCMAccessMask = 0xF003F
)

// Access Masks for Services
type ServiceAccessMask uint32

const (
	ServiceQueryConfig         ServiceAccessMask = 0x0001
	ServiceChangeConfig        ServiceAccessMask = 0x0002
	ServiceQueryStatus         ServiceAccessMask = 0x0004
	ServiceEnumerateDependents ServiceAccessMask = 0x0008
	ServiceStart               ServiceAccessMask = 0x0010
	ServiceStop                ServiceAccessMask = 0x0020
	ServicePauseContinue       ServiceAccessMask = 0x0040
	ServiceInterrogate         ServiceAccessMask = 0x0080
	ServiceUserDefinedControl  ServiceAccessMask = 0x0100
	ServiceAllAccess           ServiceAccessMask = 0xF01FF
	Delete                     ServiceAccessMask = 0x10000
)

// Service Types
type ServiceType uint32

const (
	ServiceKernelDriver       ServiceType = 0x00000001
	ServiceFileSystemDriver   ServiceType = 0x00000002
	ServiceWin32OwnProcess    ServiceType = 0x00000010
	ServiceWin32ShareProcess  ServiceType = 0x00000020
	ServiceInteractiveProcess ServiceType = 0x00000100
)

// Service Start Types
type ServiceStartType uint32

const (
	ServiceBootStart   ServiceStartType = 0x00000000
	ServiceSystemStart ServiceStartType = 0x00000001
	ServiceAutoStart   ServiceStartType = 0x00000002
	ServiceDemandStart ServiceStartType = 0x00000003
	ServiceDisabled    ServiceStartType = 0x00000004
)

// Service Error Control
type ServiceErrorControl uint32

const (
	ServiceErrorIgnore   ServiceErrorControl = 0x00000000
	ServiceErrorNormal   ServiceErrorControl = 0x00000001
	ServiceErrorSevere   ServiceErrorControl = 0x00000002
	ServiceErrorCritical ServiceErrorControl = 0x00000003
)

// Service States
type ServiceState uint32

const (
	ServiceStopped         ServiceState = 0x00000001
	ServiceStartPending    ServiceState = 0x00000002
	ServiceStopPending     ServiceState = 0x00000003
	ServiceRunning         ServiceState = 0x00000004
	ServiceContinuePending ServiceState = 0x00000005
	ServicePausePending    ServiceState = 0x00000006
	ServicePaused          ServiceState = 0x00000007
)

// Handle represents an RPC context handle (20 bytes)
type Handle [20]byte

// ServiceStatus represents SERVICE_STATUS structure
type ServiceStatus struct {
	ServiceType      ServiceType
	CurrentState     ServiceState
	ControlsAccepted uint32
	Win32ExitCode    uint32
	ServiceExitCode  uint32
	CheckPoint       uint32
	WaitHint         uint32
}

// ServiceInfo represents enumerated service information
type ServiceInfo struct {
	ServiceName string
	DisplayName string
	Status      ServiceStatus
}

// StateString returns a human-readable state string
func (s ServiceState) String() string {
	switch s {
	case ServiceStopped:
		return "Stopped"
	case ServiceStartPending:
		return "Start Pending"
	case ServiceStopPending:
		return "Stop Pending"
	case ServiceRunning:
		return "Running"
	case ServiceContinuePending:
		return "Continue Pending"
	case ServicePausePending:
		return "Pause Pending"
	case ServicePaused:
		return "Paused"
	default:
		return "Unknown"
	}
}

// TypeString returns a human-readable type string
func (t ServiceType) String() string {
	switch {
	case t&ServiceWin32OwnProcess != 0:
		return "Win32"
	case t&ServiceWin32ShareProcess != 0:
		return "Win32 Share"
	case t&ServiceKernelDriver != 0:
		return "Kernel Driver"
	case t&ServiceFileSystemDriver != 0:
		return "FS Driver"
	default:
		return "Other"
	}
}
