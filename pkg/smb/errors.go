package smb

import (
	"errors"
	"fmt"

	"github.com/ineffectivecoder/SMBGooser/pkg/smb/types"
)

// Common SMB errors
var (
	ErrConnectionFailed = errors.New("connection failed")
	ErrAuthFailed       = errors.New("authentication failed")
	ErrAccessDenied     = errors.New("access denied")
	ErrNotFound         = errors.New("object not found")
	ErrAlreadyExists    = errors.New("object already exists")
	ErrInvalidParameter = errors.New("invalid parameter")
	ErrNotConnected     = errors.New("not connected")
	ErrSessionExpired   = errors.New("session expired")
	ErrBadNetworkName   = errors.New("bad network name")
	ErrNotSupported     = errors.New("operation not supported")
)

// NTStatusError wraps an NT status code as an error
type NTStatusError struct {
	Status types.NTStatus
}

// Error implements the error interface
func (e *NTStatusError) Error() string {
	return fmt.Sprintf("NT status error: 0x%08X (%s)", uint32(e.Status), e.StatusName())
}

// StatusName returns a human-readable name for the status
func (e *NTStatusError) StatusName() string {
	switch e.Status {
	case types.StatusSuccess:
		return "STATUS_SUCCESS"
	case types.StatusMoreProcessingReq:
		return "STATUS_MORE_PROCESSING_REQUIRED"
	case types.StatusInvalidParameter:
		return "STATUS_INVALID_PARAMETER"
	case types.StatusNoSuchFile:
		return "STATUS_NO_SUCH_FILE"
	case types.StatusEndOfFile:
		return "STATUS_END_OF_FILE"
	case types.StatusAccessDenied:
		return "STATUS_ACCESS_DENIED"
	case types.StatusObjectNameNotFound:
		return "STATUS_OBJECT_NAME_NOT_FOUND"
	case types.StatusObjectNameCollision:
		return "STATUS_OBJECT_NAME_COLLISION"
	case types.StatusObjectPathNotFound:
		return "STATUS_OBJECT_PATH_NOT_FOUND"
	case types.StatusLogonFailure:
		return "STATUS_LOGON_FAILURE"
	case types.StatusAccountDisabled:
		return "STATUS_ACCOUNT_DISABLED"
	case types.StatusPasswordExpired:
		return "STATUS_PASSWORD_EXPIRED"
	case types.StatusBadNetworkName:
		return "STATUS_BAD_NETWORK_NAME"
	case types.StatusNotSupported:
		return "STATUS_NOT_SUPPORTED"
	case types.StatusNetworkSessionExpired:
		return "STATUS_NETWORK_SESSION_EXPIRED"
	case types.StatusNoMoreFiles:
		return "STATUS_NO_MORE_FILES"
	default:
		return "UNKNOWN"
	}
}

// NewNTStatusError creates a new NTStatusError
func NewNTStatusError(status types.NTStatus) *NTStatusError {
	return &NTStatusError{Status: status}
}

// StatusToError converts an NT status to an appropriate Go error
func StatusToError(status types.NTStatus) error {
	if status.IsSuccess() {
		return nil
	}

	switch status {
	case types.StatusAccessDenied:
		return ErrAccessDenied
	case types.StatusNoSuchFile, types.StatusObjectNameNotFound, types.StatusObjectPathNotFound:
		return ErrNotFound
	case types.StatusObjectNameCollision:
		return ErrAlreadyExists
	case types.StatusLogonFailure, types.StatusAccountDisabled, types.StatusPasswordExpired:
		return ErrAuthFailed
	case types.StatusBadNetworkName:
		return ErrBadNetworkName
	case types.StatusNetworkSessionExpired:
		return ErrSessionExpired
	case types.StatusNotSupported:
		return ErrNotSupported
	case types.StatusInvalidParameter:
		return ErrInvalidParameter
	default:
		return NewNTStatusError(status)
	}
}
