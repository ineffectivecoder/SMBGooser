package dcerpc

import "errors"

// Common errors
var (
	ErrBufferTooSmall = errors.New("buffer too small")
	ErrBindFailed     = errors.New("bind failed")
	ErrCallFailed     = errors.New("RPC call failed")
	ErrNotBound       = errors.New("not bound to interface")
)
