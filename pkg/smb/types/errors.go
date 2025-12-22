package types

import (
	"errors"
)

// ErrBufferTooSmall indicates the buffer is too small for the message
var ErrBufferTooSmall = errors.New("buffer too small")
