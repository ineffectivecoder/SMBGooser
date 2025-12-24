// Package debug provides global debug/verbose logging control
package debug

import "fmt"

// Verbose controls whether debug output is enabled
var Verbose bool

// Printf prints debug output if verbose mode is enabled
func Printf(format string, args ...interface{}) {
	if Verbose {
		fmt.Printf("[DEBUG] "+format, args...)
	}
}

// Println prints debug output if verbose mode is enabled
func Println(args ...interface{}) {
	if Verbose {
		fmt.Print("[DEBUG] ")
		fmt.Println(args...)
	}
}
