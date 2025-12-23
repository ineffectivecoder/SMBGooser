package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"
	"github.com/ineffectivecoder/SMBGooser/pkg/pipe"
)

func init() {
	commands.Register(&Command{
		Name:        "eventlog",
		Aliases:     []string{"events", "logs"},
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
	result := make([]byte, len(s)*2)
	for i, c := range s {
		result[i*2] = byte(c)
		result[i*2+1] = 0
	}
	return result
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
func cmdEventLogClear(ctx context.Context, args []string) error {
	if len(args) < 1 {
		fmt.Println("Usage: eventlog clear <log> [backup_path]")
		return nil
	}

	logName := args[0]
	backupPath := ""
	if len(args) > 1 {
		backupPath = args[1]
	}

	info_("Connecting to Event Log service...")
	rpc, logHandle, err := openEventLog(ctx, logName)
	if err != nil {
		return err
	}
	defer closeEventLog(rpc, logHandle)

	if backupPath != "" {
		info_("Clearing %s log with backup to %s...", logName, backupPath)
	} else {
		warn_("Clearing %s log WITHOUT backup...", logName)
	}

	// Encode clear request
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

// cmdEventLogBackup backs up an event log
func cmdEventLogBackup(ctx context.Context, args []string) error {
	if len(args) < 2 {
		fmt.Println("Usage: eventlog backup <log> <path>")
		fmt.Println("Example: eventlog backup Security C:\\Windows\\Temp\\sec.evtx")
		return nil
	}

	logName := args[0]
	backupPath := args[1]

	info_("Connecting to Event Log service...")
	rpc, logHandle, err := openEventLog(ctx, logName)
	if err != nil {
		return err
	}
	defer closeEventLog(rpc, logHandle)

	info_("Backing up %s to %s...", logName, backupPath)

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

	success_("Event log backed up to %s", backupPath)
	return nil
}

// cmdEventLogWrite writes a custom event to the log
func cmdEventLogWrite(ctx context.Context, args []string) error {
	if len(args) < 2 {
		fmt.Println("Usage: eventlog write <log> <message>")
		fmt.Println("Example: eventlog write Application \"Test event from SMBGooser\"")
		return nil
	}

	logName := args[0]
	message := strings.Join(args[1:], " ")

	info_("Connecting to Event Log service...")
	rpc, logHandle, err := openEventLog(ctx, logName)
	if err != nil {
		return err
	}
	defer closeEventLog(rpc, logHandle)

	info_("Writing event to %s log...", logName)

	// Encode write request
	writeStub := encodeWriteEventLog(logHandle, eventInformation, 1000, message)
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

	success_("Event written to %s log", logName)
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
func encodeClearEventLog(handle [20]byte, backupPath string) []byte {
	stub := make([]byte, 0, 64)
	stub = append(stub, handle[:]...)

	if backupPath == "" {
		// NULL pointer for backup file
		stub = appendUint32EL(stub, 0)
	} else {
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
func encodeWriteEventLog(handle [20]byte, eventType uint16, eventID uint32, message string) []byte {
	stub := make([]byte, 0, 256)
	stub = append(stub, handle[:]...)

	// Time - current time in seconds since 1970
	stub = appendUint32EL(stub, uint32(time.Now().Unix()))

	// EventType (EVENTLOG_INFORMATION_TYPE=4, EVENTLOG_WARNING_TYPE=2, EVENTLOG_ERROR_TYPE=1)
	stub = appendUint16EL(stub, eventType)

	// EventCategory
	stub = appendUint16EL(stub, 0)

	// EventID
	stub = appendUint32EL(stub, eventID)

	// NumStrings - number of strings in the message
	stub = appendUint16EL(stub, 1)

	// DataSize - size of binary data (none)
	stub = appendUint32EL(stub, 0)

	// ComputerName - RPC_UNICODE_STRING
	computerName := "SMBGOOSER"
	nameBytes := utf16Encode(computerName)
	stub = appendUint16EL(stub, uint16(len(nameBytes)))
	stub = appendUint16EL(stub, uint16(len(nameBytes)+2))
	stub = appendUint32EL(stub, 0x00020000) // Pointer

	// UserSID - NULL
	stub = appendUint32EL(stub, 0)

	// Strings array pointer
	stub = appendUint32EL(stub, 0x00020004) // Pointer

	// Data - NULL (no binary data)
	stub = appendUint32EL(stub, 0)

	// Flags
	stub = appendUint16EL(stub, 0)

	// RecordNumber (output only, set to 0)
	stub = appendUint32EL(stub, 0)

	// TimeWritten (output only)
	stub = appendUint32EL(stub, 0)

	// ComputerName data
	stub = appendUint32EL(stub, uint32(len(computerName)+1)) // MaxCount
	stub = appendUint32EL(stub, 0)                           // Offset
	stub = appendUint32EL(stub, uint32(len(computerName)+1)) // ActualCount
	stub = append(stub, nameBytes...)
	stub = append(stub, 0, 0) // Null terminator
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	// Strings array - just the message
	stub = appendUint32EL(stub, 1) // Array count
	msgBytes := utf16Encode(message)
	stub = appendUint16EL(stub, uint16(len(msgBytes)))
	stub = appendUint16EL(stub, uint16(len(msgBytes)+2))
	stub = appendUint32EL(stub, 0x00020008) // Pointer

	// Message string data
	stub = appendUint32EL(stub, uint32(len(message)+1)) // MaxCount
	stub = appendUint32EL(stub, 0)                      // Offset
	stub = appendUint32EL(stub, uint32(len(message)+1)) // ActualCount
	stub = append(stub, msgBytes...)
	stub = append(stub, 0, 0) // Null terminator
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	return stub
}
