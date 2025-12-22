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

// Eventlog opnums
const (
	opElfrOpenELW         = 7
	opElfrReadELW         = 10
	opElfrNumberOfRecords = 4
	opElfrOldestRecord    = 5
	opElfrCloseEL         = 2
)

// Event types
const (
	eventError        = 1
	eventWarning      = 2
	eventInformation  = 4
	eventAuditSuccess = 8
	eventAuditFailure = 16
)

// cmdEventLog reads event logs
func cmdEventLog(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	logName := "Security"
	count := 10

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "security", "Security":
			logName = "Security"
		case "system", "System":
			logName = "System"
		case "application", "Application":
			logName = "Application"
		case "help":
			printEventLogHelp()
			return nil
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
	stub := make([]byte, 0, 64)

	// UNCServerName (null)
	stub = appendUint32EL(stub, 0)

	// ModuleName (RPC_UNICODE_STRING)
	nameBytes := utf16Encode(logName)
	length := uint16(len(nameBytes))
	maxLength := length + 2

	stub = appendUint16EL(stub, length)
	stub = appendUint16EL(stub, maxLength)
	stub = appendUint32EL(stub, 0x00020000) // Pointer

	// String data
	stub = appendUint32EL(stub, uint32(len(logName)+1)) // MaxCount
	stub = appendUint32EL(stub, 0)                      // Offset
	stub = appendUint32EL(stub, uint32(len(logName)+1)) // ActualCount
	stub = append(stub, nameBytes...)
	stub = append(stub, 0, 0) // Null terminator

	// Pad to 4 bytes
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	// RegModuleName (empty)
	stub = appendUint16EL(stub, 0)
	stub = appendUint16EL(stub, 0)
	stub = appendUint32EL(stub, 0)

	// MajorVersion, MinorVersion
	stub = appendUint32EL(stub, 1)
	stub = appendUint32EL(stub, 1)

	return stub
}

func encodeReadEventLog(handle [20]byte, count int) []byte {
	stub := make([]byte, 0, 40)

	stub = append(stub, handle[:]...)

	// ReadFlags: EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ
	stub = appendUint32EL(stub, 0x0002|0x0008)

	// RecordOffset
	stub = appendUint32EL(stub, 0)

	// NumberOfBytesToRead
	stub = appendUint32EL(stub, uint32(count*1024)) // Estimate

	return stub
}

func parseEventLogResponse(resp []byte) []string {
	var events []string

	if len(resp) < 20 {
		return events
	}

	// Response has variable event records
	// Simplified parsing - look for event structures
	bytesRead := binary.LittleEndian.Uint32(resp[:4])
	if bytesRead == 0 || bytesRead > uint32(len(resp)) {
		return events
	}

	// Parse EVENTLOGRECORD structures
	offset := 8
	for i := 0; i < 20 && offset+56 < len(resp); i++ {
		// Length (4 bytes)
		if offset+4 > len(resp) {
			break
		}

		length := binary.LittleEndian.Uint32(resp[offset:])
		if length < 56 || length > 65535 || offset+int(length) > len(resp) {
			break
		}

		// Parse event record
		record := resp[offset : offset+int(length)]
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

	// EVENTLOGRECORD structure
	// recordNumber := binary.LittleEndian.Uint32(record[4:8])
	timeGenerated := binary.LittleEndian.Uint32(record[8:12])
	eventID := binary.LittleEndian.Uint16(record[20:22])
	eventType := binary.LittleEndian.Uint16(record[24:26])

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

	return fmt.Sprintf("[%s] %-7s EventID: %d",
		t.Format("2006-01-02 15:04:05"), typeStr, eventID)
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
	fmt.Println("\nUsage: eventlog [log] [count]")
	fmt.Println("\nReads Windows Event Logs via RPC.")
	fmt.Println("\nLogs:")
	fmt.Println("  Security     Security events (default)")
	fmt.Println("  System       System events")
	fmt.Println("  Application  Application events")
	fmt.Println("\nExamples:")
	fmt.Println("  eventlog")
	fmt.Println("  eventlog Security 20")
	fmt.Println("  eventlog System 50")
	fmt.Println()
}
