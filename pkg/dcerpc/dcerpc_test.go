package dcerpc

import (
	"bytes"
	"testing"
)

func TestParseUUID(t *testing.T) {
	// Test valid UUID with dashes
	uuid, err := ParseUUID("c681d488-d850-11d0-8c52-00c04fd90f7e")
	if err != nil {
		t.Errorf("failed to parse valid UUID: %v", err)
	}

	// String representation should match
	str := uuid.String()
	if str != "c681d488-d850-11d0-8c52-00c04fd90f7e" {
		t.Errorf("expected c681d488-d850-11d0-8c52-00c04fd90f7e, got %s", str)
	}

	// Test UUID without dashes
	uuid2, err := ParseUUID("c681d488d85011d08c5200c04fd90f7e")
	if err != nil {
		t.Errorf("failed to parse UUID without dashes: %v", err)
	}
	if !bytes.Equal(uuid[:], uuid2[:]) {
		t.Error("UUIDs should be equal regardless of dash format")
	}
}

func TestParseUUIDInvalid(t *testing.T) {
	// Invalid length
	_, err := ParseUUID("c681d488-d850")
	if err == nil {
		t.Error("expected error for invalid UUID length")
	}

	// Invalid hex
	_, err = ParseUUID("zzzzzzzz-d850-11d0-8c52-00c04fd90f7e")
	if err == nil {
		t.Error("expected error for invalid hex characters")
	}
}

func TestMustParseUUID(t *testing.T) {
	// Should not panic with valid UUID
	uuid := MustParseUUID("12345678-1234-abcd-ef00-0123456789ab")
	if uuid.String() != "12345678-1234-abcd-ef00-0123456789ab" {
		t.Error("UUID should be parseable")
	}
}

func TestLookupInterface(t *testing.T) {
	// Lookup a well-known interface
	iface := LookupInterface(EFSR_UUID)
	if iface == nil {
		t.Fatal("expected to find EFSR interface")
	}
	if iface.Name != "EFSR" {
		t.Errorf("expected name EFSR, got %s", iface.Name)
	}
	if iface.Pipe != "efsrpc,lsarpc" {
		t.Errorf("unexpected pipe: %s", iface.Pipe)
	}
}

func TestLookupInterfaceByName(t *testing.T) {
	// Case-insensitive lookup
	iface := LookupInterfaceByName("efsr")
	if iface == nil {
		t.Fatal("expected to find EFSR by lowercase name")
	}
	if iface.Name != "EFSR" {
		t.Errorf("expected name EFSR, got %s", iface.Name)
	}

	iface2 := LookupInterfaceByName("EFSR")
	if iface2 == nil {
		t.Fatal("expected to find EFSR by uppercase name")
	}

	// Unknown interface
	iface3 := LookupInterfaceByName("nonexistent")
	if iface3 != nil {
		t.Error("expected nil for unknown interface")
	}
}

func TestSyntaxIDMarshal(t *testing.T) {
	sid := &SyntaxID{
		UUID:    EFSR_UUID,
		Version: 1,
	}

	data := sid.Marshal()
	if len(data) != 20 {
		t.Errorf("expected 20 bytes, got %d", len(data))
	}
}

func TestCommonHeaderMarshal(t *testing.T) {
	header := &CommonHeader{
		Version:            RPCVersionMajor,
		VersionMinor:       RPCVersionMinor,
		PacketType:         PacketTypeBind,
		PacketFlags:        PacketFlagFirstFrag | PacketFlagLastFrag,
		DataRepresentation: NDRDataRepresentation,
		FragLength:         72,
		AuthLength:         0,
		CallID:             1,
	}

	data := header.Marshal()
	if len(data) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(data))
	}

	// Verify fields
	if data[0] != RPCVersionMajor {
		t.Error("wrong version major")
	}
	if data[1] != RPCVersionMinor {
		t.Error("wrong version minor")
	}
	if data[2] != byte(PacketTypeBind) {
		t.Error("wrong packet type")
	}
}

func TestCommonHeaderUnmarshal(t *testing.T) {
	// Create a header buffer
	buf := make([]byte, 16)
	buf[0] = 5 // Version
	buf[1] = 0 // Version Minor
	buf[2] = byte(PacketTypeBindAck)
	buf[3] = PacketFlagFirstFrag | PacketFlagLastFrag

	var header CommonHeader
	err := header.Unmarshal(buf)
	if err != nil {
		t.Errorf("unmarshal failed: %v", err)
	}

	if header.Version != 5 {
		t.Errorf("expected version 5, got %d", header.Version)
	}
	if header.PacketType != PacketTypeBindAck {
		t.Error("wrong packet type")
	}
}

func TestCommonHeaderUnmarshalTooShort(t *testing.T) {
	buf := make([]byte, 10) // Too short
	var header CommonHeader
	err := header.Unmarshal(buf)
	if err == nil {
		t.Error("expected error for buffer too short")
	}
}
