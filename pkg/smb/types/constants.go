// Package types defines SMB2/SMB3 protocol constants and message structures.
package types

// Dialect versions for SMB2/SMB3 negotiation
type Dialect uint16

const (
	DialectSMB2_0_2 Dialect = 0x0202 // SMB 2.0.2
	DialectSMB2_1   Dialect = 0x0210 // SMB 2.1
	DialectSMB3_0   Dialect = 0x0300 // SMB 3.0
	DialectSMB3_0_2 Dialect = 0x0302 // SMB 3.0.2
	DialectSMB3_1_1 Dialect = 0x0311 // SMB 3.1.1
	DialectWildcard Dialect = 0x02FF // Wildcard (multi-protocol negotiate)
)

// Command values for SMB2 header
type Command uint16

const (
	CommandNegotiate      Command = 0x0000
	CommandSessionSetup   Command = 0x0001
	CommandLogoff         Command = 0x0002
	CommandTreeConnect    Command = 0x0003
	CommandTreeDisconnect Command = 0x0004
	CommandCreate         Command = 0x0005
	CommandClose          Command = 0x0006
	CommandFlush          Command = 0x0007
	CommandRead           Command = 0x0008
	CommandWrite          Command = 0x0009
	CommandLock           Command = 0x000A
	CommandIoctl          Command = 0x000B
	CommandCancel         Command = 0x000C
	CommandEcho           Command = 0x000D
	CommandQueryDirectory Command = 0x000E
	CommandChangeNotify   Command = 0x000F
	CommandQueryInfo      Command = 0x0010
	CommandSetInfo        Command = 0x0011
	CommandOplockBreak    Command = 0x0012
)

// HeaderFlags for SMB2 header
type HeaderFlags uint32

const (
	FlagsServerToRedir   HeaderFlags = 0x00000001 // Response from server
	FlagsAsyncCommand    HeaderFlags = 0x00000002 // Async command
	FlagsRelatedOps      HeaderFlags = 0x00000004 // Related operations (compounded)
	FlagsSigned          HeaderFlags = 0x00000008 // Message is signed
	FlagsPriorityMask    HeaderFlags = 0x00000070 // Priority mask (SMB 3.1.1)
	FlagsDFSOperations   HeaderFlags = 0x10000000 // DFS operations
	FlagsReplayOperation HeaderFlags = 0x20000000 // Replay operation (SMB 3.0)
)

// NT Status codes commonly encountered
type NTStatus uint32

const (
	StatusSuccess               NTStatus = 0x00000000
	StatusPending               NTStatus = 0x00000103 // Async operation pending
	StatusMoreProcessingReq     NTStatus = 0xC0000016 // Continue (used in auth)
	StatusInvalidParameter      NTStatus = 0xC000000D
	StatusNoSuchFile            NTStatus = 0xC000000F
	StatusEndOfFile             NTStatus = 0xC0000011
	StatusMoreEntries           NTStatus = 0x00000105
	StatusAccessDenied          NTStatus = 0xC0000022
	StatusObjectNameNotFound    NTStatus = 0xC0000034
	StatusObjectNameCollision   NTStatus = 0xC0000035
	StatusObjectPathNotFound    NTStatus = 0xC000003A
	StatusLogonFailure          NTStatus = 0xC000006D
	StatusAccountDisabled       NTStatus = 0xC0000072
	StatusPasswordExpired       NTStatus = 0xC0000071
	StatusBadNetworkName        NTStatus = 0xC00000CC
	StatusNotSupported          NTStatus = 0xC00000BB
	StatusNetworkSessionExpired NTStatus = 0xC000035C
	StatusSMBBadUID             NTStatus = 0x005B0002
	StatusNoMoreFiles           NTStatus = 0x80000006
	StatusBufferOverflow        NTStatus = 0x80000005
)

// IsSuccess returns true if the status indicates success
func (s NTStatus) IsSuccess() bool {
	return s == StatusSuccess || s == StatusMoreEntries || s == StatusBufferOverflow
}

// IsError returns true if the status indicates an error
func (s NTStatus) IsError() bool {
	return s&0xC0000000 == 0xC0000000
}

// AccessMask for file access rights
type AccessMask uint32

const (
	FileReadData        AccessMask = 0x00000001
	FileWriteData       AccessMask = 0x00000002
	FileAppendData      AccessMask = 0x00000004
	FileReadEA          AccessMask = 0x00000008
	FileWriteEA         AccessMask = 0x00000010
	FileExecute         AccessMask = 0x00000020
	FileDeleteChild     AccessMask = 0x00000040
	FileReadAttributes  AccessMask = 0x00000080
	FileWriteAttributes AccessMask = 0x00000100
	Delete              AccessMask = 0x00010000
	ReadControl         AccessMask = 0x00020000
	WriteDAC            AccessMask = 0x00040000
	WriteOwner          AccessMask = 0x00080000
	Synchronize         AccessMask = 0x00100000
	AccessSystemSec     AccessMask = 0x01000000
	MaximumAllowed      AccessMask = 0x02000000
	GenericAll          AccessMask = 0x10000000
	GenericExecute      AccessMask = 0x20000000
	GenericWrite        AccessMask = 0x40000000
	GenericRead         AccessMask = 0x80000000
)

// CreateDisposition for create operations
type CreateDisposition uint32

const (
	FileSupersede   CreateDisposition = 0 // Replace if exists, create if not
	FileOpen        CreateDisposition = 1 // Open existing, fail if not exists
	FileCreate      CreateDisposition = 2 // Create new, fail if exists
	FileOpenIf      CreateDisposition = 3 // Open if exists, create if not
	FileOverwrite   CreateDisposition = 4 // Overwrite existing, fail if not
	FileOverwriteIf CreateDisposition = 5 // Overwrite if exists, create if not
)

// CreateOptions for create operations
type CreateOptions uint32

const (
	FileDirectoryFile           CreateOptions = 0x00000001
	FileWriteThrough            CreateOptions = 0x00000002
	FileSequentialOnly          CreateOptions = 0x00000004
	FileNoIntermediateBuffering CreateOptions = 0x00000008
	FileSynchronousIOAlert      CreateOptions = 0x00000010
	FileSynchronousIONonAlert   CreateOptions = 0x00000020
	FileNonDirectoryFile        CreateOptions = 0x00000040
	FileCompleteIfOplocked      CreateOptions = 0x00000100
	FileNoEAKnowledge           CreateOptions = 0x00000200
	FileRandomAccess            CreateOptions = 0x00000800
	FileDeleteOnClose           CreateOptions = 0x00001000
	FileOpenByFileID            CreateOptions = 0x00002000
	FileOpenForBackupIntent     CreateOptions = 0x00004000
	FileNoCompression           CreateOptions = 0x00008000
	FileOpenRemoteInstance      CreateOptions = 0x00000400
	FileOpenReparsePoint        CreateOptions = 0x00200000
	FileOpenNoRecall            CreateOptions = 0x00400000
	FileOpenForFreeSpaceQuery   CreateOptions = 0x00800000
)

// FileAttributes for files and directories
type FileAttributes uint32

const (
	FileAttributeReadOnly          FileAttributes = 0x00000001
	FileAttributeHidden            FileAttributes = 0x00000002
	FileAttributeSystem            FileAttributes = 0x00000004
	FileAttributeDirectory         FileAttributes = 0x00000010
	FileAttributeArchive           FileAttributes = 0x00000020
	FileAttributeNormal            FileAttributes = 0x00000080
	FileAttributeTemporary         FileAttributes = 0x00000100
	FileAttributeSparseFile        FileAttributes = 0x00000200
	FileAttributeReparsePoint      FileAttributes = 0x00000400
	FileAttributeCompressed        FileAttributes = 0x00000800
	FileAttributeOffline           FileAttributes = 0x00001000
	FileAttributeNotContentIndexed FileAttributes = 0x00002000
	FileAttributeEncrypted         FileAttributes = 0x00004000
)

// ShareAccess for file sharing
type ShareAccess uint32

const (
	FileShareRead   ShareAccess = 0x00000001
	FileShareWrite  ShareAccess = 0x00000002
	FileShareDelete ShareAccess = 0x00000004
)

// ShareType indicates the type of share
type ShareType uint8

const (
	ShareTypeDisk  ShareType = 0x01
	ShareTypePipe  ShareType = 0x02
	ShareTypePrint ShareType = 0x03
)

// SecurityMode flags
type SecurityMode uint8

const (
	NegotiateSigningEnabled  SecurityMode = 0x01
	NegotiateSigningRequired SecurityMode = 0x02
)

// Capabilities flags
type Capabilities uint32

const (
	GlobalCapDFS               Capabilities = 0x00000001
	GlobalCapLeasing           Capabilities = 0x00000002
	GlobalCapLargeMTU          Capabilities = 0x00000004
	GlobalCapMultiChannel      Capabilities = 0x00000008
	GlobalCapPersistentHandles Capabilities = 0x00000010
	GlobalCapDirectoryLeasing  Capabilities = 0x00000020
	GlobalCapEncryption        Capabilities = 0x00000040
)

// Protocol magic bytes
var (
	SMB2ProtocolID = [4]byte{0xFE, 'S', 'M', 'B'}
	SMB1ProtocolID = [4]byte{0xFF, 'S', 'M', 'B'}
)

// Header sizes
const (
	SMB2HeaderSize = 64 // SMB2 header is always 64 bytes
)
