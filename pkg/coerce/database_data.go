package coerce

import "github.com/ineffectivecoder/SMBGooser/pkg/dcerpc"

// knownInterfaces contains the pre-populated interface database
// Data sourced from MS-* specifications and security research
var knownInterfaces = []InterfaceInfo{
	// MS-EFSR - Encrypting File System Remote Protocol (PetitPotam)
	{
		Name:        "MS-EFSR",
		Description: "Encrypting File System Remote Protocol",
		UUID:        dcerpc.MustParseUUID("c681d488-d850-11d0-8c52-00c04fd90f7e"),
		Version:     1,
		Pipe:        "lsarpc",
		Methods: []MethodInfo{
			{Opnum: 0, Name: "EfsRpcOpenFileRaw",
				PathParams: []PathParam{{Position: 1, Name: "FileName", Type: "wchar_t*"}},
				Status:     StatusConfirmed, Notes: "PetitPotam original - works on most systems"},
			{Opnum: 4, Name: "EfsRpcEncryptFileSrv",
				PathParams: []PathParam{{Position: 0, Name: "FileName", Type: "wchar_t*"}},
				Status:     StatusConfirmed, Notes: "Works on unpatched systems"},
			{Opnum: 5, Name: "EfsRpcDecryptFileSrv",
				PathParams: []PathParam{{Position: 0, Name: "FileName", Type: "wchar_t*"}},
				Status:     StatusConfirmed, Notes: "Works on unpatched systems"},
			{Opnum: 6, Name: "EfsRpcQueryUsersOnFile",
				PathParams: []PathParam{{Position: 0, Name: "FileName", Type: "wchar_t*"}},
				Status:     StatusCandidate, Notes: "Has path param, untested"},
			{Opnum: 9, Name: "EfsRpcQueryRecoveryAgents",
				PathParams: []PathParam{{Position: 0, Name: "FileName", Type: "wchar_t*"}},
				Status:     StatusCandidate, Notes: "Has path param, untested"},
			{Opnum: 12, Name: "EfsRpcFileKeyInfo",
				PathParams: []PathParam{{Position: 0, Name: "FileName", Type: "wchar_t*"}},
				Status:     StatusConfirmed, Notes: "Works on some systems"},
		},
	},

	// MS-RPRN - Print System Remote Protocol (PrinterBug/SpoolSample)
	{
		Name:        "MS-RPRN",
		Description: "Print System Remote Protocol",
		UUID:        dcerpc.MustParseUUID("12345678-1234-abcd-ef00-0123456789ab"),
		Version:     1,
		Pipe:        "spoolss",
		Methods: []MethodInfo{
			{Opnum: 58, Name: "RpcRemoteFindFirstPrinterChangeNotificationEx",
				PathParams: []PathParam{{Position: 3, Name: "pszLocalMachine", Type: "wchar_t*"}},
				Status:     StatusConfirmed, Notes: "PrinterBug/SpoolSample - requires Print Spooler"},
			{Opnum: 69, Name: "RpcOpenPrinterEx",
				PathParams: []PathParam{{Position: 0, Name: "pPrinterName", Type: "wchar_t*"}},
				Status:     StatusCandidate, Notes: "May accept UNC printer paths"},
			{Opnum: 0, Name: "RpcEnumPrinters",
				PathParams: []PathParam{{Position: 2, Name: "Name", Type: "wchar_t*"}},
				Status:     StatusCandidate, Notes: "Server name field"},
		},
	},

	// MS-DFSNM - Distributed File System Namespace Management (DFSCoerce)
	{
		Name:        "MS-DFSNM",
		Description: "DFS Namespace Management Protocol",
		UUID:        dcerpc.MustParseUUID("4fc742e0-4a10-11cf-8273-00aa004ae673"),
		Version:     3,
		Pipe:        "netdfs",
		Methods: []MethodInfo{
			{Opnum: 12, Name: "NetrDfsAddStdRoot",
				PathParams: []PathParam{{Position: 0, Name: "ServerName", Type: "wchar_t*"}},
				Status:     StatusConfirmed, Notes: "DFSCoerce - requires DFS role"},
			{Opnum: 13, Name: "NetrDfsRemoveStdRoot",
				PathParams: []PathParam{{Position: 0, Name: "ServerName", Type: "wchar_t*"}},
				Status:     StatusConfirmed, Notes: "DFSCoerce variant"},
			{Opnum: 14, Name: "NetrDfsAddStdRootForced",
				PathParams: []PathParam{{Position: 0, Name: "ServerName", Type: "wchar_t*"}},
				Status:     StatusConfirmed, Notes: "DFSCoerce variant"},
		},
	},

	// MS-FSRVP - File Server Remote VSS Protocol (ShadowCoerce)
	{
		Name:        "MS-FSRVP",
		Description: "File Server Remote VSS Protocol",
		UUID:        dcerpc.MustParseUUID("a8e0653c-2744-4389-a61d-7373df8b2292"),
		Version:     1,
		Pipe:        "fssagentrpc",
		Methods: []MethodInfo{
			{Opnum: 8, Name: "IsPathShadowCopied",
				PathParams: []PathParam{{Position: 0, Name: "ShareName", Type: "wchar_t*"}},
				Status:     StatusConfirmed, Notes: "ShadowCoerce - requires VSS service"},
			{Opnum: 9, Name: "GetShareMapping",
				PathParams: []PathParam{{Position: 0, Name: "ShareName", Type: "wchar_t*"}},
				Status:     StatusConfirmed, Notes: "ShadowCoerce variant"},
			{Opnum: 11, Name: "IsPathSupported",
				PathParams: []PathParam{{Position: 0, Name: "ShareName", Type: "wchar_t*"}},
				Status:     StatusCandidate, Notes: "Has ShareName param"},
		},
	},

	// MS-EVEN - EventLog Remoting Protocol
	{
		Name:        "MS-EVEN",
		Description: "EventLog Remoting Protocol",
		UUID:        dcerpc.MustParseUUID("82273fdc-e32a-18c3-3f78-827929dc23ea"),
		Version:     0,
		Pipe:        "eventlog",
		Methods: []MethodInfo{
			{Opnum: 0, Name: "ElfrClearELFW",
				PathParams: []PathParam{{Position: 1, Name: "BackupFileName", Type: "PRPC_UNICODE_STRING"}},
				Status:     StatusCandidate, Notes: "Clears log to backup path"},
			{Opnum: 7, Name: "ElfrBackupELFW",
				PathParams: []PathParam{{Position: 1, Name: "BackupFileName", Type: "PRPC_UNICODE_STRING"}},
				Status:     StatusCandidate, Notes: "Backs up log to path"},
			{Opnum: 12, Name: "ElfrOpenBELW",
				PathParams: []PathParam{{Position: 1, Name: "BackupFileName", Type: "PRPC_UNICODE_STRING"}},
				Status:     StatusCandidate, Notes: "Opens backup event log"},
		},
	},

	// MS-SCMR - Service Control Manager Remote Protocol
	{
		Name:        "MS-SCMR",
		Description: "Service Control Manager Remote Protocol",
		UUID:        dcerpc.MustParseUUID("367abb81-9844-35f1-ad32-98f038001003"),
		Version:     2,
		Pipe:        "svcctl",
		Methods: []MethodInfo{
			{Opnum: 15, Name: "RCreateServiceW",
				PathParams: []PathParam{
					{Position: 7, Name: "lpBinaryPathName", Type: "wchar_t*"},
					{Position: 9, Name: "lpLoadOrderGroup", Type: "wchar_t*"},
				},
				Status: StatusCandidate, Notes: "Binary path could be UNC"},
			{Opnum: 12, Name: "RChangeServiceConfigW",
				PathParams: []PathParam{{Position: 3, Name: "lpBinaryPathName", Type: "wchar_t*"}},
				Status:     StatusCandidate, Notes: "Change service binary path"},
		},
	},

	// MS-WKST - Workstation Service Remote Protocol
	{
		Name:        "MS-WKST",
		Description: "Workstation Service Remote Protocol",
		UUID:        dcerpc.MustParseUUID("6bffd098-a112-3610-9833-46c3f87e345a"),
		Version:     1,
		Pipe:        "wkssvc",
		Methods: []MethodInfo{
			{Opnum: 23, Name: "NetrJoinDomain2",
				PathParams: []PathParam{{Position: 1, Name: "DomainName", Type: "wchar_t*"}},
				Status:     StatusCandidate, Notes: "Domain name could trigger lookup"},
			{Opnum: 13, Name: "NetrUseAdd",
				PathParams: []PathParam{{Position: 1, Name: "UncServerName", Type: "wchar_t*"}},
				Status:     StatusCandidate, Notes: "UNC path for network use"},
		},
	},

	// MS-TSCH - Task Scheduler Service Remote Protocol
	{
		Name:        "MS-TSCH",
		Description: "Task Scheduler Service Remote Protocol",
		UUID:        dcerpc.MustParseUUID("86d35949-83c9-4044-b424-db363231fd0c"),
		Version:     1,
		Pipe:        "atsvc",
		Methods: []MethodInfo{
			{Opnum: 1, Name: "SchRpcRegisterTask",
				PathParams: []PathParam{{Position: 2, Name: "xml", Type: "wchar_t*"}},
				Status:     StatusCandidate, Notes: "Task XML could contain UNC paths"},
		},
	},
}
