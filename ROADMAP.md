# SMBGooser - Red Team SMB Library & Tool

## Phase 1: Research & Design Documentation ✅

- [x] Research SMB2/SMB3 protocol specifications (MS-SMB2)
- [x] Study NTLM/NTLMSSP authentication mechanism
- [x] Analyze named pipe operations and IPC$ share
- [x] Research coercion techniques and RPC over named pipes
- [x] Evaluate Go SMB libraries (hirochachacha/go-smb2)
- [x] Create SMB Protocol Design Document
- [x] Create Library Architecture Design
- [x] Create Implementation Plan

## Phase 2: Core Library - SMB Protocol (`pkg/smb`) ✅

- [x] Transport layer (TCP, NetBIOS)
- [x] SMB2/SMB3 types (constants.go, header.go, negotiate.go, session.go, tree.go)
- [x] Dialect negotiation (SMB 2.0.2 → 3.1.1)
- [x] Error handling (errors.go)
- [x] Session management (session.go)
- [x] Tree connect/disconnect (tree.go)

## Phase 3: Core Library - Authentication (`pkg/auth`) ✅

- [x] NTLMSSP Type 1/2/3 message handling
- [x] NTLMv2 response computation
- [x] Session key derivation
- [x] Pass-the-hash support

## Phase 4: Core Library - Operations (`pkg/smb`) ✅

- [x] Directory listing and traversal
- [x] Directory creation/deletion
- [x] File read/write operations
- [x] File/directory deletion

## Phase 5: Core Library - Named Pipes (`pkg/pipe`) + DCE/RPC (`pkg/dcerpc`) ✅

- [x] IPC$ share connection (pkg/pipe)
- [x] Named pipe enumeration
- [x] Pipe open/read/write/close
- [x] DCE/RPC binding and calls
- [x] NDR encoding/decoding
- [x] Well-known interface UUIDs (EFSR, RPRN, DFSNM, FSRVP, etc.)

## Phase 6: Core Library - Coercion (`pkg/coerce`) ✅

- [x] Known coercion method implementations (PetitPotam, SpoolSample, DFSCoerce, ShadowCoerce)
- [x] Coercer interface and runner framework
- [x] Path utilities (UNC, HTTP/WebDAV)
- [x] Discovery framework for finding new methods (opnum enumeration)

## Phase 7: CLI Client (`cmd/smbgooser`) ✅

- [x] Interactive shell with command parser
- [x] Menacing goose ASCII banner
- [x] Path-aware prompt with [SMBGooser]
- [x] Core commands (help, exit, whoami, info, clear)
- [x] Share commands (shares, use, disconnect, shareaccess)
- [x] File commands (ls, cd, pwd, cat, get, put, mkdir, rmdir, rm, find, acl)
- [x] Pipe commands (pipes, rpc)
- [x] Coercion commands (coerce, discover)
- [x] Color output (green=success, red=error, cyan=info)

## Phase 8: RPC Exploration & Coercion Discovery ✅

- [x] `rpc bind <interface|uuid>` - Bind to DCE/RPC interface on a pipe
- [x] `rpc call <opnum> [stub_hex]` - Call specific opnum with optional stub data
- [x] `rpc scan <interface> <listener>` - Scan opnums for coercion candidates
- [x] `pipe open/read/write/transact` - Raw pipe I/O

## Phase 9: Security & Testing ✅

- [x] Message signing (SMB3)
- [x] Message sealing/encryption (AES-CCM/GCM)
- [x] Unit tests for each package (60+ tests)
- [x] README and documentation

## Phase 10: Red Team Operations ✅

- [x] Remote Service Execution (`exec`) - via SCMR/svcctl
- [x] Scheduled Task Execution (`atexec`) - via Task Scheduler/atsvc
- [x] Remote Registry (`reg`) - query/add/delete via winreg
- [x] Service Control (`svc`) - query/start/stop/list via svcctl
- [x] Secrets Dumping (`secretsdump`) - SAM hashes, LSA secrets, cached creds
- [x] SOCKS5 Proxy Support (`--socks5`) - tunnel through proxy

## Phase 11: Recon & Enumeration ✅

- [x] User/Group Enumeration (`users`) - via SAMR
- [x] Computer Enumeration (`users -c`) - via SAMR
- [x] Password Policy (`users -p`) - via SAMR
- [x] Session Enumeration (`sessions`) - via SRVSVC
- [x] Logged-On Users (`loggedon`) - via WKSSVC
- [x] Domain Trusts (`trusts`) - via LSARPC
- [x] Local Admin Members (`localadmins`) - via SAMR
- [x] Event Log Reading (`eventlog read`) - via EVENTLOG RPC, with full event details

## Phase 12: Advanced Features ✅

- [x] Search/Find (`find <pattern>`) - Search for files across shares
- [x] ACL Viewer (`acl`) - Show file/directory permissions
- [x] Shadow Copies (`shadow`) - Access VSS snapshots
- [x] GPO Access (`gpo`) - List/enumerate Group Policy Objects

---

## Future Features

### 🔧 Protocol Enhancements

- [x] SMB1 Support - Package complete (`pkg/smb/smb1/`), CLI flag `--smb1` added
- [ ] Multi-channel SMB3 - Faster transfers
- [ ] Credit Management - Better handling for large transfers

### 🛠️ Utility Features

- [x] Non-interactive Mode (`-x`) - Execute commands and exit
- [x] Tab Completion - Commands, file paths, share names (`chzyer/readline`)
- [x] Recursive Download (`get -r`) - Download entire directories
- [x] File Timestomping (`touch`) - Modify file timestamps for forensic evasion
- [x] Event Log Clearing (`eventlog clear`) - Fixed! Works with device path format
- [x] Event Log Backup (`eventlog backup`) - Fixed! Uses toDevicePath helper
- [x] Event Log Writing (`eventlog write`) - Fixed! RPC method works, -schtask fallback
- [x] Registry VFS (`use reg`) - Interactive directory-style registry navigation
- [ ] Enhanced Event Log Viewer - Directory-style navigation, rendered details view
- [ ] Alternate Data Streams (`ads`) - Hide data in NTFS ADS

---

## 🟢 COMPLETED: Native LSASS Credential Extraction

**Goal:** Extract NT hashes from LSASS minidumps without external dependencies (pypykatz).

### Completed ✅

- `lsadump` command with svcctl/tsch execution for remote LSASS dumping
- `-a` flag for ADS-based stealth dumping  
- Minidump parsing (`pkg/minidump`)
- Module enumeration and lsasrv.dll/msv1_0.dll finding
- **VA-to-offset translation** - `MemoryRanges`, `VAToOffset()`, `ReadVA()`
- **LSA key extraction** - IV, AES key, DES key all extracted correctly (validated against pypykatz)
- MSV signature finding at correct offset
- LogonSessionList pointer resolution
- **Multiple logon session list support** - Windows 8+ stores sessions in multiple linked lists
- **Credential list walking** - extracting credentials with correct Username/Domain
- KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC structure parsing
- **NT hash decryption** - AES-CFB and 3DES-CBC modes working correctly ✅
- **SHA1 hash extraction** - from MSV1_0_PRIMARY_CREDENTIAL_10_1607_DEC structure ✅
- **Credential deduplication** - removes duplicate entries from multiple list traversals

### Verified Output

```
Domain: IIS APPPOOL | User: DefaultAppPool | NT: dca73295c4666c7ccf20acbe9811c135 | SHA1: df4f1565fc4e1a11bf4f075594bb14bb19f7c6b9
Domain: ROOTSHELL | User: SENSEI$ | NT: dca73295c4666c7ccf20acbe9811c135 | SHA1: df4f1565fc4e1a11bf4f075594bb14bb19f7c6b9
Domain: Font Driver Host | User: UMFD-0 | NT: dca73295c4666c7ccf20acbe9811c135 | SHA1: df4f1565fc4e1a11bf4f075594bb14bb19f7c6b9
Domain: Font Driver Host | User: UMFD-1 | NT: dca73295c4666c7ccf20acbe9811c135 | SHA1: df4f1565fc4e1a11bf4f075594bb14bb19f7c6b9
```

All NT and SHA1 hashes match pypykatz output.

### Test Command

```bash
go build ./... && go run pkg/minidump/test_parse.go lsass_192.168.90.10_1766528649.dmp
```

---

### Task Scheduler Fix (Resolved ✅)

**Problem:** `atexec` failed with `rpc_s_access_denied` / RPC fault 0x05

**Root Cause:** Using `TASK_LOGON_S4U` (2) instead of `TASK_LOGON_NONE` (0)

**Fix Applied:**

- Changed `logonType` from `TASK_LOGON_S4U` to `TASK_LOGON_NONE` in `pkg/tsch/ndr.go`
- Updated XML format in `pkg/tsch/tsch.go` to match Impacket's `atexec.py`

---

## Not Planned (Use Other Tools)

| Feature | Alternative |
|---------|-------------|
| DCSync (DRSUAPI) | Requires RPC/TCP port 135, use Impacket `secretsdump.py -just-dc` |
| SMB Relay | Use `credgoblin` |
| WMI Execution | Uses DCOM (port 135), out of scope |
| Print Nightmare | Patched, limited value |

---

## Package Overview

| Package | Purpose |
|---------|---------|
| `pkg/smb` | Core SMB2/3 client |
| `pkg/smb/smb1` | SMB1 protocol support (WIP) |
| `pkg/auth` | NTLM authentication |
| `pkg/pipe` | Named pipe operations |
| `pkg/dcerpc` | DCE/RPC protocol |
| `pkg/coerce` | Coercion attacks |
| `pkg/svcctl` | Service Control Manager |
| `pkg/tsch` | Task Scheduler |
| `pkg/rrp` | Remote Registry |
| `pkg/samr` | SAM Remote Protocol |
| `pkg/secrets` | SAM/LSA dumping |
| `pkg/hive` | Registry hive parsing |
| `pkg/srvsvc` | Server Service |
| `pkg/wkssvc` | Workstation Service |
| `pkg/lsarpc` | LSA Remote Protocol |
