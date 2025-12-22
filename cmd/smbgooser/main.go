package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/mjwhitta/cli"
	"github.com/peterh/liner"
	"golang.org/x/term"

	"github.com/ineffectivecoder/SMBGooser/pkg/auth"
	"github.com/ineffectivecoder/SMBGooser/pkg/smb"
)

// Version info
const (
	Version = "0.1.0"
	Banner  = "SMBGooser"
)

// ASCII art menacing goose
const gooseBanner = `
                                   ___
                               ,-""   ` + "`" + `.
                             ,'  _   e )` + "`" + `-._
                            /  ,' ` + "`" + `-._<.===-'
                           /  /
                          /  ;
              _.--.__    /   ;
 (` + "`" + `._    _.-""       "--'    |
 <_  ` + "`" + `-""                     \
  <` + "`" + `-                          :
   (__   <__.                  ;
     ` + "`" + `-.   '-.__.      _.'    /
        \      ` + "`" + `-.__,-'    _,'
         ` + "`" + `._    ,    /__,-'    HONK HONK!
            ""._\__,'< <____       SMBGooser v%s
                 | |  ` + "`" + `---._` + "`" + `-.   Red Team SMB Tool
                 | |        ` + "`" + `\ ` + "`" + `\
                 ; |___,.--""` + "`" + `` + "`" + `-'
                 \/--'
`

// Colors for output
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

// Global state
var (
	verbose       bool
	client        *smb.Client
	session       *smb.Session
	currentTree   *smb.Tree
	currentPath   string
	targetHost    string
	currentUser   string
	currentDomain string
)

func main() {
	var (
		target   string
		username string
		password string
		hash     string
		domain   string
		ccache   string
		keytab   string
		pfxPath  string
		pfxPass  string
		socks5   string
		shell    bool
		execCmd  string
	)

	// Configure CLI
	cli.Align = true
	cli.Banner = fmt.Sprintf("smbgooser [OPTIONS]")
	cli.Info("Red Team SMB Client - Directory ops, pipes, coercion, and more")
	cli.Authors = []string{"SMBGooser Team"}

	// Define flags
	cli.Flag(&target, "t", "target", "", "Target server IP/hostname")
	cli.Flag(&username, "u", "user", "", "Username")
	cli.Flag(&domain, "d", "domain", "", "Domain name / Kerberos realm")
	cli.Flag(&password, "p", "password", "", "Password")
	cli.Flag(&hash, "H", "hash", "", "NTLM hash (32 hex chars)")
	cli.Flag(&ccache, "k", "ccache", "", "Kerberos ccache file (e.g., /tmp/krb5cc_1000)")
	cli.Flag(&keytab, "K", "keytab", "", "Kerberos keytab file")
	cli.Flag(&pfxPath, "c", "cert", "", "PFX/PKCS12 certificate for PKINIT")
	cli.Flag(&pfxPass, "C", "cert-pass", "", "PFX certificate password")
	cli.Flag(&socks5, "s", "socks5", "", "SOCKS5 proxy (e.g., 127.0.0.1:1080 or user:pass@host:port)")
	cli.Flag(&execCmd, "x", "exec", "", "Execute command(s) and exit (semicolon separated)")
	cli.Flag(&shell, "i", "interactive", true, "Start interactive shell (default)")
	cli.Flag(&verbose, "v", "verbose", false, "Verbose output")

	cli.Parse()

	// Print banner
	printBanner()

	// Validate
	if target == "" {
		error_("Missing target (-t)")
		cli.Usage(1)
	}

	// Check for KRB5CCNAME environment variable if no explicit ccache
	if ccache == "" {
		if envCcache := os.Getenv("KRB5CCNAME"); envCcache != "" {
			// Strip "FILE:" prefix if present
			if len(envCcache) > 5 && envCcache[:5] == "FILE:" {
				ccache = envCcache[5:]
			} else {
				ccache = envCcache
			}
			debug_("Using KRB5CCNAME: %s", ccache)
		}
	}

	// Check auth method - need one of: password, hash, ccache, keytab, pfx
	hasPKINIT := pfxPath != ""
	hasKerberos := ccache != "" || keytab != ""
	hasNTLM := password != "" || hash != ""

	if !hasPKINIT && !hasKerberos && !hasNTLM {
		if username == "" || domain == "" {
			error_("Missing credentials (-u, -d) or Kerberos ticket (-k / $KRB5CCNAME)")
			cli.Usage(1)
		}
		password = promptPassword()
	}

	if (hasKerberos || hasPKINIT) && domain == "" {
		error_("Kerberos/PKINIT requires realm (-d)")
		cli.Usage(1)
	}

	// Connect
	targetHost = target
	ctx := context.Background()

	// Build client config
	clientConfig := smb.DefaultClientConfig()
	if socks5 != "" {
		// Normalize SOCKS5 URL
		if !strings.HasPrefix(socks5, "socks5://") {
			socks5 = "socks5://" + socks5
		}
		clientConfig.Socks5URL = socks5
		info_("Using SOCKS5 proxy: %s", socks5)
	}

	info_("Connecting to %s...", target)

	client = smb.NewClientWithConfig(clientConfig)
	if err := client.Connect(ctx, target, 445); err != nil {
		error_("Connection failed: %v", err)
		os.Exit(1)
	}
	defer client.Close()

	success_("Connected! Dialect: %s", client.DialectName())

	// Authenticate
	var creds auth.Credentials
	var err error

	if pfxPath != "" {
		// PKINIT certificate authentication
		info_("Authenticating with PKINIT certificate...")
		certCreds, cerr := auth.NewCertificateCredentials(pfxPath, pfxPass, username, domain)
		if cerr != nil {
			error_("Failed to load certificate: %v", cerr)
			os.Exit(1)
		}
		certCreds.SetKDC(target + ":88")
		if cerr := certCreds.RequestTGT(); cerr != nil {
			error_("PKINIT TGT request failed: %v", cerr)
			os.Exit(1)
		}
		success_("Got TGT via PKINIT! AS-REP key: %s", certCreds.GetASRepKey())
		info_("Certificate: %s (issued by %s)", certCreds.GetCertificateSubject(), certCreds.GetIssuer())
		// TODO: Integrate PKINIT with SMB - for now fall back to NTLM
		warn_("PKINIT→SMB not integrated yet, use password/hash for SMB")
		os.Exit(0)
	} else if ccache != "" {
		// Kerberos from ccache - use SPNEGO for SMB
		info_("Authenticating with Kerberos ccache...")
		krbCreds, kerr := auth.NewKerberosCredentialsFromCCache(ccache, domain)
		if kerr != nil {
			error_("Failed to load ccache: %v", kerr)
			os.Exit(1)
		}
		defer krbCreds.Close()
		if kerr := krbCreds.Login(); kerr != nil {
			error_("Kerberos login failed: %v", kerr)
			os.Exit(1)
		}
		info_("Kerberos auth as %s@%s", krbCreds.Username(), domain)
		creds = krbCreds // Use Kerberos credentials for SMB
	} else if keytab != "" {
		// Kerberos from keytab
		if username == "" {
			error_("Keytab requires username (-u)")
			os.Exit(1)
		}
		info_("Authenticating with Kerberos keytab...")
		krbCreds, kerr := auth.NewKerberosCredentialsFromKeytab(keytab, username, domain)
		if kerr != nil {
			error_("Failed to load keytab: %v", kerr)
			os.Exit(1)
		}
		defer krbCreds.Close()
		if kerr := krbCreds.Login(); kerr != nil {
			error_("Kerberos login failed: %v", kerr)
			os.Exit(1)
		}
		creds = krbCreds // Use Kerberos credentials for SMB
	} else if hash != "" {
		hashBytes := parseHash(hash)
		creds = auth.NewHashCredentials(domain, username, hashBytes)
		info_("Authenticating with hash (pass-the-hash)...")
	} else {
		creds = auth.NewPasswordCredentials(domain, username, password)
		info_("Authenticating as %s\\%s...", domain, username)
	}

	if err = client.Authenticate(ctx, creds); err != nil {
		error_("Authentication failed: %v", err)
		os.Exit(1)
	}

	session = client.Session()
	currentUser = username
	currentDomain = domain
	success_("Authenticated!")

	// Execute commands or start interactive shell
	if execCmd != "" {
		// Non-interactive: execute command(s) and exit
		for _, cmd := range strings.Split(execCmd, ";") {
			cmd = strings.TrimSpace(cmd)
			if cmd == "" {
				continue
			}
			args := parseArgs(cmd)
			if len(args) > 0 {
				if !executeCommand(ctx, strings.ToLower(args[0]), args[1:]) {
					break
				}
			}
		}
	} else {
		// Interactive shell
		runShell(ctx)
	}
}

func printBanner() {
	fmt.Printf(colorCyan+gooseBanner+colorReset, Version)
	fmt.Println()
}

func runShell(ctx context.Context) {
	line := liner.NewLiner()
	defer line.Close()

	line.SetCtrlCAborts(true)

	// Set up tab completion
	line.SetCompleter(func(input string) []string {
		return completeInput(ctx, input)
	})

	for {
		prompt := buildPrompt()
		input, err := line.Prompt(prompt)
		if err != nil {
			if err == liner.ErrPromptAborted {
				fmt.Println("^C")
				continue
			}
			break // EOF or error
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		line.AppendHistory(input)

		args := parseArgs(input)
		if len(args) == 0 {
			continue
		}

		cmd := strings.ToLower(args[0])
		cmdArgs := args[1:]

		if !executeCommand(ctx, cmd, cmdArgs) {
			break
		}
	}
}

// completeInput provides tab completion for commands and paths
func completeInput(ctx context.Context, input string) []string {
	parts := strings.Fields(input)

	// Complete command names
	if len(parts) == 0 || (len(parts) == 1 && !strings.HasSuffix(input, " ")) {
		prefix := ""
		if len(parts) == 1 {
			prefix = strings.ToLower(parts[0])
		}
		return completeCommands(prefix)
	}

	// Complete file paths for file commands
	cmd := strings.ToLower(parts[0])
	pathCommands := map[string]bool{
		"ls": true, "dir": true, "cd": true, "cat": true, "type": true,
		"get": true, "download": true, "put": true, "upload": true,
		"rm": true, "del": true, "mkdir": true, "md": true, "rmdir": true,
		"acl": true, "find": true,
	}

	if pathCommands[cmd] {
		// Get the path being typed
		pathArg := ""
		if len(parts) > 1 {
			pathArg = parts[len(parts)-1]
			if strings.HasSuffix(input, " ") {
				pathArg = ""
			}
		}
		return completePaths(ctx, cmd, pathArg, input)
	}

	// Complete share names for 'use' command
	if cmd == "use" {
		shareArg := ""
		if len(parts) > 1 {
			shareArg = parts[1]
		}
		return completeShares(shareArg, input)
	}

	return nil
}

// completeCommands returns command names matching prefix
func completeCommands(prefix string) []string {
	var matches []string
	seen := make(map[string]bool)

	for _, cmd := range commands.List() {
		if strings.HasPrefix(strings.ToLower(cmd.Name), prefix) && !seen[cmd.Name] {
			matches = append(matches, cmd.Name)
			seen[cmd.Name] = true
		}
	}

	sort.Strings(matches)
	return matches
}

// completePaths returns path completions from the remote share
func completePaths(ctx context.Context, cmd, pathArg, fullInput string) []string {
	if currentTree == nil {
		return nil
	}

	// Get directory to list
	dir := currentPath
	prefix := ""
	if pathArg != "" {
		if strings.Contains(pathArg, "/") || strings.Contains(pathArg, "\\") {
			// Has path separator - split into dir and prefix
			pathArg = strings.ReplaceAll(pathArg, "/", "\\")
			lastSep := strings.LastIndex(pathArg, "\\")
			dir = filepath.Join(currentPath, pathArg[:lastSep])
			prefix = strings.ToLower(pathArg[lastSep+1:])
		} else {
			prefix = strings.ToLower(pathArg)
		}
	}

	// List directory
	entries, err := currentTree.ListDirectory(ctx, dir)
	if err != nil {
		return nil
	}

	var matches []string
	baseInput := strings.TrimSuffix(fullInput, pathArg)

	for _, e := range entries {
		name := e.Name
		if name == "." || name == ".." {
			continue
		}
		if prefix == "" || strings.HasPrefix(strings.ToLower(name), prefix) {
			// Build the full completion
			if e.IsDir {
				name += "/"
			}
			if pathArg != "" && (strings.Contains(pathArg, "/") || strings.Contains(pathArg, "\\")) {
				lastSep := strings.LastIndex(strings.ReplaceAll(pathArg, "/", "\\"), "\\")
				matches = append(matches, baseInput+pathArg[:lastSep+1]+name)
			} else {
				matches = append(matches, baseInput+name)
			}
		}
	}

	sort.Strings(matches)
	return matches
}

// completeShares returns share completions
func completeShares(prefix, fullInput string) []string {
	// Common shares
	shares := []string{"C$", "ADMIN$", "IPC$", "SYSVOL", "NETLOGON"}
	var matches []string
	baseInput := strings.TrimSuffix(fullInput, prefix)

	for _, s := range shares {
		if prefix == "" || strings.HasPrefix(strings.ToLower(s), strings.ToLower(prefix)) {
			matches = append(matches, baseInput+s)
		}
	}
	return matches
}

func buildPrompt() string {
	var parts []string
	parts = append(parts, colorBold+"[SMBGooser]"+colorReset)

	if targetHost != "" {
		hostPart := colorCyan + targetHost + colorReset
		if currentTree != nil {
			hostPart += "/" + currentTree.ShareName()
			if currentPath != "" {
				hostPart += "/" + currentPath
			}
		}
		parts = append(parts, hostPart)
	}

	return strings.Join(parts, " ") + "> "
}

func parseArgs(line string) []string {
	// Simple arg parsing - splits on spaces, handles quotes
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := rune(0)

	for _, r := range line {
		switch {
		case r == '"' || r == '\'':
			if inQuote && r == quoteChar {
				inQuote = false
			} else if !inQuote {
				inQuote = true
				quoteChar = r
			} else {
				current.WriteRune(r)
			}
		case r == ' ' && !inQuote:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}

// Output helpers
func info_(format string, args ...interface{}) {
	fmt.Printf(colorCyan+"[*]"+colorReset+" "+format+"\n", args...)
}

func success_(format string, args ...interface{}) {
	fmt.Printf(colorGreen+"[+]"+colorReset+" "+format+"\n", args...)
}

func error_(format string, args ...interface{}) {
	fmt.Printf(colorRed+"[!]"+colorReset+" "+format+"\n", args...)
}

func warn_(format string, args ...interface{}) {
	fmt.Printf(colorYellow+"[-]"+colorReset+" "+format+"\n", args...)
}

func debug_(format string, args ...interface{}) {
	if verbose {
		fmt.Printf(colorBlue+"[D]"+colorReset+" "+format+"\n", args...)
	}
}

func promptPassword() string {
	fmt.Print("Password: ")
	passBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Print newline after password entry
	if err != nil {
		error_("Failed to read password: %v", err)
		os.Exit(1)
	}
	return string(passBytes)
}

func parseHash(hash string) []byte {
	hash = strings.TrimSpace(hash)
	if len(hash) != 32 {
		error_("Invalid hash length (expected 32 hex chars)")
		os.Exit(1)
	}

	bytes := make([]byte, 16)
	for i := 0; i < 16; i++ {
		fmt.Sscanf(hash[i*2:i*2+2], "%02x", &bytes[i])
	}
	return bytes
}
