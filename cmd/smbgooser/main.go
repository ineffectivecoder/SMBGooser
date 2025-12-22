package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/mjwhitta/cli"
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

	// Start interactive shell
	runShell(ctx)
}

func printBanner() {
	fmt.Printf(colorCyan+gooseBanner+colorReset, Version)
	fmt.Println()
}

func runShell(ctx context.Context) {
	reader := bufio.NewReader(os.Stdin)

	for {
		// Build prompt
		prompt := buildPrompt()
		fmt.Print(prompt)

		// Read command
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse and execute
		args := parseArgs(line)
		if len(args) == 0 {
			continue
		}

		cmd := strings.ToLower(args[0])
		cmdArgs := args[1:]

		if !executeCommand(ctx, cmd, cmdArgs) {
			break // exit command
		}
	}
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
