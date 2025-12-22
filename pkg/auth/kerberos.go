package auth

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// KerberosCredentials holds Kerberos authentication material
type KerberosCredentials struct {
	domain     string
	username   string
	realm      string
	ccachePath string // Path to ccache file
	keytabPath string // Path to keytab file
	password   string // Password for AS-REQ
	krbClient  *client.Client
}

// NewKerberosCredentialsFromCCache creates credentials from a ccache file
func NewKerberosCredentialsFromCCache(ccachePath, realm string) (*KerberosCredentials, error) {
	// Load ccache
	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load ccache: %w", err)
	}

	// Create client from ccache
	cfg, err := loadKrb5Config()
	if err != nil {
		return nil, err
	}

	krbClient, err := client.NewFromCCache(ccache, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kerberos client: %w", err)
	}

	username := ""
	if len(ccache.DefaultPrincipal.PrincipalName.NameString) > 0 {
		username = ccache.DefaultPrincipal.PrincipalName.NameString[0]
	}

	creds := &KerberosCredentials{
		domain:     strings.ToUpper(realm),
		username:   username,
		realm:      realm,
		ccachePath: ccachePath,
		krbClient:  krbClient,
	}

	return creds, nil
}

// NewKerberosCredentialsFromKeytab creates credentials from a keytab file
func NewKerberosCredentialsFromKeytab(keytabPath, username, realm string) (*KerberosCredentials, error) {
	cfg, err := loadKrb5Config()
	if err != nil {
		return nil, err
	}

	// Load keytab
	kt, err := keytab.Load(keytabPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load keytab: %w", err)
	}

	krbClient := client.NewWithKeytab(username, realm, kt, cfg)

	creds := &KerberosCredentials{
		domain:     strings.ToUpper(realm),
		username:   username,
		realm:      realm,
		keytabPath: keytabPath,
		krbClient:  krbClient,
	}

	return creds, nil
}

// NewKerberosCredentialsFromPassword creates credentials from username/password
func NewKerberosCredentialsFromPassword(username, realm, password string) (*KerberosCredentials, error) {
	cfg, err := loadKrb5Config()
	if err != nil {
		return nil, err
	}

	krbClient := client.NewWithPassword(username, realm, password, cfg)

	creds := &KerberosCredentials{
		domain:    strings.ToUpper(realm),
		username:  username,
		realm:     realm,
		password:  password,
		krbClient: krbClient,
	}

	return creds, nil
}

// Domain returns the domain
func (k *KerberosCredentials) Domain() string {
	return k.domain
}

// Username returns the username
func (k *KerberosCredentials) Username() string {
	return k.username
}

// IsHashAuth returns false for Kerberos
func (k *KerberosCredentials) IsHashAuth() bool {
	return false
}

// IsKerberos returns true
func (k *KerberosCredentials) IsKerberos() bool {
	return true
}

// Login performs Kerberos AS-REQ authentication
func (k *KerberosCredentials) Login() error {
	if k.krbClient == nil {
		return fmt.Errorf("Kerberos client not initialized")
	}
	return k.krbClient.Login()
}

// GetSPNEGOToken gets a SPNEGO token for the given SPN
func (k *KerberosCredentials) GetSPNEGOToken(spn string) ([]byte, error) {
	if k.krbClient == nil {
		return nil, fmt.Errorf("Kerberos client not initialized")
	}

	// Get service ticket via SPNEGO
	spnegoClient := spnego.SPNEGOClient(k.krbClient, spn)

	token, err := spnegoClient.InitSecContext()
	if err != nil {
		return nil, fmt.Errorf("failed to create SPNEGO token: %w", err)
	}

	return token.Marshal()
}

// GetServiceTicket gets a TGS ticket for the given SPN
func (k *KerberosCredentials) GetServiceTicket(spn string) ([]byte, error) {
	if k.krbClient == nil {
		return nil, fmt.Errorf("Kerberos client not initialized")
	}

	// Get TGS ticket
	ticket, _, err := k.krbClient.GetServiceTicket(spn)
	if err != nil {
		return nil, fmt.Errorf("failed to get service ticket: %w", err)
	}

	return ticket.Marshal()
}

// Client returns the underlying Kerberos client
func (k *KerberosCredentials) Client() *client.Client {
	return k.krbClient
}

// Close destroys the Kerberos client
func (k *KerberosCredentials) Close() {
	if k.krbClient != nil {
		k.krbClient.Destroy()
	}
}

// loadKrb5Config loads Kerberos config from standard locations
func loadKrb5Config() (*config.Config, error) {
	// Try standard locations
	paths := []string{
		"/etc/krb5.conf",
		"/etc/krb5/krb5.conf",
		os.Getenv("KRB5_CONFIG"),
	}

	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return config.Load(path)
		}
	}

	// Create minimal config if none found
	minimalConfig := `[libdefaults]
default_realm = DOMAIN.LOCAL
dns_lookup_realm = true
dns_lookup_kdc = true
`
	return config.NewFromString(minimalConfig)
}

// ParseKerberosTicket parses a base64-encoded Kerberos ticket
func ParseKerberosTicket(ticketB64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(ticketB64)
}
