// Package auth provides NTLM/NTLMSSP authentication for SMB.
package auth

// Credentials represents authentication credentials
type Credentials interface {
	Domain() string
	Username() string
	IsHashAuth() bool
}

// KerberosProvider is implemented by credentials that support Kerberos authentication
type KerberosProvider interface {
	Credentials
	IsKerberos() bool
	GetSPNEGOToken(spn string) ([]byte, error)
}

// PasswordCredentials for password-based authentication
type PasswordCredentials struct {
	domain   string
	username string
	password string
}

// NewPasswordCredentials creates password-based credentials
func NewPasswordCredentials(domain, username, password string) *PasswordCredentials {
	return &PasswordCredentials{
		domain:   domain,
		username: username,
		password: password,
	}
}

// Domain returns the domain name
func (c *PasswordCredentials) Domain() string {
	return c.domain
}

// Username returns the username
func (c *PasswordCredentials) Username() string {
	return c.username
}

// Password returns the password
func (c *PasswordCredentials) Password() string {
	return c.password
}

// IsHashAuth returns false for password auth
func (c *PasswordCredentials) IsHashAuth() bool {
	return false
}

// HashCredentials for pass-the-hash authentication
type HashCredentials struct {
	domain   string
	username string
	ntHash   []byte // 16-byte NT hash
}

// NewHashCredentials creates hash-based credentials
func NewHashCredentials(domain, username string, ntHash []byte) *HashCredentials {
	h := make([]byte, 16)
	copy(h, ntHash)
	return &HashCredentials{
		domain:   domain,
		username: username,
		ntHash:   h,
	}
}

// Domain returns the domain name
func (c *HashCredentials) Domain() string {
	return c.domain
}

// Username returns the username
func (c *HashCredentials) Username() string {
	return c.username
}

// NTHash returns the NT hash
func (c *HashCredentials) NTHash() []byte {
	h := make([]byte, 16)
	copy(h, c.ntHash)
	return h
}

// IsHashAuth returns true for hash auth
func (c *HashCredentials) IsHashAuth() bool {
	return true
}

// AnonymousCredentials for anonymous/guest authentication
type AnonymousCredentials struct{}

// NewAnonymousCredentials creates anonymous credentials
func NewAnonymousCredentials() *AnonymousCredentials {
	return &AnonymousCredentials{}
}

// Domain returns empty string
func (c *AnonymousCredentials) Domain() string {
	return ""
}

// Username returns empty string
func (c *AnonymousCredentials) Username() string {
	return ""
}

// IsHashAuth returns false
func (c *AnonymousCredentials) IsHashAuth() bool {
	return false
}
