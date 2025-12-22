package auth

import (
	"fmt"

	"github.com/ineffectivecoder/gopkinit/pkg/pkinit"
)

// CertificateCredentials holds PKINIT certificate authentication material
type CertificateCredentials struct {
	domain       string
	username     string
	pfxPath      string
	pfxPassword  string
	kdcAddress   string
	pkinitClient *pkinit.PKINITClient
	tgtResult    *pkinit.TGTResult
}

// NewCertificateCredentials creates credentials from a PFX/PKCS12 certificate
func NewCertificateCredentials(pfxPath, pfxPassword, username, domain string) (*CertificateCredentials, error) {
	client, err := pkinit.NewFromPFX(pfxPath, pfxPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	return &CertificateCredentials{
		domain:       domain,
		username:     username,
		pfxPath:      pfxPath,
		pfxPassword:  pfxPassword,
		pkinitClient: client,
	}, nil
}

// Domain returns the domain/realm
func (c *CertificateCredentials) Domain() string {
	return c.domain
}

// Username returns the username
func (c *CertificateCredentials) Username() string {
	return c.username
}

// IsHashAuth returns false
func (c *CertificateCredentials) IsHashAuth() bool {
	return false
}

// IsKerberos returns true
func (c *CertificateCredentials) IsKerberos() bool {
	return true
}

// IsPKINIT returns true
func (c *CertificateCredentials) IsPKINIT() bool {
	return true
}

// SetKDC sets the KDC address for authentication
func (c *CertificateCredentials) SetKDC(kdcAddress string) {
	c.kdcAddress = kdcAddress
}

// RequestTGT requests a TGT using PKINIT
func (c *CertificateCredentials) RequestTGT() error {
	if c.pkinitClient == nil {
		return fmt.Errorf("PKINIT client not initialized")
	}

	kdcAddr := c.kdcAddress
	if kdcAddr == "" {
		// Try to discover KDC from domain
		kdcAddr = c.domain + ":88"
	}

	result, err := c.pkinitClient.GetTGT(c.domain, c.username, kdcAddr, "")
	if err != nil {
		return fmt.Errorf("PKINIT TGT request failed: %w", err)
	}

	c.tgtResult = result
	return nil
}

// SaveCCache saves the TGT to a ccache file
// Note: Use gopkinit CLI tools for ccache writing, or access TGTResult() directly
func (c *CertificateCredentials) SaveCCache(path string) error {
	if c.tgtResult == nil {
		return fmt.Errorf("no TGT available - call RequestTGT first")
	}

	// TODO: Implement ccache writing that handles the type differences
	// For now, users can use the gopkinit CLI or access the ticket directly
	return fmt.Errorf("SaveCCache not implemented - use gopkinit gettgtpkinit CLI or TGTResult() for direct access")
}

// GetASRepKey returns the AS-REP encryption key (for getNTHash attacks)
func (c *CertificateCredentials) GetASRepKey() string {
	if c.tgtResult != nil {
		return c.tgtResult.ASRepKey
	}
	return ""
}

// GetCertificateSubject returns the certificate subject
func (c *CertificateCredentials) GetCertificateSubject() string {
	if c.pkinitClient != nil && c.pkinitClient.GetCertificate() != nil {
		return c.pkinitClient.GetCertificate().Subject.CommonName
	}
	return ""
}

// GetIssuer returns the certificate issuer
func (c *CertificateCredentials) GetIssuer() string {
	if c.pkinitClient != nil {
		return c.pkinitClient.GetIssuer()
	}
	return ""
}

// TGTResult returns the raw TGT result for advanced usage
func (c *CertificateCredentials) TGTResult() *pkinit.TGTResult {
	return c.tgtResult
}
