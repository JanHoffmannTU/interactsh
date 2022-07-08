package server

import (
	"github.com/projectdiscovery/interactsh/pkg/server/acme"
	"github.com/projectdiscovery/interactsh/pkg/storage"
	"github.com/projectdiscovery/stringsutil"
	"strings"
)

// Options contains configuration options for the servers
type Options struct {
	// Domains is the list domains for the instance.
	Domains []string
	// IPAddress is the IP address of the current server.
	IPAddress string
	// ListenIP is the IP address to listen servers on
	ListenIP string
	// DomainPort is the port to listen DNS servers on
	DnsPort int
	// HttpPort is the port to listen HTTP server on
	HttpPort int
	// HttpsPort is the port to listen HTTPS server on
	HttpsPort int
	// SmbPort is the port to listen Smb server on
	SmbPort int
	// SmtpPort is the port to listen Smtp server on
	SmtpPort int
	// SmtpsPort is the port to listen Smtps server on
	SmtpsPort int
	// SmtpAutoTLSPort is the port to listen Smtp autoTLS server on
	SmtpAutoTLSPort int
	// FtpPort is the port to listen Ftp server on
	FtpPort int
	// FtpPort is the port to listen Ftp server on
	LdapPort int
	// Hostmaster is the hostmaster email for the server.
	Hostmasters []string
	// Storage is a storage for interaction data storage
	Storage *storage.Storage
	// Auth requires client to authenticate
	Auth bool
	// Token required to retrieve interactions
	Token string
	// Enable root tld interactions
	RootTLD bool
	// OriginURL for the HTTP Server
	OriginURL string
	// FTPDirectory or temporary one
	FTPDirectory string
	// ScanEverywhere for potential correlation id
	ScanEverywhere bool
	// CorrelationIdLength of preamble
	CorrelationIdLength int
	// CorrelationIdNonceLength of the unique identifier
	CorrelationIdNonceLength int
	// Certificate Path
	CertificatePath string
	// Private Key Path
	PrivateKeyPath string
	// HTTP header containing origin IP
	OriginIPHeader string

	ACMEStore *acme.Provider
}

func (options *Options) GetIdLength() int {
	return options.CorrelationIdLength + options.CorrelationIdNonceLength
}

// URLReflection returns a reversed part of the URL payload
// which is checked in the response.
func (options *Options) URLReflection(URL string) string {
	randomID := options.getURLIDComponent(URL)

	rns := []rune(randomID)
	for i, j := 0, len(rns)-1; i < j; i, j = i+1, j-1 {
		rns[i], rns[j] = rns[j], rns[i]
	}
	return string(rns)
}

// getURLIDComponent returns the interactsh ID
func (options *Options) getURLIDComponent(URL string) string {
	parts := strings.Split(URL, ".")

	var randomID string
	for _, part := range parts {
		for scanChunk := range stringsutil.SlideWithLength(part, options.GetIdLength()) {
			if options.isCorrelationID(scanChunk) {
				randomID = part
			}
		}
	}

	return randomID
}
