package communication

import "time"

// Interaction is an interaction received to the server.
type Interaction struct {
	// Protocol for interaction, can contains HTTP/DNS/SMTP,etc.
	Protocol string `json:"protocol"`
	// UniqueID is the uniqueID for the subdomain receiving the interaction.
	UniqueID string `json:"unique-id"`
	// FullId is the full path for the subdomain receiving the interaction.
	FullId string `json:"full-id"`
	// QType is the question type for the interaction
	QType string `json:"q-type,omitempty"`
	// RawRequest is the raw request received by the interactsh server.
	RawRequest string `json:"raw-request,omitempty"`
	// RawResponse is the raw response sent by the interactsh server.
	RawResponse string `json:"raw-response,omitempty"`
	// SMTPFrom is the mail form field
	SMTPFrom string `json:"smtp-from,omitempty"`
	// RemoteAddress is the remote address for interaction
	RemoteAddress string `json:"remote-address"`
	// Timestamp is the timestamp for the interaction
	Timestamp time.Time `json:"timestamp"`
}

// RegisterRequest is a request for client registration to interactsh server.
type RegisterRequest struct {
	// PublicKey is the public RSA Key of the client.
	PublicKey string `json:"public-key"`
	// SecretKey is the secret-key for correlation ID registered for the client.
	SecretKey string `json:"secret-key"`
	// CorrelationID is an ID for correlation with requests.
	CorrelationID string `json:"correlation-id"`
	//Description is a String describing the context of the connection.
	Description string `json:"description"`
}

// DeregisterRequest is a request for client deregistration to interactsh server.
type DeregisterRequest struct {
	// CorrelationID is an ID for correlation with requests.
	CorrelationID string `json:"correlation-id"`
	// SecretKey is the secretKey for the interactsh client.
	SecretKey string `json:"secret-key"`
}

// PollResponse is the response for a polling request
type PollResponse struct {
	Data    []string `json:"data"`
	Extra   []string `json:"extra"`
	AESKey  string   `json:"aes_key,omitempty"`
	TLDData []string `json:"tlddata,omitempty"`
}

type DescriptionEntry struct {
	CorrelationID string `json:"id"`
	Date          string `json:"date"`
	Description   string `json:"desc"`
}

type SessionEntry struct {
	ID             string `json:"id"`
	RegisterDate   string `json:"registeredAt"`
	DeregisterDate string `json:"deregisteredAt"`
	Description    string `json:"description"`
}

const DateOnly = "2006-01-02"
const DateAndTime = "2006-01-02 15:04"
