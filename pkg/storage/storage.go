// storage defines a storage mechanism
package storage

import (
	"github.com/JanHoffmannTU/interactsh/pkg/communication"
	"time"
)

type Storage interface {
	GetCacheMetrics() (*CacheMetrics, error)
	SetIDPublicKey(correlationID, secretKey, publicKey, description string) error
	SetID(ID string) error
	AddInteraction(correlationID string, data []byte) error
	AddInteractionWithId(id string, data []byte) error
	GetInteractions(correlationID, secret string) ([]string, string, error)
	GetInteractionsWithId(id string) ([]string, error)
	RemoveID(correlationID, secret string) error
	GetCacheItem(token string) (*CorrelationData, error)
	Close() error
	GetDescription(correlationID string) (string, error)
	GetAllDescriptions() []*communication.DescriptionEntry
	SetDescription(correlationID string, description string) error
	GetPersistentInteractions(correlationID string) ([]string, error)
	GetRegisteredSessions(activeOnly bool, from, to time.Time, desc, layout string) ([]*communication.SessionEntry, error)
}
