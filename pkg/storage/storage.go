// Package storage implements a encrypted storage mechanism
// for interactsh external interaction data.
package storage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/JanHoffmannTU/interactsh/pkg/communication"
	"github.com/projectdiscovery/gologger"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/goburrow/cache"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zlib"
	"github.com/pkg/errors"
)

// Storage is an storage for interactsh interaction data as well
// as correlation-id -> rsa-public-key data.
type Storage struct {
	cache           cache.Cache
	evictionTTL     time.Duration
	persistentStore map[string][]*PersistentEntry
}

type PersistentEntry struct {
	data           *CorrelationData
	registeredAt   time.Time
	deregisteredAt time.Time
	//Description of the connection
	Description string
}

// CorrelationData is the data for a correlation-id.
type CorrelationData struct {
	// data contains data for a correlation-id in AES encrypted json format.
	Data []string `json:"data"`
	// dataMutex is a mutex for the data slice.
	dataMutex *sync.Mutex
	// secretkey is a secret key for original user verification
	secretKey string
	// AESKey is the AES encryption key in encrypted format.
	AESKey string `json:"aes-key"`
	aesKey []byte // decrypted AES key for signing
}

type CacheMetrics struct {
	HitCount         uint64        `json:"hit-count"`
	MissCount        uint64        `json:"miss-count"`
	LoadSuccessCount uint64        `json:"load-success-count"`
	LoadErrorCount   uint64        `json:"load-error-count"`
	TotalLoadTime    time.Duration `json:"total-load-time"`
	EvictionCount    uint64        `json:"eviction-count"`
}

func (s *Storage) GetCacheMetrics() *CacheMetrics {
	info := &cache.Stats{}
	s.cache.Stats(info)

	return &CacheMetrics{
		HitCount:         info.HitCount,
		MissCount:        info.MissCount,
		LoadSuccessCount: info.LoadSuccessCount,
		LoadErrorCount:   info.LoadErrorCount,
		TotalLoadTime:    info.TotalLoadTime,
		EvictionCount:    info.EvictionCount,
	}
}

// GetInteractions returns the uncompressed interactions for a correlation-id
func (c *CorrelationData) GetInteractions() []string {
	c.dataMutex.Lock()
	data := c.Data
	c.Data = make([]string, 0)
	c.dataMutex.Unlock()

	return decompressData(data)
}

func decompressData(data []string) []string {
	// Decompress the data and return a new slice
	if len(data) == 0 {
		return []string{}
	}

	buf := new(strings.Builder)
	results := make([]string, len(data))

	var reader io.ReadCloser
	for i, item := range data {
		var err error

		if reader == nil {
			reader, err = zlib.NewReader(strings.NewReader(item))
		} else {
			err = reader.(zlib.Resetter).Reset(strings.NewReader(item), nil)
		}
		if err != nil {
			continue
		}
		if _, err := io.Copy(buf, reader); err != nil {
			buf.Reset()
			continue
		}
		results[i] = buf.String()
		buf.Reset()
	}
	if reader != nil {
		_ = reader.Close()
	}
	return results
}

const defaultCacheMaxSize = 2500000

// New creates a new storage instance for interactsh data.
func New(evictionTTL time.Duration) *Storage {
	return &Storage{cache: cache.New(cache.WithMaximumSize(defaultCacheMaxSize), cache.WithExpireAfterWrite(evictionTTL)), evictionTTL: evictionTTL, persistentStore: make(map[string][]*PersistentEntry)}
}

// SetIDPublicKey sets the correlation ID and publicKey into the cache for further operations.
func (s *Storage) SetIDPublicKey(correlationID, secretKey string, publicKey string, description string) error {
	// If we already have this correlation ID, return.
	_, found := s.cache.GetIfPresent(correlationID)
	if found {
		return errors.New("correlation-id provided already exists")
	}
	pValue, pFound := s.persistentStore[correlationID]
	//If there is an entry in the persistent store but not in the cache, it means the same id is being reused.
	if pFound && !found && len(pValue) > 0 {
		//If it has no unregisteredAt timing yet - for whatever reason - add one now.
		//This should not happen, however, so we log the occurrence.
		if pValue[len(pValue)-1].deregisteredAt.IsZero() {
			pValue[len(pValue)-1].deregisteredAt = time.Now()
			gologger.Warning().Msgf("Deregister Time added to %s when overwritten!", correlationID)
		}
	}
	publicKeyData, err := parseB64RSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return errors.Wrap(err, "could not read public Key")
	}
	aesKey := uuid.New().String()[:32]

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKeyData, []byte(aesKey), []byte(""))
	if err != nil {
		return errors.New("could not encrypt event data")
	}

	data := &CorrelationData{
		Data:      make([]string, 0),
		secretKey: secretKey,
		dataMutex: &sync.Mutex{},
		aesKey:    []byte(aesKey),
		AESKey:    base64.StdEncoding.EncodeToString(ciphertext),
	}
	s.cache.Put(correlationID, data)
	pData := &CorrelationData{}
	*pData = *data
	pEntry := &PersistentEntry{data: pData, registeredAt: time.Now(), Description: description}
	s.persistentStore[correlationID] = append(pValue, pEntry)
	return nil
}

func (s *Storage) SetID(ID string) error {
	data := &CorrelationData{
		Data:      make([]string, 0),
		dataMutex: &sync.Mutex{},
	}
	s.cache.Put(ID, data)

	pValue, _ := s.persistentStore[ID]
	pData := &CorrelationData{}
	*pData = *data
	pEntry := &PersistentEntry{data: pData}
	s.persistentStore[ID] = append(pValue, pEntry)

	return nil
}

func compressData(data []byte) (string, error) {
	buffer := &bytes.Buffer{}

	gz := zippers.Get().(*zlib.Writer)
	defer zippers.Put(gz)
	gz.Reset(buffer)

	if _, err := gz.Write(data); err != nil {
		_ = gz.Close()
		return "", err
	}
	_ = gz.Close()

	return buffer.String(), nil
}

// AddInteraction adds an interaction data to the correlation ID after encrypting
// it with Public Key for the provided correlation ID.
func (s *Storage) AddInteraction(correlationID string, data []byte) error {
	item, found := s.cache.GetIfPresent(correlationID)
	if !found {
		return errors.New("could not get correlation-id from cache")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return errors.New("invalid correlation-id cache value found")
	}

	pItem, pFound := s.persistentStore[correlationID]
	if !pFound || len(pItem) < 1 {
		gologger.Warning().Msgf("Interaction for ID that was logged by cache but not persistent store arrived!")
		s.persistentStore[correlationID] = append(pItem, &PersistentEntry{data: value, registeredAt: time.Now()})
	}

	ct, err := aesEncrypt(value.aesKey, data)
	if err != nil {
		return errors.Wrap(err, "could not encrypt event data")
	}
	value.dataMutex.Lock()
	value.Data = append(value.Data, ct)

	compressed, err := compressData(data)
	if err != nil {
		gologger.Error().Msgf("The data could not be compressed: %s", err)
		compressed = string(data)
	}
	pItem[len(pItem)-1].data.Data = append(pItem[len(pItem)-1].data.Data, compressed)
	value.dataMutex.Unlock()
	return nil
}

// AddInteractionWithId adds an interaction data to the id bucket
func (s *Storage) AddInteractionWithId(id string, data []byte) error {
	item, ok := s.cache.GetIfPresent(id)
	if !ok {
		return errors.New("could not get correlation-id from cache")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return errors.New("invalid correlation-id cache value found")
	}

	compressed, err := compressData(data)
	if err != nil {
		return err
	}

	value.dataMutex.Lock()
	value.Data = append(value.Data, compressed)
	//In most contexts, this is called with IDs that have nothing to do with the correlation ID, so we aren't surprised
	//if the ID is not in our persistent store
	pItem, pFound := s.persistentStore[id]
	if pFound && len(pItem) > 0 {
		pItem[len(pItem)-1].data.Data = append(pItem[len(pItem)-1].data.Data, compressed)
	}
	value.dataMutex.Unlock()
	return nil
}

// GetInteractions returns the interactions for a correlationID and removes
// it from the storage. It also returns AES Encrypted Key for the IDs.
func (s *Storage) GetInteractions(correlationID, secret string) ([]string, string, error) {
	item, ok := s.cache.GetIfPresent(correlationID)
	if !ok {
		return nil, "", errors.New("could not get correlation-id from cache")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return nil, "", errors.New("invalid correlation-id cache value found")
	}
	if !strings.EqualFold(value.secretKey, secret) {
		return nil, "", errors.New("invalid secret key passed for user")
	}
	data := value.GetInteractions()
	return data, value.AESKey, nil
}

// GetInteractions returns the interactions for a id and empty the cache
func (s *Storage) GetInteractionsWithId(id string) ([]string, error) {
	item, ok := s.cache.GetIfPresent(id)
	if !ok {
		return nil, errors.New("could not get id from cache")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return nil, errors.New("invalid id cache value found")
	}
	data := value.GetInteractions()
	return data, nil
}

// RemoveID removes data for a correlation ID and data related to it.
func (s *Storage) RemoveID(correlationID, secret string) error {
	item, ok := s.cache.GetIfPresent(correlationID)
	if !ok {
		return errors.New("could not get correlation-id from cache")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return errors.New("invalid correlation-id cache value found")
	}
	if !strings.EqualFold(value.secretKey, secret) {
		return errors.New("invalid secret key passed for deregister")
	}

	pItem, pOk := s.persistentStore[correlationID]
	if !pOk || len(pItem) < 1 {
		gologger.Warning().Msgf("CorrelationID %s has deregistered without being contained in the persistent store!\n", correlationID)
	} else {
		pItem[len(pItem)-1].deregisteredAt = time.Now()
	}

	value.dataMutex.Lock()
	value.Data = nil
	value.dataMutex.Unlock()
	s.cache.Invalidate(correlationID)
	return nil
}

// parseB64RSAPublicKeyFromPEM parses a base64 encoded rsa pem to a public key structure
func parseB64RSAPublicKeyFromPEM(pubPEM string) (*rsa.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(pubPEM)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(decoded)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}

var zippers = sync.Pool{New: func() interface{} {
	return zlib.NewWriter(nil)
}}

// aesEncrypt encrypts a message using AES and puts IV at the beginning of ciphertext.
func aesEncrypt(key []byte, message []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// It's common to put IV at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(message))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], message)

	encMessage := make([]byte, base64.StdEncoding.EncodedLen(len(cipherText)))
	base64.StdEncoding.Encode(encMessage, cipherText)

	compressed, err := compressData(encMessage)
	if err != nil {
		return "", err
	}

	return compressed, nil
}

// GetCacheItem returns an item as is
func (s *Storage) GetCacheItem(token string) (*CorrelationData, error) {
	item, ok := s.cache.GetIfPresent(token)
	if !ok {
		return nil, errors.New("cache item not found")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return nil, errors.New("cache item not found")
	}
	return value, nil
}

// GetDescription returns the description for a correlationID
func (s *Storage) GetDescription(correlationID string) (string, error) {
	item, ok := s.persistentStore[correlationID]
	if !ok {
		return "", errors.New("could not get correlation-id from cache when trying to fetch Description")
	}
	data := item[len(item)-1].Description
	if data == "" {
		data = "No Description provided!"
	}
	return data, nil
}

const YYYYMMDD = "2006-01-02"

// GetAllDescriptions returns all descriptions
func (s *Storage) GetAllDescriptions() []*communication.DescriptionEntry {
	descs := make([]*communication.DescriptionEntry, 0)
	for key, val := range s.persistentStore {
		for i := range val {
			desc := val[i].Description
			if desc == "" {
				desc = "No Description provided!"
			}
			descs = append(descs, &communication.DescriptionEntry{CorrelationID: key, Date: val[i].registeredAt.Format(YYYYMMDD), Description: desc})
		}
	}
	return descs
}

// SetDescription sets the description of an associated ID
func (s *Storage) SetDescription(correlationID string, description string) error {
	item, ok := s.persistentStore[correlationID]
	if !ok || len(item) < 1 {
		return errors.New("could not get correlation-id from cache when trying to set Description")
	}
	if item[len(item)-1].Description != "" {
		gologger.Verbose().Msgf("Description set for ID that already had an associated description")
	}
	item[len(item)-1].Description = description
	return nil
}

// GetPersistentInteractions returns the interactions for a correlationID.
// It also returns AES Encrypted Key for the IDs.
func (s *Storage) GetPersistentInteractions(correlationID string) ([]string, error) {
	item, ok := s.persistentStore[correlationID]
	if !ok || len(item) < 1 {
		return nil, errors.New("could not get correlation-id from persistent store")
	}

	value := make([]string, 0)
	for i := range item {
		value = append(value, item[i].data.Data...)
	}
	return decompressData(value), nil
}

func (s *Storage) GetRegisteredSessions(activeOnly bool, from, to time.Time, desc string) ([]*communication.SessionEntry, error) {
	if to.IsZero() {
		//Basically just an arbitrary date in the far future, ensuring the cases always pass
		to = time.Now().AddDate(100, 0, 0)
	}
	if from.After(to) {
		return nil, errors.New("The 'from' date has to be earlier than the 'to' date!")
	}
	entries := make([]*communication.SessionEntry, 0)
	for key, val := range s.persistentStore {
		for i := range val {
			registeredAt, deregisteredAt, description := val[i].registeredAt, val[i].deregisteredAt, val[i].Description
			if (!activeOnly || deregisteredAt.IsZero()) &&
				(registeredAt.Before(to) && (deregisteredAt.After(from) || (deregisteredAt.IsZero() && time.Now().After(from)))) &&
				(desc == "" || strings.Contains(strings.ToLower(description), strings.ToLower(desc))) {
				entry := &communication.SessionEntry{
					ID:             key,
					RegisterDate:   registeredAt.Format(time.RFC822),
					DeregisterDate: deregisteredAt.Format(time.RFC822),
					Description:    description,
				}
				if deregisteredAt.IsZero() {
					entry.DeregisterDate = "-"
				}
				entries = append(entries, entry)
			}
		}
	}

	return entries, nil
}
