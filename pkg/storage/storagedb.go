// storage implements a encrypted memory mechanism
package storage

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"github.com/JanHoffmannTU/interactsh/pkg/communication"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/rs/xid"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"go.uber.org/multierr"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goburrow/cache"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// Storage is an storage for interactsh interaction data as well
// as correlation-id -> rsa-public-key data.
type StorageDB struct {
	Options         *Options
	cache           cache.Cache
	db              *leveldb.DB
	dbpath          string
	persistentStore map[string][]*PersistentEntry
}

// New creates a new storage instance for interactsh data.
func New(options *Options) (*StorageDB, error) {
	storageDB := &StorageDB{Options: options}
	cacheOptions := []cache.Option{
		cache.WithMaximumSize(options.MaxSize),
		cache.WithExpireAfterWrite(options.EvictionTTL),
	}
	if options.UseDisk() {
		cacheOptions = append(cacheOptions, cache.WithRemovalListener(storageDB.OnCacheRemovalCallback))
	}
	cacheDb := cache.New(cacheOptions...)
	storageDB.cache = cacheDb

	if options.UseDisk() {
		// if the path exists we create a random temporary subfolder
		if !fileutil.FolderExists(options.DbPath) {
			return nil, errors.New("folder doesn't exist")
		}
		dbpath := filepath.Join(options.DbPath, xid.New().String())

		if err := os.MkdirAll(dbpath, 0644); err != nil {
			return nil, err
		}
		levDb, err := leveldb.OpenFile(dbpath, &opt.Options{})
		if err != nil {
			return nil, err
		}
		storageDB.dbpath = dbpath
		storageDB.db = levDb
	}

	storageDB.persistentStore = make(map[string][]*PersistentEntry)

	return storageDB, nil
}

func (s *StorageDB) OnCacheRemovalCallback(key cache.Key, value cache.Value) {
	if key, ok := value.([]byte); ok {
		_ = s.db.Delete(key, &opt.WriteOptions{})
	}
}

func (s *StorageDB) GetCacheMetrics() (*CacheMetrics, error) {
	info := &cache.Stats{}
	s.cache.Stats(info)

	cacheMetrics := &CacheMetrics{
		HitCount:         info.HitCount,
		MissCount:        info.MissCount,
		LoadSuccessCount: info.LoadSuccessCount,
		LoadErrorCount:   info.LoadErrorCount,
		TotalLoadTime:    info.TotalLoadTime,
		EvictionCount:    info.EvictionCount,
	}

	return cacheMetrics, nil
}

// SetIDPublicKey sets the correlation ID and publicKey into the cache for further operations.
func (s *StorageDB) SetIDPublicKey(correlationID, secretKey, publicKey string, description string) error {
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

	publicKeyData, err := ParseB64RSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return errors.Wrap(err, "could not read public Key")
	}
	aesKey := uuid.New().String()[:32]

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKeyData, []byte(aesKey), []byte(""))
	if err != nil {
		return errors.New("could not encrypt event data")
	}

	data := &CorrelationData{
		SecretKey:       secretKey,
		AESKey:          []byte(aesKey),
		AESKeyEncrypted: base64.StdEncoding.EncodeToString(ciphertext),
	}
	s.cache.Put(correlationID, data)
	pData := &CorrelationData{}
	*pData = *data
	pEntry := &PersistentEntry{data: pData, registeredAt: time.Now(), Description: description}
	s.persistentStore[correlationID] = append(pValue, pEntry)
	return nil
}

func (s *StorageDB) SetID(ID string) error {
	data := &CorrelationData{}
	s.cache.Put(ID, data)

	pValue := s.persistentStore[ID]
	pData := &CorrelationData{}
	*pData = *data
	pEntry := &PersistentEntry{data: pData}
	s.persistentStore[ID] = append(pValue, pEntry)

	return nil
}

// AddInteraction adds an interaction data to the correlation ID after encrypting
// it with Public Key for the provided correlation ID.
func (s *StorageDB) AddInteraction(correlationID string, data []byte) error {
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

	if s.Options.UseDisk() {
		ct, err := AESEncrypt(value.AESKey, data)
		if err != nil {
			return errors.Wrap(err, "could not encrypt event data")
		}
		value.Lock()
		existingData, _ := s.db.Get([]byte(correlationID), nil)
		_ = s.db.Put([]byte(correlationID), AppendMany("\n", existingData, []byte(ct)), nil)
		pItem[len(pItem)-1].data.Data = append(pItem[len(pItem)-1].data.Data, string(data))
		value.Unlock()
	} else {
		value.Lock()
		value.Data = append(value.Data, string(data))
		pItem[len(pItem)-1].data.Data = append(pItem[len(pItem)-1].data.Data, string(data))
		value.Unlock()
	}

	return nil
}

// AddInteractionWithId adds an interaction data to the id bucket
func (s *StorageDB) AddInteractionWithId(id string, data []byte) error {
	item, ok := s.cache.GetIfPresent(id)
	if !ok {
		return errors.New("could not get correlation-id from cache")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return errors.New("invalid correlation-id cache value found")
	}

	if s.Options.UseDisk() {
		ct, err := AESEncrypt(value.AESKey, data)
		if err != nil {
			return errors.Wrap(err, "could not encrypt event data")
		}
		value.Lock()
		existingData, _ := s.db.Get([]byte(id), nil)
		_ = s.db.Put([]byte(id), AppendMany("\n", existingData, []byte(ct)), nil)

		pItem, pFound := s.persistentStore[id]
		if pFound && len(pItem) > 0 {
			pItem[len(pItem)-1].data.Data = append(pItem[len(pItem)-1].data.Data, string(data))
		}
		value.Unlock()
	} else {
		value.Lock()
		value.Data = append(value.Data, string(data))

		pItem, pFound := s.persistentStore[id]
		if pFound && len(pItem) > 0 {
			pItem[len(pItem)-1].data.Data = append(pItem[len(pItem)-1].data.Data, string(data))
		}
		value.Unlock()
	}

	return nil
}

// GetInteractions returns the interactions for a correlationID and removes
// it from the storage. It also returns AES Encrypted Key for the IDs.
func (s *StorageDB) GetInteractions(correlationID, secret string) ([]string, string, error) {
	item, ok := s.cache.GetIfPresent(correlationID)
	if !ok {
		return nil, "", errors.New("could not get correlation-id from cache")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return nil, "", errors.New("invalid correlation-id cache value found")
	}
	if !strings.EqualFold(value.SecretKey, secret) {
		return nil, "", errors.New("invalid secret key passed for user")
	}
	data, err := s.getInteractions(value, correlationID)
	return data, value.AESKeyEncrypted, err
}

// GetInteractions returns the interactions for a id and empty the cache
func (s *StorageDB) GetInteractionsWithId(id string) ([]string, error) {
	item, ok := s.cache.GetIfPresent(id)
	if !ok {
		return nil, errors.New("could not get id from cache")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return nil, errors.New("invalid id cache value found")
	}
	return s.getInteractions(value, id)
}

// RemoveID removes data for a correlation ID and data related to it.
func (s *StorageDB) RemoveID(correlationID, secret string) error {
	item, ok := s.cache.GetIfPresent(correlationID)
	if !ok {
		return errors.New("could not get correlation-id from cache")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return errors.New("invalid correlation-id cache value found")
	}
	if !strings.EqualFold(value.SecretKey, secret) {
		return errors.New("invalid secret key passed for deregister")
	}

	pItem, pOk := s.persistentStore[correlationID]
	if !pOk || len(pItem) < 1 {
		gologger.Warning().Msgf("CorrelationID %s has deregistered without being contained in the persistent store!\n", correlationID)
	} else {
		pItem[len(pItem)-1].deregisteredAt = time.Now()
	}

	value.Lock()
	value.Data = nil
	value.Unlock()
	s.cache.Invalidate(correlationID)

	if s.Options.UseDisk() {
		return s.db.Delete([]byte(correlationID), nil)
	}
	return nil
}

// GetCacheItem returns an item as is
func (s *StorageDB) GetCacheItem(token string) (*CorrelationData, error) {
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

func (s *StorageDB) getInteractions(correlationData *CorrelationData, id string) ([]string, error) {
	correlationData.Lock()
	defer correlationData.Unlock()

	switch {
	case s.Options.UseDisk():
		data, err := s.db.Get([]byte(id), nil)
		if err != nil {
			if errors.Is(err, leveldb.ErrNotFound) {
				err = nil
			}
			return nil, err
		}
		var dataString []string
		for _, d := range bytes.Split(data, []byte("\n")) {
			dataString = append(dataString, string(d))
		}
		_ = s.db.Delete([]byte(id), nil)
		return dataString, nil
	default:
		// in memory data
		var errs []error
		data := correlationData.Data
		correlationData.Data = nil
		if len(data) == 0 {
			return nil, nil
		}

		for i, dataItem := range data {
			encryptedDataItem, err := AESEncrypt(correlationData.AESKey, []byte(dataItem))
			if err != nil {
				errs = append(errs, errors.Wrap(err, "could not encrypt event data"))
				continue
			}
			data[i] = encryptedDataItem
		}
		return data, multierr.Combine(errs...)
	}
}

func (s *StorageDB) Close() error {
	var errdbClosed error
	if s.db != nil {
		errdbClosed = s.db.Close()
	}
	return multierr.Combine(
		s.cache.Close(),
		errdbClosed,
		os.RemoveAll(s.dbpath),
	)
}

// GetDescription returns the description for a correlationID
func (s *StorageDB) GetDescription(correlationID string) (string, error) {
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
func (s *StorageDB) GetAllDescriptions() []*communication.DescriptionEntry {
	descs := make([]*communication.DescriptionEntry, 0)
	for key, val := range s.persistentStore {
		for i := range val {
			if val[i].registeredAt.IsZero() {
				continue
			}
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
func (s *StorageDB) SetDescription(correlationID string, description string) error {
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
func (s *StorageDB) GetPersistentInteractions(correlationID string) ([]string, error) {
	item, ok := s.persistentStore[correlationID]
	if !ok || len(item) < 1 {
		return nil, errors.New("could not get correlation-id from persistent store")
	}

	value := make([]string, 0)
	for i := range item {
		value = append(value, item[i].data.Data...)
	}
	return value, nil
}

func (s *StorageDB) GetRegisteredSessions(activeOnly bool, from, to time.Time, desc, layout string) ([]*communication.SessionEntry, error) {
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
			if registeredAt.IsZero() {
				continue
			}

			if (!activeOnly || deregisteredAt.IsZero()) &&
				(registeredAt.Before(to) && (deregisteredAt.After(from) || (deregisteredAt.IsZero() && time.Now().After(from)))) &&
				(desc == "" || strings.Contains(strings.ToLower(description), strings.ToLower(desc))) {
				entry := &communication.SessionEntry{
					ID:             key,
					RegisterDate:   registeredAt.Format(layout),
					DeregisterDate: deregisteredAt.Format(layout),
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
