package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goburrow/cache"
	"github.com/google/uuid"
	"github.com/karlseguin/ccache/v2"
	"github.com/klauspost/compress/zlib"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
)

func initStorage(s *Storage, desc string, t *testing.T) (string, string, *rsa.PrivateKey) {

	secret := uuid.New().String()
	correlationID := xid.New().String()

	// Generate a 2048-bit private-key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err, "could not generate rsa key")

	pub := priv.Public()

	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pub)
	require.Nil(t, err, "could not marshal public key")

	pubkeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubkeyBytes,
	})

	encoded := base64.StdEncoding.EncodeToString(pubkeyPem)

	err = s.SetIDPublicKey(correlationID, secret, encoded, desc)
	require.Nil(t, err, "could not set correlation-id and rsa public key in storage")

	return correlationID, secret, priv
}

func TestStorageSetIDPublicKey(t *testing.T) {
	storage := New(1 * time.Hour)
	desc := ""

	correlationID, secret, _ := initStorage(storage, desc, t)

	item, ok := storage.cache.GetIfPresent(correlationID)
	require.True(t, ok, "could not assert item value presence")
	require.NotNil(t, item, "could not get correlation-id item from storage")

	value, ok := item.(*CorrelationData)
	require.True(t, ok, "could not assert item value type as correlation data")

	require.Equal(t, secret, value.secretKey, "could not get correct secret key")
}

func TestStorageAddGetInteractions(t *testing.T) {
	storage := New(1 * time.Hour)
	desc := ""

	correlationID, secret, priv := initStorage(storage, desc, t)

	dataOriginal := []byte("hello world, this is unencrypted interaction")
	err := storage.AddInteraction(correlationID, dataOriginal)
	require.Nil(t, err, "could not add interaction to storage")

	data, key, err := storage.GetInteractions(correlationID, secret)
	require.Nil(t, err, "could not get interaction from storage")

	decodedKey, err := base64.StdEncoding.DecodeString(key)
	require.Nil(t, err, "could not decode key")

	// Decrypt the key plaintext first
	keyPlaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, decodedKey, nil)
	require.Nil(t, err, "could not decrypt key to plaintext")

	cipherText, err := base64.StdEncoding.DecodeString(data[0])
	require.Nil(t, err, "could not decode ciphertext")

	block, err := aes.NewCipher(keyPlaintext)
	require.Nil(t, err, "could not create aes cipher")

	if len(cipherText) < aes.BlockSize {
		require.Fail(t, "Cipher text is less than block size")
	}

	// IV is at the start of the Ciphertext
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	// XORKeyStream can work in-place if the two arguments are the same.
	stream := cipher.NewCFBDecrypter(block, iv)
	decoded := make([]byte, len(cipherText))
	stream.XORKeyStream(decoded, cipherText)

	require.Equal(t, dataOriginal, decoded, "could not get correct decrypted interaction")
}

func TestDeregister(t *testing.T) {
	storage := New(1 * time.Hour)
	desc := ""

	correlationID, secret, _ := initStorage(storage, desc, t)

	entries, err := storage.GetRegisteredSessions(false, time.Time{}, time.Time{}, "")
	require.Nil(t, err, "could not get registered sessions")

	require.Equal(t, 1, len(entries), "too many entries returned")
	require.Equal(t, "-", entries[0].DeregisterDate, "deregister date set before deregistration")
	require.NotEqual(t, "-", entries[0].RegisterDate, "register date not set")

	err = storage.RemoveID(correlationID, secret)
	require.Nil(t, err, "could not deregister connection")

	entries, err = storage.GetRegisteredSessions(false, time.Time{}, time.Time{}, "")

	require.Equal(t, 1, len(entries), "too many entries returned")
	require.NotEqual(t, "-", entries[0].DeregisterDate, "deregister date not set")
	require.NotEqual(t, "-", entries[0].RegisterDate, "register date not set")
}

func TestDeregisterRobust(t *testing.T) {
	storage := New(1 * time.Hour)
	err := storage.RemoveID("12345678901234567890", "secret")
	require.NotNil(t, err, "was able to deregister non-existent connection!")

	correlationID, _, _ := initStorage(storage, "", t)
	err = storage.RemoveID(correlationID, "false")
	require.NotNil(t, err, "was able to deregister with wrong secret!")
}

func TestGetInteractions(t *testing.T) {
	compressZlib := func(data string) string {
		var builder strings.Builder
		writer := zlib.NewWriter(&builder)
		_, _ = writer.Write([]byte(data))
		writer.Close()
		return builder.String()
	}
	data := &CorrelationData{
		dataMutex: &sync.Mutex{},
		Data:      []string{compressZlib("test"), compressZlib("another")},
	}
	decompressed := data.GetInteractions()
	require.ElementsMatch(t, []string{"test", "another"}, decompressed, "could not get correct decompressed list")
}

func TestDescription(t *testing.T) {
	storage := New(1 * time.Hour)
	oldDesc := "Initial Description"

	correlationID, _, _ := initStorage(storage, oldDesc, t)

	description, err := storage.GetDescription(correlationID)
	require.Nil(t, err, "could not get initial description")
	require.Equal(t, oldDesc, description, "could not get correct initial description")

	newDesc := "Updated Description"
	err = storage.SetDescription(correlationID, newDesc)
	require.Nil(t, err, "Could not set updated description!")

	description, err = storage.GetDescription(correlationID)
	require.Nil(t, err, "could not get updated description")
	require.Equal(t, newDesc, description, "could not get correct updated description")

	//Setting up a lot of new connections to check a large retrieval
	desc1 := "Description 1"
	desc2 := "Description 2"
	desc3 := "Description 3"
	correlationID1, _, _ := initStorage(storage, desc1, t)
	correlationID2, _, _ := initStorage(storage, desc2, t)
	correlationID3, _, _ := initStorage(storage, desc3, t)

	descs := storage.GetAllDescriptions()
	date := time.Now().Format(YYYYMMDD)

	require.Equal(t, 4, len(descs), "too many entries in description list")

	for i := range descs {
		desc := descs[i]
		require.Equal(t, date, desc.Date, "dates did not match!")
		switch desc.CorrelationID {
		case correlationID:
			require.Equal(t, newDesc, desc.Description, "non-matching description for updated session")
		case correlationID1:
			require.Equal(t, desc1, desc.Description, "non-matching description 1")
		case correlationID2:
			require.Equal(t, desc2, desc.Description, "non-matching description 2")
		case correlationID3:
			require.Equal(t, desc3, desc.Description, "non-matching description 3")
		default:
			require.Fail(t, "Unexpected ID %s", desc.CorrelationID)
		}
	}

	correlationID4, _, _ := initStorage(storage, "", t)
	description, err = storage.GetDescription(correlationID4)
	require.Nil(t, err, "could not get initial description")
	require.Equal(t, "No Description provided!", description, "incorrect empty description message")
}

func TestDescriptionRobust(t *testing.T) {
	storage := New(1 * time.Hour)
	ret, err := storage.GetDescription("12345678901234567890")
	require.NotNil(t, err, "Was able to retrieve description of non-existent connection")
	require.Equal(t, "", ret, "returned value despite raising error")
	err = storage.SetDescription("12345678901234567890", "")
	require.NotNil(t, err, "Was able to set description of non-existent connection")
}

func TestPersistentInteractions(t *testing.T) {
	//We set a very fast timeout becaues the entire point of the persistent store is to not be affected by it
	storage := New(1 * time.Second)

	correlationID, secret, _ := initStorage(storage, "", t)

	msg1 := []byte("Message 1")
	msg2 := []byte("Message 2")
	msg3 := []byte("Message 3")
	err := storage.AddInteraction(correlationID, msg1)
	require.Nil(t, err, "could not add interaction to storage")
	err = storage.AddInteraction(correlationID, msg2)
	require.Nil(t, err, "could not add interaction to storage")
	err = storage.AddInteraction(correlationID, msg3)
	require.Nil(t, err, "could not add interaction to storage")

	interactions, err := storage.GetPersistentInteractions(correlationID)
	require.Nil(t, err, "could not get persistent interactions")

	require.Equal(t, 3, len(interactions), "too many interactions were fetched")
	for i := range interactions {
		switch interactions[i] {
		case string(msg1):
		case string(msg2):
		case string(msg3):
		default:
			require.Fail(t, "Unexpected interaction in the message store!")
		}
	}

	err = storage.RemoveID(correlationID, secret)
	require.Nil(t, err, "could not deregister connection")

	//Due to being persistent, the same data should be returned even after being fetched once already + after being deregistered
	interactions, err = storage.GetPersistentInteractions(correlationID)
	require.Nil(t, err, "could not get persistent interactions")

	require.Equal(t, 3, len(interactions), "too many interactions were fetched")
	for i := range interactions {
		switch interactions[i] {
		case string(msg1):
		case string(msg2):
		case string(msg3):
		default:
			require.Fail(t, "Unexpected interaction in the message store!")
		}
	}
}

func TestPersistentInteractionsRobust(t *testing.T) {
	storage := New(1 * time.Hour)
	err := storage.AddInteraction("12345678901234567890", []byte(""))
	require.NotNil(t, err, "was able to add interaction to non-existent connection!")

	ret, err := storage.GetPersistentInteractions("12345678901234567890")
	require.NotNil(t, err, "was able to get interactions from non-existent connection!")
	require.Nil(t, ret, "returned value despite raising error")
}

func TestRegisteredSessionList(t *testing.T) {
	storage := New(1 * time.Hour)

	desc1 := "[TAG] Description"
	desc2 := "Other Description"
	correlationID1, secret1, _ := initStorage(storage, desc1, t)
	correlationID2, _, _ := initStorage(storage, desc2, t)

	err := storage.RemoveID(correlationID1, secret1)
	require.Nil(t, err, "could not deregister connection")

	var from, to time.Time

	entries, err := storage.GetRegisteredSessions(false, from, to, "")
	require.Nil(t, err, "could not get registered sessions")

	require.Equal(t, 2, len(entries), "too many entries returned")
	for i := range entries {
		entry := entries[i]
		switch entry.ID {
		case correlationID1:
			require.Equal(t, desc1, entry.Description, "wrong id-description pair")
		case correlationID2:
			require.Equal(t, desc2, entry.Description, "wrong id-description pair")
		default:
			require.Fail(t, "unexpected ID found in entries")
		}
	}

	entries, err = storage.GetRegisteredSessions(true, from, to, "")
	require.Nil(t, err, "could not get registered sessions")

	require.Equal(t, 1, len(entries), "too many entries returned")
	require.Equal(t, correlationID2, entries[0].ID, "wrong id for active-only query")
	require.Equal(t, desc2, entries[0].Description, "wrong description for active-only query")

	entries, err = storage.GetRegisteredSessions(false, from, to, "tag")
	require.Nil(t, err, "could not get registered sessions")

	require.Equal(t, 1, len(entries), "too many entries returned")
	require.Equal(t, correlationID1, entries[0].ID, "wrong id for desc-filtered query")
	require.Equal(t, desc1, entries[0].Description, "wrong description for desc-filtered query")

	from = time.Now().AddDate(1, 0, 0)
	entries, err = storage.GetRegisteredSessions(false, from, to, "")
	require.Nil(t, err, "could not get registered sessions")

	require.Equal(t, 0, len(entries), "too many entries returned")
}

func TestRegisteredSessionRobust(t *testing.T) {
	storage := New(1 * time.Hour)
	ret, err := storage.GetRegisteredSessions(false, time.Now().Add(10*time.Hour), time.Now(), "")
	require.NotNil(t, err, "was able to get sessions with nonsensical times!")
	require.Nil(t, ret, "returned value despite raising error")
}

func BenchmarkCacheParallel(b *testing.B) {
	config := ccache.Configure().MaxSize(defaultCacheMaxSize).Buckets(64).GetsPerPromote(10).PromoteBuffer(4096)
	cache := ccache.New(config)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			doStuffWithCache(cache)
		}
	})
}

func BenchmarkCacheParallelOther(b *testing.B) {
	cache := cache.New(cache.WithMaximumSize(defaultCacheMaxSize), cache.WithExpireAfterWrite(24*7*time.Hour))

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			doStuffWithOtherCache(cache)
		}
	})
}

func doStuffWithCache(cache *ccache.Cache) {
	for i := 0; i < 1e2; i++ {
		cache.Set(strconv.Itoa(i), "test", 1*time.Minute)
		_ = cache.Get(strconv.Itoa(i))
	}
}

func doStuffWithOtherCache(cache cache.Cache) {
	for i := 0; i < 1e2; i++ {
		cache.Put(strconv.Itoa(i), "test")
		_, _ = cache.GetIfPresent(strconv.Itoa(i))
	}
}
