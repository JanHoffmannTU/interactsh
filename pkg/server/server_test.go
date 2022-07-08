package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/interactsh/pkg/communication"
	"github.com/projectdiscovery/interactsh/pkg/server/acme"
	"github.com/projectdiscovery/interactsh/pkg/settings"
	"github.com/projectdiscovery/interactsh/pkg/storage"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetURLIDComponent(t *testing.T) {
	options := Options{CorrelationIdLength: settings.CorrelationIdLengthDefault, CorrelationIdNonceLength: settings.CorrelationIdNonceLengthDefault}
	random := options.getURLIDComponent("c6rj61aciaeutn2ae680cg5ugboyyyyyn.interactsh.com")
	require.Equal(t, "c6rj61aciaeutn2ae680cg5ugboyyyyyn", random, "could not get correct component")
}

func initializeRSAKeys(description string) ([]byte, error) {
	// Generate a 2048-bit private-key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Wrap(err, "could not generate rsa private key")
	}
	pub := priv.Public()

	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal public key")
	}
	pubkeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubkeyBytes,
	})

	encoded := base64.StdEncoding.EncodeToString(pubkeyPem)
	register := communication.RegisterRequest{
		PublicKey:     encoded,
		SecretKey:     uuid.New().String(),
		CorrelationID: xid.New().String(),
	}
	if description != "" {
		register.Description = description
	}
	data, err := jsoniter.Marshal(register)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal register request")
	}
	return data, nil
}

func getServerOptions() *Options {
	serverOptions := &Options{
		Domains:                  []string{"local.si"},
		ListenIP:                 "0.0.0.0",
		OriginURL:                "*",
		CorrelationIdLength:      settings.CorrelationIdLengthDefault,
		CorrelationIdNonceLength: settings.CorrelationIdNonceLengthDefault,
		DnsPort:                  53,
		HttpPort:                 80,
		HttpsPort:                443,
		SmtpPort:                 25,
		SmtpsPort:                587,
		SmtpAutoTLSPort:          465,
		LdapPort:                 389,
		SmbPort:                  445,
		FtpPort:                  21,
	}
	store := storage.New(time.Hour * 1)
	serverOptions.Storage = store

	acmeStore := acme.NewProvider()
	serverOptions.ACMEStore = acmeStore
	return serverOptions
}

func createAndRegister(description string, t *testing.T) *HTTPServer {
	serverOptions := getServerOptions()
	server, err := NewHTTPServer(serverOptions)
	require.Nil(t, err, "could not create new http server")

	payload, err := initializeRSAKeys(description)
	require.Nil(t, err, "could not create payload")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(payload))
	req.ContentLength = int64(len(payload))
	server.registerHandler(w, req)

	resp := w.Result()
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
			_, _ = io.Copy(ioutil.Discard, resp.Body)
		}
	}()

	require.Equal(t, 200, resp.StatusCode, "could not register to server")
	response := make(map[string]interface{})
	err = jsoniter.NewDecoder(resp.Body).Decode(&response)
	require.Nil(t, err, "could not decode response")
	message, ok := response["message"]
	require.Truef(t, ok, "response had no message field")
	require.Equal(t, "registration successful", message, "did not receive expected message")

	return server
}

func TestDescription(t *testing.T) {
	const desc1 = "First Description"

	_ = createAndRegister(desc1, t)
}
