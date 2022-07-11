package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/JanHoffmannTU/interactsh/pkg/communication"
	"github.com/JanHoffmannTU/interactsh/pkg/server/acme"
	"github.com/JanHoffmannTU/interactsh/pkg/settings"
	"github.com/JanHoffmannTU/interactsh/pkg/storage"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
	"gopkg.in/corvus-ch/zbase32.v1"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGetURLIDComponent(t *testing.T) {
	options := Options{CorrelationIdLength: settings.CorrelationIdLengthDefault, CorrelationIdNonceLength: settings.CorrelationIdNonceLengthDefault}
	random := options.getURLIDComponent("c6rj61aciaeutn2ae680cg5ugboyyyyyn.interactsh.com")
	require.Equal(t, "c6rj61aciaeutn2ae680cg5ugboyyyyyn", random, "could not get correct component")
}

type connectionInfo struct {
	id     string
	secret string
}

func initializeRSAKeys(c *connectionInfo) ([]byte, error) {
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
		SecretKey:     c.secret,
		CorrelationID: c.id,
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

func register(server *HTTPServer, t *testing.T) *connectionInfo {
	c := &connectionInfo{secret: uuid.New().String(), id: xid.New().String()}
	payload, err := initializeRSAKeys(c)
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

	return c
}

func createAndRegister(t *testing.T) (*HTTPServer, *connectionInfo) {
	serverOptions := getServerOptions()
	server, err := NewHTTPServer(serverOptions)
	require.Nil(t, err, "could not create new http server")

	c := register(server, t)

	return server, c
}

func setDescription(desc string, server *HTTPServer, c *connectionInfo, t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/setDescription?id=%s&desc=%s", c.id, url.QueryEscape(desc)), nil)
	server.setDescriptionHandler(w, req)

	resp := w.Result()
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
			_, _ = io.Copy(ioutil.Discard, resp.Body)
		}
	}()

	require.Equal(t, 200, resp.StatusCode, "could not set description")
	response1 := make(map[string]interface{})
	err := jsoniter.NewDecoder(resp.Body).Decode(&response1)
	require.Nil(t, err, "could not decode response")
	message, ok := response1["message"]
	require.Truef(t, ok, "response had no message field")
	require.Equal(t, "setDescription successful", message, "did not receive expected message")
}

func confirmDescription(desc string, server *HTTPServer, c *connectionInfo, t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/description?id=%s", c.id), nil)
	server.descriptionHandler(w, req)

	resp := w.Result()
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
			_, _ = io.Copy(ioutil.Discard, resp.Body)
		}
	}()

	response := make([]*communication.DescriptionEntry, 0)
	jsonErr := jsoniter.NewDecoder(resp.Body).Decode(&response)
	require.Nil(t, jsonErr, "could not get descriptions from server")

	require.Equal(t, 1, len(response), "too many descriptions returned")
	require.Equal(t, desc, response[0].Description, "wrong description returned")
	require.Equal(t, c.id, response[0].CorrelationID, "wrong correlation id returned")
}

func TestDescription(t *testing.T) {
	const desc1 = "First Description"
	const desc2 = "Other Description"

	server, c := createAndRegister(t)
	setDescription(desc1, server, c, t)
	confirmDescription(desc1, server, c, t)

	c2 := register(server, t)
	setDescription(desc2, server, c2, t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/description", nil)
	server.descriptionHandler(w, req)

	resp := w.Result()
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
			_, _ = io.Copy(ioutil.Discard, resp.Body)
		}
	}()

	response := make([]*communication.DescriptionEntry, 0)
	jsonErr := jsoniter.NewDecoder(resp.Body).Decode(&response)
	require.Nil(t, jsonErr, "could not get descriptions from server")

	require.Equal(t, 2, len(response), "wrong amount of descriptions returned")

	for i := range response {
		switch response[i].CorrelationID {
		case c.id:
			require.Equal(t, desc1, response[i].Description, "wrong description returned")
		case c2.id:
			require.Equal(t, desc2, response[i].Description, "wrong description returned")
		default:
			require.Fail(t, "unexpected id in response")
		}
	}
}

func TestInteractionHandler(t *testing.T) {
	server, c := createAndRegister(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	data := make([]byte, settings.CorrelationIdNonceLengthDefault)
	_, _ = rand.Read(data)
	random := zbase32.StdEncoding.EncodeToString(data)
	req.Host = fmt.Sprintf("%s%s.local.si", c.id, random)
	logFunc := server.logger(http.HandlerFunc(server.defaultHandler))
	logFunc(w, req)

	resp := w.Result()
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
			_, _ = io.Copy(ioutil.Discard, resp.Body)
		}
	}()

	response, err := io.ReadAll(resp.Body)
	require.Nil(t, err, "could not read response")

	require.Truef(t, strings.Contains(string(response), server.options.URLReflection(fmt.Sprintf("%s%s", c.id, random))), "did not receive expected response")

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/persistent?id=%s", c.id), nil)
	server.getInteractionsHandler(w2, req2)

	resp2 := w2.Result()
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
			_, _ = io.Copy(ioutil.Discard, resp.Body)
		}
	}()

	response2 := &communication.PollResponse{}
	jsonErr := jsoniter.NewDecoder(resp2.Body).Decode(response2)
	require.Nil(t, jsonErr, "could not decode response")
	require.Equal(t, 1, len(response2.Data), "received too many results")

	interaction := &communication.Interaction{}
	err = jsoniter.Unmarshal([]byte(response2.Data[0]), interaction)
	require.Nil(t, err, "could not unmarshal interaction response")

	require.True(t, strings.HasPrefix(interaction.FullId, c.id), "incorrect id returned")
	require.True(t, strings.HasSuffix(interaction.FullId, random), "incorrect nonce returned")
}

func TestSessionList(t *testing.T) {
	server, c := createAndRegister(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/"), nil)
	desc := "example description"

	c2 := register(server, t)
	setDescription(desc, server, c2, t)

	server.getSessionList(w, req)

	resp := w.Result()
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
			_, _ = io.Copy(ioutil.Discard, resp.Body)
		}
	}()

	response := make([]*communication.SessionEntry, 0)
	jsonErr := jsoniter.NewDecoder(resp.Body).Decode(&response)
	require.Nil(t, jsonErr, "could not decode response")
	require.Equal(t, 2, len(response), "received too many results")

	for i := range response {
		require.NotEqualf(t, "", response[i].RegisterDate, "session had register date set")
		require.Equal(t, "-", response[i].DeregisterDate, "session had deregister date set")
		switch response[i].ID {
		case c.id:
			require.Equal(t, "", response[i].Description, "first session had description set")
		case c2.id:
			require.Equal(t, desc, response[i].Description, "second session had no description set")
		default:
			require.Fail(t, "unexpected element in response")
		}
	}
}
