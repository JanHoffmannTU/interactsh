package server

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"github.com/JanHoffmannTU/interactsh/pkg/communication"
	"github.com/rs/xid"
	"gopkg.in/corvus-ch/zbase32.v1"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/stringsutil"
)

// HTTPServer is a http server instance that listens both
// TLS and Non-TLS based servers.
type HTTPServer struct {
	options       *Options
	tlsserver     http.Server
	nontlsserver  http.Server
	customBanner  string
	staticHandler http.Handler
}

type noopLogger struct {
}

func (l *noopLogger) Write(p []byte) (n int, err error) {
	return 0, nil
}

// disableDirectoryListing disables directory listing on http.FileServer
func disableDirectoryListing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") || r.URL.Path == "" {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NewHTTPServer returns a new TLS & Non-TLS HTTP server.
func NewHTTPServer(options *Options) (*HTTPServer, error) {
	server := &HTTPServer{options: options}

	// If a static directory is specified, also serve it.
	if options.HTTPDirectory != "" {
		abs, _ := filepath.Abs(options.HTTPDirectory)
		gologger.Info().Msgf("Loading directory (%s) to serve from : %s/s/", abs, strings.Join(options.Domains, ","))
		server.staticHandler = http.StripPrefix("/s/", disableDirectoryListing(http.FileServer(http.Dir(options.HTTPDirectory))))
	}
	// If custom index, read the custom index file and serve it.
	// Supports {DOMAIN} placeholders.
	if options.HTTPIndex != "" {
		abs, _ := filepath.Abs(options.HTTPDirectory)
		gologger.Info().Msgf("Using custom server index: %s", abs)
		if data, err := ioutil.ReadFile(options.HTTPIndex); err == nil {
			server.customBanner = string(data)
		}
	}
	router := &http.ServeMux{}
	router.Handle("/", server.logger(http.HandlerFunc(server.defaultHandler)))
	router.Handle("/register", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.registerHandler))))
	router.Handle("/deregister", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.deregisterHandler))))
	router.Handle("/poll", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.pollHandler))))
	if server.options.EnableMetrics {
		router.Handle("/metrics", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.metricsHandler))))
	}
	router.Handle("/metrics", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.metricsHandler))))
	router.Handle("/description", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.descriptionHandler))))
	router.Handle("/setDescription", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.setDescriptionHandler))))
	router.Handle("/persistent", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.getInteractionsHandler))))
	router.Handle("/sessions", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.getSessionList))))
	router.Handle("/displaySessions", server.corsMiddleware(server.manualAuthMiddleware(http.HandlerFunc(server.displaySessionList))))
	router.Handle("/displayInteractions", server.corsMiddleware(server.manualAuthMiddleware(http.HandlerFunc(server.displayInteractions))))
	server.tlsserver = http.Server{Addr: options.ListenIP + fmt.Sprintf(":%d", options.HttpsPort), Handler: router, ErrorLog: log.New(&noopLogger{}, "", 0)}
	server.nontlsserver = http.Server{Addr: options.ListenIP + fmt.Sprintf(":%d", options.HttpPort), Handler: router, ErrorLog: log.New(&noopLogger{}, "", 0)}
	return server, nil
}

// ListenAndServe listens on http and/or https ports for the server.
func (h *HTTPServer) ListenAndServe(tlsConfig *tls.Config, httpAlive, httpsAlive chan bool) {
	go func() {
		if tlsConfig == nil {
			return
		}
		h.tlsserver.TLSConfig = tlsConfig

		httpsAlive <- true
		if err := h.tlsserver.ListenAndServeTLS("", ""); err != nil {
			gologger.Error().Msgf("Could not serve http on tls: %s\n", err)
			httpsAlive <- false
		}
	}()

	httpAlive <- true
	if err := h.nontlsserver.ListenAndServe(); err != nil {
		httpAlive <- false
		gologger.Error().Msgf("Could not serve http: %s\n", err)
	}
}

func (h *HTTPServer) logger(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, _ := httputil.DumpRequest(r, true)
		reqString := string(req)

		gologger.Debug().Msgf("New HTTP request: %s\n", reqString)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)

		resp, _ := httputil.DumpResponse(rec.Result(), true)
		respString := string(resp)

		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		data := rec.Body.Bytes()

		w.WriteHeader(rec.Result().StatusCode)
		_, _ = w.Write(data)

		var host string
		// Check if the client's ip should be taken from a custom header (eg reverse proxy)
		if originIP := r.Header.Get(h.options.OriginIPHeader); originIP != "" {
			host = originIP
		} else {
			host, _, _ = net.SplitHostPort(r.RemoteAddr)
		}

		// if root-tld is enabled stores any interaction towards the main domain
		if h.options.RootTLD {
			for _, domain := range h.options.Domains {
				if h.options.RootTLD && stringsutil.HasSuffixI(r.Host, domain) {
					ID := domain
					host, _, _ := net.SplitHostPort(r.RemoteAddr)
					interaction := &communication.Interaction{
						Protocol:      "http",
						UniqueID:      r.Host,
						FullId:        r.Host,
						RawRequest:    reqString,
						RawResponse:   respString,
						RemoteAddress: host,
						Timestamp:     time.Now(),
					}
					buffer := &bytes.Buffer{}
					if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
						gologger.Warning().Msgf("Could not encode root tld http interaction: %s\n", err)
					} else {
						gologger.Debug().Msgf("Root TLD HTTP Interaction: \n%s\n", buffer.String())
						if err := h.options.Storage.AddInteractionWithId(ID, buffer.Bytes()); err != nil {
							gologger.Warning().Msgf("Could not store root tld http interaction: %s\n", err)
						}
					}
				}
			}
		}

		if h.options.ScanEverywhere {
			chunks := stringsutil.SplitAny(reqString, ".\n\t\"'")
			for _, chunk := range chunks {
				for part := range stringsutil.SlideWithLength(chunk, h.options.GetIdLength()) {
					normalizedPart := strings.ToLower(part)
					if h.options.isCorrelationID(normalizedPart) {
						h.handleInteraction(normalizedPart, part, reqString, respString, host)
					}
				}
			}
		} else {
			parts := strings.Split(r.Host, ".")
			for i, part := range parts {
				for partChunk := range stringsutil.SlideWithLength(part, h.options.GetIdLength()) {
					normalizedPartChunk := strings.ToLower(partChunk)
					if h.options.isCorrelationID(normalizedPartChunk) {
						fullID := part
						if i+1 <= len(parts) {
							fullID = strings.Join(parts[:i+1], ".")
						}
						h.handleInteraction(normalizedPartChunk, fullID, reqString, respString, host)
					}
				}
			}
		}
	}
}

func (h *HTTPServer) handleInteraction(uniqueID, fullID, reqString, respString, hostPort string) {
	correlationID := uniqueID[:h.options.CorrelationIdLength]

	// host, _, _ := net.SplitHostPort(hostPort)
	interaction := &communication.Interaction{
		Protocol:      "http",
		UniqueID:      uniqueID,
		FullId:        fullID,
		RawRequest:    reqString,
		RawResponse:   respString,
		RemoteAddress: hostPort,
		Timestamp:     time.Now(),
	}
	buffer := &bytes.Buffer{}
	if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
		gologger.Warning().Msgf("Could not encode http interaction: %s\n", err)
	} else {
		gologger.Debug().Msgf("HTTP Interaction: \n%s\n", buffer.String())

		if err := h.options.Storage.AddInteraction(correlationID, buffer.Bytes()); err != nil {
			gologger.Warning().Msgf("Could not store http interaction: %s\n", err)
		}
	}
}

const banner = `<h1> Interactsh Server </h1>

<a href='https://github.com/projectdiscovery/interactsh'><b>Interactsh</b></a> is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions.<br><br>

If you notice any interactions from <b>*.%s</b> in your logs, it's possible that someone (internal security engineers, pen-testers, bug-bounty hunters) has been testing your application.<br><br>

You should investigate the sites where these interactions were generated from, and if a vulnerability exists, examine the root cause and take the necessary steps to mitigate the issue.<br><br>

<a href="/displaySessions">To Sessions List</a><br>
<a href="/displayInteractions">To Interaction List</a>

`

// defaultHandler is a handler for default collaborator requests
func (h *HTTPServer) defaultHandler(w http.ResponseWriter, req *http.Request) {
	atomic.AddUint64(&h.options.Stats.Http, 1)

	reflection := h.options.URLReflection(req.Host)
	// use first domain as default (todo: should be extracted from certificate)
	var domain string
	if len(h.options.Domains) > 0 {
		// attempts to extract the domain name from host header
		for _, configuredDomain := range h.options.Domains {
			if stringsutil.HasSuffixI(req.Host, configuredDomain) {
				domain = configuredDomain
				break
			}
		}
		// fallback to first domain in case of unknown host header
		if domain == "" {
			domain = h.options.Domains[0]
		}
	}
	w.Header().Set("Server", domain)
	w.Header().Set("X-Interactsh-Version", h.options.Version)

	if stringsutil.HasPrefixI(req.URL.Path, "/s/") && h.staticHandler != nil {
		h.staticHandler.ServeHTTP(w, req)
	} else if req.URL.Path == "/" && reflection == "" {
		if h.customBanner != "" {
			fmt.Fprint(w, strings.ReplaceAll(h.customBanner, "{DOMAIN}", domain))
		} else {
			fmt.Fprintf(w, banner, domain)
		}
	} else if strings.EqualFold(req.URL.Path, "/robots.txt") {
		fmt.Fprintf(w, "User-agent: *\nDisallow: / # %s", reflection)
	} else if stringsutil.HasSuffixI(req.URL.Path, ".json") {
		fmt.Fprintf(w, "{\"data\":\"%s\"}", reflection)
		w.Header().Set("Content-Type", "application/json")
	} else if stringsutil.HasSuffixI(req.URL.Path, ".xml") {
		fmt.Fprintf(w, "<data>%s</data>", reflection)
		w.Header().Set("Content-Type", "application/xml")
	} else {
		if h.options.DynamicResp && len(req.URL.Query()) > 0 {
			writeResponseFromDynamicRequest(w, req)
			return
		}
		fmt.Fprintf(w, "<html><head></head><body>%s</body></html>", reflection)
	}
}

// writeResponseFromDynamicRequest writes a response to http.ResponseWriter
// based on dynamic data from HTTP URL Query parameters.
//
// The following parameters are supported -
// 	body (response body)
// 	header (response header)
// 	status (response status code)
// 	delay (response time)
func writeResponseFromDynamicRequest(w http.ResponseWriter, req *http.Request) {
	values := req.URL.Query()

	if headers := values["header"]; len(headers) > 0 {
		for _, header := range headers {
			if headerParts := strings.SplitN(header, ":", 2); len(headerParts) == 2 {
				w.Header().Add(headerParts[0], headerParts[1])
			}
		}
	}
	if delay := values.Get("delay"); delay != "" {
		parsed, _ := strconv.Atoi(delay)
		time.Sleep(time.Duration(parsed) * time.Second)
	}
	if status := values.Get("status"); status != "" {
		parsed, _ := strconv.Atoi(status)
		w.WriteHeader(parsed)
	}
	if body := values.Get("body"); body != "" {
		_, _ = w.Write([]byte(body))
	}
}

// registerHandler is a handler for client register requests
func (h *HTTPServer) registerHandler(w http.ResponseWriter, req *http.Request) {
	r := &communication.RegisterRequest{}
	atomic.AddInt64(&h.options.Stats.Sessions, 1)

	if err := jsoniter.NewDecoder(req.Body).Decode(r); err != nil {
		gologger.Warning().Msgf("Could not decode json body: %s\n", err)
		jsonError(w, fmt.Sprintf("could not decode json body: %s", err), http.StatusBadRequest)
		return
	}

	corrId := r.CorrelationID
	nonce := ""

	if corrId == "" {
		corrId = xid.New().String()
		if len(corrId) > 20 {
			corrId = corrId[:20]
		}

		data := make([]byte, 13)
		_, _ = rand.Read(data)
		nonce = zbase32.StdEncoding.EncodeToString(data)
		if len(nonce) > 13 {
			nonce = nonce[:13]
		}
	}

	if err := h.options.Storage.SetIDPublicKey(corrId, r.SecretKey, r.PublicKey, r.Description); err != nil {
		gologger.Warning().Msgf("Could not set id and public key for %s: %s\n", r.CorrelationID, err)
		jsonError(w, fmt.Sprintf("could not set id and public key: %s", err), http.StatusBadRequest)
		return
	}
	if nonce == "" {
		jsonMsg(w, "registration successful", http.StatusOK)
	} else {
		type IdEntry struct {
			CorrelationID string `json:"id"`
			Nonce         string `json:"nonce"`
		}

		response := &IdEntry{CorrelationID: corrId, Nonce: nonce}

		if err := jsoniter.NewEncoder(w).Encode(response); err != nil {
			gologger.Warning().Msgf("Could not encode the Id %s/%s: %s\n", corrId, nonce, err)
			jsonError(w, fmt.Sprintf("could not encode the Id: %s", err), http.StatusBadRequest)
			return
		}
	}

	gologger.Debug().Msgf("Registered correlationID %s for key\n", r.CorrelationID)
}

// deregisterHandler is a handler for client deregister requests
func (h *HTTPServer) deregisterHandler(w http.ResponseWriter, req *http.Request) {
	atomic.AddInt64(&h.options.Stats.Sessions, -1)

	r := &communication.DeregisterRequest{}
	if err := jsoniter.NewDecoder(req.Body).Decode(r); err != nil {
		gologger.Warning().Msgf("Could not decode json body: %s\n", err)
		jsonError(w, fmt.Sprintf("could not decode json body: %s", err), http.StatusBadRequest)
		return
	}

	if err := h.options.Storage.RemoveID(r.CorrelationID, r.SecretKey); err != nil {
		gologger.Warning().Msgf("Could not remove id for %s: %s\n", r.CorrelationID, err)
		jsonError(w, fmt.Sprintf("could not remove id: %s", err), http.StatusBadRequest)
		return
	}
	jsonMsg(w, "deregistration successful", http.StatusOK)
	gologger.Debug().Msgf("Deregistered correlationID %s for key\n", r.CorrelationID)
}

// pollHandler is a handler for client poll requests
func (h *HTTPServer) pollHandler(w http.ResponseWriter, req *http.Request) {
	ID := req.URL.Query().Get("id")
	if ID == "" {
		jsonError(w, "no id specified for poll", http.StatusBadRequest)
		return
	}
	secret := req.URL.Query().Get("secret")
	if secret == "" {
		jsonError(w, "no secret specified for poll", http.StatusBadRequest)
		return
	}

	data, aesKey, err := h.options.Storage.GetInteractions(ID, secret)
	if err != nil {
		gologger.Warning().Msgf("Could not get interactions for %s: %s\n", ID, err)
		jsonError(w, fmt.Sprintf("could not get interactions: %s", err), http.StatusBadRequest)
		return
	}

	// At this point the client is authenticated, so we return also the data related to the auth token
	var tlddata, extradata []string
	if h.options.RootTLD {
		for _, domain := range h.options.Domains {
			tlddata, _ = h.options.Storage.GetInteractionsWithId(domain)
		}
		extradata, _ = h.options.Storage.GetInteractionsWithId(h.options.Token)
	}
	response := &communication.PollResponse{Data: data, AESKey: aesKey, TLDData: tlddata, Extra: extradata}

	if err := jsoniter.NewEncoder(w).Encode(response); err != nil {
		gologger.Warning().Msgf("Could not encode interactions for %s: %s\n", ID, err)
		jsonError(w, fmt.Sprintf("could not encode interactions: %s", err), http.StatusBadRequest)
		return
	}
	gologger.Debug().Msgf("Polled %d interactions for %s correlationID\n", len(data), ID)
}

func (h *HTTPServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Set CORS headers for the preflight request
		if req.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", h.options.OriginURL)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", h.options.OriginURL)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		next.ServeHTTP(w, req)
	})
}

func jsonBody(w http.ResponseWriter, key, value string, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = jsoniter.NewEncoder(w).Encode(map[string]interface{}{key: value})
}

func jsonError(w http.ResponseWriter, err string, code int) {
	jsonBody(w, "error", err, code)
}

func jsonMsg(w http.ResponseWriter, err string, code int) {
	jsonBody(w, "message", err, code)
}

func (h *HTTPServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !h.checkToken(req) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func (h *HTTPServer) checkToken(req *http.Request) bool {
	return !h.options.Auth || h.options.Auth && h.options.Token == req.Header.Get("Authorization")
}

// metricsHandler is a handler for /metrics endpoint
func (h *HTTPServer) metricsHandler(w http.ResponseWriter, req *http.Request) {
	interactMetrics := h.options.Stats
	interactMetrics.Cache = GetCacheMetrics(h.options)
	interactMetrics.Cpu = GetCpuMetrics()
	interactMetrics.Memory = GetMemoryMetrics()
	interactMetrics.Network = GetNetworkMetrics()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = jsoniter.NewEncoder(w).Encode(interactMetrics)
}

// descriptionHandler is a handler for /description endpoint
func (h *HTTPServer) descriptionHandler(w http.ResponseWriter, req *http.Request) {
	ID := req.URL.Query().Get("id")
	var entries []*communication.DescriptionEntry
	if ID == "" {
		entries = h.options.Storage.GetAllDescriptions()
	} else {
		desc, err := h.options.Storage.GetDescription(ID)
		if err != nil {
			gologger.Warning().Msgf("Could not get Description for %s: %s\n", ID, err)
			jsonError(w, fmt.Sprintf("could not get Description: %s", err), http.StatusBadRequest)
			return
		}
		entries = append(entries, &communication.DescriptionEntry{Description: desc, CorrelationID: ID})
	}

	if err := jsoniter.NewEncoder(w).Encode(entries); err != nil {
		gologger.Warning().Msgf("Could not encode description for %s: %s\n", ID, err)
		jsonError(w, fmt.Sprintf("could not encode description: %s", err), http.StatusBadRequest)
		return
	}
	gologger.Debug().Msgf("Returned Description for %s correlationID\n", ID)
}

// setDescriptionHandler is a handler for setDescription requests
func (h *HTTPServer) setDescriptionHandler(w http.ResponseWriter, req *http.Request) {
	ID, err1 := url.QueryUnescape(req.URL.Query().Get("id"))
	desc, err2 := url.QueryUnescape(req.URL.Query().Get("desc"))
	if err1 != nil || err2 != nil || ID == "" {
		gologger.Warning().Msgf("Error when reading parameters!\n")
		jsonError(w, "Error when reading parameters!", http.StatusBadRequest)
		return
	}

	if err := h.options.Storage.SetDescription(ID, desc); err != nil {
		gologger.Warning().Msgf("Could not set description for %s: %s\n", ID, err)
		jsonError(w, fmt.Sprintf("could not set id and public key: %s", err), http.StatusBadRequest)
		return
	}
	jsonMsg(w, "setDescription successful", http.StatusOK)
	gologger.Debug().Msgf("Set description %s for Correlation ID %s\n", desc, ID)
}

// getInteractionsHandler is a handler for getting the persistent interactions, regardless of cache-state
func (h *HTTPServer) getInteractionsHandler(w http.ResponseWriter, req *http.Request) {
	ID := req.URL.Query().Get("id")

	data, err := h.options.Storage.GetPersistentInteractions(ID)
	if err != nil {
		gologger.Warning().Msgf("Could not get interactions for %s: %s\n", ID, err)
		jsonError(w, fmt.Sprintf("could not get interactions: %s", err), http.StatusBadRequest)
		return
	}

	// At this point the client is authenticated, so we return also the data related to the auth token
	var tlddata, extradata []string
	if h.options.RootTLD {
		for _, domain := range h.options.Domains {
			tlddata, _ = h.options.Storage.GetPersistentInteractions(domain)
		}
		extradata, _ = h.options.Storage.GetPersistentInteractions(h.options.Token)
	}
	response := &communication.PollResponse{Data: data, TLDData: tlddata, Extra: extradata}

	if err := jsoniter.NewEncoder(w).Encode(response); err != nil {
		gologger.Warning().Msgf("Could not encode interactions for %s: %s\n", ID, err)
		jsonError(w, fmt.Sprintf("could not encode interactions: %s", err), http.StatusBadRequest)
		return
	}
	gologger.Debug().Msgf("Polled %d interactions for %s correlationID\n", len(data), ID)
}

// getSessionList is a handler for getting sessions, optionally filtered by time
func (h *HTTPServer) getSessionList(w http.ResponseWriter, req *http.Request) {
	from, _ := url.QueryUnescape(req.URL.Query().Get("from"))
	to, _ := url.QueryUnescape(req.URL.Query().Get("to"))
	desc, _ := url.QueryUnescape(req.URL.Query().Get("desc"))
	var fromTime time.Time
	var toTime time.Time
	var err error

	if from != "" {
		fromTime, err = time.Parse(communication.DateOnly, from)
		if err != nil {
			fromTime, err = time.Parse(communication.DateAndTime, from)
			if err != nil {
				gologger.Warning().Msgf("Invalid format for 'from': %s: %s\n", from, err)
				jsonError(w, fmt.Sprintf("Invalid format for 'from': %s! Please use either 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM': %s\n", from, err), http.StatusBadRequest)
				return
			}
		}
	}
	if to != "" {
		toTime, err = time.Parse(communication.DateOnly, to)
		if err != nil {
			toTime, err = time.Parse(communication.DateAndTime, to)
			if err != nil {
				gologger.Warning().Msgf("Invalid format for 'to': %s: %s\n", to, err)
				jsonError(w, fmt.Sprintf("Invalid format for 'to': %s! Please use either YYYY-MM-DD or YYYY-MM-DD HH:MM:SS: %s\n", to, err), http.StatusBadRequest)
				return
			}
		}
	}

	data, err := h.options.Storage.GetRegisteredSessions(false, fromTime, toTime, desc, time.RFC822)
	if err != nil {
		gologger.Warning().Msgf("Could not get sessions: %s\n", err)
		jsonError(w, fmt.Sprintf("could not get interactions: %s", err), http.StatusBadRequest)
		return
	}

	if err := jsoniter.NewEncoder(w).Encode(data); err != nil {
		gologger.Warning().Msgf("Could not encode sessions: %s\n", err)
		jsonError(w, fmt.Sprintf("could not encode sessions: %s", err), http.StatusBadRequest)
		return
	}
	gologger.Debug().Msgf("Polled %d sessions\n", len(data))
}

func (h *HTTPServer) queryToken(req *http.Request) bool {
	if !h.options.Auth {
		return true
	}
	//The username is ignored
	_, pass, ok := req.BasicAuth()
	//This does not permit reconstructing the password based on time differences
	//However, the size can still be recovered
	return ok && subtle.ConstantTimeCompare([]byte(pass), []byte(h.options.Token)) == 1
}

func (h *HTTPServer) manualAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !h.queryToken(req) {
			w.Header().Set("WWW-Authenticate", `Basic realm="interactsh"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorised.\n"))
			return
		}
		next.ServeHTTP(w, req)
	})
}

func (h *HTTPServer) getIds() ([]string, error) {
	sessions, err := h.options.Storage.GetRegisteredSessions(false, time.Time{}, time.Time{}, "", "")
	var ids []string
	if err != nil {
		return nil, err
	}
	for _, s := range sessions {
		ids = append(ids, s.ID)
	}

	return ids, nil
}

// displaySessionList is a handler for getting sessions, optionally filtered by time
func (h *HTTPServer) displaySessionList(w http.ResponseWriter, req *http.Request) {

	t, err := template.New("SessionList").ParseFiles("pkg/server/templates/session_list.html")
	if err != nil {
		gologger.Warning().Msgf("Could not get template: %s\n", err)
		jsonError(w, fmt.Sprintf("could not get template: %s", err), http.StatusBadRequest)
		return
	}
	sessions, err := h.options.Storage.GetRegisteredSessions(false, time.Time{}, time.Time{}, "", "02 Jan, 2006 15:04:05")
	if err != nil {
		gologger.Warning().Msgf("Could not get sessions: %s\n", err)
		jsonError(w, fmt.Sprintf("could not get interactions: %s", err), http.StatusBadRequest)
		return
	}
	type sessionList struct {
		Sessions []*communication.SessionEntry
		Auth     string
	}
	_, auth, _ := req.BasicAuth()
	data := sessionList{Sessions: sessions, Auth: auth}
	err = t.ExecuteTemplate(w, "SessionList", data)
	if err != nil {
		gologger.Warning().Msgf("Could not fill template: %s\n", err)
		jsonError(w, fmt.Sprintf("could not fill template: %s", err), http.StatusBadRequest)
		return
	}
}

// displayInteractions returns a view with
func (h *HTTPServer) displayInteractions(w http.ResponseWriter, req *http.Request) {
	t, err := template.New("InteractionList").ParseFiles("pkg/server/templates/interaction_list.html")

	type interactionList struct {
		Auth string
		IDs  []string
	}
	ids, err := h.getIds()
	if err != nil {
		gologger.Warning().Msgf("Could not get IDs: %s\n", err)
		jsonError(w, fmt.Sprintf("could not get IDs: %s", err), http.StatusBadRequest)
		return
	}
	_, auth, _ := req.BasicAuth()
	data := interactionList{Auth: auth, IDs: ids}
	err = t.ExecuteTemplate(w, "InteractionList", data)
	if err != nil {
		gologger.Warning().Msgf("Could not fill template: %s\n", err)
		jsonError(w, fmt.Sprintf("could not fill template: %s", err), http.StatusBadRequest)
		return
	}
}
