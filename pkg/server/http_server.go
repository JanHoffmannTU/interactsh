package server

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"github.com/JanHoffmannTU/interactsh/pkg/communication"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/stringsutil"
)

// HTTPServer is a http server instance that listens both
// TLS and Non-TLS based servers.
type HTTPServer struct {
	options      *Options
	tlsserver    http.Server
	nontlsserver http.Server
}

type noopLogger struct {
}

func (l *noopLogger) Write(p []byte) (n int, err error) {
	return 0, nil
}

// NewHTTPServer returns a new TLS & Non-TLS HTTP server.
func NewHTTPServer(options *Options) (*HTTPServer, error) {
	server := &HTTPServer{options: options}

	router := &http.ServeMux{}
	router.Handle("/", server.logger(http.HandlerFunc(server.defaultHandler)))
	router.Handle("/register", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.registerHandler))))
	router.Handle("/deregister", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.deregisterHandler))))
	router.Handle("/poll", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.pollHandler))))
	router.Handle("/metrics", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.metricsHandler))))
	router.Handle("/description", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.descriptionHandler))))
	router.Handle("/setDescription", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.setDescriptionHandler))))
	router.Handle("/persistent", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.getInteractionsHandler))))
	router.Handle("/sessions", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.getSessionList))))
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

You should investigate the sites where these interactions were generated from, and if a vulnerability exists, examine the root cause and take the necessary steps to mitigate the issue.
`

// defaultHandler is a handler for default collaborator requests
func (h *HTTPServer) defaultHandler(w http.ResponseWriter, req *http.Request) {
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

	if req.URL.Path == "/" && reflection == "" {
		fmt.Fprintf(w, banner, domain)
	} else if strings.EqualFold(req.URL.Path, "/robots.txt") {
		fmt.Fprintf(w, "User-agent: *\nDisallow: / # %s", reflection)
	} else if stringsutil.HasSuffixI(req.URL.Path, ".json") {
		fmt.Fprintf(w, "{\"data\":\"%s\"}", reflection)
		w.Header().Set("Content-Type", "application/json")
	} else if stringsutil.HasSuffixI(req.URL.Path, ".xml") {
		fmt.Fprintf(w, "<data>%s</data>", reflection)
		w.Header().Set("Content-Type", "application/xml")
	} else {
		fmt.Fprintf(w, "<html><head></head><body>%s</body></html>", reflection)
	}
}

// registerHandler is a handler for client register requests
func (h *HTTPServer) registerHandler(w http.ResponseWriter, req *http.Request) {
	r := &communication.RegisterRequest{}
	if err := jsoniter.NewDecoder(req.Body).Decode(r); err != nil {
		gologger.Warning().Msgf("Could not decode json body: %s\n", err)
		jsonError(w, fmt.Sprintf("could not decode json body: %s", err), http.StatusBadRequest)
		return
	}

	if err := h.options.Storage.SetIDPublicKey(r.CorrelationID, r.SecretKey, r.PublicKey, r.Description); err != nil {
		gologger.Warning().Msgf("Could not set id and public key for %s: %s\n", r.CorrelationID, err)
		jsonError(w, fmt.Sprintf("could not set id and public key: %s", err), http.StatusBadRequest)
		return
	}
	jsonMsg(w, "registration successful", http.StatusOK)
	gologger.Info().Msgf("Registered correlationID %s for key\n", r.CorrelationID)
}

// deregisterHandler is a handler for client deregister requests
func (h *HTTPServer) deregisterHandler(w http.ResponseWriter, req *http.Request) {
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
	metrics := h.options.Storage.GetCacheMetrics()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = jsoniter.NewEncoder(w).Encode(metrics)
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
		jsonError(w, fmt.Sprintf("Error when reading parameters!"), http.StatusBadRequest)
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

const dateOnly = "2006-01-02"
const dateAndTime = "2006-01-02 15:04"

// getSessionList is a handler for getting sessions, optionally filtered by time
func (h *HTTPServer) getSessionList(w http.ResponseWriter, req *http.Request) {
	from, _ := url.QueryUnescape(req.URL.Query().Get("from"))
	to, _ := url.QueryUnescape(req.URL.Query().Get("to"))
	desc, _ := url.QueryUnescape(req.URL.Query().Get("desc"))
	var fromTime time.Time
	var toTime time.Time
	var err error

	if from != "" {
		fromTime, err = time.Parse(dateOnly, from)
		if err != nil {
			fromTime, err = time.Parse(dateAndTime, from)
			if err != nil {
				gologger.Warning().Msgf("Invalid format for 'from': %s: %s\n", from, err)
				jsonError(w, fmt.Sprintf("Invalid format for 'from': %s! Please use either 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM': %s\n", from, err), http.StatusBadRequest)
				return
			}
		}
	}
	if to != "" {
		toTime, err = time.Parse(dateOnly, to)
		if err != nil {
			toTime, err = time.Parse(dateAndTime, to)
			if err != nil {
				gologger.Warning().Msgf("Invalid format for 'to': %s: %s\n", to, err)
				jsonError(w, fmt.Sprintf("Invalid format for 'to': %s! Please use either YYYY-MM-DD or YYYY-MM-DD HH:MM:SS: %s\n", to, err), http.StatusBadRequest)
				return
			}
		}
	}

	data, err := h.options.Storage.GetRegisteredSessions(false, fromTime, toTime, desc)
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
