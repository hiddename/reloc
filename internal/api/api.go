// Package api is the JSON HTTP API of relocd.
package api

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/uhiddename/reloc/internal/app"
	"github.com/uhiddename/reloc/internal/store"
	"github.com/uhiddename/reloc/internal/vpn"
	"github.com/uhiddename/reloc/internal/wg"
)

// maxRequestBody limits the size of a request body.
const maxRequestBody = 1 << 20 // 1 MiB

// New returns the API handler. Every request must carry the token as
// "Authorization: Bearer <token>". It panics on an empty token: the header
// "Bearer " would then be accepted.
func New(a *app.App, token string) http.Handler {
	if token == "" {
		panic("api: empty token")
	}
	s := &server{app: a}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/servers/{id}/clients", s.listClients)
	mux.HandleFunc("POST /api/v1/servers/{id}/clients", s.createClient)
	//mux.HandleFunc("POST /api/v1/servers/{id}/apply", s.applyServer)

	mux.HandleFunc("PATCH /api/v1/clients/{id}", s.updateClient)
	mux.HandleFunc("DELETE /api/v1/clients/{id}", s.deleteClient)
	mux.HandleFunc("GET /api/v1/clients/{id}/conf", s.clientConf)

	return logRequests(requireToken(token, mux))
}

type server struct {
	app *app.App
}

func (s *server) listClients(w http.ResponseWriter, r *http.Request) {
	serverID, err := pathID(r, "server")
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	clients, err := s.app.ListClients(r.Context(), serverID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	// make, not var: no clients must encode as [], not null
	out := make([]clientResponse, 0, len(clients))
	for _, c := range clients {
		out = append(out, newClientResponse(c))
	}
	writeJSON(w, http.StatusOK, out)
}

type createClientRequest struct {
	Name           string         `json:"name"`
	TunnelNetworks []netip.Prefix `json:"tunnel_networks"`
}

func (s *server) createClient(w http.ResponseWriter, r *http.Request) {
	serverID, err := pathID(r, "server")
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	req, err := decodeBodyInto[createClientRequest](w, r)
	if err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	client, err := s.app.CreateClient(r.Context(), serverID, req.Name, req.TunnelNetworks)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, newClientResponse(client))
}

type updateClientRequest struct {
	Enabled *bool `json:"enabled"`
}

func (s *server) updateClient(w http.ResponseWriter, r *http.Request) {
	clientID, err := pathID(r, "client")
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	req, err := decodeBodyInto[updateClientRequest](w, r)
	if err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	if req.Enabled != nil {
		if err = s.app.SetClientEnabled(r.Context(), clientID, *req.Enabled); err != nil {
			writeError(w, r, err)
			return
		}
	}
	client, err := s.app.GetClient(r.Context(), clientID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, newClientResponse(client))
}

func decodeBodyInto[T any](w http.ResponseWriter, r *http.Request) (T, error) {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	dec.DisallowUnknownFields()
	var t T
	if err := dec.Decode(&t); err != nil {
		var zero T
		return zero, err
	}
	return t, nil
}

func (s *server) deleteClient(w http.ResponseWriter, r *http.Request) {
	clientID, err := pathID(r, "client")
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	if err = s.app.DeleteClient(r.Context(), clientID); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) clientConf(w http.ResponseWriter, r *http.Request) {
	clientID, err := pathID(r, "client")
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	conf, err := s.app.ClientConf(r.Context(), clientID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	var buf bytes.Buffer
	if err = wg.Render(&buf, conf); err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if _, err = w.Write(buf.Bytes()); err != nil {
		slog.Error("write response", "err", err)
	}
}

// clientResponse is a client as the API shows it. Never encode vpn.Client
// directly: it holds the private and preshared keys.
type clientResponse struct {
	ID             int64          `json:"id"`
	ServerID       int64          `json:"server_id"`
	Name           string         `json:"name"`
	IPv4           *netip.Addr    `json:"ipv4,omitempty"`
	IPv6           *netip.Addr    `json:"ipv6,omitempty"`
	TunnelNetworks []netip.Prefix `json:"tunnel_networks"`
	Enabled        bool           `json:"enabled"`
	CreatedAt      time.Time      `json:"created_at"`
}

func newClientResponse(c vpn.Client) clientResponse {
	return clientResponse{
		ID:             c.ID,
		ServerID:       c.ServerID,
		Name:           c.Name,
		IPv4:           addrPtr(c.IPv4),
		IPv6:           addrPtr(c.IPv6),
		TunnelNetworks: c.TunnelNetworks,
		Enabled:        c.Enabled,
		CreatedAt:      c.CreatedAt,
	}
}

// addrPtr returns nil for the zero address: omitempty does not treat
// a zero netip.Addr value as empty.
func addrPtr(a netip.Addr) *netip.Addr {
	if !a.IsValid() {
		return nil
	}
	return &a
}

func pathID(r *http.Request, what string) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("%s id must be a positive number", what)
	}
	return id, nil
}

func requireToken(token string, next http.Handler) http.Handler {
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		// constant time: == would leak the token through response timing
		if subtle.ConstantTimeCompare(got, want) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, errorResponse{"unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

type errorResponse struct {
	Error string `json:"error"`
}

// statusRecorder remembers the response status for logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// Unwrap lets http.ResponseController reach the original writer.
func (w *statusRecorder) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// logRequests logs every request after it is served. It does not log headers
// or the query string: they may hold the token and other secrets.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// 200 is what net/http sends if the handler never calls WriteHeader
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration", time.Since(start).Round(time.Microsecond),
		)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// the status is already sent, all that is left is to log
		slog.Error("write response", "err", err)
	}
}

func writeBadRequest(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusBadRequest, errorResponse{msg})
}

// writeError maps err to a response. The text of an unknown error goes only
// to the log: it may reveal SQL or constraint names.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	if err, ok := errors.AsType[*vpn.ValidationError](err); ok {
		writeBadRequest(w, err.Msg)
		return
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errorResponse{"not found"})
	case errors.Is(err, store.ErrClientNameTaken):
		writeJSON(w, http.StatusConflict, errorResponse{"client name is already taken"})
	case errors.Is(err, app.ErrNetworkFull):
		writeJSON(w, http.StatusConflict, errorResponse{"network is full"})
	default:
		slog.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{"internal error"})
	}
}
