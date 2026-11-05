package api

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/uhiddename/reloc/internal/vpn"
	"github.com/uhiddename/reloc/internal/wg"
)

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

// addrPtr returns nil for the zero address: omitempty does not treat
// a zero netip.Addr value as empty.
func addrPtr(a netip.Addr) *netip.Addr {
	if !a.IsValid() {
		return nil
	}
	return &a
}
