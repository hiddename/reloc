// Package api is the JSON HTTP API of relocd.
package api

import (
	"context"
	"net/http"
	"time"

	"github.com/uhiddename/reloc/internal/app"
)

// applyTimeout also limits how long a hung host can hold the server's lock.
const applyTimeout = time.Minute

type server struct {
	app *app.App
}

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
	mux.HandleFunc("POST /api/v1/servers/{id}/apply", s.applyServer)

	mux.HandleFunc("PATCH /api/v1/clients/{id}", s.updateClient)
	mux.HandleFunc("DELETE /api/v1/clients/{id}", s.deleteClient)
	mux.HandleFunc("GET /api/v1/clients/{id}/conf", s.clientConf)

	return logRequests(requireToken(token, mux))
}

type applyResponse struct {
	Action string `json:"action"`
}

func (s *server) applyServer(w http.ResponseWriter, r *http.Request) {
	serverID, err := pathID(r, "server")
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), applyTimeout)
	defer cancel()
	action, err := s.app.ApplyServer(ctx, serverID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, applyResponse{Action: action.String()})
}
