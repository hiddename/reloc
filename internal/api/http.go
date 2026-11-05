package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/uhiddename/reloc/internal/app"
	"github.com/uhiddename/reloc/internal/store"
	"github.com/uhiddename/reloc/internal/vpn"
)

// maxRequestBody limits the size of a request body.
const maxRequestBody = 1 << 20 // 1 MiB

func pathID(r *http.Request, what string) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("%s id must be a positive number", what)
	}
	return id, nil
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// the status is already sent, all that is left is to log
		slog.Error("write response", "err", err)
	}
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
	case errors.Is(err, app.ErrNoAuth):
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{"ssh key is not configured"})
	default:
		slog.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{"internal error"})
	}
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeBadRequest(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusBadRequest, errorResponse{msg})
}
