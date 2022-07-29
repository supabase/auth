package api

import (
	"context"
	"net/http"
)

func (a *API) loadSAMLState(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	state := r.FormValue("RelayState")
	if state == "" {
		return nil, badRequestError("SAML RelayState is missing")
	}

	ctx := r.Context()

	return a.loadExternalState(ctx, state)
}
