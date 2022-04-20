package api

import "net/http"

func (a *API) VerifyFactor(w http.ResponseWriter, r *http.Request) error {
	return sendJSON(w, http.StatusOK, make(map[string]string))

}

func (a *API) ChallengeFactor(w http.ResponseWriter, r *http.Request) error {
	return sendJSON(w, http.StatusOK, make(map[string]string))

}

func (a *API) EnrollFactor(w http.ResponseWriter, r *http.Request) error {
	return sendJSON(w, http.StatusOK, make(map[string]string))

}
