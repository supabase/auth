package scim

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
)

type ResourceSpec[T core.Resource] struct {
	Path     string
	Schema   *core.Schema
	New      func() T
	Validate func(T) *protocol.Error
	Location func(T) string
}

type ResourceServer[T core.Resource] struct {
	limits protocol.Limits
	svc    Service[T]
	spec   ResourceSpec[T]
}

func NewResourceServer[T core.Resource](limits protocol.Limits, svc Service[T], spec ResourceSpec[T]) *ResourceServer[T] {
	return &ResourceServer[T]{limits: limits, svc: svc, spec: spec}
}

func (s *ResourceServer[T]) List(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	query, err := s.limits.ParseSearchRequest(r.URL.Query())
	if err != nil {
		return protocol.SendError(w, err)
	}

	items, total, err := s.svc.List(ctx, query)
	if err != nil {
		return sendError(w, r, err)
	}

	return protocol.Send(w, http.StatusOK, protocol.NewListResponse(query.StartIndex, total, items))
}

func (s *ResourceServer[T]) ByID(w http.ResponseWriter, r *http.Request) error {
	id, ok := resourceID(r)
	if !ok {
		return NotFound(w, r)
	}

	item, err := s.svc.Get(r.Context(), id)
	if err != nil {
		return notFoundOr(w, r, err)
	}

	return protocol.Send(w, http.StatusOK, item)
}

func (s *ResourceServer[T]) Create(w http.ResponseWriter, r *http.Request) error {
	item, err := s.decode(r)
	if err != nil {
		return protocol.SendError(w, err)
	}
	if err := s.spec.Validate(item); err != nil {
		return protocol.SendError(w, err)
	}

	created, err := s.svc.Create(r.Context(), item)
	if err != nil {
		return sendError(w, r, err)
	}

	w.Header().Set("Location", s.spec.Location(created))
	return protocol.Send(w, http.StatusCreated, created)
}

func (s *ResourceServer[T]) Replace(w http.ResponseWriter, r *http.Request) error {
	id, ok := resourceID(r)
	if !ok {
		return NotFound(w, r)
	}

	item, err := s.decode(r)
	if err != nil {
		return protocol.SendError(w, err)
	}
	if err := s.spec.Validate(item); err != nil {
		return protocol.SendError(w, err)
	}

	replaced, err := s.svc.Replace(r.Context(), id, item)
	if err != nil {
		return notFoundOr(w, r, err)
	}

	return protocol.Send(w, http.StatusOK, replaced)
}

func (s *ResourceServer[T]) Delete(w http.ResponseWriter, r *http.Request) error {
	id, ok := resourceID(r)
	if !ok {
		return NotFound(w, r)
	}

	if err := s.svc.Delete(r.Context(), id); err != nil {
		return notFoundOr(w, r, err)
	}

	return protocol.Send(w, http.StatusNoContent, nil)
}

func (s *ResourceServer[T]) decode(r *http.Request) (T, error) {
	item := s.spec.New()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return item, protocol.ErrTooLarge("the request body is too large")
		}
		return item, protocol.ErrInvalidSyntax("could not read the request body")
	}

	if err := json.Unmarshal(body, item); err != nil {
		return item, protocol.ErrInvalidSyntax("request body is not a valid " + string(s.spec.Schema.Name))
	}
	return item, nil
}

func resourceID(r *http.Request) (string, bool) {
	id, err := uuid.FromString(urlParam(r, "id"))
	if err != nil {
		return "", false
	}
	return id.String(), true
}

func notFoundOr(w http.ResponseWriter, r *http.Request, err error) error {
	if errors.Is(err, ErrNotFound) {
		return NotFound(w, r)
	}
	return sendError(w, r, err)
}
