package shared

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/models"
)

func TestPaginate_Defaults(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	p, err := Paginate(r)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), p.Page)
	assert.Equal(t, uint64(DefaultPerPage), p.PerPage)
}

func TestPaginate_CustomValues(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/?page=3&per_page=10", nil)
	p, err := Paginate(r)
	require.NoError(t, err)
	assert.Equal(t, uint64(3), p.Page)
	assert.Equal(t, uint64(10), p.PerPage)
}

func TestPaginate_PageZeroIsInvalid(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/?page=0", nil)
	_, err := Paginate(r)
	assert.Error(t, err)
}

func TestPaginate_PerPageZeroIsInvalid(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/?per_page=0", nil)
	_, err := Paginate(r)
	assert.Error(t, err)
}

func TestPaginate_PerPageExceedsMaxIsInvalid(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/?per_page=10000", nil)
	_, err := Paginate(r)
	assert.Error(t, err)
}

func TestPaginate_MaxPerPageIsValid(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/?per_page=1000", nil)
	p, err := Paginate(r)
	require.NoError(t, err)
	assert.Equal(t, uint64(MaxPerPage), p.PerPage)
}

func TestAddPaginationHeaders_EmptyResultSet(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	p := &models.Pagination{Page: 1, PerPage: 50, Count: 0, ShowTotalCount: true}
	AddPaginationHeaders(w, r, p)

	link := w.Header().Get("Link")
	assert.Contains(t, link, `rel="last"`)
	// last page should be page=1 for empty results, not page=0
	assert.NotContains(t, link, "page=0")
	assert.Equal(t, "0", w.Header().Get("X-Total-Count"))
}

func TestAddPaginationHeaders_SinglePage(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	p := &models.Pagination{Page: 1, PerPage: 50, Count: 10, ShowTotalCount: true}
	AddPaginationHeaders(w, r, p)

	link := w.Header().Get("Link")
	assert.NotContains(t, link, `rel="next"`)
	assert.Contains(t, link, `rel="last"`)
}

func TestAddPaginationHeaders_MultiPage(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	p := &models.Pagination{Page: 1, PerPage: 10, Count: 25, ShowTotalCount: true}
	AddPaginationHeaders(w, r, p)

	link := w.Header().Get("Link")
	assert.Contains(t, link, `rel="next"`)
	assert.Contains(t, link, `rel="last"`)
	assert.Equal(t, "25", w.Header().Get("X-Total-Count"))
}

func TestAddPaginationHeaders_ShowTotalCountFalseOmitsHeader(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	p := &models.Pagination{Page: 1, PerPage: 10, Count: 25, ShowTotalCount: false}
	AddPaginationHeaders(w, r, p)

	assert.Empty(t, w.Header().Get("X-Total-Count"))
	// Link headers should still be computed correctly from Count
	assert.Contains(t, w.Header().Get("Link"), `rel="next"`)
	assert.Contains(t, w.Header().Get("Link"), `rel="last"`)
}
