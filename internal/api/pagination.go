package api

import (
	"net/http"

	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
)

func addPaginationHeaders(w http.ResponseWriter, r *http.Request, p *models.Pagination) {
	shared.AddPaginationHeaders(w, r, p)
}

func paginate(r *http.Request) (*models.Pagination, error) {
	return shared.Paginate(r)
}
