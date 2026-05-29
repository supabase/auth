package shared

import (
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"

	"github.com/supabase/auth/internal/models"
)

const DefaultPerPage = 50
const MaxPerPage = 1000

func calculateTotalPages(perPage, total uint64) uint64 {
	pages := total / perPage
	if total%perPage > 0 {
		return pages + 1
	}
	return pages
}

func AddPaginationHeaders(w http.ResponseWriter, r *http.Request, p *models.Pagination) {
	totalPages := max(calculateTotalPages(p.PerPage, p.Count), 1)
	u, _ := url.ParseRequestURI(r.URL.String())
	query := u.Query()
	header := ""
	if totalPages > p.Page {
		query.Set("page", fmt.Sprintf("%v", p.Page+1))
		u.RawQuery = query.Encode()
		header += "<" + u.String() + ">; rel=\"next\", "
	}
	query.Set("page", fmt.Sprintf("%v", totalPages))
	u.RawQuery = query.Encode()
	header += "<" + u.String() + ">; rel=\"last\""

	w.Header().Add("Link", header)
	if p.ShowTotalCount {
		w.Header().Add("X-Total-Count", fmt.Sprintf("%v", p.Count))
	}
}

func Paginate(r *http.Request) (*models.Pagination, error) {
	params := r.URL.Query()
	queryPage := params.Get("page")
	queryPerPage := params.Get("per_page")
	var page uint64 = 1
	var perPage uint64 = DefaultPerPage
	var err error
	if queryPage != "" {
		page, err = strconv.ParseUint(queryPage, 10, 64)
		if err != nil {
			return nil, err
		}
		if page == 0 {
			return nil, fmt.Errorf("page must be greater than 0")
		}
		if page > math.MaxInt32 {
			return nil, fmt.Errorf("page exceeds maximum allowed value")
		}
	}
	if queryPerPage != "" {
		perPage, err = strconv.ParseUint(queryPerPage, 10, 64)
		if err != nil {
			return nil, err
		}
		if perPage == 0 {
			return nil, fmt.Errorf("per_page must be greater than 0")
		}
		if perPage > MaxPerPage {
			return nil, fmt.Errorf("per_page must not exceed %d", MaxPerPage)
		}
	}

	return &models.Pagination{
		Page:    page,
		PerPage: perPage,
	}, nil
}
