package oauthserver

import (
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
)

// Server represents the OAuth 2.1 server functionality
type Server struct {
	config *conf.GlobalConfiguration
	db     *storage.Connection
}

// NewServer creates a new OAuth server instance
func NewServer(config *conf.GlobalConfiguration, db *storage.Connection) *Server {
	return &Server{
		config: config,
		db:     db,
	}
}
