package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/wishmatic/garagefront/internal/config"
)

type Server struct {
	cfg  config.Config
	http *http.Server
}

func New(cfg config.Config) *Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return &Server{
		cfg: cfg,
		http: &http.Server{
			Addr:              cfg.Addr(),
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
	}
}

func (s *Server) Run() error {
	if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}
