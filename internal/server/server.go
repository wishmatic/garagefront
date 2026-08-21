package server

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/wishmatic/garagefront/internal/config"
	"github.com/wishmatic/garagefront/internal/cookie"
	"github.com/wishmatic/garagefront/internal/storage"
)

type ObjectStore interface {
	Get(ctx context.Context, key string) (*storage.Object, error)
}

type Server struct {
	store    ObjectStore
	verifier *cookie.Verifier
	log      *log.Logger
	tlsCert  string
	tlsKey   string
	http     *http.Server
}

func New(cfg config.Config, store ObjectStore, logger *log.Logger) *Server {
	verifier := cookie.NewVerifier(
		cfg.TrustedSigners,
		cfg.ClockSkewSeconds,
		cookie.WithPublicHost(cfg.PublicHost),
		cookie.WithForceSchemeHTTPS(cfg.ForceSchemeHTTPS),
	)

	s := &Server{
		store:    store,
		verifier: verifier,
		log:      logger,
		tlsCert:  cfg.TLSCertFile,
		tlsKey:   cfg.TLSKeyFile,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/i/", s.handleObject)
	mux.HandleFunc("/a/", s.handleObject)

	s.http = &http.Server{
		Addr:              cfg.Addr(),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return s
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleObject(w http.ResponseWriter, r *http.Request) {
	if err := s.verifier.Verify(r); err != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	key, err := storage.MapPath(r.URL.Path)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	obj, err := s.store.Get(r.Context(), key)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	defer obj.Body.Close()

	if obj.ContentType != "" {
		w.Header().Set("Content-Type", obj.ContentType)
	}
	if obj.ContentLen > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(obj.ContentLen, 10))
	}
	if obj.ETag != "" {
		w.Header().Set("ETag", obj.ETag)
	}
	if obj.LastModified != "" {
		w.Header().Set("Last-Modified", obj.LastModified)
	}

	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")

	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, obj.Body)
}

func (s *Server) writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case errors.Is(err, storage.ErrForbidden):
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	default:
		s.log.Printf("upstream storage error: %v", err)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
	}
}

func (s *Server) Run() error {
	if s.tlsCert != "" && s.tlsKey != "" {
		s.log.Printf("listening on %s (TLS)", s.http.Addr)
		err := s.http.ListenAndServeTLS(s.tlsCert, s.tlsKey)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}

	s.log.Printf("listening on %s (plain HTTP)", s.http.Addr)
	if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) Handler() http.Handler {
	return s.http.Handler
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}
