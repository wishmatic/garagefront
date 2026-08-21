package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"log/slog"
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
	store            ObjectStore
	verifier         *cookie.Verifier
	log              *log.Logger
	tlsCert          string
	tlsKey           string
	maxResponseBytes int64
	http             *http.Server
}

func New(cfg config.Config, store ObjectStore, logger *log.Logger) *Server {
	verifier := cookie.NewVerifier(
		cfg.TrustedSigners,
		cfg.ClockSkewSeconds,
		cookie.WithPublicHost(cfg.PublicHost),
		cookie.WithForceSchemeHTTPS(cfg.ForceSchemeHTTPS),
		cookie.WithLogger(slog.New(slog.NewTextHandler(logger.Writer(), nil))),
	)

	s := &Server{
		store:            store,
		verifier:         verifier,
		log:              logger,
		tlsCert:          cfg.TLSCertFile,
		tlsKey:           cfg.TLSKeyFile,
		maxResponseBytes: cfg.MaxResponseBytes,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/i/", s.handleObject)
	mux.HandleFunc("/a/", s.handleObject)

	s.http = &http.Server{
		Addr:              cfg.Addr(),
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,

		// Cap header size to bound base64-decoding of oversized cookies before signature verification.

		MaxHeaderBytes: 64 << 10,
		TLSConfig: &tls.Config{
			// Require TLS 1.2+ when serving TLS directly. Go's default cipher suites for TLS 1.2 already exclude
			// all non-AEAD ciphers, so no explicit list is needed.

			MinVersion: tls.VersionTLS12,
		},
	}

	return s
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleObject(w http.ResponseWriter, r *http.Request) {
	if err := s.verifier.Verify(r); err != nil {
		s.log.Printf("forbidden: path=%q host=%q err=%v", r.URL.Path, r.Host, err)
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

	// Refuse known-oversized objects before committing to a response.

	if s.maxResponseBytes > 0 && obj.ContentLen > s.maxResponseBytes {
		s.log.Printf("object %q is %d bytes, exceeding max response size %d", key, obj.ContentLen, s.maxResponseBytes)
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)

		return
	}

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
	if s.maxResponseBytes > 0 {
		// Bound the streamed body as defense-in-depth. Known lengths are rejected above; for
		// chunked/unknown-length responses we probe one byte past the limit so an oversized object
		// is detected and the connection aborted rather than silently truncated.

		n, _ := io.Copy(w, io.LimitReader(obj.Body, s.maxResponseBytes))
		if n == s.maxResponseBytes {
			var extra [1]byte
			if m, _ := obj.Body.Read(extra[:]); m > 0 {
				s.log.Printf("object %q exceeded max response size %d mid-stream; aborting", key, s.maxResponseBytes)
				panic(http.ErrAbortHandler)
			}
		}
	} else {
		_, _ = io.Copy(w, obj.Body)
	}
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
