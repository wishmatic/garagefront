package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/wishmatic/garagefront/internal/config"
	"github.com/wishmatic/garagefront/internal/server"
	"github.com/wishmatic/garagefront/internal/storage"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	store := storage.NewClient(
		cfg.S3Endpoint,
		cfg.S3Bucket,
		cfg.S3Region,
		cfg.S3AccessKey,
		cfg.S3SecretKey,
	)

	logger := log.New(os.Stderr, "", log.LstdFlags)

	srv := server.New(cfg, store, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Run()
	}()

	select {
	case err := <-errCh:
		if err != nil {
			log.Fatalf("server failed: %v", err)
		}
	case <-ctx.Done():
		log.Println("shutdown signal received")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			log.Printf("graceful shutdown failed: %v", err)
		}
	}

	log.Println("server stopped")
}
