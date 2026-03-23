package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/etsy/github-app-sts/internal/server"
	"github.com/etsy/github-app-sts/internal/server/config"
)

var configPath = flag.String("config", "", "path to config file")

func main() {
	ctx := context.Background()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(ctx, logger); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}

func run(mainCtx context.Context, logger *slog.Logger) error {
	signalCtx, stop := signal.NotifyContext(mainCtx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	flag.Parse()

	if *configPath == "" {
		return fmt.Errorf("--config-file must be set")
	}

	cfg, err := config.Load(*configPath)

	if err != nil {
		return err
	}

	httpServer, err := server.New(signalCtx, logger, cfg)

	if err != nil {
		return err
	}

	go func() {
		<-signalCtx.Done()

		shutdownCtx, cancel := context.WithTimeout(mainCtx, 30*time.Second)
		defer cancel()

		httpServer.Shutdown(shutdownCtx)
	}()

	logger.Info("starting server", "port", *cfg.Port)

	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}
