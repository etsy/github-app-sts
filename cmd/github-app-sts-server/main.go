package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/ericnorris/github-app-sts/internal/server"
	"github.com/ericnorris/github-app-sts/internal/server/config"
	"github.com/ericnorris/github-app-sts/internal/server/github"
	"github.com/ericnorris/github-app-sts/internal/server/github/appkey"
	"github.com/ericnorris/github-app-sts/internal/server/oidc"
	"github.com/ericnorris/github-app-sts/internal/server/policy"
	"github.com/ericnorris/github-app-sts/internal/server/sts"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	configPath := os.Getenv("CONFIG_FILE")

	if configPath == "" {
		return fmt.Errorf("CONFIG_FILE environment variable is required")
	}

	cfg, err := config.Load(configPath)

	if err != nil {
		return err
	}

	handler, err := initHandler(ctx, logger, cfg)

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", *cfg.Port),
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		httpServer.Shutdown(context.Background())
	}()

	logger.Info("starting server", "port", *cfg.Port)

	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

func initHandler(ctx context.Context, logger *slog.Logger, cfg *config.Config) (*server.Handler, error) {
	verifier, err := oidc.NewVerifier(ctx, cfg.AllowedIssuers, *cfg.Audience, nil)

	if err != nil {
		return nil, fmt.Errorf("could not initialize OIDC verifier: %w", err)
	}

	logger.Info("initialized verifier", "allowed_issuers", cfg.AllowedIssuers, "audience", *cfg.Audience)

	loaders, err := initPolicyLoaders(ctx, logger, cfg.PolicyReaderApp, cfg.OrgPolicyRepos)

	if err != nil {
		return nil, fmt.Errorf("could not initialize policy loaders: %w", err)
	}

	apps, err := initAppRegistry(ctx, cfg.STSTargetApps)

	if err != nil {
		return nil, fmt.Errorf("could not initialize app registry: %w", err)
	}

	return server.NewHandler(sts.New(verifier, loaders, apps), logger), nil
}

func initPolicyLoaders(ctx context.Context, logger *slog.Logger, appCfg *config.AppConfig, orgRepos map[string]string) (map[string]*policy.Loader, error) {
	policyReaderApp, err := initAppTokenSource(ctx, appCfg)

	if err != nil {
		return nil, fmt.Errorf("could not initialize policy reader app: %w", err)
	}

	logger.Info("initialized policy reader app token source", "client_id", appCfg.ClientID)

	loaders := make(map[string]*policy.Loader)

	for org, installationID := range appCfg.Installations {
		loaders[org] = policy.NewLoader(
			github.NewFileReader(
				github.NewInstallationTokenSource(policyReaderApp, org, strconv.FormatInt(installationID, 10), nil),
				nil,
			),
			orgRepos[org],
		)
	}

	logger.Info("initialized policy loaders", "installation_count", len(appCfg.Installations))

	return loaders, nil
}

func initAppRegistry(ctx context.Context, appCfgs []*config.AppConfig) (sts.AppRegistry, error) {
	apps := sts.AppRegistry{}

	for _, targetAppCfg := range appCfgs {
		targetApp, err := initAppTokenSource(ctx, targetAppCfg)

		if err != nil {
			return nil, fmt.Errorf("could not initialize sts target app: %w", err)
		}

		for org, installationID := range targetAppCfg.Installations {
			installations, ok := apps[org]

			if !ok {
				installations = make(map[string]github.InstallationTokenSource)
				apps[org] = installations
			}

			installations[*targetAppCfg.ClientID] = github.NewInstallationTokenSource(
				targetApp, org, strconv.FormatInt(installationID, 10), nil,
			)
		}
	}

	return apps, nil
}

func initAppTokenSource(ctx context.Context, appCfg *config.AppConfig) (*github.AppTokenSource, error) {
	var key appkey.AppKey
	var err error

	switch {
	case appCfg.PrivateKey.EnvVar != "":
		key, err = appkey.NewRSA(*appCfg.ClientID, []byte(os.Getenv(appCfg.PrivateKey.EnvVar)))

	case appCfg.PrivateKey.File != "":
		key, err = appkey.NewRSAFromFile(*appCfg.ClientID, appCfg.PrivateKey.File)

	case appCfg.PrivateKey.GoogleKMS != "":
		key, err = appkey.NewGoogleKMS(ctx, *appCfg.ClientID, appCfg.PrivateKey.GoogleKMS)
	}

	if err != nil {
		return nil, err
	}

	return github.NewAppTokenSource(key), nil
}
