package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/etsy/github-app-sts/internal/server/config"
	"github.com/etsy/github-app-sts/internal/server/github"
	"github.com/etsy/github-app-sts/internal/server/github/appkey"
	"github.com/etsy/github-app-sts/internal/server/oidc"
	"github.com/etsy/github-app-sts/internal/server/policy"
	"github.com/etsy/github-app-sts/internal/server/sts"
)

func New(ctx context.Context, logger *slog.Logger, cfg *config.Config) (*http.Server, error) {
	tokenHandler, err := initTokenHandler(ctx, logger, cfg)

	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()

	mux.Handle("/token", tokenHandler)
	mux.Handle("/ready", &readyHandler{})

	handler := otelhttp.NewHandler(mux, "github-app-sts",
		otelhttp.WithFilter(func(r *http.Request) bool {
			return r.URL.Path != "/ready"
		}),
	)

	return &http.Server{
		Addr:    fmt.Sprintf(":%d", *cfg.Port),
		Handler: handler,

		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}, nil
}

func initTokenHandler(ctx context.Context, logger *slog.Logger, cfg *config.Config) (*tokenHandler, error) {
	verifier, err := oidc.NewVerifier(ctx, cfg.AllowedIssuers, *cfg.Audience, nil)

	if err != nil {
		return nil, fmt.Errorf("could not initialize OIDC verifier: %w", err)
	}

	logger.Info("initialized verifier", "allowed_issuers", cfg.AllowedIssuers, "audience", *cfg.Audience)

	httpClient := &http.Client{
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}

	loaders, err := initPolicyLoaders(ctx, logger, cfg.PolicyReaderApp, cfg.OrgPolicyRepos, httpClient)

	if err != nil {
		return nil, fmt.Errorf("could not initialize policy loaders: %w", err)
	}

	apps, err := initAppRegistry(ctx, cfg.STSTargetApps, httpClient)

	if err != nil {
		return nil, fmt.Errorf("could not initialize app registry: %w", err)
	}

	return &tokenHandler{sts.New(verifier, loaders, apps), logger}, nil
}

func initPolicyLoaders(ctx context.Context, logger *slog.Logger, appCfg *config.AppConfig, orgRepos map[string]string, httpClient *http.Client) (map[string]*policy.Loader, error) {
	policyReaderApp, err := initAppTokenSource(ctx, appCfg)

	if err != nil {
		return nil, fmt.Errorf("could not initialize policy reader app: %w", err)
	}

	logger.Info("initialized policy reader app token source", "client_id", appCfg.ClientID)

	loaders := make(map[string]*policy.Loader)

	for org, installationID := range appCfg.Installations {
		loaders[org] = policy.NewLoader(
			github.NewFileReader(
				github.NewInstallationTokenSource(policyReaderApp, org, strconv.FormatInt(installationID, 10), httpClient),
				httpClient,
			),
			orgRepos[org],
		)
	}

	logger.Info("initialized policy loaders", "installation_count", len(appCfg.Installations))

	return loaders, nil
}

func initAppRegistry(ctx context.Context, appCfgs []*config.AppConfig, httpClient *http.Client) (sts.AppRegistry, error) {
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
				targetApp, org, strconv.FormatInt(installationID, 10), httpClient,
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

type readyHandler struct{}

func (r *readyHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
