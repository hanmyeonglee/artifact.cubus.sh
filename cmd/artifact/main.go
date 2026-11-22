package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"cubus.sh/artifact/internal/adminapi"
	"cubus.sh/artifact/internal/auth"
	"cubus.sh/artifact/internal/config"
	"cubus.sh/artifact/internal/db"
	"cubus.sh/artifact/internal/mcpserver"
	"cubus.sh/artifact/internal/store"
	"cubus.sh/artifact/internal/web"
)

const (
	startupTimeout    = 45 * time.Second
	shutdownTimeout   = 12 * time.Second
	reaperInterval    = 15 * time.Minute
	reaperPassTimeout = 30 * time.Second
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe local /healthz endpoint and exit")
	flag.Parse()

	if *healthcheck {
		os.Exit(runHealthcheck())
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	if err := run(logger); err != nil {
		logger.Error("artifact server exited with error", "err", err)
		os.Exit(1)
	}
}

func runHealthcheck() int {
	target, err := config.HealthcheckURL(os.Getenv("LISTEN_ADDR"))
	if err != nil {
		return 1
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func run(logger *slog.Logger) error {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	logger.Info("starting artifact.cubus.sh", "config", cfg)

	sigCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	startupCtx, cancelStartup := context.WithTimeout(sigCtx, startupTimeout)
	defer cancelStartup()

	dsn, err := db.ResolveDatabaseURL(startupCtx, cfg, nil)
	if err != nil {
		return fmt.Errorf("resolve database URL: %w", err)
	}

	pool, err := db.OpenPool(startupCtx, dsn)
	if err != nil {
		return fmt.Errorf("open database pool: %w", err)
	}
	defer pool.Close()

	if err := db.Migrate(startupCtx, pool); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	hasher := auth.NewPasswordHasher(4)
	seeded, err := db.BootstrapAdmin(startupCtx, pool, cfg.BootstrapAdminUsername, cfg.BootstrapAdminPassword, hasher.Hash)
	if err != nil {
		return fmt.Errorf("bootstrap admin: %w", err)
	}
	if seeded {
		logger.Info("bootstrapped initial admin user", "username", cfg.BootstrapAdminUsername)
	}

	pgStore := store.NewPGStore(pool)
	sessions := auth.NewSessionManager(pgStore, cfg.PublicIsHTTPS)
	oauthSrv := auth.NewOAuthServer(pgStore, cfg.PublicBaseURL)
	mcpSrv := mcpserver.New(pgStore, oauthSrv, cfg.PublicBaseURL, logger)
	webSrv, err := web.New(pgStore, sessions, hasher, oauthSrv, mcpSrv, cfg.PublicBaseURL, logger)
	if err != nil {
		return fmt.Errorf("initialize web server: %w", err)
	}

	publicHTTP := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           webSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	var adminHTTP *http.Server
	if cfg.AdminAPIToken != "" {
		adminAddr, err := adminapi.ResolveBindAddr(cfg.AdminBindCIDR, cfg.AdminPort)
		if err != nil {
			return fmt.Errorf("resolve admin bind address: %w", err)
		}
		adminSrv := adminapi.New(pgStore, cfg.AdminAPIToken, cfg.AdminBindCIDR)
		adminHTTP = &http.Server{
			Addr:              adminAddr,
			Handler:           adminSrv.Handler(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 << 10,
		}
	}

	bgCtx, cancelBg := context.WithCancel(context.Background())
	var bgWG sync.WaitGroup
	bgWG.Add(1)
	go func() {
		defer bgWG.Done()
		runReaper(bgCtx, pgStore, logger)
	}()

	errCh := make(chan error, 2)
	go func() {
		logger.Info("public HTTP server listening", "addr", publicHTTP.Addr)
		if err := publicHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("public server failed: %w", err)
		}
	}()

	if adminHTTP != nil {
		go func() {
			logger.Info("internal admin API server listening", "addr", adminHTTP.Addr)
			if err := adminHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("admin server failed: %w", err)
			}
		}()
	} else {
		logger.Info("internal admin API disabled (ADMIN_API_TOKEN not set)")
	}

	var runErr error
	select {
	case <-sigCtx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		runErr = err
	}

	cancelBg()

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancelShutdown()

	if err := publicHTTP.Shutdown(shutdownCtx); err != nil {
		logger.Error("public server shutdown error", "err", err)
	}
	if adminHTTP != nil {
		if err := adminHTTP.Shutdown(shutdownCtx); err != nil {
			logger.Error("admin server shutdown error", "err", err)
		}
	}

	bgWG.Wait()
	return runErr
}

func runReaper(ctx context.Context, st store.Store, logger *slog.Logger) {
	ticker := time.NewTicker(reaperInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			passCtx, cancel := context.WithTimeout(ctx, reaperPassTimeout)
			if err := st.ReapExpired(passCtx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("expired row cleanup failed", "err", err)
			}
			cancel()
		}
	}
}
