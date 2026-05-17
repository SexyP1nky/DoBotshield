package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dobotshield/blocklist"
	"dobotshield/config"
	"dobotshield/middleware"
	"dobotshield/ratelimit"
)

func main() {
	cfg := config.Load()

	bl := blocklist.New(cfg.BlockedIPs)

	fw := ratelimit.NewManager(cfg.MaxTrackedIPs, cfg.RateLimit, cfg.BurstLimit, cfg.MaxConnsPerIP)
	if cfg.RateLimitStateFile != "" {
		if err := fw.LoadState(cfg.RateLimitStateFile); err != nil {
			log.Printf("nao foi possivel carregar estado do rate limiter: %v", err)
		}
	}

	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			fw.Cleanup()
			saveRateLimitState(fw, cfg.RateLimitStateFile)
		}
	}()

	go handleShutdown(fw, cfg.RateLimitStateFile)

	proxy, err := middleware.BuildProxy(cfg)
	if err != nil {
		log.Fatalf("TARGET_URL invalida: %v", err)
	}

	http.Handle("/", middleware.MakeSecureHandler(proxy, fw, bl, cfg))

	// HTTP_MODE=true desativa TLS — usado em ambientes de laboratorio onde o
	// termino TLS e feito por um balanceador ou nao e necessario para o teste.
	httpMode := os.Getenv("HTTP_MODE") == "true"

	server := &http.Server{
		Addr:              cfg.ProxyPort,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		},
	}

	printBanner(cfg, httpMode)

	if httpMode {
		if err := server.ListenAndServe(); err != nil {
			saveRateLimitState(fw, cfg.RateLimitStateFile)
			log.Fatal(err)
		}
	} else {
		if err := server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile); err != nil {
			saveRateLimitState(fw, cfg.RateLimitStateFile)
			log.Fatal(err)
		}
	}
}

func handleShutdown(fw *ratelimit.Manager, stateFile string) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	<-signals
	saveRateLimitState(fw, stateFile)
	log.Println("encerrando DoBot Shield")
	os.Exit(0)
}

func saveRateLimitState(fw *ratelimit.Manager, stateFile string) {
	if stateFile == "" {
		return
	}
	if err := fw.SaveState(stateFile); err != nil {
		log.Printf("nao foi possivel salvar estado do rate limiter: %v", err)
	}
}

func printBanner(cfg config.Config, httpMode bool) {
	proto := "HTTPS"
	if httpMode {
		proto = "HTTP (lab)"
	}
	fmt.Println("==================================================")
	fmt.Println("  DoBot Shield")
	fmt.Printf("  Protocolo:        %s\n", proto)
	fmt.Printf("  Proxy:            %s  ->  %s\n", cfg.ProxyPort, cfg.TargetURL)
	fmt.Printf("  WAF:              %v (%s)\n", cfg.EnableSanitizer, cfg.WAFMode)
	fmt.Printf("  Inspecao:         %v\n", cfg.EnableResponseInspection)
	fmt.Printf("  Rate limit:       %v\n", cfg.EnableRateLimit)
	if n := len(cfg.BlockedIPs); n > 0 {
		fmt.Printf("  IPs bloqueados:   %d entradas\n", n)
	}
	if cfg.RateLimitStateFile != "" {
		fmt.Printf("  Estado:           %s\n", cfg.RateLimitStateFile)
	}
	if cfg.InsecureSkipVerify {
		fmt.Println("  AVISO: TLS do backend desabilitado")
	}
	fmt.Println("==================================================")
}
