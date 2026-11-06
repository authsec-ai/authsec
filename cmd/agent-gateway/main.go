// Command agent-gateway is the AuthSec agent runtime gateway
// (SPEC-agent-runtime-gateway.md): run it next to your agents, point their
// MCP clients and OpenAI/Anthropic base URLs at it, and AuthSec decides every
// tool call and model call. Your provider keys and MCP credentials stay in
// this process; AuthSec receives decision metadata only.
//
//	agent-gateway -config /etc/agent-gateway/config.yaml   serve
//	agent-gateway gen-key                                  a new agent key and its sha256
//	agent-gateway hash-key <key>                           the sha256 to configure for a key
//	agent-gateway version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/authsec-ai/authsec/internal/agentgateway/gateway"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "gen-key":
			k, err := gateway.GenerateAgentKey()
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("key:        %s\nkey_sha256: %s\n", k, gateway.HashAgentKey(k))
			return
		case "hash-key":
			if len(os.Args) != 3 {
				log.Fatal("usage: agent-gateway hash-key <key>")
			}
			fmt.Println(gateway.HashAgentKey(os.Args[2]))
			return
		case "version":
			fmt.Println(gateway.Version)
			return
		}
	}
	path := flag.String("config", os.Getenv("AGENT_GATEWAY_CONFIG"), "path to the YAML configuration")
	flag.Parse()

	cfg, err := gateway.LoadConfig(*path)
	if err != nil {
		log.Fatalf("[agent-gateway] config: %v", err)
	}
	g, err := gateway.New(cfg, gateway.Options{})
	if err != nil {
		log.Fatalf("[agent-gateway] %v", err)
	}
	tlsCfg, err := g.ServerTLSConfig()
	if err != nil {
		log.Fatalf("[agent-gateway] %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan struct{})
	go func() { g.Run(ctx); close(done) }()

	srv := &http.Server{Addr: cfg.Listen, Handler: g.Handler(), TLSConfig: tlsCfg,
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	var admin *http.Server
	if h := g.AdminHandler(); h != nil {
		admin = &http.Server{Addr: cfg.AdminListen, Handler: h, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			log.Printf("[agent-gateway] admin API on %s", cfg.AdminListen)
			if err := admin.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("[agent-gateway] admin: %v", err)
			}
		}()
	}
	go func() {
		log.Printf("[agent-gateway] %s listening on %s (fail_mode=%s, pdp=%s)", gateway.Version, cfg.Listen, cfg.FailMode, cfg.AuthSec.URL)
		var err error
		if tlsCfg != nil {
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[agent-gateway] %v", err)
		}
	}()
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	if admin != nil {
		_ = admin.Shutdown(sctx)
	}
	<-done // the uploader flushes once more
}
