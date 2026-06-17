package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/yourusername/siem/internal/correlator"
	"github.com/yourusername/siem/internal/generator"
	"github.com/yourusername/siem/internal/parser"
	"github.com/yourusername/siem/internal/reporter"
	"github.com/yourusername/siem/internal/store"
)

func main() {
	logger := log.New(os.Stdout, "[SIEM] ", log.LstdFlags)

	// ── Initialize core components ───────────────────────────────────────
	memStore := store.New()

	// Channels for async event/alert flow
	eventCh := make(chan *store.LogEvent, 1000)     // from generator -> pipeline
	broadcastCh := make(chan *store.LogEvent, 1000) // from pipeline -> websocket clients
	alertCh := make(chan *store.Alert, 100)

	// Parser registry knows how to decode each log format
	parserReg := parser.NewRegistry()

	// Correlation engine evaluates rules on each incoming event
	engine := correlator.New(memStore, alertCh)
	logger.Printf("Loaded %d correlation rules", engine.RuleCount())

	// Log generator produces realistic synthetic traffic for demo
	gen := generator.New(parserReg, eventCh)

	// HTTP + WebSocket server (ingestCh shares the same pipeline as eventCh)
	apiServer := reporter.New(memStore, alertCh, broadcastCh, eventCh, parserReg)

	// ── Event processing pipeline ────────────────────────────────────────
	go func() {
		for ev := range eventCh {
			memStore.AddEvent(ev)
			engine.Process(ev)
			// Fan out to websocket broadcaster (non-blocking)
			select {
			case broadcastCh <- ev:
			default:
			}
		}
	}()

	// ── Start log generators ─────────────────────────────────────────────
	gen.StartNormal(500 * time.Millisecond) // normal traffic every 500ms
	gen.StartAttacks()                      // attack traffic on random schedules
	logger.Println("Log generators started (normal + attack simulation)")

	// ── HTTP Router ───────────────────────────────────────────────────────
	r := mux.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			logger.Printf("[%s] %s", req.Method, req.RequestURI)
			next.ServeHTTP(w, req)
		})
	})
	apiServer.RegisterRoutes(r)

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type"},
	})

	port := "8080"
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}

	fmt.Printf(`
╔══════════════════════════════════════════════════════╗
║           NEXUS SIEM — Security Intelligence         ║
╠══════════════════════════════════════════════════════╣
║  Dashboard:  http://localhost:%s                   ║
║  API Base:   http://localhost:%s/api               ║
║  WebSocket:  ws://localhost:%s/api/ws              ║
╠══════════════════════════════════════════════════════╣
║  Correlation Rules: %d active                        ║
║  Log Sources: nginx, apache, ssh, firewall,          ║
║               auth, syslog                           ║
║  Attack Sim: ON — watch alerts appear in real-time   ║
╚══════════════════════════════════════════════════════╝

`, port, port, port, engine.RuleCount())

	logger.Fatal(http.ListenAndServe(":"+port, c.Handler(r)))
}
