package reporter

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/yourusername/siem/internal/alerter"
	"github.com/yourusername/siem/internal/parser"
	"github.com/yourusername/siem/internal/store"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// Server handles all HTTP and WebSocket endpoints
type Server struct {
	store    *store.MemStore
	alertCh  chan *store.Alert
	eventCh  chan *store.LogEvent
	ingestCh chan *store.LogEvent
	registry *parser.Registry
	clients  map[*websocket.Conn]bool
	mu       sync.RWMutex
}

func New(s *store.MemStore, alertCh chan *store.Alert, eventCh chan *store.LogEvent, ingestCh chan *store.LogEvent, registry *parser.Registry) *Server {
	srv := &Server{
		store:    s,
		alertCh:  alertCh,
		eventCh:  eventCh,
		ingestCh: ingestCh,
		registry: registry,
		clients:  make(map[*websocket.Conn]bool),
	}
	go srv.broadcastLoop()
	return srv
}

func (s *Server) RegisterRoutes(r *mux.Router) {
	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/stats", s.handleStats).Methods("GET")
	api.HandleFunc("/events", s.handleEvents).Methods("GET")
	api.HandleFunc("/alerts", s.handleAlerts).Methods("GET")
	api.HandleFunc("/alerts/{id}/resolve", s.handleResolve).Methods("POST")
	api.HandleFunc("/ingest", s.handleIngest).Methods("POST")
	api.HandleFunc("/ws", s.handleWS)

	// Serve frontend
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./frontend")))
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := s.store.GetStats()
	// Enrich top IPs with geo
	for i := range stats.TopAttackerIPs {
		if geo := alerter.EnrichIP(stats.TopAttackerIPs[i].IP, s.store); geo != nil {
			stats.TopAttackerIPs[i].Geo = geo
		}
	}
	respondJSON(w, stats)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 100
	sourceStr := q.Get("source")
	var src store.LogSource
	if sourceStr != "" {
		src = store.LogSource(sourceStr)
	}
	events := s.store.GetEvents(limit, src)
	respondJSON(w, map[string]interface{}{"events": events, "count": len(events)})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	onlyActive := r.URL.Query().Get("active") == "true"
	alerts := s.store.GetAlerts(onlyActive)
	respondJSON(w, map[string]interface{}{"alerts": alerts, "count": len(alerts)})
}

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if s.store.ResolveAlert(id) {
		respondJSON(w, map[string]interface{}{"success": true, "message": "alert resolved"})
	} else {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

// handleIngest accepts raw log lines via HTTP POST and feeds them into the pipeline
func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Source string `json:"source"`
		Line   string `json:"line"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if payload.Line == "" {
		http.Error(w, `{"error":"line is required"}`, http.StatusBadRequest)
		return
	}

	ev, err := s.registry.ParseLine(store.LogSource(payload.Source), payload.Line)
	if err != nil {
		http.Error(w, `{"error":"could not parse log line"}`, http.StatusBadRequest)
		return
	}

	select {
	case s.ingestCh <- ev:
	default:
		// pipeline busy — drop rather than block the HTTP request
	}

	respondJSON(w, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("ingested log from source %s", payload.Source),
		"event":   ev,
	})
}

// handleWS upgrades to WebSocket and registers the client
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws upgrade error: %v", err)
		return
	}
	s.mu.Lock()
	s.clients[conn] = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, conn)
		s.mu.Unlock()
		conn.Close()
	}()

	// Keep connection alive
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

// broadcastLoop sends real-time updates to all WebSocket clients
func (s *Server) broadcastLoop() {
	statsTicker := time.NewTicker(3 * time.Second)
	defer statsTicker.Stop()

	for {
		select {
		case alert := <-s.alertCh:
			// Enrich with geo
			if alert.SrcIP != "" {
				alerter.EnrichIP(alert.SrcIP, s.store)
			}
			s.broadcast("alert", alert)

		case ev := <-s.eventCh:
			s.broadcast("event", ev)

		case <-statsTicker.C:
			s.broadcast("stats", s.store.GetStats())
		}
	}
}

type WSMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

func (s *Server) broadcast(msgType string, payload interface{}) {
	msg, err := json.Marshal(WSMessage{Type: msgType, Payload: payload})
	if err != nil {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for conn := range s.clients {
		if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			conn.Close()
		}
	}
}

func respondJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
