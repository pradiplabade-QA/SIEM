package store

import (
	"sync"
	"time"
)

// Severity levels for log events and alerts
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// LogSource identifies where a log came from
type LogSource string

const (
	SourceNginx    LogSource = "nginx"
	SourceApache   LogSource = "apache"
	SourceSSH      LogSource = "ssh"
	SourceFirewall LogSource = "firewall"
	SourceSyslog   LogSource = "syslog"
	SourceAuth     LogSource = "auth"
)

// LogEvent is a normalized log entry from any source
type LogEvent struct {
	ID         string            `json:"id"`
	Timestamp  time.Time         `json:"timestamp"`
	Source     LogSource         `json:"source"`
	RawLine    string            `json:"raw_line"`
	Level      string            `json:"level"`
	Message    string            `json:"message"`
	SrcIP      string            `json:"src_ip,omitempty"`
	DstPort    int               `json:"dst_port,omitempty"`
	Username   string            `json:"username,omitempty"`
	StatusCode int               `json:"status_code,omitempty"`
	Method     string            `json:"method,omitempty"`
	URL        string            `json:"url,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty"`
	BytesSent  int64             `json:"bytes_sent,omitempty"`
	Tags       []string          `json:"tags,omitempty"`
	Extra      map[string]string `json:"extra,omitempty"`
}

// Alert is generated when correlation rules fire
type Alert struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	RuleName    string    `json:"rule_name"`
	Severity    Severity  `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	SrcIP       string    `json:"src_ip,omitempty"`
	Username    string    `json:"username,omitempty"`
	EventCount  int       `json:"event_count"`
	EventIDs    []string  `json:"event_ids"`
	Tags        []string  `json:"tags"`
	Resolved    bool      `json:"resolved"`
}

// GeoIP holds basic geographic + reputation info per IP
type GeoIP struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	ISP         string  `json:"isp"`
	ThreatScore int     `json:"threat_score"` // 0-100
}

// Stats holds dashboard metrics
type Stats struct {
	TotalEvents    int64             `json:"total_events"`
	TotalAlerts    int64             `json:"total_alerts"`
	AlertsByLevel  map[Severity]int  `json:"alerts_by_level"`
	EventsBySource map[LogSource]int `json:"events_by_source"`
	TopAttackerIPs []IPCount         `json:"top_attacker_ips"`
	EventsPerHour  []HourCount       `json:"events_per_hour"`
	RecentAlerts   []*Alert          `json:"recent_alerts"`
	ActiveRules    int               `json:"active_rules"`
}

type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
	Geo   *GeoIP `json:"geo,omitempty"`
}

type HourCount struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

// MemStore is a thread-safe in-memory store for all SIEM data
type MemStore struct {
	mu       sync.RWMutex
	Events   []*LogEvent
	Alerts   []*Alert
	GeoCache map[string]*GeoIP

	totalEvents    int64
	totalAlerts    int64
	alertsByLevel  map[Severity]int
	eventsBySource map[LogSource]int
	ipEventCount   map[string]int
	hourlyEvents   map[string]int
}

func New() *MemStore {
	return &MemStore{
		GeoCache:       make(map[string]*GeoIP),
		alertsByLevel:  make(map[Severity]int),
		eventsBySource: make(map[LogSource]int),
		ipEventCount:   make(map[string]int),
		hourlyEvents:   make(map[string]int),
	}
}

func (s *MemStore) AddEvent(e *LogEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Keep last 10,000 events in memory
	if len(s.Events) >= 10000 {
		s.Events = s.Events[1:]
	}
	s.Events = append(s.Events, e)
	s.totalEvents++
	s.eventsBySource[e.Source]++
	if e.SrcIP != "" {
		s.ipEventCount[e.SrcIP]++
	}
	hour := e.Timestamp.Format("2006-01-02 15:00")
	s.hourlyEvents[hour]++
}

func (s *MemStore) AddAlert(a *Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Alerts = append(s.Alerts, a)
	s.totalAlerts++
	s.alertsByLevel[a.Severity]++
}

func (s *MemStore) ResolveAlert(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.Alerts {
		if a.ID == id {
			a.Resolved = true
			return true
		}
	}
	return false
}

func (s *MemStore) GetStats() *Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Copy maps
	abl := make(map[Severity]int)
	for k, v := range s.alertsByLevel {
		abl[k] = v
	}
	ebs := make(map[LogSource]int)
	for k, v := range s.eventsBySource {
		ebs[k] = v
	}

	// Top attacker IPs (top 10)
	type kv struct {
		k string
		v int
	}
	var pairs []kv
	for k, v := range s.ipEventCount {
		pairs = append(pairs, kv{k, v})
	}
	// simple sort
	for i := 0; i < len(pairs); i++ {
		for j := i + 1; j < len(pairs); j++ {
			if pairs[j].v > pairs[i].v {
				pairs[i], pairs[j] = pairs[j], pairs[i]
			}
		}
	}
	var topIPs []IPCount
	for i, p := range pairs {
		if i >= 10 {
			break
		}
		ic := IPCount{IP: p.k, Count: p.v}
		if geo, ok := s.GeoCache[p.k]; ok {
			ic.Geo = geo
		}
		topIPs = append(topIPs, ic)
	}

	// Events per hour (last 24 hours)
	var hourCounts []HourCount
	now := time.Now()
	for h := 23; h >= 0; h-- {
		t := now.Add(-time.Duration(h) * time.Hour)
		key := t.Format("2006-01-02 15:00")
		hourCounts = append(hourCounts, HourCount{Hour: t.Format("15:00"), Count: s.hourlyEvents[key]})
	}

	// Recent alerts (last 20, newest first)
	var recent []*Alert
	for i := len(s.Alerts) - 1; i >= 0 && len(recent) < 20; i-- {
		recent = append(recent, s.Alerts[i])
	}

	return &Stats{
		TotalEvents:    s.totalEvents,
		TotalAlerts:    s.totalAlerts,
		AlertsByLevel:  abl,
		EventsBySource: ebs,
		TopAttackerIPs: topIPs,
		EventsPerHour:  hourCounts,
		RecentAlerts:   recent,
		ActiveRules:    12, // will be updated by correlator
	}
}

func (s *MemStore) GetEvents(limit int, sourceFilter LogSource) []*LogEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*LogEvent
	for i := len(s.Events) - 1; i >= 0 && len(result) < limit; i-- {
		e := s.Events[i]
		if sourceFilter != "" && e.Source != sourceFilter {
			continue
		}
		result = append(result, e)
	}
	return result
}

func (s *MemStore) GetAlerts(onlyActive bool) []*Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Alert
	for i := len(s.Alerts) - 1; i >= 0; i-- {
		a := s.Alerts[i]
		if onlyActive && a.Resolved {
			continue
		}
		result = append(result, a)
	}
	return result
}

func (s *MemStore) CacheGeo(ip string, geo *GeoIP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GeoCache[ip] = geo
}

// GetRecentEventsForIP returns the last N events from a given IP
func (s *MemStore) GetRecentEventsForIP(ip string, window time.Duration) []*LogEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cutoff := time.Now().Add(-window)
	var result []*LogEvent
	for _, e := range s.Events {
		if e.SrcIP == ip && e.Timestamp.After(cutoff) {
			result = append(result, e)
		}
	}
	return result
}

func (s *MemStore) GetRecentEventsByUser(user string, window time.Duration) []*LogEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cutoff := time.Now().Add(-window)
	var result []*LogEvent
	for _, e := range s.Events {
		if e.Username == user && e.Timestamp.After(cutoff) {
			result = append(result, e)
		}
	}
	return result
}
