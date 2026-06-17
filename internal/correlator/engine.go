package correlator

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/yourusername/siem/internal/store"
)

// Rule defines a correlation rule
type Rule struct {
	ID          string
	Name        string
	Description string
	Severity    store.Severity
	Tags        []string
	Evaluate    func(ev *store.LogEvent, s *store.MemStore) *store.Alert
}

// Engine runs correlation rules against incoming events
type Engine struct {
	rules   []*Rule
	store   *store.MemStore
	mu      sync.Mutex
	alertCh chan *store.Alert
	// counters per IP for rate-based detection
	ipFailCounts  map[string][]time.Time
	scanPorts     map[string]map[int]time.Time
	sqliAttempts  map[string][]time.Time
	xssAttempts   map[string][]time.Time
	userFailCount map[string][]time.Time
	privEscCount  map[string][]time.Time
}

func New(s *store.MemStore, alertCh chan *store.Alert) *Engine {
	e := &Engine{
		store:         s,
		alertCh:       alertCh,
		ipFailCounts:  make(map[string][]time.Time),
		scanPorts:     make(map[string]map[int]time.Time),
		sqliAttempts:  make(map[string][]time.Time),
		xssAttempts:   make(map[string][]time.Time),
		userFailCount: make(map[string][]time.Time),
		privEscCount:  make(map[string][]time.Time),
	}
	e.loadRules()
	return e
}

func (e *Engine) RuleCount() int { return len(e.rules) }

// Process evaluates all rules for an incoming event
func (e *Engine) Process(ev *store.LogEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, rule := range e.rules {
		if alert := rule.Evaluate(ev, e.store); alert != nil {
			e.store.AddAlert(alert)
			select {
			case e.alertCh <- alert:
			default:
			}
		}
	}
}

// loadRules registers all correlation rules
func (e *Engine) loadRules() {
	e.rules = []*Rule{

		// ── RULE 1: SSH Brute Force ──────────────────────────────────────
		{
			ID: "R001", Name: "SSH Brute Force", Severity: store.SeverityHigh,
			Description: "More than 5 SSH auth failures from same IP within 60 seconds",
			Tags:        []string{"brute-force", "ssh"},
			Evaluate: func(ev *store.LogEvent, s *store.MemStore) *store.Alert {
				if ev.Source != store.SourceSSH || !hasTag(ev, "auth-failure") {
					return nil
				}
				ip := ev.SrcIP
				e.ipFailCounts[ip] = appendWindow(e.ipFailCounts[ip], ev.Timestamp, 60*time.Second)
				if len(e.ipFailCounts[ip]) >= 5 {
					e.ipFailCounts[ip] = nil // reset
					evts := s.GetRecentEventsForIP(ip, 60*time.Second)
					return makeAlert("R001", "SSH Brute Force Detected", store.SeverityHigh,
						fmt.Sprintf("IP %s made %d SSH auth failures in 60s — possible brute force attack", ip, len(evts)),
						ip, "", len(evts), evts, []string{"brute-force", "ssh"})
				}
				return nil
			},
		},

		// ── RULE 2: Port Scan Detection ─────────────────────────────────
		{
			ID: "R002", Name: "Port Scan Detected", Severity: store.SeverityMedium,
			Description: "Single IP accessed more than 10 distinct ports in 30 seconds",
			Tags:        []string{"port-scan", "reconnaissance"},
			Evaluate: func(ev *store.LogEvent, s *store.MemStore) *store.Alert {
				if ev.Source != store.SourceFirewall || ev.DstPort == 0 {
					return nil
				}
				ip := ev.SrcIP
				if e.scanPorts[ip] == nil {
					e.scanPorts[ip] = make(map[int]time.Time)
				}
				// Expire old port entries
				cutoff := time.Now().Add(-30 * time.Second)
				for port, t := range e.scanPorts[ip] {
					if t.Before(cutoff) {
						delete(e.scanPorts[ip], port)
					}
				}
				e.scanPorts[ip][ev.DstPort] = ev.Timestamp
				if len(e.scanPorts[ip]) >= 10 {
					ports := len(e.scanPorts[ip])
					e.scanPorts[ip] = nil
					return makeAlert("R002", "Port Scan Detected", store.SeverityMedium,
						fmt.Sprintf("IP %s probed %d distinct ports in 30s — likely network scan", ip, ports),
						ip, "", ports, nil, []string{"port-scan", "reconnaissance"})
				}
				return nil
			},
		},

		// ── RULE 3: SQL Injection Attempt ────────────────────────────────
		{
			ID: "R003", Name: "SQL Injection Attempt", Severity: store.SeverityHigh,
			Description: "SQL injection payload detected in HTTP request URL",
			Tags:        []string{"sqli", "web-attack"},
			Evaluate: func(ev *store.LogEvent, s *store.MemStore) *store.Alert {
				if ev.Source != store.SourceNginx && ev.Source != store.SourceApache {
					return nil
				}
				url := strings.ToLower(ev.URL)
				sqliPatterns := []string{
					"' or ", "1=1", "1 or 1", "union select", "union all select",
					"drop table", "insert into", "select from", "--", "';--",
					"xp_cmdshell", "exec(", "execute(",
				}
				for _, p := range sqliPatterns {
					if strings.Contains(url, p) {
						ip := ev.SrcIP
						e.sqliAttempts[ip] = appendWindow(e.sqliAttempts[ip], ev.Timestamp, 5*time.Minute)
						return makeAlert("R003", "SQL Injection Attempt", store.SeverityHigh,
							fmt.Sprintf("SQLi pattern '%s' detected in request to %s from %s", p, ev.URL, ip),
							ip, "", 1, []*store.LogEvent{ev}, []string{"sqli", "web-attack"})
					}
				}
				return nil
			},
		},

		// ── RULE 4: XSS Attempt ─────────────────────────────────────────
		{
			ID: "R004", Name: "Cross-Site Scripting Attempt", Severity: store.SeverityMedium,
			Description: "XSS payload detected in HTTP request",
			Tags:        []string{"xss", "web-attack"},
			Evaluate: func(ev *store.LogEvent, s *store.MemStore) *store.Alert {
				if ev.Source != store.SourceNginx && ev.Source != store.SourceApache {
					return nil
				}
				url := strings.ToLower(ev.URL)
				xssPatterns := []string{
					"<script", "javascript:", "onerror=", "onload=",
					"alert(", "document.cookie", "eval(", "fromcharcode",
					"<img src=x", "vbscript:", "onmouseover=",
				}
				for _, p := range xssPatterns {
					if strings.Contains(url, p) {
						ip := ev.SrcIP
						e.xssAttempts[ip] = appendWindow(e.xssAttempts[ip], ev.Timestamp, 5*time.Minute)
						return makeAlert("R004", "XSS Attempt Detected", store.SeverityMedium,
							fmt.Sprintf("XSS pattern '%s' in request from %s to %s", p, ip, ev.URL),
							ip, "", 1, []*store.LogEvent{ev}, []string{"xss", "web-attack"})
					}
				}
				return nil
			},
		},

		// ── RULE 5: Directory Traversal ──────────────────────────────────
		{
			ID: "R005", Name: "Directory Traversal Attempt", Severity: store.SeverityHigh,
			Description: "Path traversal attack detected in HTTP request",
			Tags:        []string{"path-traversal", "web-attack"},
			Evaluate: func(ev *store.LogEvent, s *store.MemStore) *store.Alert {
				if ev.Source != store.SourceNginx && ev.Source != store.SourceApache {
					return nil
				}
				url := ev.URL
				traversalPatterns := []string{
					"../", "..\\", "%2e%2e%2f", "%2e%2e/", "..%2f",
					"etc/passwd", "etc/shadow", "windows/system32", "boot.ini",
				}
				for _, p := range traversalPatterns {
					if strings.Contains(strings.ToLower(url), p) {
						return makeAlert("R005", "Directory Traversal Detected", store.SeverityHigh,
							fmt.Sprintf("Path traversal pattern '%s' in request from %s", p, ev.SrcIP),
							ev.SrcIP, "", 1, []*store.LogEvent{ev}, []string{"path-traversal", "web-attack"})
					}
				}
				return nil
			},
		},

		// ── RULE 6: Privilege Escalation ─────────────────────────────────
		{
			ID: "R006", Name: "Privilege Escalation", Severity: store.SeverityCritical,
			Description: "User executed root-level commands via sudo/su",
			Tags:        []string{"privilege-escalation", "insider-threat"},
			Evaluate: func(ev *store.LogEvent, s *store.MemStore) *store.Alert {
				if ev.Source != store.SourceAuth {
					return nil
				}
				if !hasTag(ev, "privilege-escalation") {
					return nil
				}
				user := ev.Username
				e.privEscCount[user] = appendWindow(e.privEscCount[user], ev.Timestamp, 10*time.Minute)
				if len(e.privEscCount[user]) >= 3 {
					e.privEscCount[user] = nil
					return makeAlert("R006", "Repeated Privilege Escalation", store.SeverityCritical,
						fmt.Sprintf("User '%s' performed %d privilege escalations in 10 minutes", user, 3),
						"", user, 3, []*store.LogEvent{ev}, []string{"privilege-escalation", "insider-threat"})
				}
				// Single sudo to root is also notable
				if hasTag(ev, "root-exec") {
					return makeAlert("R006", "Root Command Execution", store.SeverityHigh,
						fmt.Sprintf("User '%s' executed command as root: %s", user, ev.Extra["command"]),
						"", user, 1, []*store.LogEvent{ev}, []string{"root-exec", "privilege-escalation"})
				}
				return nil
			},
		},

		// ── RULE 7: Firewall Block Spike ─────────────────────────────────
		{
			ID: "R007", Name: "Firewall Block Spike", Severity: store.SeverityMedium,
			Description: "More than 20 firewall blocks from same IP in 1 minute",
			Tags:        []string{"ddos", "scanning"},
			Evaluate: func(ev *store.LogEvent, s *store.MemStore) *store.Alert {
				if ev.Source != store.SourceFirewall || !hasTag(ev, "blocked") {
					return nil
				}
				ip := ev.SrcIP
				e.ipFailCounts["fw:"+ip] = appendWindow(e.ipFailCounts["fw:"+ip], ev.Timestamp, 60*time.Second)
				if len(e.ipFailCounts["fw:"+ip]) >= 20 {
					count := len(e.ipFailCounts["fw:"+ip])
					e.ipFailCounts["fw:"+ip] = nil
					return makeAlert("R007", "Firewall Block Spike", store.SeverityMedium,
						fmt.Sprintf("IP %s triggered %d firewall blocks in 60s — possible DoS or aggressive scan", ip, count),
						ip, "", count, nil, []string{"ddos", "firewall-spike"})
				}
				return nil
			},
		},

		// ── RULE 8: Credential Stuffing ──────────────────────────────────
		{
			ID: "R008", Name: "Credential Stuffing", Severity: store.SeverityHigh,
			Description: "Many failed logins for different users from same IP",
			Tags:        []string{"credential-stuffing", "account-takeover"},
			Evaluate: func(ev *store.LogEvent, s *store.MemStore) *store.Alert {
				if ev.Source != store.SourceNginx && ev.Source != store.SourceApache {
					return nil
				}
				// POST to login/auth paths with 401/403 responses
				if ev.StatusCode != 401 && ev.StatusCode != 403 {
					return nil
				}
				loginPaths := []string{"/login", "/auth", "/signin", "/wp-login", "/admin/login", "/user/login"}
				isLogin := false
				for _, p := range loginPaths {
					if strings.Contains(strings.ToLower(ev.URL), p) {
						isLogin = true
						break
					}
				}
				if !isLogin {
					return nil
				}
				ip := ev.SrcIP
				e.ipFailCounts["cred:"+ip] = appendWindow(e.ipFailCounts["cred:"+ip], ev.Timestamp, 5*time.Minute)
				if len(e.ipFailCounts["cred:"+ip]) >= 10 {
					count := len(e.ipFailCounts["cred:"+ip])
					e.ipFailCounts["cred:"+ip] = nil
					return makeAlert("R008", "Credential Stuffing Attack", store.SeverityHigh,
						fmt.Sprintf("IP %s made %d failed login attempts to %s in 5 minutes", ip, count, ev.URL),
						ip, "", count, nil, []string{"credential-stuffing", "account-takeover"})
				}
				return nil
			},
		},

		// ── RULE 9: Scanner User-Agent ────────────────────────────────────
		{
			ID: "R009", Name: "Vulnerability Scanner Detected", Severity: store.SeverityLow,
			Description: "Known vulnerability scanner or attack tool user-agent detected",
			Tags:        []string{"scanner", "reconnaissance"},
			Evaluate: func(ev *store.LogEvent, s *store.MemStore) *store.Alert {
				if ev.UserAgent == "" {
					return nil
				}
				scannerAgents := []string{
					"sqlmap", "nikto", "nmap", "masscan", "nessus", "openvas",
					"metasploit", "burpsuite", "dirbuster", "gobuster", "hydra",
					"zgrab", "nuclei", "acunetix", "w3af",
				}
				ua := strings.ToLower(ev.UserAgent)
				for _, sig := range scannerAgents {
					if strings.Contains(ua, sig) {
						return makeAlert("R009", "Security Scanner Detected", store.SeverityLow,
							fmt.Sprintf("Known scanner '%s' detected from IP %s (UA: %s)", sig, ev.SrcIP, ev.UserAgent),
							ev.SrcIP, "", 1, []*store.LogEvent{ev}, []string{"scanner", "reconnaissance"})
					}
				}
				return nil
			},
		},

		// ── RULE 10: Sensitive File Access ───────────────────────────────
		{
			ID: "R010", Name: "Sensitive File Access", Severity: store.SeverityHigh,
			Description: "Access to sensitive configuration or credential files",
			Tags:        []string{"data-exfiltration", "web-attack"},
			Evaluate: func(ev *store.LogEvent, s *store.MemStore) *store.Alert {
				if ev.Source != store.SourceNginx && ev.Source != store.SourceApache {
					return nil
				}
				sensitiveFiles := []string{
					".env", ".git/config", "wp-config.php", "config.php",
					"database.yml", "settings.py", "application.properties",
					"id_rsa", ".htpasswd", "shadow", "passwd",
					"backup.sql", "dump.sql", ".aws/credentials",
				}
				url := strings.ToLower(ev.URL)
				for _, f := range sensitiveFiles {
					if strings.Contains(url, f) {
						return makeAlert("R010", "Sensitive File Access", store.SeverityHigh,
							fmt.Sprintf("Attempt to access sensitive file '%s' from %s (HTTP %d)", f, ev.SrcIP, ev.StatusCode),
							ev.SrcIP, "", 1, []*store.LogEvent{ev}, []string{"data-exfiltration", "file-access"})
					}
				}
				return nil
			},
		},

		// ── RULE 11: HTTP 500 Spike ─────────────────────────────────────
		{
			ID: "R011", Name: "Server Error Spike", Severity: store.SeverityMedium,
			Description: "More than 10 server errors (5xx) from same IP in 2 minutes",
			Tags:        []string{"fuzzing", "dos"},
			Evaluate: func(ev *store.LogEvent, s *store.MemStore) *store.Alert {
				if (ev.Source != store.SourceNginx && ev.Source != store.SourceApache) ||
					ev.StatusCode < 500 {
					return nil
				}
				ip := ev.SrcIP
				e.ipFailCounts["5xx:"+ip] = appendWindow(e.ipFailCounts["5xx:"+ip], ev.Timestamp, 2*time.Minute)
				if len(e.ipFailCounts["5xx:"+ip]) >= 10 {
					count := len(e.ipFailCounts["5xx:"+ip])
					e.ipFailCounts["5xx:"+ip] = nil
					return makeAlert("R011", "HTTP 5xx Spike", store.SeverityMedium,
						fmt.Sprintf("IP %s caused %d server errors in 2 minutes — possible fuzzing/DoS", ip, count),
						ip, "", count, nil, []string{"fuzzing", "error-spike"})
				}
				return nil
			},
		},

		// ── RULE 12: RDP Brute Force ─────────────────────────────────────
		{
			ID: "R012", Name: "RDP Brute Force", Severity: store.SeverityCritical,
			Description: "Multiple connection attempts to RDP port (3389) from same IP",
			Tags:        []string{"rdp", "brute-force"},
			Evaluate: func(ev *store.LogEvent, s *store.MemStore) *store.Alert {
				if ev.Source != store.SourceFirewall || ev.DstPort != 3389 {
					return nil
				}
				ip := ev.SrcIP
				e.ipFailCounts["rdp:"+ip] = appendWindow(e.ipFailCounts["rdp:"+ip], ev.Timestamp, 60*time.Second)
				if len(e.ipFailCounts["rdp:"+ip]) >= 5 {
					count := len(e.ipFailCounts["rdp:"+ip])
					e.ipFailCounts["rdp:"+ip] = nil
					return makeAlert("R012", "RDP Brute Force Attack", store.SeverityCritical,
						fmt.Sprintf("IP %s made %d RDP connection attempts in 60s — active brute force", ip, count),
						ip, "", count, nil, []string{"rdp", "brute-force", "ransomware-precursor"})
				}
				return nil
			},
		},
	}
}

// ── HELPERS ───────────────────────────────────────────────────────────────────

func hasTag(ev *store.LogEvent, tag string) bool {
	for _, t := range ev.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// appendWindow adds a timestamp and removes entries older than the window
func appendWindow(times []time.Time, ts time.Time, window time.Duration) []time.Time {
	cutoff := time.Now().Add(-window)
	var fresh []time.Time
	for _, t := range times {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	return append(fresh, ts)
}

func makeAlert(ruleID, title string, sev store.Severity, desc, srcIP, user string,
	count int, evts []*store.LogEvent, tags []string) *store.Alert {
	var ids []string
	for _, e := range evts {
		ids = append(ids, e.ID)
	}
	return &store.Alert{
		ID:          uuid.New().String(),
		Timestamp:   time.Now(),
		RuleName:    ruleID + ": " + title,
		Severity:    sev,
		Title:       title,
		Description: desc,
		SrcIP:       srcIP,
		Username:    user,
		EventCount:  count,
		EventIDs:    ids,
		Tags:        tags,
	}
}
