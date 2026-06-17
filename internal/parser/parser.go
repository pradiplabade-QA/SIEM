package parser

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/yourusername/siem/internal/store"
)

// Parser defines the interface each log source parser must implement
type Parser interface {
	Parse(line string) (*store.LogEvent, error)
	Source() store.LogSource
}

// Registry holds all registered parsers
type Registry struct {
	parsers []Parser
}

func NewRegistry() *Registry {
	r := &Registry{}
	r.parsers = []Parser{
		&NginxParser{},
		&ApacheParser{},
		&SSHParser{},
		&FirewallParser{},
		&AuthParser{},
		&SyslogParser{},
	}
	return r
}

// ParseLine tries each parser in order and returns on first match
func (r *Registry) ParseLine(source store.LogSource, line string) (*store.LogEvent, error) {
	for _, p := range r.parsers {
		if source == "" || p.Source() == source {
			if ev, err := p.Parse(line); err == nil {
				return ev, nil
			}
		}
	}
	// Fallback: create a raw event
	return &store.LogEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Source:    source,
		RawLine:   line,
		Message:   line,
		Level:     "INFO",
	}, nil
}

// ── NGINX PARSER ──────────────────────────────────────────────────────────────
// Format: 192.168.1.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://ref" "Mozilla/4.08"
type NginxParser struct{}

var nginxRe = regexp.MustCompile(
	`^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)(?:\s+"([^"]*)"\s+"([^"]*)")?`)

func (p *NginxParser) Source() store.LogSource { return store.SourceNginx }

func (p *NginxParser) Parse(line string) (*store.LogEvent, error) {
	m := nginxRe.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Errorf("no match")
	}
	ts, _ := time.Parse("02/Jan/2006:15:04:05 -0700", m[3])
	status, _ := strconv.Atoi(m[6])
	bytes, _ := strconv.ParseInt(m[7], 10, 64)

	level := "INFO"
	var tags []string
	if status >= 400 && status < 500 {
		level = "WARN"
		tags = append(tags, "client-error")
	}
	if status >= 500 {
		level = "ERROR"
		tags = append(tags, "server-error")
	}

	// Detect common attack patterns
	url := m[5]
	if containsAny(url, []string{"../", "..", "etc/passwd", "cmd=", "exec(", "<script", "UNION SELECT", "' OR ", "1=1"}) {
		tags = append(tags, "suspicious-url")
	}

	ev := &store.LogEvent{
		ID:         uuid.New().String(),
		Timestamp:  ts,
		Source:     store.SourceNginx,
		RawLine:    line,
		Level:      level,
		Message:    fmt.Sprintf("%s %s -> %d", m[4], m[5], status),
		SrcIP:      m[1],
		Method:     m[4],
		URL:        m[5],
		StatusCode: status,
		BytesSent:  bytes,
		UserAgent:  m[9],
		Tags:       tags,
		Extra:      map[string]string{"referer": m[8]},
	}
	return ev, nil
}

// ── APACHE PARSER ─────────────────────────────────────────────────────────────
// Same Combined Log Format as nginx
type ApacheParser struct{}

func (p *ApacheParser) Source() store.LogSource { return store.SourceApache }
func (p *ApacheParser) Parse(line string) (*store.LogEvent, error) {
	// Apache uses same combined log format, reuse nginx regex
	np := &NginxParser{}
	ev, err := np.Parse(line)
	if err != nil {
		return nil, err
	}
	ev.Source = store.SourceApache
	return ev, nil
}

// ── SSH AUTH LOG PARSER ───────────────────────────────────────────────────────
// Format: Jun 13 10:22:33 hostname sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
type SSHParser struct{}

var sshFailRe = regexp.MustCompile(
	`(\w+ +\d+ \d+:\d+:\d+).*sshd\[\d+\]: (Failed|Invalid|error:) .*?(?:for (?:invalid user )?(\S+) )?from (\S+) port (\d+)`)
var sshSuccessRe = regexp.MustCompile(
	`(\w+ +\d+ \d+:\d+:\d+).*sshd\[\d+\]: Accepted (\S+) for (\S+) from (\S+) port (\d+)`)
var sshDisconnectRe = regexp.MustCompile(
	`(\w+ +\d+ \d+:\d+:\d+).*sshd\[\d+\]: Received disconnect from (\S+)`)

func (p *SSHParser) Source() store.LogSource { return store.SourceSSH }

func (p *SSHParser) Parse(line string) (*store.LogEvent, error) {
	year := time.Now().Year()

	if m := sshFailRe.FindStringSubmatch(line); m != nil {
		ts, _ := time.Parse("Jan  2 15:04:05 2006", m[1]+" "+strconv.Itoa(year))
		port, _ := strconv.Atoi(m[5])
		return &store.LogEvent{
			ID: uuid.New().String(), Timestamp: ts, Source: store.SourceSSH,
			RawLine: line, Level: "WARN",
			Message: fmt.Sprintf("SSH auth failure for user '%s' from %s", m[3], m[4]),
			SrcIP:   m[4], DstPort: port, Username: m[3],
			Tags: []string{"auth-failure", "ssh"},
		}, nil
	}

	if m := sshSuccessRe.FindStringSubmatch(line); m != nil {
		ts, _ := time.Parse("Jan  2 15:04:05 2006", m[1]+" "+strconv.Itoa(year))
		port, _ := strconv.Atoi(m[5])
		return &store.LogEvent{
			ID: uuid.New().String(), Timestamp: ts, Source: store.SourceSSH,
			RawLine: line, Level: "INFO",
			Message: fmt.Sprintf("SSH login successful for '%s' from %s via %s", m[3], m[4], m[2]),
			SrcIP:   m[4], DstPort: port, Username: m[3],
			Tags: []string{"auth-success", "ssh"},
		}, nil
	}

	if m := sshDisconnectRe.FindStringSubmatch(line); m != nil {
		ts, _ := time.Parse("Jan  2 15:04:05 2006", m[1]+" "+strconv.Itoa(year))
		return &store.LogEvent{
			ID: uuid.New().String(), Timestamp: ts, Source: store.SourceSSH,
			RawLine: line, Level: "INFO",
			Message: fmt.Sprintf("SSH disconnect from %s", m[2]),
			SrcIP:   m[2], Tags: []string{"ssh"},
		}, nil
	}

	return nil, fmt.Errorf("no SSH match")
}

// ── FIREWALL PARSER ───────────────────────────────────────────────────────────
// iptables format: Jun 13 10:00:01 hostname kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=10.0.0.1 PROTO=TCP SPT=12345 DPT=22
type FirewallParser struct{}

var fwRe = regexp.MustCompile(
	`(\w+ +\d+ \d+:\d+:\d+).*\[(UFW BLOCK|UFW ALLOW|BLOCK|ALLOW|DROP|ACCEPT)\].*SRC=(\S+).*DST=(\S+).*PROTO=(\S+).*DPT=(\d+)`)

func (p *FirewallParser) Source() store.LogSource { return store.SourceFirewall }

func (p *FirewallParser) Parse(line string) (*store.LogEvent, error) {
	m := fwRe.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Errorf("no match")
	}
	year := time.Now().Year()
	ts, _ := time.Parse("Jan  2 15:04:05 2006", m[1]+" "+strconv.Itoa(year))
	dpt, _ := strconv.Atoi(m[6])

	action := m[2]
	level := "INFO"
	var tags []string
	if strings.Contains(action, "BLOCK") || strings.Contains(action, "DROP") {
		level = "WARN"
		tags = append(tags, "blocked")
	} else {
		tags = append(tags, "allowed")
	}

	// Flag suspicious destination ports
	suspPorts := map[int]string{22: "ssh", 23: "telnet", 3389: "rdp", 445: "smb", 1433: "mssql", 3306: "mysql"}
	if svc, ok := suspPorts[dpt]; ok {
		tags = append(tags, "port-"+svc)
	}

	return &store.LogEvent{
		ID: uuid.New().String(), Timestamp: ts, Source: store.SourceFirewall,
		RawLine: line, Level: level,
		Message: fmt.Sprintf("Firewall %s: %s → %s:%d via %s", action, m[3], m[4], dpt, m[5]),
		SrcIP:   m[3], DstPort: dpt, Tags: tags,
		Extra: map[string]string{"action": action, "dst": m[4], "proto": m[5]},
	}, nil
}

// ── AUTH LOG PARSER ───────────────────────────────────────────────────────────
// /var/log/auth.log: Jun 13 10:05:01 host sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash
type AuthParser struct{}

var sudoRe = regexp.MustCompile(`(\w+ +\d+ \d+:\d+:\d+).*sudo:\s+(\S+)\s+:.*USER=(\S+).*COMMAND=(.+)`)
var suRe = regexp.MustCompile(`(\w+ +\d+ \d+:\d+:\d+).*su\[.*\]: Successful su for (\S+) by (\S+)`)
var loginRe = regexp.MustCompile(`(\w+ +\d+ \d+:\d+:\d+).*login\[.*\]: ROOT LOGIN on (\S+)`)

func (p *AuthParser) Source() store.LogSource { return store.SourceAuth }

func (p *AuthParser) Parse(line string) (*store.LogEvent, error) {
	year := time.Now().Year()

	if m := sudoRe.FindStringSubmatch(line); m != nil {
		ts, _ := time.Parse("Jan  2 15:04:05 2006", m[1]+" "+strconv.Itoa(year))
		tags := []string{"sudo", "privilege-escalation"}
		level := "WARN"
		if m[3] == "root" {
			tags = append(tags, "root-exec")
			level = "HIGH"
		}
		return &store.LogEvent{
			ID: uuid.New().String(), Timestamp: ts, Source: store.SourceAuth,
			RawLine: line, Level: level,
			Message:  fmt.Sprintf("sudo: %s executed as %s: %s", m[2], m[3], m[4]),
			Username: m[2], Tags: tags,
			Extra: map[string]string{"target_user": m[3], "command": m[4]},
		}, nil
	}

	if m := suRe.FindStringSubmatch(line); m != nil {
		ts, _ := time.Parse("Jan  2 15:04:05 2006", m[1]+" "+strconv.Itoa(year))
		return &store.LogEvent{
			ID: uuid.New().String(), Timestamp: ts, Source: store.SourceAuth,
			RawLine: line, Level: "WARN",
			Message:  fmt.Sprintf("su: %s switched to %s", m[3], m[2]),
			Username: m[3], Tags: []string{"su", "privilege-escalation"},
		}, nil
	}

	if m := loginRe.FindStringSubmatch(line); m != nil {
		ts, _ := time.Parse("Jan  2 15:04:05 2006", m[1]+" "+strconv.Itoa(year))
		return &store.LogEvent{
			ID: uuid.New().String(), Timestamp: ts, Source: store.SourceAuth,
			RawLine: line, Level: "HIGH",
			Message:  fmt.Sprintf("ROOT LOGIN on terminal %s", m[2]),
			Username: "root", Tags: []string{"root-login", "privilege-escalation"},
		}, nil
	}

	return nil, fmt.Errorf("no auth match")
}

// ── SYSLOG PARSER ─────────────────────────────────────────────────────────────
// Jun 13 10:05:01 hostname cron[1234]: (root) CMD (/usr/sbin/logrotate ...)
type SyslogParser struct{}

var syslogRe = regexp.MustCompile(`^(\w+ +\d+ \d+:\d+:\d+) (\S+) (\S+?)(?:\[(\d+)\])?: (.+)`)

func (p *SyslogParser) Source() store.LogSource { return store.SourceSyslog }

func (p *SyslogParser) Parse(line string) (*store.LogEvent, error) {
	m := syslogRe.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Errorf("no match")
	}
	year := time.Now().Year()
	ts, _ := time.Parse("Jan  2 15:04:05 2006", m[1]+" "+strconv.Itoa(year))

	level := "INFO"
	msg := m[5]
	if containsAny(strings.ToLower(msg), []string{"error", "critical", "crit", "emerg", "alert"}) {
		level = "ERROR"
	} else if containsAny(strings.ToLower(msg), []string{"warn", "warning"}) {
		level = "WARN"
	}

	return &store.LogEvent{
		ID: uuid.New().String(), Timestamp: ts, Source: store.SourceSyslog,
		RawLine: line, Level: level,
		Message: fmt.Sprintf("[%s] %s", m[3], msg),
		Extra:   map[string]string{"host": m[2], "process": m[3], "pid": m[4]},
	}, nil
}

// ── HELPERS ───────────────────────────────────────────────────────────────────
func containsAny(s string, subs []string) bool {
	lower := strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}
