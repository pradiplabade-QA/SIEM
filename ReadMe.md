# NEXUS SIEM — Log Analysis & Correlation Engine in Go

A real-time Security Information and Event Management (SIEM) tool that ingests logs from **6 source types** (nginx, apache, ssh, firewall, auth, syslog), normalizes them into a common schema, runs **12 correlation rules** to detect multi-stage attack patterns, and streams everything to a live terminal-style dashboard over WebSocket.

Runs standalone with a built-in synthetic traffic generator — no external log files or database required to see it working.

---

## 📁 Project Structure

```
siem/
├── cmd/
│   └── siem/
│       └── main.go            # Entry point — wires pipeline together
├── internal/
│   ├── store/
│   │   └── store.go            # In-memory event/alert store + models
│   ├── parser/
│   │   └── parsers.go          # 6 log format parsers (regex-based)
│   ├── correlator/
│   │   └── engine.go           # 12 correlation rules
│   ├── alerter/
│   │   └── geoip.go             # IP geolocation + threat scoring
│   ├── generator/
│   │   └── generator.go        # Synthetic log traffic generator
│   └── reporter/
│       └── server.go            # HTTP API + WebSocket broadcaster
├── frontend/
│   └── index.html               # Live SOC-style dashboard
├── go.mod
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites
- Go 1.21+

### Run

```bash
cd siem
go mod tidy
go run ./cmd/siem
```

Open **http://localhost:8080**

The dashboard starts populating immediately — a built-in generator produces normal background traffic plus periodic attack bursts (SSH brute force, port scans, SQLi/XSS probes, RDP brute force, privilege escalation, credential stuffing) so you can watch alerts fire in real time.

---

## 🧠 How It Works

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│  Log Sources │ --> │   Parsers    │ --> │  Event Pipeline  │ --> │  In-Memory    │
│ (6 formats)  │     │ (normalize)  │     │  + Correlation   │     │  Store        │
└─────────────┘     └──────────────┘     │     Engine       │     └──────┬───────┘
                                          └────────┬─────────┘            │
                                                   │                       │
                                                   ▼                       ▼
                                          ┌──────────────────┐   ┌─────────────────┐
                                          │   Alert Channel    │   │  WebSocket /     │
                                          │  (rule matches)    │-->│  REST API        │
                                          └──────────────────┘   └────────┬─────────┘
                                                                            │
                                                                            ▼
                                                                  ┌──────────────────┐
                                                                  │  Live Dashboard   │
                                                                  │  (SOC view)       │
                                                                  └──────────────────┘
```

1. **Parsers** (`internal/parser`) — each log line is matched against regex patterns for nginx/apache combined log format, SSH auth logs, iptables/UFW firewall logs, sudo/su privilege logs, and generic syslog. Unmatched lines fall back to a raw event.

2. **Correlation Engine** (`internal/correlator`) — every normalized event is run through 12 stateful rules that track sliding time windows per IP/user (e.g. "5 SSH failures from the same IP in 60 seconds"). A match produces an `Alert`.

3. **Store** (`internal/store`) — thread-safe in-memory store holding the last 10,000 events and all alerts, with running counters for dashboard stats (events by source, top attacker IPs, hourly histogram, alert severity breakdown).

4. **GeoIP Enrichment** (`internal/alerter`) — attacker IPs are enriched with country/city/ISP and a 0–100 threat score (mock data covering common hosting providers and known Tor exit ranges — swap in MaxMind GeoLite2 for production).

5. **Reporter** (`internal/reporter`) — exposes REST endpoints for initial page load and a WebSocket (`/api/ws`) that pushes `event`, `alert`, and `stats` messages to connected dashboards every few seconds / as they happen.

6. **Generator** (`internal/generator`) — for demo purposes, produces realistic background traffic plus scheduled attack bursts. **Remove this in production** and feed real logs via the ingest endpoint or by tailing log files.

---

## 🛡️ Correlation Rules

| ID | Rule | Severity | Trigger |
|----|------|----------|---------|
| R001 | SSH Brute Force | HIGH | 5+ SSH auth failures from one IP in 60s |
| R002 | Port Scan Detected | MEDIUM | 10+ distinct ports probed by one IP in 30s |
| R003 | SQL Injection Attempt | HIGH | SQLi payload in HTTP request URL |
| R004 | XSS Attempt | MEDIUM | XSS payload in HTTP request URL |
| R005 | Directory Traversal | HIGH | Path traversal pattern (`../`, `/etc/passwd`, etc.) |
| R006 | Privilege Escalation | CRITICAL | Repeated sudo/su to root, or single root command exec |
| R007 | Firewall Block Spike | MEDIUM | 20+ firewall blocks from one IP in 60s |
| R008 | Credential Stuffing | HIGH | 10+ failed logins to `/login` etc. from one IP in 5min |
| R009 | Vulnerability Scanner | LOW | Known scanner user-agent (sqlmap, nikto, nmap, etc.) |
| R010 | Sensitive File Access | HIGH | Request for `.env`, `.git/config`, `wp-config.php`, etc. |
| R011 | HTTP 5xx Spike | MEDIUM | 10+ server errors from one IP in 2min — fuzzing |
| R012 | RDP Brute Force | CRITICAL | 5+ connection attempts to port 3389 in 60s |

All rules live in `internal/correlator/engine.go` as plain Go functions — adding a new rule means adding one entry to the `loadRules()` slice with an `Evaluate` closure.

---

## 📡 REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats` | Dashboard metrics (events, alerts, top IPs, hourly histogram) |
| GET | `/api/events?source=ssh` | Recent normalized events, optional source filter |
| GET | `/api/alerts?active=true` | All alerts, optional active-only filter |
| POST | `/api/alerts/{id}/resolve` | Mark an alert as resolved |
| POST | `/api/ingest` | Submit a raw log line `{"source":"ssh","line":"..."}` |
| WS | `/api/ws` | Real-time stream of `event`, `alert`, `stats` messages |

---

## 🔌 Feeding Real Logs

Replace the generator with a real ingestion path. Two common patterns:

**1. Tail log files directly** (add to `main.go`):
```go
// e.g. using github.com/hpcloud/tail
t, _ := tail.TailFile("/var/log/nginx/access.log", tail.Config{Follow: true})
for line := range t.Lines {
    if ev, err := parserReg.ParseLine(store.SourceNginx, line.Text); err == nil {
        eventCh <- ev
    }
}
```

**2. Push via the ingest API:**
```bash
curl -X POST http://localhost:8080/api/ingest \
  -H "Content-Type: application/json" \
  -d '{"source":"ssh","line":"Jun 13 10:22:33 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"}'
```
*(Note: the current `/api/ingest` handler validates input but doesn't push to the pipeline yet — wire it to `eventCh` via a shared reference for production use.)*

---

## 🔮 Extending the Project

- **Persistent storage** — swap `MemStore` for PostgreSQL/ClickHouse/Elasticsearch for long-term retention and complex queries
- **Real GeoIP** — integrate MaxMind GeoLite2 or ipinfo.io for accurate IP intelligence
- **Notification channels** — Slack/email/PagerDuty webhooks on CRITICAL alerts
- **Rule persistence** — load/save rules from YAML so SOC analysts can tune thresholds without recompiling
- **Multi-tenancy** — namespace events/alerts per organization
- **MITRE ATT&CK mapping** — tag each rule with corresponding technique IDs
- **Log file tailing** — real-time ingestion from `/var/log/*` using fsnotify