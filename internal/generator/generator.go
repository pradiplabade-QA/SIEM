package generator

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/yourusername/siem/internal/parser"
	"github.com/yourusername/siem/internal/store"
)

// Generator produces realistic synthetic log lines for demo purposes
type Generator struct {
	registry *parser.Registry
	eventCh  chan *store.LogEvent
}

func New(reg *parser.Registry, ch chan *store.LogEvent) *Generator {
	return &Generator{registry: reg, eventCh: ch}
}

var (
	normalIPs   = []string{"10.0.0.50", "192.168.1.10", "192.168.1.22", "172.16.0.5", "10.10.1.100"}
	attackerIPs = []string{
		"185.220.101.55", "45.33.32.156", "198.199.119.161",
		"209.141.36.214", "104.236.247.8", "23.92.20.19",
		"95.142.46.35", "80.82.77.33",
	}
	usernames   = []string{"admin", "root", "ubuntu", "deploy", "git", "mysql", "www-data"}
	normalPaths = []string{"/", "/index.html", "/about", "/contact", "/api/health", "/static/main.js", "/favicon.ico"}
	attackPaths = []string{
		"/?id=1' OR '1'='1", "/wp-login.php", "/../../../etc/passwd",
		"/admin/config.php", "/.env", "/?q=<script>alert(1)</script>",
		"/login?user=admin'--", "/phpmyadmin/", "/?page=../../../../etc/shadow",
		"/xmlrpc.php", "/.git/config", "/backup.sql",
	}
	months = []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
)

func randIP(attacker bool) string {
	if attacker {
		return attackerIPs[rand.Intn(len(attackerIPs))]
	}
	return normalIPs[rand.Intn(len(normalIPs))]
}

func ts() string {
	now := time.Now()
	return fmt.Sprintf("%s %2d %02d:%02d:%02d", months[now.Month()-1], now.Day(), now.Hour(), now.Minute(), now.Second())
}

func nginxLine(ip, method, path string, status int, ua string) string {
	return fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d %d "https://example.com" "%s"`,
		ip,
		time.Now().Format("02/Jan/2006:15:04:05 -0700"),
		method, path, status, rand.Intn(5000)+200, ua)
}

func sshLine(ip, user string, success bool) string {
	t := ts()
	if success {
		return fmt.Sprintf("%s server01 sshd[%d]: Accepted password for %s from %s port %d ssh2",
			t, rand.Intn(9000)+1000, user, ip, rand.Intn(40000)+20000)
	}
	return fmt.Sprintf("%s server01 sshd[%d]: Failed password for %s from %s port %d ssh2",
		t, rand.Intn(9000)+1000, user, ip, rand.Intn(40000)+20000)
}

func firewallLine(ip string, port int, action string) string {
	protos := []string{"TCP", "UDP"}
	proto := protos[rand.Intn(len(protos))]
	return fmt.Sprintf("%s server01 kernel: [UFW %s] IN=eth0 OUT= SRC=%s DST=10.0.0.1 PROTO=%s SPT=%d DPT=%d",
		ts(), action, ip, proto, rand.Intn(40000)+20000, port)
}

func authLine(user, targetUser, cmd string) string {
	return fmt.Sprintf("%s server01 sudo: %s : TTY=pts/0 ; PWD=/home/%s ; USER=%s ; COMMAND=%s",
		ts(), user, user, targetUser, cmd)
}

func syslogLine(process, msg string) string {
	return fmt.Sprintf("%s server01 %s[%d]: %s", ts(), process, rand.Intn(9000)+100, msg)
}

// StartNormal generates steady background traffic (legit + noisy)
func (g *Generator) StartNormal(interval time.Duration) {
	go func() {
		for {
			time.Sleep(interval)
			ip := randIP(false)
			path := normalPaths[rand.Intn(len(normalPaths))]
			uas := []string{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
				"curl/7.68.0",
			}
			ua := uas[rand.Intn(len(uas))]
			statuses := []int{200, 200, 200, 304, 404}
			status := statuses[rand.Intn(len(statuses))]

			lines := []struct {
				src  store.LogSource
				line string
			}{
				{store.SourceNginx, nginxLine(ip, "GET", path, status, ua)},
				{store.SourceSSH, sshLine(randIP(false), usernames[rand.Intn(len(usernames))], rand.Intn(5) == 0)},
				{store.SourceFirewall, firewallLine(ip, []int{80, 443, 22, 8080}[rand.Intn(4)], "ALLOW")},
				{store.SourceSyslog, syslogLine("cron", "Job completed successfully")},
			}
			line := lines[rand.Intn(len(lines))]
			if ev, err := g.registry.ParseLine(line.src, line.line); err == nil {
				g.eventCh <- ev
			}
		}
	}()
}

// StartAttacks injects realistic attack traffic to trigger correlation rules
func (g *Generator) StartAttacks() {
	// SSH Brute Force burst
	go func() {
		for {
			time.Sleep(time.Duration(rand.Intn(30)+20) * time.Second)
			ip := attackerIPs[rand.Intn(len(attackerIPs))]
			count := rand.Intn(10) + 6 // 6-15 failures
			for i := 0; i < count; i++ {
				user := usernames[rand.Intn(len(usernames))]
				line := sshLine(ip, user, false)
				if ev, err := g.registry.ParseLine(store.SourceSSH, line); err == nil {
					g.eventCh <- ev
					time.Sleep(300 * time.Millisecond)
				}
			}
		}
	}()

	// Port Scan
	go func() {
		for {
			time.Sleep(time.Duration(rand.Intn(45)+30) * time.Second)
			ip := attackerIPs[rand.Intn(len(attackerIPs))]
			ports := []int{21, 22, 23, 25, 80, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017}
			for _, port := range ports {
				action := "BLOCK"
				if port == 80 || port == 443 {
					action = "ALLOW"
				}
				line := firewallLine(ip, port, action)
				if ev, err := g.registry.ParseLine(store.SourceFirewall, line); err == nil {
					g.eventCh <- ev
					time.Sleep(100 * time.Millisecond)
				}
			}
		}
	}()

	// Web Attacks: SQLi, XSS, traversal
	go func() {
		for {
			time.Sleep(time.Duration(rand.Intn(15)+8) * time.Second)
			ip := attackerIPs[rand.Intn(len(attackerIPs))]
			path := attackPaths[rand.Intn(len(attackPaths))]
			scannerUAs := []string{
				"sqlmap/1.7.8#stable (https://sqlmap.org)",
				"Nikto/2.1.6",
				"Mozilla/5.0 (compatible; Nuclei)",
				"python-requests/2.28.0", // generic, often scanners
				"Mozilla/5.0 zgrab/0.x",
			}
			ua := scannerUAs[rand.Intn(len(scannerUAs))]
			statuses := []int{200, 403, 404, 500}
			line := nginxLine(ip, "GET", path, statuses[rand.Intn(len(statuses))], ua)
			if ev, err := g.registry.ParseLine(store.SourceNginx, line); err == nil {
				g.eventCh <- ev
			}
		}
	}()

	// RDP Brute Force via firewall
	go func() {
		for {
			time.Sleep(time.Duration(rand.Intn(60)+60) * time.Second)
			ip := attackerIPs[rand.Intn(len(attackerIPs))]
			for i := 0; i < rand.Intn(8)+5; i++ {
				line := firewallLine(ip, 3389, "BLOCK")
				if ev, err := g.registry.ParseLine(store.SourceFirewall, line); err == nil {
					g.eventCh <- ev
					time.Sleep(400 * time.Millisecond)
				}
			}
		}
	}()

	// Privilege Escalation
	go func() {
		for {
			time.Sleep(time.Duration(rand.Intn(120)+60) * time.Second)
			users := []string{"deploy", "ubuntu", "git", "www-data"}
			user := users[rand.Intn(len(users))]
			cmds := []string{"/bin/bash", "/usr/bin/passwd", "/bin/su -", "/usr/bin/id", "/bin/chmod 777 /etc/passwd"}
			for i := 0; i < 3; i++ {
				line := authLine(user, "root", cmds[rand.Intn(len(cmds))])
				if ev, err := g.registry.ParseLine(store.SourceAuth, line); err == nil {
					g.eventCh <- ev
					time.Sleep(500 * time.Millisecond)
				}
			}
		}
	}()

	// Credential stuffing on login endpoint
	go func() {
		for {
			time.Sleep(time.Duration(rand.Intn(30)+20) * time.Second)
			ip := attackerIPs[rand.Intn(len(attackerIPs))]
			loginPaths := []string{"/login", "/wp-login.php", "/admin/login", "/auth/signin"}
			path := loginPaths[rand.Intn(len(loginPaths))]
			for i := 0; i < rand.Intn(8)+10; i++ {
				line := nginxLine(ip, "POST", path, 401, "Mozilla/5.0 (compatible)")
				if ev, err := g.registry.ParseLine(store.SourceNginx, line); err == nil {
					g.eventCh <- ev
					time.Sleep(200 * time.Millisecond)
				}
			}
		}
	}()
}
