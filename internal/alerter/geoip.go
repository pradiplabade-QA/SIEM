package alerter

import (
	"github.com/yourusername/siem/internal/store"
)

// MockGeoIP provides realistic geographic data for demo IPs
// In production, replace with MaxMind GeoLite2 or ip-api.com
func EnrichIP(ip string, s *store.MemStore) *store.GeoIP {
	// Check cache first
	if geo := s.GeoCache[ip]; geo != nil {
		return geo
	}

	geo := lookupMock(ip)
	if geo != nil {
		s.CacheGeo(ip, geo)
	}
	return geo
}

func lookupMock(ip string) *store.GeoIP {
	// Mock database mapping known attacker IPs to locations
	db := map[string]*store.GeoIP{
		"185.220.101.55":  {IP: "185.220.101.55", Country: "Germany", CountryCode: "DE", City: "Frankfurt", Lat: 50.1109, Lon: 8.6821, ISP: "Tor Exit Node", ThreatScore: 95},
		"45.33.32.156":    {IP: "45.33.32.156", Country: "United States", CountryCode: "US", City: "Fremont", Lat: 37.5485, Lon: -121.9886, ISP: "Linode", ThreatScore: 72},
		"198.199.119.161": {IP: "198.199.119.161", Country: "United States", CountryCode: "US", City: "New York", Lat: 40.7128, Lon: -74.0060, ISP: "DigitalOcean", ThreatScore: 81},
		"209.141.36.214":  {IP: "209.141.36.214", Country: "United States", CountryCode: "US", City: "Las Vegas", Lat: 36.1699, Lon: -115.1398, ISP: "Frantech Solutions", ThreatScore: 88},
		"104.236.247.8":   {IP: "104.236.247.8", Country: "United States", CountryCode: "US", City: "San Francisco", Lat: 37.7749, Lon: -122.4194, ISP: "DigitalOcean", ThreatScore: 65},
		"23.92.20.19":     {IP: "23.92.20.19", Country: "Russia", CountryCode: "RU", City: "Moscow", Lat: 55.7558, Lon: 37.6173, ISP: "Hosting Ukraine", ThreatScore: 92},
		"95.142.46.35":    {IP: "95.142.46.35", Country: "China", CountryCode: "CN", City: "Beijing", Lat: 39.9042, Lon: 116.4074, ISP: "ChinaNet", ThreatScore: 85},
		"80.82.77.33":     {IP: "80.82.77.33", Country: "Netherlands", CountryCode: "NL", City: "Amsterdam", Lat: 52.3676, Lon: 4.9041, ISP: "Shadowserver", ThreatScore: 78},
		// Normal IPs
		"10.0.0.50":    {IP: "10.0.0.50", Country: "Private", CountryCode: "--", City: "LAN", Lat: 0, Lon: 0, ISP: "Internal", ThreatScore: 0},
		"192.168.1.10": {IP: "192.168.1.10", Country: "Private", CountryCode: "--", City: "LAN", Lat: 0, Lon: 0, ISP: "Internal", ThreatScore: 0},
		"192.168.1.22": {IP: "192.168.1.22", Country: "Private", CountryCode: "--", City: "LAN", Lat: 0, Lon: 0, ISP: "Internal", ThreatScore: 0},
		"172.16.0.5":   {IP: "172.16.0.5", Country: "Private", CountryCode: "--", City: "LAN", Lat: 0, Lon: 0, ISP: "Internal", ThreatScore: 0},
		"10.10.1.100":  {IP: "10.10.1.100", Country: "Private", CountryCode: "--", City: "LAN", Lat: 0, Lon: 0, ISP: "Internal", ThreatScore: 0},
	}
	if g, ok := db[ip]; ok {
		return g
	}
	// Generic unknown IP
	return &store.GeoIP{IP: ip, Country: "Unknown", CountryCode: "??", City: "Unknown", ThreatScore: 30}
}
