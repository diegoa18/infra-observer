package detection

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestDetectServiceByPort(t *testing.T) {
	tests := []struct {
		name string
		port int
		want string
	}{
		{
			name: "ftp",
			port: 21,
			want: "FTP",
		},
		{
			name: "ssh",
			port: 22,
			want: "SSH",
		},
		{
			name: "dns",
			port: 53,
			want: "DNS",
		},
		{
			name: "http",
			port: 80,
			want: "HTTP",
		},
		{
			name: "https",
			port: 443,
			want: "HTTPS",
		},
		{
			name: "mysql",
			port: 3306,
			want: "MySQL",
		},
		{
			name: "postgresql",
			port: 5432,
			want: "PostgreSQL",
		},
		{
			name: "redis",
			port: 6379,
			want: "Redis",
		},
		{
			name: "unknown",
			port: 9999,
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectService(
				tt.port,
				"",
			)

			if got.Name != tt.want {
				t.Fatalf(
					"DetectService() = %q, want %q",
					got.Name,
					tt.want,
				)
			}

			if tt.want == "unknown" && got.Method != "none" {
				t.Fatalf(
					"unknown service method = %q, want %q",
					got.Method,
					"none",
				)
			}
		})
	}
}

func TestDetectServiceByBanner(t *testing.T) {
	tests := []struct {
		name   string
		port   int
		banner string
		want   string
	}{
		{
			name:   "ssh",
			port:   22,
			banner: "SSH-2.0-OpenSSH_9.0",
			want:   "SSH",
		},
		{
			name:   "ftp",
			port:   21,
			banner: "220 FTP server ready",
			want:   "FTP",
		},
		{
			name:   "smtp",
			port:   25,
			banner: "220 smtp.example.com ESMTP",
			want:   "SMTP",
		},
		{
			name:   "pop3",
			port:   110,
			banner: "+OK Dovecot ready.",
			want:   "POP3",
		},
		{
			name:   "imap",
			port:   143,
			banner: "* OK [CAPABILITY IMAP4rev1] Dovecot ready.",
			want:   "IMAP",
		},
		{
			name:   "mysql",
			port:   3306,
			banner: "J 8.0.36-0ubuntu0.22.04.1 mysql_native_password",
			want:   "MySQL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectService(
				tt.port,
				tt.banner,
			)

			if got.Name != tt.want {
				t.Fatalf(
					"DetectService() = %q, want %q",
					got.Name,
					tt.want,
				)
			}

			if got.Method != "banner" {
				t.Fatalf(
					"DetectService() method = %q, want %q",
					got.Method,
					"banner",
				)
			}
		})
	}
}

func TestSanitizeBannerStripsNullAndControlBytes(t *testing.T) {
	raw := []byte("J\x00\x00\x00\x0a8.0.36-MariaDB\x00\x1b[31mmysql_native_password\x00\r\n")
	got := sanitizeBanner(raw)
	want := "J 8.0.36-MariaDB[31mmysql_native_password"

	if got != want {
		t.Fatalf("sanitizeBanner() = %q, want %q", got, want)
	}
}

func TestProbeTLSAndHTTPSWithSelfSignedCert(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "infra-test-tls")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	parsedURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	host, portStr, err := net.SplitHostPort(parsedURL.Host)
	if err != nil {
		t.Fatalf("net.SplitHostPort() error = %v", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("strconv.Atoi() error = %v", err)
	}

	tlsResult, err := ProbeTLS(context.Background(), host, host, port, time.Second)
	if err != nil {
		t.Fatalf("ProbeTLS() error = %v", err)
	}

	if tlsResult.Version == "" || tlsResult.Version == "unknown" {
		t.Fatalf("expected valid TLS version, got %q", tlsResult.Version)
	}

	if tlsResult.NotAfter == "" {
		t.Fatal("expected certificate NotAfter timestamp")
	}
}
