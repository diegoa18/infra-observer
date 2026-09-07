package detection

import "testing"

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
