package detection

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type ServiceDetection struct {
	Name   string
	Method string
}

type HTTPProbeResult struct {
	StatusCode int
	Server     string
	PoweredBy  string
}

type TLSProbeResult struct {
	Version  string
	Subject  string
	Issuer   string
	SANs     string
	NotAfter string
}

var commonPorts = map[int]string{
	21:   "FTP",
	22:   "SSH",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	143:  "IMAP",
	443:  "HTTPS",
	465:  "SMTPS",
	587:  "SMTP",
	993:  "IMAPS",
	995:  "POP3S",
	3306: "MySQL",
	5432: "PostgreSQL",
	6379: "Redis",
	8080: "HTTP",
	8443: "HTTPS",
}

func DetectService(port int, banner string) ServiceDetection {
	if banner != "" {
		lower := strings.ToLower(banner)
		switch {
		case strings.HasPrefix(lower, "ssh-"):
			return ServiceDetection{Name: "SSH", Method: "banner"}
		case strings.HasPrefix(lower, "220 "):
			if strings.Contains(lower, "ftp") {
				return ServiceDetection{Name: "FTP", Method: "banner"}
			}
			if strings.Contains(lower, "smtp") || strings.Contains(lower, "esmtp") || strings.Contains(lower, "mail") {
				return ServiceDetection{Name: "SMTP", Method: "banner"}
			}
		case strings.HasPrefix(lower, "+ok"):
			return ServiceDetection{Name: "POP3", Method: "banner"}
		case strings.HasPrefix(lower, "* ok"):
			return ServiceDetection{Name: "IMAP", Method: "banner"}
		case strings.Contains(lower, "mariadb") || strings.Contains(lower, "mysql"):
			return ServiceDetection{Name: "MySQL", Method: "banner"}
		case strings.HasPrefix(lower, "-err") || strings.HasPrefix(lower, "+pong") || strings.Contains(lower, "redis"):
			return ServiceDetection{Name: "Redis", Method: "banner"}
		}
	}

	if service, ok := commonPorts[port]; ok {
		return ServiceDetection{Name: service, Method: "port"}
	}
	return ServiceDetection{Name: "unknown", Method: "none"}
}

func GrabBanner(conn net.Conn, port int, timeout time.Duration) string {
	if !SupportsPassiveBanner(port) {
		return ""
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return ""
	}
	reader := bufio.NewReader(conn)
	buffer := make([]byte, 1024)
	n, err := reader.Read(buffer)
	if err != nil {
		return ""
	}
	return sanitizeBanner(buffer[:n])
}

func sanitizeBanner(raw []byte) string {
	const maxBannerLength = 256
	var b strings.Builder
	b.Grow(len(raw))
	lastWasSpace := false

	for _, ch := range raw {
		if ch == '\r' || ch == '\n' || ch == '\t' || ch == ' ' {
			if b.Len() > 0 && !lastWasSpace {
				b.WriteByte(' ')
				lastWasSpace = true
			}
			continue
		}
		if ch >= 0x20 && ch <= 0x7e {
			b.WriteByte(ch)
			lastWasSpace = false
			if b.Len() >= maxBannerLength {
				break
			}
		}
	}
	return strings.TrimSpace(b.String())
}

func SupportsPassiveBanner(port int) bool {
	switch port {
	case 21, 22, 25, 110, 143, 587, 3306:
		return true
	default:
		return false
	}
}

func SupportsTLSProbe(port int, serviceName string) bool {
	switch serviceName {
	case "HTTPS", "SMTPS", "IMAPS", "POP3S":
		return true
	}
	switch port {
	case 443, 465, 993, 995, 8443:
		return true
	default:
		return false
	}
}

func ProbeHTTP(
	ctx context.Context,
	targetIP string,
	hostname string,
	port int,
	timeout time.Duration,
) (HTTPProbeResult, error) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d", scheme, targetIP, port)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         hostname,
		},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return HTTPProbeResult{}, err
	}

	if hostname != "" {
		req.Host = hostname
	}

	resp, err := client.Do(req)
	if err != nil {
		return HTTPProbeResult{}, err
	}
	defer resp.Body.Close()

	return HTTPProbeResult{
		StatusCode: resp.StatusCode,
		Server:     resp.Header.Get("Server"),
		PoweredBy:  resp.Header.Get("X-Powered-By"),
	}, nil
}

func ProbeTLS(
	ctx context.Context,
	targetIP string,
	hostname string,
	port int,
	timeout time.Duration,
) (TLSProbeResult, error) {
	address := net.JoinHostPort(targetIP, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: timeout}

	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 && remaining < dialer.Timeout {
			dialer.Timeout = remaining
		}
	}

	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		address,
		&tls.Config{
			InsecureSkipVerify: true,
			ServerName:         hostname,
		},
	)
	if err != nil {
		return TLSProbeResult{}, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result := TLSProbeResult{
		Version: tlsVersionName(state.Version),
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Subject = cert.Subject.CommonName
		if result.Subject == "" && len(cert.Subject.Organization) > 0 {
			result.Subject = cert.Subject.Organization[0]
		}
		result.Issuer = cert.Issuer.CommonName
		if result.Issuer == "" && len(cert.Issuer.Organization) > 0 {
			result.Issuer = cert.Issuer.Organization[0]
		}
		if len(cert.DNSNames) > 0 {
			result.SANs = strings.Join(cert.DNSNames, ",")
		}
		result.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	}

	return result, nil
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}
