package detection

import (
	"bufio"
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
			return ServiceDetection{
				Name:   "SSH",
				Method: "banner",
			}

		case strings.HasPrefix(lower, "220 "):
			if strings.Contains(lower, "ftp") {
				return ServiceDetection{
					Name:   "FTP",
					Method: "banner",
				}
			}

			if strings.Contains(lower, "smtp") ||
				strings.Contains(lower, "mail") {
				return ServiceDetection{
					Name:   "SMTP",
					Method: "banner",
				}
			}
		}
	}

	if service, ok := commonPorts[port]; ok {
		return ServiceDetection{
			Name:   service,
			Method: "port",
		}
	}

	return ServiceDetection{
		Name:   "unknown",
		Method: "none",
	}
}

func GrabBanner(
	conn net.Conn,
	port int,
	timeout time.Duration,
) string {
	if !supportsPassiveBanner(port) {
		return ""
	}

	if err := conn.SetReadDeadline(
		time.Now().Add(timeout),
	); err != nil {
		return ""
	}

	reader := bufio.NewReader(conn)

	buffer := make([]byte, 1024)

	n, err := reader.Read(buffer)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(
		string(buffer[:n]),
	)
}

func supportsPassiveBanner(port int) bool {
	switch port {
	case 21, 22, 25, 110, 143:
		return true

	default:
		return false
	}
}

func ProbeHTTP(
	target string,
	port int,
	timeout time.Duration,
) (HTTPProbeResult, error) {
	scheme := "http"

	if port == 443 || port == 8443 {
		scheme = "https"
	}

	url := fmt.Sprintf(
		"%s://%s:%d",
		scheme,
		target,
		port,
	)

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(
			req *http.Request,
			via []*http.Request,
		) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest(
		http.MethodHead,
		url,
		nil,
	)
	if err != nil {
		return HTTPProbeResult{}, err
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
