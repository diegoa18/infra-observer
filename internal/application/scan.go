package application

import (
	"context"
	"fmt"
	"net"
	"time"

	"infra-observer/internal/detection"
	"infra-observer/internal/discovery"
	"infra-observer/internal/domain"
	"infra-observer/internal/scanner"
)

type ScanOptions struct {
	Ports       []int
	Timeout     time.Duration
	Concurrency int
	Discovery   bool
	HTTPProbe   bool
}

type ScanService struct{}

func NewScanService() *ScanService {
	return &ScanService{}
}

func (s *ScanService) Scan(
	ctx context.Context,
	targets []string,
	opts ScanOptions,
) ([]domain.Observation, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets provided")
	}

	if len(opts.Ports) == 0 {
		return nil, fmt.Errorf("no ports provided")
	}

	if opts.Timeout <= 0 {
		return nil, fmt.Errorf("timeout must be greater than zero")
	}

	if opts.Concurrency <= 0 {
		opts.Concurrency = 100
	}

	var observations []domain.Observation

	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return observations, err
		}

		discoveryResult, err := s.discover(
			ctx,
			target,
			opts,
		)
		if err != nil {
			return observations, fmt.Errorf(
				"discover %s: %w",
				target,
				err,
			)
		}

		if !discoveryResult.Alive {
			continue
		}

		portResults := scanner.ScanPorts(
			ctx,
			target,
			opts.Ports,
			opts.Timeout,
			opts.Concurrency,
		)

		portObservations := make(
			[]domain.PortObservation,
			0,
			len(portResults),
		)

		for _, result := range portResults {
			portObservations = append(
				portObservations,
				domain.PortObservation{
					Port:     result.Port,
					Protocol: "tcp",
					State:    string(result.State),
				},
			)
		}

		services := detectServices(
			ctx,
			target,
			portResults,
			opts,
		)

		observation := domain.Observation{
			ObservedAt: time.Now(),
			Asset: domain.Asset{
				IP: target,
			},
			Discovery: domain.DiscoveryEvidence{
				Method: discoveryResult.Method,
				RTT:    discoveryResult.RTT,
				Reason: discoveryResult.Reason,
			},
			Ports:    portObservations,
			Services: services,
		}

		observations = append(
			observations,
			observation,
		)
	}

	return observations, nil
}

func (s *ScanService) discover(
	ctx context.Context,
	target string,
	opts ScanOptions,
) (discovery.Result, error) {
	if !opts.Discovery {
		return discovery.Result{
			IP:        target,
			Alive:     true,
			Method:    "skipped",
			Reason:    "discovery-disabled",
			Timestamp: time.Now(),
		}, nil
	}

	icmpResult, icmpErr := discovery.DiscoverHost(
		ctx,
		target,
		opts.Timeout,
	)

	if icmpErr == nil && icmpResult.Alive {
		return icmpResult, nil
	}

	if ctx.Err() != nil {
		return icmpResult, ctx.Err()
	}

	tcpResult, tcpErr := discovery.DiscoverHostTCP(
		ctx,
		target,
		opts.Timeout,
	)

	if tcpErr == nil && tcpResult.Alive {
		return tcpResult, nil
	}

	if tcpErr != nil && icmpErr != nil {
		return icmpResult, fmt.Errorf(
			"ICMP discovery failed: %v; TCP discovery failed: %w",
			icmpErr,
			tcpErr,
		)
	}

	if tcpErr != nil {
		return tcpResult, tcpErr
	}

	return tcpResult, nil
}

func detectServices(
	ctx context.Context,
	target string,
	portResults []scanner.PortResult,
	opts ScanOptions,
) []domain.Service {
	var services []domain.Service

	for _, result := range portResults {
		if err := ctx.Err(); err != nil {
			return services
		}

		if result.State != scanner.PortOpen {
			continue
		}

		banner := grabPassiveBanner(
			ctx,
			target,
			result.Port,
			opts.Timeout,
		)

		detectionResult := detection.DetectService(
			result.Port,
			banner,
		)

		service := domain.Service{
			Port:     result.Port,
			Protocol: "tcp",
			Name:     detectionResult.Name,
			State:    domain.ServiceAccessible,
			Banner:   banner,
			Metadata: map[string]string{
				"detection_method": detectionResult.Method,
			},
		}

		if opts.HTTPProbe &&
			(detectionResult.Name == "HTTP" ||
				detectionResult.Name == "HTTPS") {
			probeResult, err := detection.ProbeHTTP(
				target,
				result.Port,
				opts.Timeout,
			)

			if err == nil {
				if probeResult.StatusCode != 0 {
					service.Metadata["http_status_code"] =
						fmt.Sprintf(
							"%d",
							probeResult.StatusCode,
						)
				}

				if probeResult.Server != "" {
					service.Metadata["http_server"] =
						probeResult.Server
				}

				if probeResult.PoweredBy != "" {
					service.Metadata["http_powered_by"] =
						probeResult.PoweredBy
				}
			}
		}

		services = append(
			services,
			service,
		)
	}

	return services
}

func grabPassiveBanner(
	ctx context.Context,
	target string,
	port int,
	timeout time.Duration,
) string {
	if ctx.Err() != nil {
		return ""
	}

	address := net.JoinHostPort(
		target,
		fmt.Sprintf("%d", port),
	)

	dialer := net.Dialer{
		Timeout: timeout,
	}

	conn, err := dialer.DialContext(
		ctx,
		"tcp",
		address,
	)
	if err != nil {
		return ""
	}

	defer conn.Close()

	return detection.GrabBanner(
		conn,
		port,
		timeout,
	)
}
