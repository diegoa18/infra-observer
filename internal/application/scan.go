package application

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"infra-observer/internal/detection"
	"infra-observer/internal/discovery"
	"infra-observer/internal/domain"
	"infra-observer/internal/scanner"
)

const maxConcurrentHosts = 16

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

type targetScanOutcome struct {
	observation domain.Observation
	alive       bool
	err         error
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

	hostWorkers := len(targets)
	if hostWorkers > maxConcurrentHosts {
		hostWorkers = maxConcurrentHosts
	}

	outcomes := make([]targetScanOutcome, len(targets))
	jobs := make(chan int)

	var wg sync.WaitGroup

	for worker := 0; worker < hostWorkers; worker++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for index := range jobs {
				if ctx.Err() != nil {
					return
				}

				obs, alive, err := s.scanTarget(
					ctx,
					targets[index],
					opts,
				)

				outcomes[index] = targetScanOutcome{
					observation: obs,
					alive:       alive,
					err:         err,
				}
			}
		}()
	}

dispatch:
	for index := range targets {
		select {
		case <-ctx.Done():
			break dispatch
		case jobs <- index:
		}
	}

	close(jobs)
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var observations []domain.Observation

	for index, outcome := range outcomes {
		if outcome.err != nil {
			if len(targets) == 1 {
				return nil, fmt.Errorf(
					"discover %s: %w",
					targets[index],
					outcome.err,
				)
			}
			continue
		}

		if !outcome.alive {
			continue
		}

		observations = append(
			observations,
			outcome.observation,
		)
	}

	return observations, nil
}

func (s *ScanService) scanTarget(
	ctx context.Context,
	target string,
	opts ScanOptions,
) (domain.Observation, bool, error) {
	discoveryResult, err := s.discover(
		ctx,
		target,
		opts,
	)
	if err != nil {
		return domain.Observation{}, false, err
	}

	if !discoveryResult.Alive {
		return domain.Observation{}, false, nil
	}

	portResults := scanner.ScanPorts(
		ctx,
		target,
		opts.Ports,
		opts.Timeout,
		opts.Concurrency,
	)

	if err := ctx.Err(); err != nil {
		return domain.Observation{}, false, err
	}

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

	if err := ctx.Err(); err != nil {
		return domain.Observation{}, false, err
	}

	hostname := resolveHostname(
		ctx,
		target,
		opts.Timeout,
	)

	observation := domain.Observation{
		ObservedAt: time.Now(),
		Asset: domain.Asset{
			IP:       target,
			Hostname: hostname,
		},
		Discovery: domain.DiscoveryEvidence{
			Method: discoveryResult.Method,
			RTT:    discoveryResult.RTT,
			Reason: discoveryResult.Reason,
		},
		Ports:    portObservations,
		Services: services,
	}

	return observation, true, nil
}

func (s *ScanService) discover(
	ctx context.Context,
	target string,
	opts ScanOptions,
) (discovery.Result, error) {
	if !opts.Discovery {
		return discovery.Result{
			IP:     target,
			Alive:  true,
			Method: "skipped",
			Reason: "discovery-disabled",
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
		opts.Ports...,
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

func resolveHostname(
	ctx context.Context,
	ip string,
	timeout time.Duration,
) string {
	lookupCtx, cancel := context.WithTimeout(
		ctx,
		timeout,
	)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(
		lookupCtx,
		ip,
	)
	if err != nil || len(names) == 0 {
		return ""
	}

	return strings.TrimSuffix(
		names[0],
		".",
	)
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

		if opts.HTTPProbe {
			if detectionResult.Name == "HTTP" ||
				detectionResult.Name == "HTTPS" {
				probeResult, err := detection.ProbeHTTP(
					ctx,
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

			if detection.SupportsTLSProbe(result.Port, detectionResult.Name) {
				tlsResult, err := detection.ProbeTLS(
					ctx,
					target,
					result.Port,
					opts.Timeout,
				)

				if err == nil {
					if tlsResult.Version != "" {
						service.Metadata["tls_version"] = tlsResult.Version
					}

					if tlsResult.Subject != "" {
						service.Metadata["tls_subject"] = tlsResult.Subject
					}

					if tlsResult.Issuer != "" {
						service.Metadata["tls_issuer"] = tlsResult.Issuer
					}

					if tlsResult.SANs != "" {
						service.Metadata["tls_sans"] = tlsResult.SANs
					}

					if tlsResult.NotAfter != "" {
						service.Metadata["tls_not_after"] = tlsResult.NotAfter
					}
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
	if !detection.SupportsPassiveBanner(port) {
		return ""
	}

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
