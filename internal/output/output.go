package output

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"infra-observer/internal/domain"
)

func PrintObservations(observations []domain.Observation) {
	if len(observations) == 0 {
		fmt.Println("No active hosts found.")
		return
	}

	sort.Slice(observations, func(i, j int) bool {
		return observations[i].Asset.IP < observations[j].Asset.IP
	})

	fmt.Println()
	fmt.Println("Network observations")
	fmt.Println("====================")

	for _, observation := range observations {
		fmt.Printf(
			"\nHost: %s\n",
			observation.Asset.IP,
		)

		if observation.Asset.Hostname != "" {
			fmt.Printf(
				"Hostname: %s\n",
				observation.Asset.Hostname,
			)
		}

		fmt.Printf(
			"Discovery: %s (%s)\n",
			observation.Discovery.Method,
			observation.Discovery.Reason,
		)

		if observation.Discovery.RTT > 0 {
			fmt.Printf(
				"RTT: %v\n",
				observation.Discovery.RTT,
			)
		}

		printPorts(observation.Ports)
		printServices(observation.Services)
	}

	fmt.Println()
}

func printPorts(ports []domain.PortObservation) {
	if len(ports) == 0 {
		fmt.Println("Ports: none observed")
		return
	}

	portsCopy := append(
		[]domain.PortObservation(nil),
		ports...,
	)

	sort.Slice(portsCopy, func(i, j int) bool {
		return portsCopy[i].Port < portsCopy[j].Port
	})

	fmt.Println("Ports:")

	w := tabwriter.NewWriter(
		os.Stdout,
		0,
		0,
		2,
		' ',
		0,
	)

	fmt.Fprintln(
		w,
		"PORT\tPROTOCOL\tSTATE",
	)

	for _, port := range portsCopy {
		fmt.Fprintf(
			w,
			"%d\t%s\t%s\n",
			port.Port,
			port.Protocol,
			port.State,
		)
	}

	w.Flush()
}

func printServices(services []domain.Service) {
	if len(services) == 0 {
		fmt.Println("Services: none detected")
		return
	}

	servicesCopy := append(
		[]domain.Service(nil),
		services...,
	)

	sort.Slice(servicesCopy, func(i, j int) bool {
		return servicesCopy[i].Port < servicesCopy[j].Port
	})

	fmt.Println("Services:")

	w := tabwriter.NewWriter(
		os.Stdout,
		0,
		0,
		2,
		' ',
		0,
	)

	fmt.Fprintln(
		w,
		"PORT\tPROTOCOL\tSERVICE\tSTATE\tDETAILS",
	)

	for _, service := range servicesCopy {
		fmt.Fprintf(
			w,
			"%d\t%s\t%s\t%s\t%s\n",
			service.Port,
			service.Protocol,
			service.Name,
			service.State,
			formatServiceDetails(&service),
		)
	}

	w.Flush()
}

func formatServiceDetails(service *domain.Service) string {
	if service == nil {
		return "-"
	}

	var parts []string

	if service.Banner != "" {
		parts = append(
			parts,
			fmt.Sprintf("banner=%q", service.Banner),
		)
	}

	if len(service.Metadata) > 0 {
		keys := make([]string, 0, len(service.Metadata))
		for k, v := range service.Metadata {
			if k == "detection_method" || v == "" {
				continue
			}
			keys = append(keys, k)
		}

		sort.Strings(keys)

		for _, k := range keys {
			parts = append(
				parts,
				fmt.Sprintf("%s=%s", k, service.Metadata[k]),
			)
		}
	}

	if len(parts) == 0 {
		return "-"
	}

	return strings.Join(parts, ", ")
}
