package output

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"go-scanner/internal/domain"
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

		if len(observation.Services) == 0 {
			fmt.Println("Services: none detected")
			continue
		}

		services := append(
			[]domain.Service(nil),
			observation.Services...,
		)

		sort.Slice(services, func(i, j int) bool {
			return services[i].Port < services[j].Port
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
			"PORT\tPROTOCOL\tSERVICE\tSTATE",
		)

		for _, service := range services {
			fmt.Fprintf(
				w,
				"%d\t%s\t%s\t%s\n",
				service.Port,
				service.Protocol,
				service.Name,
				service.State,
			)
		}

		w.Flush()
	}

	fmt.Println()
}
