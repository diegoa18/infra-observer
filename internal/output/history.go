package output

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"infra-observer/internal/domain"
)

func PrintHistory(
	target string,
	observations []domain.Observation,
) {
	fmt.Println()
	fmt.Printf("History for %s\n", target)
	fmt.Println("====================")

	if len(observations) == 0 {
		fmt.Println("No stored observations.")
		fmt.Println()
		return
	}

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
		"OBSERVED AT\tOPEN\tCLOSED\tUNKNOWN\tSERVICES\tDISCOVERY",
	)

	for _, observation := range observations {
		open, closed, unknown := countPortStates(
			observation.Ports,
		)

		fmt.Fprintf(
			w,
			"%s\t%d\t%d\t%d\t%d\t%s\n",
			observation.ObservedAt.Format(
				time.RFC3339,
			),
			open,
			closed,
			unknown,
			len(observation.Services),
			observation.Discovery.Method,
		)
	}

	w.Flush()
	fmt.Println()
}

func countPortStates(
	ports []domain.PortObservation,
) (
	open int,
	closed int,
	unknown int,
) {
	for _, port := range ports {
		switch port.State {
		case "open":
			open++

		case "closed":
			closed++

		default:
			unknown++
		}
	}

	return open, closed, unknown
}
