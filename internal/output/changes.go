package output

import (
	"fmt"
	"os"
	"text/tabwriter"

	"infra-observer/internal/change"
)

func PrintChanges(result change.Result) {
	fmt.Println()
	fmt.Printf(
		"Changes for %s\n",
		result.Current.Asset.IP,
	)
	fmt.Println("====================")

	fmt.Printf(
		"Previous observation: %s\n",
		result.Previous.ObservedAt.Format(
			"2006-01-02 15:04:05 MST",
		),
	)

	fmt.Printf(
		"Current observation:  %s\n",
		result.Current.ObservedAt.Format(
			"2006-01-02 15:04:05 MST",
		),
	)

	if result.Empty() {
		fmt.Println("No changes detected.")
		fmt.Println()
		return
	}

	printPortChanges(result.Ports)
	printServiceChanges(result.Services)

	fmt.Println()
}

func printPortChanges(changes []change.PortChange) {
	if len(changes) == 0 {
		return
	}

	fmt.Println("Port changes:")

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
		"PORT\tPROTOCOL\tBEFORE\tAFTER",
	)

	for _, item := range changes {
		fmt.Fprintf(
			w,
			"%d\t%s\t%s\t%s\n",
			item.Port,
			item.Protocol,
			item.Before,
			item.After,
		)
	}

	w.Flush()
}

func printServiceChanges(
	changes []change.ServiceChange,
) {
	if len(changes) == 0 {
		return
	}

	fmt.Println("Service changes:")

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
		"TYPE\tPORT\tPROTOCOL\tBEFORE\tAFTER",
	)

	for _, item := range changes {
		fmt.Fprintf(
			w,
			"%s\t%d\t%s\t%s\t%s\n",
			item.Kind,
			item.Port,
			item.Protocol,
			serviceDescription(
				item.BeforeName,
				item.BeforeState,
			),
			serviceDescription(
				item.AfterName,
				item.AfterState,
			),
		)
	}

	w.Flush()
}

func serviceDescription(
	name string,
	state string,
) string {
	if name == "" {
		return "-"
	}

	if state == "" {
		return name
	}

	return fmt.Sprintf(
		"%s (%s)",
		name,
		state,
	)
}
