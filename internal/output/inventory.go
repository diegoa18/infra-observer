package output

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"infra-observer/internal/domain"
)

func PrintInventory(
	inventory []domain.InventoryAsset,
) {
	fmt.Println()
	fmt.Println("Infrastructure inventory")
	fmt.Println("========================")

	if len(inventory) == 0 {
		fmt.Println("No inventory entries found.")
		fmt.Println()
		return
	}

	for _, asset := range inventory {
		printInventoryAsset(asset)
	}

	fmt.Println()
}

func printInventoryAsset(
	asset domain.InventoryAsset,
) {
	fmt.Printf(
		"\nHost: %s\n",
		asset.Asset.IP,
	)

	if asset.Asset.Hostname != "" {
		fmt.Printf(
			"Hostname: %s\n",
			asset.Asset.Hostname,
		)
	}

	fmt.Printf(
		"First seen: %s\n",
		asset.FirstSeen.Format(
			time.RFC3339,
		),
	)

	fmt.Printf(
		"Last seen:  %s\n",
		asset.LastSeen.Format(
			time.RFC3339,
		),
	)

	if len(asset.Ports) == 0 {
		fmt.Println("Ports: none observed")
		return
	}

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
		"PORT\tPROTOCOL\tSTATE\tSERVICE\tLAST OBSERVED",
	)

	for _, port := range asset.Ports {
		service := "-"

		if port.Service != nil {
			service = port.Service.Name
		}

		fmt.Fprintf(
			w,
			"%d\t%s\t%s\t%s\t%s\n",
			port.Port,
			port.Protocol,
			port.State,
			service,
			port.LastObservedAt.Format(
				time.RFC3339,
			),
		)
	}

	w.Flush()
}
