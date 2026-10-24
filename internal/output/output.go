package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"infra-observer/internal/change"
	"infra-observer/internal/domain"
)

func PrintObservations(observations []domain.Observation, asJSON bool) {
	if asJSON {
		printJSON(observations)
		return
	}

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

func PrintInventory(inventory []domain.InventoryAsset, asJSON bool) {
	if asJSON {
		printJSON(inventory)
		return
	}

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

func PrintHistory(target string, observations []domain.Observation, asJSON bool) {
	if asJSON {
		printJSON(observations)
		return
	}

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
				"2006-01-02 15:04:05 MST",
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

func PrintChanges(result change.Result, asJSON bool) {
	if asJSON {
		printJSON(result)
		return
	}

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

func printJSON(v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error encoding json: %v\n", err)
		return
	}
	fmt.Println(string(data))
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
			"2006-01-02 15:04:05 MST",
		),
	)

	fmt.Printf(
		"Last seen:  %s\n",
		asset.LastSeen.Format(
			"2006-01-02 15:04:05 MST",
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
		"PORT\tPROTOCOL\tSTATE\tSERVICE\tLAST OBSERVED\tDETAILS",
	)

	for _, port := range asset.Ports {
		service := "-"

		if port.Service != nil {
			service = port.Service.Name
		}

		fmt.Fprintf(
			w,
			"%d\t%s\t%s\t%s\t%s\t%s\n",
			port.Port,
			port.Protocol,
			port.State,
			service,
			port.LastObservedAt.Format(
				"2006-01-02 15:04:05 MST",
			),
			formatServiceDetails(port.Service),
		)
	}

	w.Flush()
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
		"TYPE\tPORT\tPROTOCOL\tSERVICE\tDETAILS",
	)

	for _, item := range changes {
		serviceDesc := serviceDescription(item.BeforeName, item.BeforeState)
		if item.Kind == change.ServiceModified && item.BeforeName != item.AfterName {
			serviceDesc = fmt.Sprintf("%s -> %s", serviceDescription(item.BeforeName, item.BeforeState), serviceDescription(item.AfterName, item.AfterState))
		} else if item.Kind == change.ServiceAdded {
			serviceDesc = serviceDescription(item.AfterName, item.AfterState)
		} else if item.Kind == change.ServiceRemoved {
			serviceDesc = serviceDescription(item.BeforeName, item.BeforeState)
		}

		details := item.Details
		if details == "" {
			details = "-"
		}

		fmt.Fprintf(
			w,
			"%s\t%d\t%s\t%s\t%s\n",
			item.Kind,
			item.Port,
			item.Protocol,
			serviceDesc,
			details,
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
