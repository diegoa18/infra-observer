package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"infra-observer/internal/application"
	"infra-observer/internal/change"
	"infra-observer/internal/domain"
	"infra-observer/internal/output"
	"infra-observer/internal/storage/postgres"
	"infra-observer/internal/utils"
)

const version = "1.0.0"

func Execute(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	switch args[0] {
	case "scan":
		return handleScan(args[1:])
	case "inventory":
		return handleInventory(args[1:])
	case "history":
		return handleHistory(args[1:])
	case "changes":
		return handleChanges(args[1:])
	case "help", "--help", "-h":
		printUsage()
		return nil
	case "version":
		fmt.Println("infra-observer", version)
		return nil
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func printUsage() {
	fmt.Println("infra-observer - Network Asset Discovery & Inventory")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  infra-observer scan [flags] <target>")
	fmt.Println("  infra-observer inventory [flags] [target]")
	fmt.Println("  infra-observer history [flags] <target>")
	fmt.Println("  infra-observer changes [flags] <target>")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  scan       Discover hosts and accessible services")
	fmt.Println("  inventory  Show the latest known infrastructure state")
	fmt.Println("  history    Show stored observations for a target")
	fmt.Println("  changes    Compare the two latest stored observations")
	fmt.Println("  help       Show this help")
	fmt.Println("  version    Show version")
	fmt.Println()
	fmt.Println("Global Flags:")
	fmt.Println("  -json               Output results in structured JSON format")
	fmt.Println()
	fmt.Println("Scan flags:")
	fmt.Println("  -p <ports>          Ports to scan")
	fmt.Println("  -timeout <ms>       Connection timeout")
	fmt.Println("  -concurrency <n>    Maximum concurrent connections")
	fmt.Println("  -no-discovery       Skip host discovery")
	fmt.Println("  -probe              Enable HTTP/HTTPS and TLS probing")
	fmt.Println("  -store              Store observations in PostgreSQL")
	fmt.Println()
	fmt.Println("History flags:")
	fmt.Println("  -limit <n>          Maximum observations to show")
}

func prepareArgs(args []string, boolFlags []string) []string {
	var flags []string
	var pos []string
	isBool := func(f string) bool {
		f = strings.TrimLeft(f, "-")
		for _, b := range boolFlags {
			if f == b {
				return true
			}
		}
		return false
	}
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flags = append(flags, args[i])
			if !isBool(args[i]) && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			pos = append(pos, args[i])
		}
	}
	return append(flags, pos...)
}

func handleScan(args []string) error {
	cmd := flag.NewFlagSet("scan", flag.ContinueOnError)
	portRange := cmd.String("p", "1-1024", "Ports to scan")
	timeoutMs := cmd.Int("timeout", 1000, "Connection timeout in milliseconds")
	concurrency := cmd.Int("concurrency", 100, "Maximum concurrent connections")
	noDiscovery := cmd.Bool("no-discovery", false, "Skip host discovery")
	probe := cmd.Bool("probe", false, "Enable HTTP/HTTPS and TLS probing")
	storeObservations := cmd.Bool("store", false, "Store observations in PostgreSQL")
	asJSON := cmd.Bool("json", false, "Output results in JSON format")

	cmd.SetOutput(os.Stderr)
	args = prepareArgs(args, []string{"no-discovery", "probe", "store", "json"})

	if err := cmd.Parse(args); err != nil {
		return err
	}
	if cmd.NArg() != 1 {
		return fmt.Errorf("exactly one target is required")
	}

	targets, err := utils.ParseTarget(cmd.Arg(0))
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	ports, err := utils.ParsePortRange(*portRange)
	if err != nil {
		return fmt.Errorf("invalid ports: %w", err)
	}

	options := application.ScanOptions{
		Ports:       ports,
		Timeout:     time.Duration(*timeoutMs) * time.Millisecond,
		Concurrency: *concurrency,
		Discovery:   !*noDiscovery,
		HTTPProbe:   *probe,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var databaseStore domain.Repository
	if *storeObservations {
		databaseStore, err = openDatabase(ctx)
		if err != nil {
			return err
		}
		defer databaseStore.Close()
	}

	service := application.NewScanService()
	observations, err := service.Scan(ctx, targets, options)
	if err != nil {
		return err
	}

	if databaseStore != nil {
		for _, observation := range observations {
			if err := databaseStore.SaveObservation(ctx, observation); err != nil {
				return err
			}
		}
	}

	output.PrintObservations(observations, *asJSON)
	if databaseStore != nil && !*asJSON {
		fmt.Printf("Stored %d observation(s).\n", len(observations))
	}

	return nil
}

func handleInventory(args []string) error {
	cmd := flag.NewFlagSet("inventory", flag.ContinueOnError)
	asJSON := cmd.Bool("json", false, "Output results in JSON format")
	cmd.SetOutput(os.Stderr)
	args = prepareArgs(args, []string{"json"})

	if err := cmd.Parse(args); err != nil {
		return err
	}
	if cmd.NArg() > 1 {
		return fmt.Errorf("inventory accepts at most one target")
	}

	var targetIPs []string
	if cmd.NArg() == 1 {
		targets, err := utils.ParseTarget(cmd.Arg(0))
		if err != nil {
			return fmt.Errorf("invalid target: %w", err)
		}
		for _, t := range targets {
			targetIPs = append(targetIPs, t.IP)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	databaseStore, err := openDatabase(ctx)
	if err != nil {
		return err
	}
	defer databaseStore.Close()

	inventory, err := databaseStore.Inventory(ctx, targetIPs)
	if err != nil {
		return err
	}

	output.PrintInventory(inventory, *asJSON)
	return nil
}

func handleHistory(args []string) error {
	cmd := flag.NewFlagSet("history", flag.ContinueOnError)
	limit := cmd.Int("limit", 10, "Maximum observations to show")
	asJSON := cmd.Bool("json", false, "Output results in JSON format")
	cmd.SetOutput(os.Stderr)
	args = prepareArgs(args, []string{"json"})

	if err := cmd.Parse(args); err != nil {
		return err
	}
	if cmd.NArg() != 1 {
		return fmt.Errorf("exactly one target is required")
	}
	if *limit <= 0 {
		return fmt.Errorf("history limit must be greater than zero")
	}

	targets, err := utils.ParseTarget(cmd.Arg(0))
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	databaseStore, err := openDatabase(ctx)
	if err != nil {
		return err
	}
	defer databaseStore.Close()

	for _, target := range targets {
		observations, err := databaseStore.LatestObservations(ctx, target.IP, *limit)
		if err != nil {
			return err
		}
		output.PrintHistory(target.IP, observations, *asJSON)
	}
	return nil
}

func handleChanges(args []string) error {
	cmd := flag.NewFlagSet("changes", flag.ContinueOnError)
	asJSON := cmd.Bool("json", false, "Output results in JSON format")
	cmd.SetOutput(os.Stderr)
	args = prepareArgs(args, []string{"json"})

	if err := cmd.Parse(args); err != nil {
		return err
	}
	if cmd.NArg() != 1 {
		return fmt.Errorf("exactly one target is required")
	}

	targets, err := utils.ParseTarget(cmd.Arg(0))
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	databaseStore, err := openDatabase(ctx)
	if err != nil {
		return err
	}
	defer databaseStore.Close()

	for _, target := range targets {
		observations, err := databaseStore.LatestObservations(ctx, target.IP, 2)
		if err != nil {
			return err
		}
		if len(observations) < 2 {
			fmt.Printf("No comparison available for %s: need at least two stored observations.\n", target.IP)
			continue
		}
		result := change.Compare(observations[0], observations[1])
		output.PrintChanges(result, *asJSON)
	}
	return nil
}

func openDatabase(ctx context.Context) (domain.Repository, error) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	store, err := postgres.Open(connectCtx, databaseURL)
	if err != nil {
		return nil, err
	}
	return store, nil
}
