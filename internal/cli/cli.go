package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"infra-observer/internal/application"
	"infra-observer/internal/output"
	"infra-observer/internal/storage/postgres"
	"infra-observer/internal/utils"
)

const version = "0.1.0"

func Execute(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	switch args[0] {
	case "scan":
		return handleScan(args[1:])

	case "help", "--help", "-h":
		printUsage()
		return nil

	case "version":
		fmt.Println("infra-observer", version)
		return nil

	default:
		return fmt.Errorf(
			"unknown command: %s",
			args[0],
		)
	}
}

func printUsage() {
	fmt.Println("infra-observer - Network Asset Discovery & Inventory")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  infra-observer scan [flags] <target>")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  scan       Discover hosts and accessible services")
	fmt.Println("  help       Show this help")
	fmt.Println("  version    Show version")
	fmt.Println()
	fmt.Println("Scan flags:")
	fmt.Println("  -p <ports>          Ports to scan")
	fmt.Println("  -timeout <ms>       Connection timeout")
	fmt.Println("  -concurrency <n>    Maximum concurrent connections")
	fmt.Println("  -no-discovery       Skip host discovery")
	fmt.Println("  -probe              Enable HTTP/HTTPS probing")
	fmt.Println("  -store              Store observations in PostgreSQL")
}

func handleScan(args []string) error {
	cmd := flag.NewFlagSet(
		"scan",
		flag.ContinueOnError,
	)

	portRange := cmd.String(
		"p",
		"1-1024",
		"Ports to scan",
	)

	timeoutMs := cmd.Int(
		"timeout",
		1000,
		"Connection timeout in milliseconds",
	)

	concurrency := cmd.Int(
		"concurrency",
		100,
		"Maximum concurrent connections",
	)

	noDiscovery := cmd.Bool(
		"no-discovery",
		false,
		"Skip host discovery",
	)

	probe := cmd.Bool(
		"probe",
		false,
		"Enable HTTP/HTTPS probing",
	)

	storeObservations := cmd.Bool(
		"store",
		false,
		"Store observations in PostgreSQL",
	)

	cmd.SetOutput(os.Stderr)

	if err := cmd.Parse(args); err != nil {
		return err
	}

	if cmd.NArg() != 1 {
		return fmt.Errorf(
			"exactly one target is required",
		)
	}

	targets, err := utils.ParseTarget(
		cmd.Arg(0),
	)
	if err != nil {
		return fmt.Errorf(
			"invalid target: %w",
			err,
		)
	}

	ports, err := utils.ParsePortRange(
		*portRange,
	)
	if err != nil {
		return fmt.Errorf(
			"invalid ports: %w",
			err,
		)
	}

	options := application.ScanOptions{
		Ports:       ports,
		Timeout:     time.Duration(*timeoutMs) * time.Millisecond,
		Concurrency: *concurrency,
		Discovery:   !*noDiscovery,
		HTTPProbe:   *probe,
	}

	ctx := context.Background()

	var databaseStore *postgres.Store

	if *storeObservations {
		databaseURL := os.Getenv("DATABASE_URL")
		if databaseURL == "" {
			return fmt.Errorf(
				"DATABASE_URL is required when -store is enabled",
			)
		}

		connectCtx, cancel := context.WithTimeout(
			ctx,
			5*time.Second,
		)

		databaseStore, err = postgres.Open(
			connectCtx,
			databaseURL,
		)

		cancel()

		if err != nil {
			return err
		}

		defer databaseStore.Close()
	}

	service := application.NewScanService()

	observations, err := service.Scan(
		ctx,
		targets,
		options,
	)
	if err != nil {
		return err
	}

	if databaseStore != nil {
		for _, observation := range observations {
			if err := databaseStore.SaveObservation(
				ctx,
				observation,
			); err != nil {
				return err
			}
		}
	}

	output.PrintObservations(observations)

	if databaseStore != nil {
		fmt.Printf(
			"Stored %d observation(s).\n",
			len(observations),
		)
	}

	return nil
}
