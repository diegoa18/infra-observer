package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"go-scanner/internal/application"
	"go-scanner/internal/output"
	"go-scanner/internal/utils"
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
		fmt.Println("go-scanner", version)
		return nil

	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func printUsage() {
	fmt.Println("go-scanner - Network Asset Discovery & Inventory")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  go-scanner scan [flags] <target>")
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
}

func handleScan(args []string) error {
	cmd := flag.NewFlagSet("scan", flag.ContinueOnError)

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

	cmd.SetOutput(os.Stderr)

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

	ctx := context.Background()
	service := application.NewScanService()
	observations, err := service.Scan(
		ctx,
		targets,
		options,
	)
	if err != nil {
		return err
	}

	output.PrintObservations(observations)
	return nil
}
