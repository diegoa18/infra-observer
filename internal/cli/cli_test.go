package cli

import (
	"flag"
	"io"
	"os"
	"strings"
	"testing"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	original := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	os.Stderr = writer
	defer func() {
		os.Stderr = original
	}()

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close() error = %v", err)
	}

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("io.ReadAll() error = %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("reader.Close() error = %v", err)
	}

	return string(output)
}

func TestWarnIfInsecureDatabaseURLWarnsForRemoteDisabledSSL(t *testing.T) {
	output := captureStderr(t, func() {
		warnIfInsecureDatabaseURL("postgres://user:secret@db.example.com:5432/infra?sslmode=disable")
	})

	if !strings.Contains(output, "[WARN]") || !strings.Contains(output, "sslmode=disable") {
		t.Fatalf("expected insecure remote warning, got %q", output)
	}
}

func TestWarnIfInsecureDatabaseURLSilentForLoopback(t *testing.T) {
	for _, databaseURL := range []string{
		"postgres://user:secret@127.0.0.1:5432/infra?sslmode=disable",
		"postgres://user:secret@localhost:5432/infra?sslmode=disable",
		"postgres://user:secret@[::1]:5432/infra?sslmode=disable",
	} {
		output := captureStderr(t, func() {
			warnIfInsecureDatabaseURL(databaseURL)
		})
		if output != "" {
			t.Fatalf("expected no warning for %q, got %q", databaseURL, output)
		}
	}
}

func TestWarnIfInsecureDatabaseURLSilentForEncryptedRemote(t *testing.T) {
	output := captureStderr(t, func() {
		warnIfInsecureDatabaseURL("postgres://user:secret@db.example.com:5432/infra?sslmode=require")
	})

	if output != "" {
		t.Fatalf("expected no warning, got %q", output)
	}
}

func TestPrepareArgsParsesExcludeBeforeTarget(t *testing.T) {
	testPrepareArgsExclude(t, []string{"-exclude", "10.0.0.0/8,192.168.1.5", "127.0.0.1"})
}

func TestPrepareArgsParsesExcludeAfterTarget(t *testing.T) {
	testPrepareArgsExclude(t, []string{"127.0.0.1", "-exclude", "10.0.0.0/8,192.168.1.5"})
}

func testPrepareArgsExclude(t *testing.T, args []string) {
	t.Helper()

	cmd := flag.NewFlagSet("scan", flag.ContinueOnError)
	exclude := cmd.String("exclude", "", "Comma-separated IPs or CIDRs to exclude")
	rateLimit := cmd.Int("rate", 0, "Max packets per second")

	prepared := prepareArgs(
		args,
		[]string{"no-discovery", "probe", "store", "json", "diff", "audit"},
		"p", "timeout", "concurrency", "exclude", "rate",
	)
	if err := cmd.Parse(prepared); err != nil {
		t.Fatalf("cmd.Parse() error = %v", err)
	}

	if got := cmd.Arg(0); got != "127.0.0.1" {
		t.Fatalf("target = %q, want %q", got, "127.0.0.1")
	}
	if *exclude != "10.0.0.0/8,192.168.1.5" {
		t.Fatalf("exclude = %q, want %q", *exclude, "10.0.0.0/8,192.168.1.5")
	}
	if *rateLimit != 0 {
		t.Fatalf("rate = %d, want 0", *rateLimit)
	}
}
