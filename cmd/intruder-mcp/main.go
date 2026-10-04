// Command intruder-mcp serves the Intruder API to MCP clients over stdio.
// The API key is read from INTRUDER_API_KEY.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/yurhasko/intruder-mcp-go/internal/intruder"
	"github.com/yurhasko/intruder-mcp-go/internal/tools"
)

// Set at link time with -X main.version=...
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr); err != nil {
		slog.New(slog.NewTextHandler(os.Stderr, nil)).Error("intruder-mcp stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("intruder-mcp", flag.ContinueOnError)
	flags.SetOutput(stderr)

	showVersion := flags.Bool("version", false, "print version and exit")

	requestTimeout := flags.Duration("request-timeout", 30*time.Second, "timeout for each HTTP request")
	toolTimeout := flags.Duration("tool-timeout", 2*time.Minute, "deadline for a complete tool call including pagination")
	concurrency := flags.Int("max-concurrent", 4, "maximum simultaneous API requests")
	interval := flags.Duration("request-interval", 750*time.Millisecond, "interval between requests; 1s for trials, 0 disables pacing")
	retries := flags.Int("read-retries", 2, "maximum retries for eligible GET requests (0-5); writes are never retried")

	maxResponse := flags.Int64("max-response-bytes", 8<<20, "maximum bytes per API response body")
	maxList := flags.Int64("max-list-bytes", 64<<20, "maximum response body bytes across a paginated list")
	maxOutput := flags.Int("max-output-bytes", 8<<20, "maximum tool result bytes after JSON escaping")
	maxPages := flags.Int("max-pages", 1000, "maximum pages fetched by a list tool")
	maxItems := flags.Int("max-items", 100000, "maximum items fetched by a list tool")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}

	if *showVersion {
		_, err := fmt.Fprintln(stdout, version)
		return err
	}

	if *requestTimeout <= 0 || *toolTimeout <= 0 || *maxOutput <= 0 || *concurrency <= 0 ||
		*maxResponse <= 0 || *maxList <= 0 || *maxPages <= 0 || *maxItems <= 0 {
		return errors.New("timeouts and resource limits must be positive")
	}

	client, err := intruder.New(getenv("INTRUDER_API_KEY"), intruder.Options{
		RequestTimeout:   *requestTimeout,
		MaxConcurrent:    *concurrency,
		Interval:         *interval,
		MaxResponseBytes: *maxResponse,
		MaxListBytes:     *maxList,
		MaxPages:         *maxPages,
		MaxItems:         *maxItems,
		Retries:          *retries,
		UserAgent:        "Intruder-MCP-Go/" + version,
	})
	if err != nil {
		return err
	}
	defer client.Close()

	server, err := tools.New(client, tools.Options{
		Version:        version,
		ToolTimeout:    *toolTimeout,
		MaxOutputBytes: *maxOutput,
	})
	if err != nil {
		return err
	}

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
