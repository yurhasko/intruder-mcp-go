package intruder

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Request construction and fixture decoding only: no network, no MCP
// encoding, no scanning. An allocation regression check, not a timing.

func benchmarkClient(b *testing.B, body string) *Client {
	b.Helper()

	handler := func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) }
	client, err := New("fixture-key", Options{
		HTTPClient: &http.Client{Transport: handlerTransport{handler}},
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(client.Close)
	return client
}

func BenchmarkHealth(b *testing.B) {
	client := benchmarkClient(b, `{"status":"ok","authenticated_as":"user@example.com"}`)
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		if _, err := client.Health(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTargets100(b *testing.B) {
	items := make([]string, 100)
	for i := range items {
		items[i] = fmt.Sprintf(`{"id":%d,"address":"target-%d.example.com","target_status":"live","tags":["prod",null]}`, i+1, i+1)
	}

	client := benchmarkClient(b, `{"count":100,"results":[`+strings.Join(items, ",")+`]}`)
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		if _, err := client.Targets(ctx, TargetFilters{}); err != nil {
			b.Fatal(err)
		}
	}
}
