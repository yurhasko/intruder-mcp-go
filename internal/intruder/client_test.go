package intruder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// handlerTransport replaces the network while keeping the real http.Client
// request and redirect pipeline.
type handlerTransport struct{ handler http.HandlerFunc }

func (h handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	h.handler(w, r)

	if err := r.Context().Err(); err != nil {
		return nil, err
	}

	response := w.Result()
	response.Request = r
	return response, nil
}

const (
	targetJSON = `{"id":1,"address":"example.com","target_status":"live","tags":["prod",null]}`
	scanJSON   = `{"id":2,"status":"in_progress","scan_type":"assessment_schedule","created_at":"2026-01-01T00:00:00Z","schedule_period":"one_off"}`
)

func testClient(t *testing.T, handler http.HandlerFunc, opts Options) *Client {
	t.Helper()

	opts.BaseURL = "https://api.test/v1"
	opts.HTTPClient = &http.Client{Transport: handlerTransport{handler}}

	client, err := New("test-key", opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestPaginationPreservesFilters(t *testing.T) {
	var offsets []string

	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" || r.Header.Get("User-Agent") == "" {
			t.Error("missing authentication or user agent")
		}

		q := r.URL.Query()
		// One parameter, comma-separated.
		if !reflect.DeepEqual(q["tag_names"], []string{"prod,a&b"}) || q.Get("snoozed") != "false" {
			t.Errorf("filters = %v", q)
		}
		offsets = append(offsets, q.Get("offset"))

		if q.Get("offset") == "0" {
			fmt.Fprint(w, `{"count":2,"next":"?limit=100&offset=1&tag_names=prod%2Ca%26b&snoozed=false","results":[{"id":1,"title":"TLS","severity":"high"}]}`)
		} else {
			fmt.Fprint(w, `{"count":2,"next":null,"results":[{"id":2,"title":"SSH","severity":"low"}]}`)
		}
	}, Options{})

	snoozed := false
	items, err := client.Issues(context.Background(), IssueFilters{TagNames: []string{"prod", "a&b"}, Snoozed: &snoozed})
	if err != nil || len(items) != 2 || !reflect.DeepEqual(offsets, []string{"0", "1"}) {
		t.Fatalf("items=%v offsets=%v err=%v", items, offsets, err)
	}
}

func TestInvalidPagination(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"missing_results", `{"count":0}`, "invalid paginated"},
		{"null_results", `{"count":0,"results":null}`, "invalid paginated"},
		{"missing_count", `{"results":[]}`, "invalid paginated"},
		{"empty_next", `{"count":1,"next":"?offset=1","results":[]}`, "empty page"},
		{"external_next", `{"count":2,"next":"https://attacker.invalid/v1/targets/","results":[` + targetJSON + `]}`, "escaped"},
		{"outside_prefix", `{"count":2,"next":"/other/","results":[` + targetJSON + `]}`, "escaped"},
		{"missing_next", `{"count":2,"results":[` + targetJSON + `]}`, "omitted pagination"},
		{"loop", `{"count":3,"next":"?offset=0&limit=100","results":[` + targetJSON + `]}`, "repeated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, tc.body)
			}, Options{})

			_, err := client.Targets(context.Background(), TargetFilters{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %s", err, tc.want)
			}
		})
	}
}

func TestHTTPFailuresAreNotSuccess(t *testing.T) {
	for _, status := range []int{401, 403, 404, 422, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var requests atomic.Int32

			client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.Header().Set("X-Request-ID", "request-123")
				w.WriteHeader(status)
				fmt.Fprint(w, `{"error":"test-key and private scanner output"}`)
			}, Options{Retries: 2})

			err := client.DeleteTarget(context.Background(), 1)

			var apiError *APIError
			if !errors.As(err, &apiError) || apiError.Status != status || apiError.RequestID != "request-123" {
				t.Fatalf("error = %v", err)
			}
			if requests.Load() != 1 || strings.Contains(err.Error(), "test-key") || strings.Contains(err.Error(), "private") {
				t.Fatalf("unsafe error or retried write: %v, requests=%d", err, requests.Load())
			}
		})
	}
}

func TestReadRetryAndWriteNoRetry(t *testing.T) {
	var reads, writes atomic.Int32

	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if reads.Add(1) == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(429)
				return
			}
			fmt.Fprint(w, `{"status":"ok","authenticated_as":"user@example.com"}`)
			return
		}

		writes.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(503)
	}, Options{Retries: 2})

	if _, err := client.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateScan(context.Background(), ScanRequest{}); err == nil {
		t.Fatal("write succeeded unexpectedly")
	}

	if reads.Load() != 2 || writes.Load() != 1 {
		t.Fatalf("reads=%d writes=%d", reads.Load(), writes.Load())
	}
}

func TestCancellationDuringBackoff(t *testing.T) {
	reached := make(chan struct{})
	var requests atomic.Int32

	client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(429)
		close(reached)
	}, Options{Retries: 2})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { _, err := client.Health(ctx); done <- err }()

	<-reached
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("backoff did not cancel")
	}
	if requests.Load() != 1 {
		t.Fatal("retried after cancellation")
	}
}

func TestCancellationDuringNetworkWait(t *testing.T) {
	reached := make(chan struct{})
	client := testClient(t, func(_ http.ResponseWriter, r *http.Request) {
		close(reached)
		<-r.Context().Done()
	}, Options{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { _, err := client.Health(ctx); done <- err }()

	<-reached
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("network wait did not cancel")
	}
}

func TestConcurrencyLimit(t *testing.T) {
	var active, peak atomic.Int32
	entered := make(chan struct{}, 8)
	release := make(chan struct{})

	client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		n := active.Add(1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}

		entered <- struct{}{}
		<-release

		active.Add(-1)
		fmt.Fprint(w, `{"status":"ok","authenticated_as":"user@example.com"}`)
	}, Options{MaxConcurrent: 2})

	var group sync.WaitGroup
	failures := make(chan error, 8)
	for range 8 {
		group.Go(func() { _, err := client.Health(context.Background()); failures <- err })
	}

	<-entered
	<-entered
	if peak.Load() != 2 {
		t.Errorf("peak = %d", peak.Load())
	}

	close(release)
	group.Wait()
	close(failures)

	for err := range failures {
		if err != nil {
			t.Error(err)
		}
	}
	if peak.Load() > 2 {
		t.Fatalf("peak = %d exceeded limit", peak.Load())
	}
}

func TestLimits(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts Options
		want string
	}{
		{"response", Options{MaxResponseBytes: 8}, "response exceeded"},
		{"items", Options{MaxItems: 1}, "item limit"},
		{"list_bytes", Options{MaxListBytes: 1}, "list exceeded"},
		{"pages", Options{MaxPages: 1}, "page limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, `{"count":4,"next":"?offset=2","results":[`+targetJSON+`,`+targetJSON+`]}`)
			}, tc.opts)

			_, err := client.Targets(context.Background(), TargetFilters{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestRedirectDoesNotTransmitCredentials(t *testing.T) {
	var followed atomic.Bool

	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "api.test" {
			followed.Store(true)
		}
		http.Redirect(w, r, "https://other.test/", http.StatusFound)
	}, Options{})

	_, err := client.Health(context.Background())
	if err == nil || followed.Load() {
		t.Fatalf("err=%v followed=%t", err, followed.Load())
	}
}

func TestDeleteAndEscapedTagPath(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/v1/targets/1/tags/a%2Fb%20&%20c/" {
			t.Errorf("path = %s", r.URL.EscapedPath())
		}
		w.WriteHeader(204)
	}, Options{})

	if err := client.DeleteTargetTag(context.Background(), 1, "a/b & c"); err != nil {
		t.Fatal(err)
	}
}

func TestBulkCreationCountsAndDeduplicates(t *testing.T) {
	var posts int

	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `{"count":1,"results":[`+targetJSON+`]}`)
			return
		}

		posts++
		var request []TargetRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(request, []TargetRequest{{Address: "new.example.com"}}) {
			t.Errorf("request = %v", request)
		}
		fmt.Fprint(w, `[{"id":3,"address":"new.example.com","target_status":"unscanned"}]`)
	}, Options{})

	result, err := client.CreateTargets(context.Background(), []string{"example.com", "new.example.com", "new.example.com"})
	if err != nil || result != (BulkResult{Created: 1, Existing: 1}) || posts != 1 {
		t.Fatalf("result=%v posts=%d err=%v", result, posts, err)
	}
}

func TestBulkPartialResponseIsError(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `{"count":0,"results":[]}`)
		} else {
			fmt.Fprint(w, `[]`) // Asked for one, got none back.
		}
	}, Options{})

	_, err := client.CreateTargets(context.Background(), []string{"new.example.com"})
	if err == nil || !strings.Contains(err.Error(), "partial") {
		t.Fatalf("error = %v", err)
	}
}

func TestResponseModelEdges(t *testing.T) {
	for _, raw := range []string{
		`{"id":1,"target":"x","protocol":"tcp","port":443}`,
		`{"id":1,"target":"x","protocol":"tcp","port":"443"}`,
	} {
		var occurrence Occurrence
		if err := json.Unmarshal([]byte(raw), &occurrence); err != nil || occurrence.Port != "443" {
			t.Fatalf("occurrence=%v error=%v", occurrence, err)
		}
	}

	var occurrence Occurrence
	if err := json.Unmarshal([]byte(`{"id":1,"target":"x","protocol":"tcp","port":null}`), &occurrence); err != nil || occurrence.Port != "" {
		t.Fatal(err)
	}

	for _, raw := range []string{
		`{"id":1,"target":"x","port":443}`,          // No protocol.
		`{"id":null,"target":"x","protocol":"tcp"}`, // Null ID.
		`{"id":1,"target":"x","protocol":"tcp","port":1.5}`,
	} {
		if err := json.Unmarshal([]byte(raw), &occurrence); err == nil {
			t.Fatalf("accepted malformed occurrence %s", raw)
		}
	}

	var output ScannerOutput
	if err := json.Unmarshal([]byte(`{"id":1,"plugin":{"name":"TLS"},"scanner_output":null}`), &output); err != nil {
		t.Fatal(err)
	}

	var target Target
	if err := json.Unmarshal([]byte(targetJSON), &target); err != nil || target.Tags[1] != nil {
		t.Fatal(err)
	}
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		value string
		want  time.Duration
		ok    bool
	}{
		{"0", 0, true},
		{"5", 5 * time.Second, true},
		{now.Add(time.Minute).Format(http.TimeFormat), time.Minute, true},
		{"bad", 0, false},
		{"-1", 0, false},
	} {
		got, ok := retryAfter(tc.value, now)
		if got != tc.want || ok != tc.ok {
			t.Errorf("retryAfter(%q) = %v,%v", tc.value, got, ok)
		}
	}
}
