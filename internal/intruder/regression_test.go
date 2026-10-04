package intruder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// deadlineEOFReader returns EOF only once the context is done: a truncated
// body whose final read looks like success after the deadline passed.
type deadlineEOFReader struct{ ctx context.Context }

func (r deadlineEOFReader) Read([]byte) (int, error) {
	<-r.ctx.Done()
	return 0, io.EOF
}

type deadlineEOFTransport struct{}

func (deadlineEOFTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body := io.MultiReader(strings.NewReader(`{"status":`), deadlineEOFReader{r.Context()})
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(body),
		Request:    r,
	}, nil
}

func TestDeadlineBeforeEOF(t *testing.T) {
	client, err := New("fixture-key", Options{
		HTTPClient:     &http.Client{Transport: deadlineEOFTransport{}},
		RequestTimeout: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)

	_, err = client.Health(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline followed by EOF returned %v", err)
	}
}

func TestBackoffReleasesConcurrencySlot(t *testing.T) {
	backingOff := make(chan struct{})
	var requests atomic.Int32

	client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(503)
			close(backingOff)
			return
		}
		fmt.Fprint(w, `{"status":"ok","authenticated_as":"user"}`)
	}, Options{MaxConcurrent: 1, Retries: 1})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { _, err := client.Health(ctx); done <- err }()

	select {
	case <-backingOff:
	case <-time.After(time.Second):
		t.Fatal("first request did not start")
	}

	independent, cancelIndependent := context.WithTimeout(context.Background(), time.Second)
	defer cancelIndependent()
	if _, err := client.Health(independent); err != nil {
		t.Fatalf("backoff blocked an independent request: %v", err)
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("backoff did not cancel")
	}
}

func TestErrorStatusSurvivesLargeBody(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, strings.Repeat("private", 100))
	}, Options{MaxResponseBytes: 8})

	err := client.DeleteTarget(context.Background(), 1)

	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.Status != 403 {
		t.Fatalf("error = %v", err)
	}
}

func TestListBudgetIncludesUnknownFields(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"count":1,"results":[{"id":1,"address":"example.com","target_status":"live","unused":"%s"}]}`,
			strings.Repeat("x", 1000))
	}, Options{MaxListBytes: 500})

	_, err := client.Targets(context.Background(), TargetFilters{})
	if err == nil || !strings.Contains(err.Error(), "list exceeded") {
		t.Fatalf("error = %v", err)
	}
}

func TestRequiredResponseFields(t *testing.T) {
	for _, tc := range []struct {
		name   string
		create func() any
		valid  string
		fields []string
	}{
		{"health", func() any { return new(Health) }, `{"status":"ok","authenticated_as":"user"}`, []string{"status", "authenticated_as"}},
		{"target", func() any { return new(Target) }, targetJSON, []string{"id", "address", "target_status"}},
		{"issue", func() any { return new(Issue) }, `{"id":1,"title":"TLS","severity":"high"}`, []string{"id", "title", "severity"}},
		{"occurrence", func() any { return new(Occurrence) }, `{"id":1,"target":"example.com","protocol":"tcp"}`, []string{"id", "target", "protocol"}},
		{"plugin", func() any { return new(Plugin) }, `{"name":"TLS"}`, []string{"name"}},
		{"scan", func() any { return new(Scan) }, scanJSON, []string{"id", "status", "scan_type", "created_at"}},
		{"tag", func() any { return new(Tag) }, `{"name":"prod"}`, []string{"name"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tc.valid), &fields); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tc.valid), tc.create()); err != nil {
				t.Fatal(err)
			}

			for _, name := range tc.fields {
				original := fields[name]

				for _, null := range []bool{false, true} {
					if null {
						fields[name] = json.RawMessage("null")
					} else {
						delete(fields, name)
					}

					encoded, err := json.Marshal(fields)
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(encoded, tc.create()); err == nil {
						t.Fatalf("accepted missing/null %s", name)
					}
				}

				fields[name] = original
			}
		})
	}
}

func TestResponseReuseClearsOptionalFields(t *testing.T) {
	var scan Scan
	if err := json.Unmarshal([]byte(scanJSON), &scan); err != nil {
		t.Fatal(err)
	}
	if scan.SchedulePeriod == nil {
		t.Fatal("missing initial schedule")
	}

	second := `{"id":3,"status":"completed","scan_type":"new_service","created_at":"2026-01-02T00:00:00Z"}`
	if err := json.Unmarshal([]byte(second), &scan); err != nil {
		t.Fatal(err)
	}

	if scan.ID != 3 || scan.SchedulePeriod != nil {
		t.Fatalf("reused scan = %+v", scan)
	}
}

func TestMutationResponseReuseRejectsEmptyObject(t *testing.T) {
	var result MutationResult
	if err := json.Unmarshal([]byte(`{"message":"Snoozed"}`), &result); err != nil {
		t.Fatal(err)
	}

	if err := json.Unmarshal([]byte(`{}`), &result); err == nil {
		t.Fatal("previous mutation fields masked an empty response")
	}
}

func TestEncodedPaginationTraversal(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"count":2,"next":"/v1/%2e%2e/private/","results":[`+targetJSON+`]}`)
	}, Options{})

	_, err := client.Targets(context.Background(), TargetFilters{})
	if err == nil || !strings.Contains(err.Error(), "escaped") {
		t.Fatalf("error = %v", err)
	}
}

func TestRetryAfterCannotOverflow(t *testing.T) {
	delay, ok := retryAfter("9223372036854775807", time.Now())
	if !ok || delay <= 0 {
		t.Fatalf("Retry-After overflow: %v, %t", delay, ok)
	}
}

// Multi-value filters go out as one comma-separated parameter: the API keeps
// only the last occurrence of a repeated one and drops the rest.
func TestMultiValueFiltersAreCommaSeparated(t *testing.T) {
	for _, tc := range []struct {
		name  string
		call  func(*Client) error
		field string
		want  string
	}{
		{"issue tags", func(c *Client) error {
			_, err := c.Issues(context.Background(), IssueFilters{TagNames: []string{"prod", "staging"}})
			return err
		}, "tag_names", "prod,staging"},
		{"issue addresses", func(c *Client) error {
			_, err := c.Issues(context.Background(), IssueFilters{TargetAddresses: []string{"a.example.com", "b.example.com"}})
			return err
		}, "target_addresses", "a.example.com,b.example.com"},
		{"issue ids", func(c *Client) error {
			_, err := c.Issues(context.Background(), IssueFilters{IssueIDs: []int64{3, 1, 2}})
			return err
		}, "issue_ids", "3,1,2"},
		{"vulnerability categories", func(c *Client) error {
			_, err := c.Issues(context.Background(), IssueFilters{VulnerabilityCategories: []string{"Attack Surface Reduction", "TLS"}})
			return err
		}, "vulnerability_categories", "Attack Surface Reduction,TLS"},
		{"target tags", func(c *Client) error {
			_, err := c.Targets(context.Background(), TargetFilters{TagNames: []string{"prod", "staging"}})
			return err
		}, "tag_names", "prod,staging"},
		{"scan tags", func(c *Client) error {
			_, err := c.Scans(context.Background(), ScanFilters{TagNames: []string{"prod", "staging"}})
			return err
		}, "tag_names", "prod,staging"},
		{"occurrence tags", func(c *Client) error {
			_, err := c.Occurrences(context.Background(), 1, IssueFilters{TagNames: []string{"prod", "staging"}})
			return err
		}, "tag_names", "prod,staging"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var values []string
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				values = r.URL.Query()[tc.field]
				fmt.Fprint(w, `{"count":0,"results":[]}`)
			}, Options{})

			if err := tc.call(client); err != nil {
				t.Fatal(err)
			}
			if len(values) != 1 || values[0] != tc.want {
				t.Fatalf("%s = %q, want exactly one value %q", tc.field, values, tc.want)
			}
		})
	}
}

func TestCommaInFilterValueIsRejected(t *testing.T) {
	client := testClient(t, func(http.ResponseWriter, *http.Request) {
		t.Error("request made with an unencodable filter")
	}, Options{})

	_, err := client.Issues(context.Background(), IssueFilters{TagNames: []string{"a,b"}})
	if err == nil || !strings.Contains(err.Error(), "comma") {
		t.Fatalf("error = %v", err)
	}
}

func TestOccurrenceQueryOmitsIssueOnlyFilters(t *testing.T) {
	var query url.Values
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query()
		fmt.Fprint(w, `{"count":0,"results":[]}`)
	}, Options{})

	severity, likelihood := "high", "known"
	_, err := client.Occurrences(context.Background(), 1, IssueFilters{
		Severity:                &severity,
		ExploitLikelihood:       &likelihood,
		IssueIDs:                []int64{1},
		VulnerabilityCategories: []string{"TLS"},
		TagNames:                []string{"prod"},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, field := range []string{"severity", "exploit_likelihood", "issue_ids", "vulnerability_categories"} {
		if query.Has(field) {
			t.Errorf("occurrence query carried issue-only filter %s", field)
		}
	}
	if query.Get("tag_names") != "prod" {
		t.Errorf("shared filter was dropped: %v", query)
	}
}

func TestScheduleNullableFirstScanTime(t *testing.T) {
	const base = `{"id":1,"name":"s","schedule_period":"weekly","status":"scheduled",` +
		`"throttled":false,"web_ports_only":false,"upload_to_drata":false,` +
		`"upload_to_vanta":false,"scan_all_targets":true`

	var schedule Schedule
	if err := json.Unmarshal([]byte(base+`,"first_scan_time":null}`), &schedule); err != nil {
		t.Fatalf("null first_scan_time rejected: %v", err)
	}
	if schedule.FirstScanTime != nil || !schedule.ScanAllTargets {
		t.Fatalf("schedule = %+v", schedule)
	}

	if err := json.Unmarshal([]byte(base+`}`), &schedule); err != nil {
		t.Fatalf("absent first_scan_time rejected: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"id":1,"name":"s","schedule_period":"weekly","status":"scheduled",`+
		`"throttled":false,"web_ports_only":false,"upload_to_drata":false,"upload_to_vanta":false}`), &schedule); err == nil {
		t.Fatal("accepted a schedule with no scan_all_targets")
	}
}
