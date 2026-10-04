package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/yurhasko/intruder-mcp-go/internal/intruder"
)

type fixtureTransport struct{ handler http.HandlerFunc }

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	f.handler(w, r)

	if err := r.Context().Err(); err != nil {
		return nil, err
	}

	response := w.Result()
	response.Request = r
	return response, nil
}

func session(t *testing.T, handler http.HandlerFunc, opts Options) *mcp.ClientSession {
	t.Helper()

	api, err := intruder.New("fixture-key", intruder.Options{
		HTTPClient: &http.Client{Transport: fixtureTransport{handler}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(api.Close)

	server, err := New(api, opts)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, arguments any) *mcp.CallToolResult {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: arguments})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func resultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()

	if len(result.Content) != 1 {
		t.Fatalf("content = %#v", result.Content)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content = %T", result.Content[0])
	}
	return text.Text
}

func TestToolContract(t *testing.T) {
	reads := []string{
		"get_user", "get_status", "list_targets", "list_issues", "list_scans", "list_tags",
		"list_occurrences", "get_scanner_output", "get_scan", "list_licenses", "list_scan_schedules",
	}
	writes := []string{
		"create_scan", "cancel_scan", "delete_target", "create_targets", "create_target_tag",
		"delete_target_tag", "snooze_issue", "snooze_occurrence", "create_scan_schedule",
		"update_scan_schedule", "delete_scan_schedule",
	}

	cs := session(t, func(http.ResponseWriter, *http.Request) {
		t.Error("discovery made an API request")
	}, Options{})

	list, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Tools) != len(reads)+len(writes) {
		t.Fatalf("tools = %d", len(list.Tools))
	}

	var got []string
	for _, tool := range list.Tools {
		got = append(got, tool.Name)

		wantReadOnly := slices.Contains(reads, tool.Name) || tool.Name == "snooze_issue"
		if tool.Description == "" || tool.Annotations == nil || tool.Annotations.ReadOnlyHint != wantReadOnly {
			t.Errorf("invalid metadata: %s", tool.Name)
		}

		encoded, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		var schema map[string]any
		if err := json.Unmarshal(encoded, &schema); err != nil {
			t.Fatal(err)
		}
		if schema["type"] != "object" || schema["additionalProperties"] != false {
			t.Errorf("schema %s = %s", tool.Name, encoded)
		}

		if tool.OutputSchema != nil {
			t.Errorf("unexpected structured output schema for %s", tool.Name)
		}
	}

	want := append(reads, writes...)
	slices.Sort(want)
	slices.Sort(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("names = %v", got)
	}
}

const (
	scanFixture     = `{"id":2,"status":"in_progress","scan_type":"assessment_schedule","created_at":"2026-01-01T00:00:00Z"}`
	scheduleFixture = `{"id":3,"name":"Weekly","schedule_period":"weekly","status":"active","first_scan_time":"2026-01-01T00:00:00Z","throttled":false,"web_ports_only":true,"upload_to_drata":false,"upload_to_vanta":false,"scan_all_targets":false}`
)

func TestToolsThroughProtocol(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body, want string
		args                           map[string]any
	}{
		{"get_user", "GET", "/v1/health/", `{"status":"ok","authenticated_as":"user@example.com"}`, "user@example.com", nil},
		{"get_status", "GET", "/v1/health/", `{"status":"ok","authenticated_as":"user@example.com"}`, "ok", nil},
		{"list_targets", "GET", "/v1/targets/", `{"count":1,"results":[{"id":1,"address":"example.com","target_status":"live"}]}`, "1 - example.com (live)", nil},
		{"list_issues", "GET", "/v1/issues/", `{"count":1,"results":[{"id":1,"title":"TLS","severity":"high"}]}`, "1 - TLS (high)", map[string]any{"snoozed": false, "severity": "high"}},
		{"list_scans", "GET", "/v1/scans/", `{"count":1,"results":[` + scanFixture + `]}`, "2 - assessment_schedule (in_progress)", nil},
		{"list_tags", "GET", "/v1/tags/", `{"count":3,"results":[{"name":"prod"},{"name":"dev"},{"name":"prod"}]}`, "dev\nprod", nil},
		{"list_occurrences", "GET", "/v1/issues/1/occurrences/", `{"count":1,"results":[{"id":4,"target":"example.com","port":443,"protocol":"tcp"}]}`, "4 - example.com:443/tcp", map[string]any{"issue_id": 1}},
		{"get_scanner_output", "GET", "/v1/issues/1/occurrences/4/scanner_output/", `{"count":1,"results":[{"id":8,"plugin":{"name":"TLS","cve":["CVE-test"]},"scanner_output":["line",{"key":true},null]}]}`, "Plugin: TLS (CVEs: CVE-test)\nOutput:\nline\n{\"key\":true}\nnull\n", map[string]any{"issue_id": 1, "occurrence_id": 4}},
		{"get_scan", "GET", "/v1/scans/2/", scanFixture, "Scan 2 (assessment_schedule)", map[string]any{"scan_id": 2}},
		{"list_licenses", "GET", "/v1/licenses/", `{"count":1,"results":[{"total_infrastructure_licenses":10,"available_infrastructure_licenses":8,"consumed_infrastructure_licenses":2,"total_application_licenses":5,"available_application_licenses":4,"consumed_application_licenses":1}]}`, "Infrastructure Licenses:\n  Total: 10", nil},
		{"list_scan_schedules", "GET", "/v1/scans/schedules/", `{"count":1,"results":[` + scheduleFixture + `]}`, "3 - Weekly\n  schedule_period: weekly", nil},
		{"create_scan", "POST", "/v1/scans/", scanFixture, "Created scan 2 (assessment_schedule)", map[string]any{"target_addresses": []string{"example.com"}}},
		{"cancel_scan", "POST", "/v1/scans/2/cancel/", `{"notice":"cancelled"}`, "Cancelled scan 2", map[string]any{"scan_id": 2}},
		{"delete_target", "DELETE", "/v1/targets/1/", "", "Deleted target 1", map[string]any{"target_id": "1"}},
		{"create_target_tag", "POST", "/v1/targets/1/tags/", `{"name":"prod"}`, "Added tag 'prod' to target 1", map[string]any{"target_id": 1, "name": "prod"}},
		{"delete_target_tag", "DELETE", "/v1/targets/1/tags/prod/", "", "Removed tag 'prod' from target 1", map[string]any{"target_id": 1, "tag_name": "prod"}},
		{"snooze_occurrence", "POST", "/v1/issues/1/occurrences/4/snooze/", `{"message":"Snoozed"}`, "Snoozed", map[string]any{"issue_id": 1, "occurrence_id": 4, "reason": "ACCEPT_RISK"}},
		{"create_scan_schedule", "POST", "/v1/scans/schedules/", `{"id":3,"notice":"scheduled"}`, "Created scan schedule 3: scheduled", map[string]any{"name": "Weekly", "first_scan_time": "2099-01-01T00:00:00Z", "scan_frequency": "weekly"}},
		{"update_scan_schedule", "PATCH", "/v1/scans/schedules/3/", `{"notice":"updated"}`, "Updated scan schedule 3: updated", map[string]any{"schedule_id": 3, "throttled": false, "target_ids": []int{}}},
		{"delete_scan_schedule", "DELETE", "/v1/scans/schedules/3/", "", "Deleted scan schedule 3", map[string]any{"schedule_id": 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests int

			cs := session(t, func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != tc.method || r.URL.Path != tc.path {
					t.Errorf("request = %s %s", r.Method, r.URL.Path)
				}

				if tc.name == "list_issues" && r.URL.Query().Get("snoozed") != "false" {
					t.Error("explicit false filter was lost")
				}

				if tc.name == "update_scan_schedule" {
					var payload map[string]any
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Error(err)
					}
					if !reflect.DeepEqual(payload, map[string]any{"throttled": false, "targets": []any{}}) {
						t.Errorf("patch = %#v", payload)
					}
				}

				if tc.body == "" {
					w.WriteHeader(http.StatusNoContent)
				} else {
					fmt.Fprint(w, tc.body)
				}
			}, Options{})

			result := call(t, cs, tc.name, tc.args)
			if result.IsError || !strings.Contains(resultText(t, result), tc.want) || requests != 1 || result.StructuredContent != nil {
				t.Fatalf("result=%+v text=%q requests=%d", result, resultText(t, result), requests)
			}
		})
	}
}

func TestRetiredAndInvalidToolsMakeNoRequests(t *testing.T) {
	var requests atomic.Int32
	cs := session(t, func(http.ResponseWriter, *http.Request) { requests.Add(1) }, Options{})

	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"snooze_issue", map[string]any{"issue_id": 1, "reason": "ACCEPT_RISK"}},
		{"delete_target", map[string]any{"target_id": "0"}},
		{"get_scan", map[string]any{"scan_id": 0}},
		{"get_scan", map[string]any{"scan_id": 1, "unexpected": true}},
		{"list_issues", map[string]any{"severity": "nonsense"}},
		{"create_scan", map[string]any{"target_addresses": []string{}}},
		{"create_targets", map[string]any{"addresses": []string{}}},
		{"create_target_tag", map[string]any{"target_id": 1, "name": ".."}},
		{"update_scan_schedule", map[string]any{"schedule_id": 1}},
		{"create_scan_schedule", map[string]any{"name": "Weekly", "scan_frequency": "weekly", "first_scan_time": "2099-01-01T00:01:00Z"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tc.name, Arguments: tc.args})
			if err == nil && (result == nil || !result.IsError) {
				t.Fatalf("accepted invalid or retired tool: %+v", result)
			}
		})
	}

	if requests.Load() != 0 {
		t.Fatalf("requests = %d", requests.Load())
	}
}

func TestFailedDeleteReturnsToolError(t *testing.T) {
	cs := session(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"detail":"private"}`)
	}, Options{})

	result := call(t, cs, "delete_target", map[string]any{"target_id": "1"})

	text := resultText(t, result)
	if !result.IsError || !strings.Contains(text, "403") || strings.Contains(text, "private") || strings.Contains(text, "Deleted") {
		t.Fatalf("result = %+v text=%q", result, text)
	}
}

func TestToolDeadlineAndOutputLimit(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		cs := session(t, func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}, Options{ToolTimeout: 20 * time.Millisecond})

		result := call(t, cs, "get_status", nil)
		if !result.IsError || !strings.Contains(resultText(t, result), "deadline") {
			t.Fatalf("result = %+v", result)
		}
	})

	t.Run("output", func(t *testing.T) {
		cs := session(t, func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `{"status":"healthy","authenticated_as":"test"}`)
		}, Options{MaxOutputBytes: 2})

		result := call(t, cs, "get_status", nil)
		if !result.IsError || !strings.Contains(resultText(t, result), "output exceeded") {
			t.Fatalf("result = %+v", result)
		}
	})
}

func TestBulkToolAndFilteredTags(t *testing.T) {
	cs := session(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			fmt.Fprint(w, `[{"id":2,"address":"new.example.com","target_status":"unscanned"}]`)
			return
		}
		fmt.Fprint(w, `{"count":1,"results":[{"id":1,"address":"example.com","target_status":"live","tags":["prod",null,"prod"]}]}`)
	}, Options{})

	created := call(t, cs, "create_targets", map[string]any{
		"addresses": []string{"example.com", "new.example.com", "new.example.com"},
	})
	if created.IsError || resultText(t, created) != "Created 1 targets; 1 already existed" {
		t.Fatalf("result = %+v", created)
	}

	tags := call(t, cs, "list_tags", map[string]any{"target_address": "example.com"})
	if tags.IsError || resultText(t, tags) != "prod" {
		t.Fatalf("result = %+v", tags)
	}
}

func TestConcurrentProtocolCallsRemainResponsive(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)

	cs := session(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/targets/" {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
			}
			fmt.Fprint(w, `{"count":0,"results":[]}`)
			return
		}
		fmt.Fprint(w, `{"status":"ok","authenticated_as":"user"}`)
	}, Options{})

	done := make(chan error, 1)
	go func() {
		_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_targets"})
		done <- err
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("slow request did not start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	status, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_status"})
	if err != nil || status.IsError {
		t.Fatalf("independent call was blocked: %v %+v", err, status)
	}
}

func TestProtocolCancellationReachesAPI(t *testing.T) {
	entered := make(chan struct{})
	canceled := make(chan struct{})

	cs := session(t, func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
	}, Options{ToolTimeout: time.Second})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_status"})
		done <- err
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("API request did not start")
	}

	cancel()

	select {
	case <-canceled:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("MCP cancellation did not reach API")
	}

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("call error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("client call did not finish")
	}
}

// scan_all_targets covers the account and empties both selection lists;
// "(none)" would say the opposite of what the schedule does.
func TestScheduleCoveringAllTargets(t *testing.T) {
	cs := session(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"count":1,"results":[{"id":3,"name":"Monthly","schedule_period":"monthly",`+
			`"status":"scheduled","first_scan_time":null,"throttled":false,"web_ports_only":false,`+
			`"upload_to_drata":false,"upload_to_vanta":false,"scan_all_targets":true,`+
			`"targets":[],"target_tags":[]}]}`)
	}, Options{})

	text := resultText(t, call(t, cs, "list_scan_schedules", nil))
	for _, want := range []string{"scan_all_targets: true", "targets: (all targets)", "target_tags: (all targets)"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if !strings.Contains(text, "first_scan_time: None") {
		t.Errorf("null first_scan_time not rendered:\n%s", text)
	}
}

func TestNewFiltersReachTheAPI(t *testing.T) {
	for _, tc := range []struct {
		tool  string
		args  map[string]any
		field string
		want  string
	}{
		{"list_issues", map[string]any{"exploit_likelihood": "known"}, "exploit_likelihood", "known"},
		{"list_issues", map[string]any{"issue_ids": []int{7, 9}}, "issue_ids", "7,9"},
		{"list_issues", map[string]any{"vulnerability_categories": []string{"TLS", "Headers"}}, "vulnerability_categories", "TLS,Headers"},
		{"list_issues", map[string]any{"since": "2026-01-15T10:00:00Z"}, "since", "2026-01-15T10:00:00Z"},
		{"list_issues", map[string]any{"exclude_deleted_targets": true}, "exclude_deleted_targets", "true"},
		{"list_targets", map[string]any{"target_status": "live"}, "target_status", "live"},
		{"list_targets", map[string]any{"target_type": "container_image"}, "target_type", "container_image"},
		{"list_targets", map[string]any{"ordering": "-last_scanned"}, "ordering", "-last_scanned"},
		{"list_targets", map[string]any{"tag_names": []string{"a", "b"}}, "tag_names", "a,b"},
		{"list_targets", map[string]any{"waf_interference": true}, "waf_interference", "true"},
		{"list_scans", map[string]any{"scan_type": "container_image"}, "scan_type", "container_image"},
		{"list_scans", map[string]any{"schedule_period": "one_off"}, "schedule_period", "one_off"},
		{"list_scans", map[string]any{"tag_names": []string{"a", "b"}}, "tag_names", "a,b"},
		{"list_occurrences", map[string]any{"issue_id": 1, "since": "2026-01-15T10:00:00Z"}, "since", "2026-01-15T10:00:00Z"},
	} {
		t.Run(tc.tool+"/"+tc.field, func(t *testing.T) {
			var values []string
			cs := session(t, func(w http.ResponseWriter, r *http.Request) {
				values = r.URL.Query()[tc.field]
				fmt.Fprint(w, `{"count":0,"results":[]}`)
			}, Options{})

			if result := call(t, cs, tc.tool, tc.args); result.IsError {
				t.Fatalf("tool error: %s", resultText(t, result))
			}
			if len(values) != 1 || values[0] != tc.want {
				t.Fatalf("%s = %q, want exactly one value %q", tc.field, values, tc.want)
			}
		})
	}
}

func TestCreateScanOptions(t *testing.T) {
	var payload map[string]any
	cs := session(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&payload)
		fmt.Fprint(w, scanFixture)
	}, Options{})

	result := call(t, cs, "create_scan", map[string]any{
		"target_addresses": []string{"example.com"},
		"throttled":        true,
		"web_ports_only":   false,
	})
	if result.IsError {
		t.Fatalf("tool error: %s", resultText(t, result))
	}

	want := map[string]any{
		"target_addresses": []any{"example.com"},
		"throttled":        true,
		"web_ports_only":   false,
	}
	if !reflect.DeepEqual(payload, want) {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestSnoozeDurationTypeIsConstrained(t *testing.T) {
	cs := session(t, func(http.ResponseWriter, *http.Request) {
		t.Error("invalid duration_type reached the API")
	}, Options{})

	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "snooze_occurrence",
		Arguments: map[string]any{
			"issue_id": 1, "occurrence_id": 4, "reason": "ACCEPT_RISK",
			"duration": 3, "duration_type": "hours", // What the Python docstring claimed.
		},
	})
	if err == nil && (result == nil || !result.IsError) {
		t.Fatalf("accepted invalid duration_type: %+v", result)
	}
}
