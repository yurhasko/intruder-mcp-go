package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		key  string
		want string
	}{
		{"missing_key", nil, "", "INTRUDER_API_KEY"},
		{"invalid_key", nil, "key\nheader", "INTRUDER_API_KEY"}, // Header injection.
		{"timeout", []string{"-request-timeout=0"}, "key", "positive"},
		{"concurrency", []string{"-max-concurrent=0"}, "key", "positive"},
		{"pages", []string{"-max-pages=0"}, "key", "positive"},
		{"list_bytes", []string{"-max-list-bytes=0"}, "key", "positive"},
		{"retries", []string{"-read-retries=6"}, "key", "resource limits"},
		{"interval", []string{"-request-interval=-1s"}, "key", "resource limits"},
		{"positional", []string{"unexpected"}, "key", "positional"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			err := run(context.Background(), tc.args, func(string) string { return tc.key }, &stdout, &stderr)
			if err == nil || !strings.Contains(err.Error(), tc.want) || stdout.Len() != 0 {
				t.Fatalf("error=%v stdout=%q", err, stdout.String())
			}
		})
	}
}

// Starts the server as a real child process, speaks JSON-RPC over a pipe,
// calls every tool, and closes stdin to shut it down. The child half is this
// same binary, re-executed with INTRUDER_TEST_STDIO_CHILD set.
func TestStdioServerProcess(t *testing.T) {
	if os.Getenv("INTRUDER_TEST_STDIO_CHILD") == "1" {
		http.DefaultTransport = apiFixture{}
		if err := run(context.Background(), []string{"-request-interval=0", "-read-retries=0"}, os.Getenv, os.Stdout, os.Stderr); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStdioServerProcess$")
	cmd.Env = append(os.Environ(), "INTRUDER_TEST_STDIO_CHILD=1", "INTRUDER_API_KEY=fixture-key")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 1<<20)

	request := func(message string, id int) map[string]json.RawMessage {
		t.Helper()

		if _, err := fmt.Fprintln(stdin, message); err != nil {
			t.Fatal(err)
		}
		for scanner.Scan() {
			var response map[string]json.RawMessage
			if err := json.Unmarshal(scanner.Bytes(), &response); err != nil {
				t.Fatalf("non-protocol stdout: %q", scanner.Text())
			}
			var got int
			if json.Unmarshal(response["id"], &got) == nil && got == id {
				return response
			}
		}
		t.Fatalf("no response to %d: %v", id, scanner.Err())
		return nil
	}

	initialized := request(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`, 1)
	if initialized["error"] != nil {
		t.Fatalf("initialize = %s", initialized["error"])
	}
	if _, err := fmt.Fprintln(stdin, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); err != nil {
		t.Fatal(err)
	}

	listed := request(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, 2)
	var list struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(listed["result"], &list); err != nil || len(list.Tools) != 22 {
		t.Fatalf("tools/list = %s error=%v", listed["result"], err)
	}

	for index, tc := range []struct {
		name, args, want string
		isError          bool
	}{
		{"get_user", `{}`, "user@example.com", false},
		{"get_status", `{}`, "ok", false},
		{"list_targets", `{}`, "1 - example.com (live)", false},
		{"list_issues", `{}`, "1 - TLS (high)", false},
		{"list_scans", `{}`, "2 - assessment_schedule", false},
		{"list_tags", `{}`, "prod", false},
		{"list_occurrences", `{"issue_id":1}`, "example.com:443/tcp", false},
		{"get_scanner_output", `{"issue_id":1,"occurrence_id":4}`, "Plugin: TLS", false},
		{"get_scan", `{"scan_id":2}`, "Scan 2", false},
		{"create_scan", `{"target_addresses":["example.com"]}`, "Created scan 2", false},
		{"cancel_scan", `{"scan_id":2}`, "Cancelled scan 2", false},
		{"delete_target", `{"target_id":"1"}`, "403", true},
		{"create_targets", `{"addresses":["example.com","new.example.com"]}`, "Created 1 targets; 1 already existed", false},
		{"create_target_tag", `{"target_id":1,"name":"prod"}`, "Added tag 'prod'", false},
		{"delete_target_tag", `{"target_id":1,"tag_name":"prod"}`, "Removed tag 'prod'", false},
		{"list_licenses", `{}`, "Infrastructure Licenses:", false},
		{"snooze_issue", `{"issue_id":1,"reason":"ACCEPT_RISK"}`, "no longer supported", true},
		{"snooze_occurrence", `{"issue_id":1,"occurrence_id":4,"reason":"ACCEPT_RISK"}`, "Snoozed", false},
		{"list_scan_schedules", `{}`, "No scan schedules found.", false},
		{"create_scan_schedule", `{"name":"Weekly","first_scan_time":"2099-01-01T00:00:00Z","scan_frequency":"weekly"}`, "Created scan schedule 3", false},
		{"update_scan_schedule", `{"schedule_id":3,"throttled":false,"target_ids":[]}`, "Updated scan schedule 3", false},
		{"delete_scan_schedule", `{"schedule_id":3}`, "Deleted scan schedule 3", false},
	} {
		id := index + 3
		message := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, id, tc.name, tc.args)
		response := request(message, id)

		var result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(response["result"], &result); err != nil ||
			result.IsError != tc.isError || len(result.Content) != 1 ||
			!strings.Contains(result.Content[0].Text, tc.want) {
			t.Fatalf("%s = %s error=%v", tc.name, response["result"], err)
		}
	}

	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("process exit: %v stderr=%q", err, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestVersionAndHelpDoNotRequireCredentials(t *testing.T) {
	for _, args := range [][]string{{"-version"}, {"-help"}} {
		var stdout, stderr bytes.Buffer

		getenv := func(string) string {
			t.Fatal("read credentials for version/help")
			return ""
		}
		if err := run(context.Background(), args, getenv, &stdout, &stderr); err != nil {
			t.Fatal(err)
		}

		if args[0] == "-version" && stdout.String() != version+"\n" {
			t.Fatalf("version = %q", stdout.String())
		}
		if args[0] == "-help" && !strings.Contains(stderr.String(), "request-interval") {
			t.Fatalf("help = %q", stderr.String())
		}
	}
}
