package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
)

// apiFixture stands in for api.intruder.io in the child process started by
// TestStdioServerProcess, rejecting anything without the right origin or
// credentials.
type apiFixture struct{}

func (apiFixture) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		defer r.Body.Close()
	}

	w := httptest.NewRecorder()
	if r.URL.Scheme != "https" || r.URL.Host != "api.intruder.io" ||
		r.Header.Get("Authorization") != "Bearer fixture-key" || r.Header.Get("User-Agent") == "" {
		w.WriteHeader(403)
		return w.Result(), nil
	}

	const scan = `{"id":2,"status":"in_progress","scan_type":"assessment_schedule","created_at":"2026-01-01T00:00:00Z"}`

	var body string
	switch r.Method + " " + r.URL.Path {
	case "GET /v1/health/":
		body = `{"status":"ok","authenticated_as":"user@example.com"}`

	case "GET /v1/targets/":
		body = `{"count":1,"results":[{"id":1,"address":"example.com","target_status":"live","tags":["prod",null]}]}`
	case "POST /v1/targets/bulk/":
		body = `[{"id":3,"address":"new.example.com","target_status":"unscanned"}]`

	case "GET /v1/issues/":
		body = `{"count":1,"results":[{"id":1,"title":"TLS","severity":"high"}]}`
	case "GET /v1/issues/1/occurrences/":
		body = `{"count":1,"results":[{"id":4,"target":"example.com","protocol":"tcp","port":443}]}`
	case "GET /v1/issues/1/occurrences/4/scanner_output/":
		body = `{"count":1,"results":[{"id":8,"plugin":{"name":"TLS"},"scanner_output":["line"]}]}`
	case "POST /v1/issues/1/occurrences/4/snooze/":
		body = `{"message":"Snoozed"}`

	case "GET /v1/tags/":
		body = `{"count":1,"results":[{"name":"prod"}]}`
	case "GET /v1/licenses/":
		body = `{"count":1,"results":[{"total_infrastructure_licenses":10,"available_infrastructure_licenses":8,"consumed_infrastructure_licenses":2,"total_application_licenses":5,"available_application_licenses":4,"consumed_application_licenses":1}]}`

	case "GET /v1/scans/":
		body = `{"count":1,"results":[` + scan + `]}`
	case "GET /v1/scans/2/", "POST /v1/scans/":
		body = scan
	case "POST /v1/scans/2/cancel/":
		body = `{"notice":"cancelled"}`

	case "POST /v1/targets/1/tags/":
		body = `{"name":"prod"}`
	case "DELETE /v1/targets/1/tags/prod/", "DELETE /v1/scans/schedules/3/":
		w.WriteHeader(204)

	case "DELETE /v1/targets/1/":
		w.WriteHeader(403)

	case "GET /v1/scans/schedules/":
		body = `{"count":0,"results":[]}`
	case "POST /v1/scans/schedules/":
		body = `{"id":3,"notice":"scheduled"}`
	case "PATCH /v1/scans/schedules/3/":
		var patch map[string]any
		if json.NewDecoder(r.Body).Decode(&patch) != nil ||
			!reflect.DeepEqual(patch, map[string]any{"throttled": false, "targets": []any{}}) {
			w.WriteHeader(422)
		} else {
			body = `{"notice":"updated"}`
		}

	default:
		w.WriteHeader(404)
	}

	_, _ = io.WriteString(w, body)
	return w.Result(), nil
}
