package intruder

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// The models decode themselves so a required field the API omits or nulls is
// an error rather than a zero value. Unknown fields are ignored. Hot-path
// types shadow their required fields with pointers and decode in one pass;
// wider types use decodeRequired, which costs a second pass.

var errMissingField = errors.New("API response missing a required field")

// decodeRequired rejects data where a named field is absent or null.
func decodeRequired(data []byte, target any, fields ...string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return err
	}

	for _, field := range fields {
		value, ok := object[field]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("API response missing required field %s", field)
		}
	}
	return json.Unmarshal(data, target)
}

type Health struct {
	Status          string `json:"status"`
	AuthenticatedAs string `json:"authenticated_as"`
}

func (h *Health) UnmarshalJSON(data []byte) error {
	var wire struct {
		Status          *string `json:"status"`
		AuthenticatedAs *string `json:"authenticated_as"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Status == nil || wire.AuthenticatedAs == nil {
		return errMissingField
	}

	*h = Health{Status: *wire.Status, AuthenticatedAs: *wire.AuthenticatedAs}
	return nil
}

type Target struct {
	ID      int64  `json:"id"`
	Address string `json:"address"`
	Status  string `json:"target_status"`
	// Pointers: the API includes nulls in this array.
	Tags []*string `json:"tags"`
}

func (t *Target) UnmarshalJSON(data []byte) error {
	var wire struct {
		ID      *int64    `json:"id"`
		Address *string   `json:"address"`
		Status  *string   `json:"target_status"`
		Tags    []*string `json:"tags"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.ID == nil || wire.Address == nil || wire.Status == nil {
		return errMissingField
	}

	*t = Target{ID: *wire.ID, Address: *wire.Address, Status: *wire.Status, Tags: wire.Tags}
	return nil
}

type Issue struct {
	ID       int64  `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
}

func (i *Issue) UnmarshalJSON(data []byte) error {
	var wire struct {
		ID       *int64  `json:"id"`
		Title    *string `json:"title"`
		Severity *string `json:"severity"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.ID == nil || wire.Title == nil || wire.Severity == nil {
		return errMissingField
	}

	*i = Issue{ID: *wire.ID, Title: *wire.Title, Severity: *wire.Severity}
	return nil
}

// Port may arrive as a string, an integer, or null.
type Port string

func (p *Port) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		*p = ""
		return nil
	}
	var text string
	if json.Unmarshal(data, &text) == nil {
		*p = Port(text)
		return nil
	}

	var number json.Number
	if err := json.Unmarshal(data, &number); err != nil {
		return errors.New("port must be a string, integer, or null")
	}
	if _, err := strconv.ParseInt(number.String(), 10, 64); err != nil {
		return errors.New("port must be an integer")
	}

	*p = Port(number.String())
	return nil
}

type Occurrence struct {
	ID       int64  `json:"id"`
	Target   string `json:"target"`
	Port     Port   `json:"port"`
	Protocol string `json:"protocol"`
}

func (o *Occurrence) UnmarshalJSON(data []byte) error {
	var wire struct {
		ID       *int64  `json:"id"`
		Target   *string `json:"target"`
		Port     Port    `json:"port"`
		Protocol *string `json:"protocol"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.ID == nil || wire.Target == nil || wire.Protocol == nil {
		return errMissingField
	}

	*o = Occurrence{ID: *wire.ID, Target: *wire.Target, Port: wire.Port, Protocol: *wire.Protocol}
	return nil
}

type Plugin struct {
	Name string `json:"name"`
	// Raw: the API has not committed to a shape.
	CVE []json.RawMessage `json:"cve"`
}

func (p *Plugin) UnmarshalJSON(data []byte) error {
	var wire struct {
		Name *string           `json:"name"`
		CVE  []json.RawMessage `json:"cve"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Name == nil {
		return errMissingField
	}

	*p = Plugin{Name: *wire.Name, CVE: wire.CVE}
	return nil
}

type ScannerOutput struct {
	ID     int64  `json:"id"`
	Plugin Plugin `json:"plugin"`
	// Raw: free-form scanner text.
	Lines []json.RawMessage `json:"scanner_output"`
}

func (s *ScannerOutput) UnmarshalJSON(data []byte) error {
	type wire ScannerOutput

	var decoded wire
	if err := decodeRequired(data, &decoded, "id", "plugin"); err != nil {
		return err
	}

	*s = ScannerOutput(decoded)
	return nil
}

type Scan struct {
	ID              int64      `json:"id"`
	Status          string     `json:"status"`
	Type            string     `json:"scan_type"`
	SchedulePeriod  *string    `json:"schedule_period"`
	Throttled       *bool      `json:"throttled"`
	WebPortsOnly    *bool      `json:"web_ports_only"`
	CreatedAt       time.Time  `json:"created_at"`
	StartTime       *time.Time `json:"start_time"`
	CompletedTime   *time.Time `json:"completed_time"`
	TargetAddresses []string   `json:"target_addresses"`
}

func (s *Scan) UnmarshalJSON(data []byte) error {
	// The alias picks up the optional fields; the pointers shadow the rest.
	type optionalFields Scan

	var wire struct {
		optionalFields
		ID        *int64     `json:"id"`
		Status    *string    `json:"status"`
		Type      *string    `json:"scan_type"`
		CreatedAt *time.Time `json:"created_at"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.ID == nil || wire.Status == nil || wire.Type == nil || wire.CreatedAt == nil {
		return errMissingField
	}

	*s = Scan(wire.optionalFields)
	s.ID, s.Status, s.Type, s.CreatedAt = *wire.ID, *wire.Status, *wire.Type, *wire.CreatedAt
	return nil
}

type Tag struct {
	Name string `json:"name"`
}

func (t *Tag) UnmarshalJSON(data []byte) error {
	var wire struct {
		Name *string `json:"name"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Name == nil {
		return errMissingField
	}

	*t = Tag{Name: *wire.Name}
	return nil
}

// Licenses is the account quota. A consumed license is held for 30 days.
type Licenses struct {
	TotalInfrastructure     int64 `json:"total_infrastructure_licenses"`
	AvailableInfrastructure int64 `json:"available_infrastructure_licenses"`
	ConsumedInfrastructure  int64 `json:"consumed_infrastructure_licenses"`
	TotalApplication        int64 `json:"total_application_licenses"`
	AvailableApplication    int64 `json:"available_application_licenses"`
	ConsumedApplication     int64 `json:"consumed_application_licenses"`
}

func (l *Licenses) UnmarshalJSON(data []byte) error {
	type wire Licenses

	var decoded wire
	err := decodeRequired(data, &decoded,
		"total_infrastructure_licenses", "available_infrastructure_licenses", "consumed_infrastructure_licenses",
		"total_application_licenses", "available_application_licenses", "consumed_application_licenses",
	)
	if err != nil {
		return err
	}

	*l = Licenses(decoded)
	return nil
}

type Schedule struct {
	ID             int64      `json:"id"`
	Name           string     `json:"name"`
	SchedulePeriod string     `json:"schedule_period"`
	Status         string     `json:"status"`
	FirstScanTime  *time.Time `json:"first_scan_time"`
	NextScanDate   *time.Time `json:"next_scan_date"`

	Throttled     bool `json:"throttled"`
	WebPortsOnly  bool `json:"web_ports_only"`
	UploadToDrata bool `json:"upload_to_drata"`
	UploadToVanta bool `json:"upload_to_vanta"`
	// Overrides Targets and TargetTags, which then come back empty.
	ScanAllTargets bool `json:"scan_all_targets"`

	LatestScanID      *int64     `json:"latest_scan_id"`
	LatestScanStatus  *string    `json:"latest_scan_status"`
	LastScanStartTime *time.Time `json:"last_scan_start_time"`
	LastScanEndTime   *time.Time `json:"last_scan_end_time"`

	Targets    []int64  `json:"targets"`
	TargetTags []string `json:"target_tags"`
}

func (s *Schedule) UnmarshalJSON(data []byte) error {
	type wire Schedule

	var decoded wire
	err := decodeRequired(data, &decoded,
		"id", "name", "schedule_period", "status",
		"throttled", "web_ports_only", "upload_to_drata", "upload_to_vanta",
		"scan_all_targets",
	)
	if err != nil {
		return err
	}

	*s = Schedule(decoded)
	return nil
}

// MutationResult is the API's loose write reply: an ID, a notice, or a message.
type MutationResult struct {
	ID      *int64 `json:"id"`
	Notice  string `json:"notice"`
	Message string `json:"message"`
}

func (m *MutationResult) UnmarshalJSON(data []byte) error {
	type wire MutationResult

	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	// An empty object would otherwise read as a success with nothing in it.
	if decoded.ID == nil && decoded.Notice == "" && decoded.Message == "" {
		return errors.New("API returned an unrecognized mutation result")
	}
	if decoded.ID != nil {
		if err := positiveID(*decoded.ID); err != nil {
			return err
		}
	}

	*m = MutationResult(decoded)
	return nil
}

// ScanRequest with no selectors scans the whole account.
type ScanRequest struct {
	TargetAddresses []string `json:"target_addresses,omitempty"`
	TagNames        []string `json:"tag_names,omitempty"`
	Throttled       *bool    `json:"throttled,omitempty"`
	WebPortsOnly    *bool    `json:"web_ports_only,omitempty"`
}

type TargetRequest struct {
	Address string `json:"address"`
}

// ScheduleRequest fields are pointers so nil omits the field while a non-nil
// pointer can still send false or an empty array, which is how one is cleared.
type ScheduleRequest struct {
	Name          *string    `json:"name,omitempty"`
	FirstScanTime *time.Time `json:"first_scan_time,omitempty"`
	Frequency     *string    `json:"scan_frequency,omitempty"`
	Targets       *[]int64   `json:"targets,omitempty"`
	Tags          *[]string  `json:"tags,omitempty"`
	Throttled     *bool      `json:"throttled,omitempty"`
	WebPortsOnly  *bool      `json:"web_ports_only,omitempty"`
	UploadToDrata *bool      `json:"upload_to_drata,omitempty"`
	UploadToVanta *bool      `json:"upload_to_vanta,omitempty"`
}

type SnoozeRequest struct {
	// ACCEPT_RISK, FALSE_POSITIVE, or MITIGATING_CONTROLS.
	Reason       string  `json:"reason"`
	Details      *string `json:"details,omitempty"`
	Duration     *int64  `json:"duration,omitempty"`
	DurationType *string `json:"duration_type,omitempty"`
}

// positiveID rejects IDs that would be printed back as if addressable.
func positiveID(id int64) error {
	if id <= 0 {
		return errors.New("API returned a nonpositive ID")
	}
	return nil
}
