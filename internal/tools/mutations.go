package tools

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yurhasko/intruder-mcp-go/internal/intruder"
)

const maxTagLength = 40

// CreateScanInput with no selectors scans the whole account.
type CreateScanInput struct {
	TargetAddresses []string `json:"target_addresses,omitempty"`
	TagNames        []string `json:"tag_names,omitempty"`
	Throttled       *bool    `json:"throttled,omitempty"`
	WebPortsOnly    *bool    `json:"web_ports_only,omitempty"`
}

// DeleteTargetInput takes a string ID, as the Python tool did.
type DeleteTargetInput struct {
	TargetID string `json:"target_id"`
}

type CreateTargetsInput struct {
	Addresses []string `json:"addresses"`
}

type CreateTagInput struct {
	TargetID int64  `json:"target_id"`
	Name     string `json:"name"`
}

type DeleteTagInput struct {
	TargetID int64  `json:"target_id"`
	TagName  string `json:"tag_name"`
}

type SnoozeInput struct {
	IssueID int64 `json:"issue_id"`
	// Optional so the retired snooze_issue tool can share this type.
	OccurrenceID int64   `json:"occurrence_id,omitempty"`
	Reason       string  `json:"reason"`
	Details      *string `json:"details,omitempty"`
	Duration     *int64  `json:"duration,omitempty"`
	DurationType *string `json:"duration_type,omitempty"`
}

// ScheduleInput pointers separate "leave alone" from "set to false or empty".
type ScheduleInput struct {
	ScheduleID    int64     `json:"schedule_id,omitempty"`
	Name          *string   `json:"name,omitempty"`
	FirstScanTime *string   `json:"first_scan_time,omitempty"`
	Frequency     *string   `json:"scan_frequency,omitempty"`
	Targets       *[]int64  `json:"target_ids,omitempty"`
	Tags          *[]string `json:"tag_names,omitempty"`
	Throttled     *bool     `json:"throttled,omitempty"`
	WebPortsOnly  *bool     `json:"web_ports_only,omitempty"`
	UploadToDrata *bool     `json:"upload_to_drata,omitempty"`
	UploadToVanta *bool     `json:"upload_to_vanta,omitempty"`
}

type ScheduleIDInput struct {
	ScheduleID int64 `json:"schedule_id"`
}

func (s *server) registerMutations() {
	add(s, "create_scan", "Create a scan. Omit both selectors to scan the account.",
		write, object(map[string]any{
			"target_addresses": selectorList("Addresses to scan"),
			"tag_names":        selectorList("Tags whose targets should be scanned"),
			"throttled":        optional(boolField("Throttle the scan")),
			"web_ports_only":   optional(boolField("Scan only standard web ports")),
		}), s.createScan)

	add(s, "cancel_scan", "Cancel a running scan.",
		destructive, object(map[string]any{"scan_id": id("Scan ID")}, "scan_id"), s.cancelScan)

	add(s, "create_targets", "Create targets, skipping duplicates. Report created and existing counts.",
		write, object(map[string]any{
			"addresses": addressList("Target addresses to create"),
		}, "addresses"), s.createTargets)

	add(s, "delete_target", "Delete a target.",
		destructive|idempotent, object(map[string]any{
			"target_id": map[string]any{
				"type":        "string",
				"pattern":     `^[1-9][0-9]*$`,
				"description": "Target ID as a decimal string",
			},
		}, "target_id"), s.deleteTarget)

	add(s, "create_target_tag", fmt.Sprintf("Add a tag to a target (1-%d characters).", maxTagLength),
		write, object(map[string]any{
			"target_id": id("Target ID"),
			"name":      tagField("Tag name"),
		}, "target_id", "name"), s.createTargetTag)

	add(s, "delete_target_tag", "Remove a tag from a target.",
		destructive|idempotent, object(map[string]any{
			"target_id": id("Target ID"),
			"tag_name":  tagField("Tag name to remove"),
		}, "target_id", "tag_name"), s.deleteTargetTag)

	// Intruder removed the endpoint. The tool stays registered so a client
	// still calling it gets an explanation rather than "unknown tool", and is
	// read-only because it never reaches the API.
	add(s, "snooze_issue", "Retired. Use snooze_occurrence; future occurrences are not snoozed.",
		readOnly|idempotent, snoozeSchema(false), s.snoozeIssue)

	add(s, "snooze_occurrence", "Snooze an issue occurrence.",
		destructive, snoozeSchema(true), s.snoozeOccurrence)

	add(s, "create_scan_schedule", "Create a recurring scan schedule.",
		write, scheduleSchema(true), s.createScanSchedule)

	add(s, "update_scan_schedule", "Update a schedule. Omit unchanged fields; false and empty arrays are preserved.",
		destructive|idempotent, scheduleSchema(false), s.updateScanSchedule)

	add(s, "delete_scan_schedule", "Delete a scan schedule.",
		destructive|idempotent, object(map[string]any{"schedule_id": id("Schedule ID")}, "schedule_id"), s.deleteScanSchedule)
}

func (s *server) createScan(ctx context.Context, in CreateScanInput) (string, error) {
	if err := validateStrings(in.TargetAddresses, "target_addresses"); err != nil {
		return "", err
	}
	if err := validateStrings(in.TagNames, "tag_names"); err != nil {
		return "", err
	}

	scan, err := s.client.CreateScan(ctx, intruder.ScanRequest{
		TargetAddresses: in.TargetAddresses,
		TagNames:        in.TagNames,
		Throttled:       in.Throttled,
		WebPortsOnly:    in.WebPortsOnly,
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Created scan %d (%s)", scan.ID, scan.Type), nil
}

func (s *server) cancelScan(ctx context.Context, in ScanIDInput) (string, error) {
	result, err := s.client.CancelScan(ctx, in.ScanID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Cancelled scan %d: %s", in.ScanID, result), nil
}

func (s *server) createTargets(ctx context.Context, in CreateTargetsInput) (string, error) {
	if err := validateStrings(in.Addresses, "addresses"); err != nil {
		return "", err
	}

	result, err := s.client.CreateTargets(ctx, in.Addresses)
	if err != nil {
		return "", err
	}
	if result.Existing > 0 {
		return fmt.Sprintf("Created %d targets; %d already existed", result.Created, result.Existing), nil
	}
	return fmt.Sprintf("Created %d targets", result.Created), nil
}

func (s *server) deleteTarget(ctx context.Context, in DeleteTargetInput) (string, error) {
	targetID, err := strconv.ParseInt(in.TargetID, 10, 64)
	if err != nil || targetID <= 0 {
		return "", errors.New("target_id must be a positive decimal ID")
	}

	if err := s.client.DeleteTarget(ctx, targetID); err != nil {
		return "", err
	}
	return "Deleted target " + in.TargetID, nil
}

func (s *server) createTargetTag(ctx context.Context, in CreateTagInput) (string, error) {
	if err := validateTag(in.Name); err != nil {
		return "", err
	}

	tag, err := s.client.CreateTargetTag(ctx, in.TargetID, in.Name)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Added tag '%s' to target %d", tag.Name, in.TargetID), nil
}

func (s *server) deleteTargetTag(ctx context.Context, in DeleteTagInput) (string, error) {
	if err := validateTag(in.TagName); err != nil {
		return "", err
	}

	if err := s.client.DeleteTargetTag(ctx, in.TargetID, in.TagName); err != nil {
		return "", err
	}
	return fmt.Sprintf("Removed tag '%s' from target %d", in.TagName, in.TargetID), nil
}

func (s *server) snoozeIssue(context.Context, SnoozeInput) (string, error) {
	return "", errors.New("snooze_issue is no longer supported; use snooze_occurrence. " +
		"Future occurrences are not automatically snoozed")
}

func (s *server) snoozeOccurrence(ctx context.Context, in SnoozeInput) (string, error) {
	result, err := s.client.SnoozeOccurrence(ctx, in.IssueID, in.OccurrenceID, intruder.SnoozeRequest{
		Reason:       in.Reason,
		Details:      in.Details,
		Duration:     in.Duration,
		DurationType: in.DurationType,
	})
	if err != nil {
		return "", err
	}

	if result.Message != "" {
		return result.Message, nil
	}
	return result.Notice, nil
}

func (s *server) createScanSchedule(ctx context.Context, in ScheduleInput) (string, error) {
	request, err := in.request(time.Now())
	if err != nil {
		return "", err
	}

	result, err := s.client.CreateSchedule(ctx, request)
	if err != nil {
		return "", err
	}
	return formatScheduleResult("Created", result.ID, result), nil
}

func (s *server) updateScanSchedule(ctx context.Context, in ScheduleInput) (string, error) {
	request, err := in.request(time.Now())
	if err != nil {
		return "", err
	}
	if in.Name == nil && in.FirstScanTime == nil && in.Frequency == nil && in.Targets == nil && in.Tags == nil &&
		in.Throttled == nil && in.WebPortsOnly == nil && in.UploadToDrata == nil && in.UploadToVanta == nil {
		return "", errors.New("provide at least one schedule field to update")
	}

	result, err := s.client.UpdateSchedule(ctx, in.ScheduleID, request)
	if err != nil {
		return "", err
	}
	return formatScheduleResult("Updated", &in.ScheduleID, result), nil
}

func (s *server) deleteScanSchedule(ctx context.Context, in ScheduleIDInput) (string, error) {
	if err := s.client.DeleteSchedule(ctx, in.ScheduleID); err != nil {
		return "", err
	}
	return fmt.Sprintf("Deleted scan schedule %d", in.ScheduleID), nil
}

func addressList(description string) map[string]any {
	field := array(map[string]any{"type": "string", "minLength": 1}, description)
	field["minItems"] = 1
	return field
}

// selectorList must be non-empty if present: an empty selector usually came
// from a filter that matched nothing, and scanning everything instead would
// be a nasty surprise.
func selectorList(description string) map[string]any {
	field := array(stringField(description), description)
	field["minItems"] = 1
	return optional(field)
}

func tagField(description string) map[string]any {
	return map[string]any{
		"type":        "string",
		"minLength":   1,
		"maxLength":   maxTagLength,
		"description": description,
	}
}

func validateStrings(values []string, field string) error {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s must not contain empty values", field)
		}
	}
	return nil
}

// validateTag rejects dot segments: the name goes into a URL path.
func validateTag(name string) error {
	if strings.TrimSpace(name) == "" || utf8.RuneCountInString(name) > maxTagLength || name == "." || name == ".." {
		return fmt.Errorf("tag name must contain 1-%d characters and must not be a dot path segment", maxTagLength)
	}
	return nil
}

func snoozeSchema(occurrence bool) map[string]any {
	properties := map[string]any{
		"issue_id": id("Issue ID"),
		"reason":   enum("Snooze reason", "ACCEPT_RISK", "FALSE_POSITIVE", "MITIGATING_CONTROLS"),
		"details":  optional(stringField("Snooze explanation")),
		"duration": optional(map[string]any{
			"type":        "integer",
			"minimum":     1,
			"maximum":     maxSafeInteger,
			"description": "Number of duration_type units to snooze for",
		}),
		"duration_type": optional(enum("Snooze duration unit; 'forever' ignores duration",
			"forever", "day", "week", "month")),
	}
	required := []string{"issue_id", "reason"}

	if occurrence {
		properties["occurrence_id"] = id("Occurrence ID")
		required = append(required, "occurrence_id")
	}
	return object(properties, required...)
}

// scheduleSchema builds both schemas from one set of fields: create requires
// the three a schedule cannot exist without, update requires the ID instead.
func scheduleSchema(create bool) map[string]any {
	name := map[string]any{"type": "string", "minLength": 1, "description": "Schedule name"}
	timestamp := stringField("RFC 3339 timestamp in the future on a whole UTC hour")
	frequency := enum("Scan frequency", "daily", "weekly", "monthly", "quarterly")

	properties := map[string]any{
		"name":            optional(name),
		"first_scan_time": optional(timestamp),
		"scan_frequency":  optional(frequency),
		"target_ids":      optional(array(id("Target ID"), "Target IDs; an empty array clears the set on update")),
		"tag_names":       optional(array(stringField("Tag name"), "Target tags; an empty array clears the set on update")),
		"throttled":       optional(boolField("Throttle scanning")),
		"web_ports_only":  optional(boolField("Scan only standard web ports")),
		"upload_to_drata": optional(boolField("Upload to Drata")),
		"upload_to_vanta": optional(boolField("Upload to Vanta")),
	}

	if create {
		properties["name"] = name
		properties["first_scan_time"] = timestamp
		properties["scan_frequency"] = frequency
		return object(properties, "name", "first_scan_time", "scan_frequency")
	}

	properties["schedule_id"] = id("Schedule ID")
	return object(properties, "schedule_id")
}

// request validates what the schema cannot. now is a parameter so tests can pin it.
func (i ScheduleInput) request(now time.Time) (intruder.ScheduleRequest, error) {
	request := intruder.ScheduleRequest{
		Name:          i.Name,
		Frequency:     i.Frequency,
		Targets:       i.Targets,
		Tags:          i.Tags,
		Throttled:     i.Throttled,
		WebPortsOnly:  i.WebPortsOnly,
		UploadToDrata: i.UploadToDrata,
		UploadToVanta: i.UploadToVanta,
	}

	if i.Name != nil && strings.TrimSpace(*i.Name) == "" {
		return request, errors.New("schedule name must not be empty")
	}

	if i.FirstScanTime != nil {
		parsed, err := time.Parse(time.RFC3339Nano, *i.FirstScanTime)
		if err != nil {
			return request, errors.New("first_scan_time must be an RFC 3339 timestamp with a time zone")
		}

		// The API wants a future start on the hour; catch it before the request.
		parsed = parsed.UTC()
		if !parsed.After(now) || parsed.Minute() != 0 || parsed.Second() != 0 || parsed.Nanosecond() != 0 {
			return request, errors.New("first_scan_time must be in the future on a whole UTC hour")
		}
		request.FirstScanTime = &parsed
	}

	if i.Tags != nil {
		if err := validateStrings(*i.Tags, "tag_names"); err != nil {
			return request, err
		}
	}
	return request, nil
}

func formatScheduleResult(action string, id *int64, result intruder.MutationResult) string {
	notice := result.Notice
	if notice == "" {
		notice = result.Message
	}
	if notice == "" {
		notice = "OK"
	}

	if id == nil {
		return fmt.Sprintf("%s scan schedule: %s", action, notice)
	}
	return fmt.Sprintf("%s scan schedule %d: %s", action, *id, notice)
}
