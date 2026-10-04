package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/yurhasko/intruder-mcp-go/internal/intruder"
)

type Empty struct{}

type IssueInput struct {
	TargetAddresses         []string `json:"target_addresses,omitempty"`
	TagNames                []string `json:"tag_names,omitempty"`
	IssueIDs                []int64  `json:"issue_ids,omitempty"`
	VulnerabilityCategories []string `json:"vulnerability_categories,omitempty"`
	Snoozed                 *bool    `json:"snoozed,omitempty"`
	Severity                *string  `json:"severity,omitempty"`
	ExploitLikelihood       *string  `json:"exploit_likelihood,omitempty"`
	Since                   *string  `json:"since,omitempty"`
	ExcludeDeletedTargets   *bool    `json:"exclude_deleted_targets,omitempty"`
}

func (i IssueInput) filters() intruder.IssueFilters {
	return intruder.IssueFilters{
		TargetAddresses:         i.TargetAddresses,
		TagNames:                i.TagNames,
		IssueIDs:                i.IssueIDs,
		VulnerabilityCategories: i.VulnerabilityCategories,
		Snoozed:                 i.Snoozed,
		Severity:                i.Severity,
		ExploitLikelihood:       i.ExploitLikelihood,
		Since:                   i.Since,
		ExcludeDeletedTargets:   i.ExcludeDeletedTargets,
	}
}

type TargetsInput struct {
	Address           *string  `json:"address,omitempty"`
	TagNames          []string `json:"tag_names,omitempty"`
	Status            *string  `json:"target_status,omitempty"`
	Type              *string  `json:"target_type,omitempty"`
	Ordering          *string  `json:"ordering,omitempty"`
	LastScannedAfter  *string  `json:"last_scanned_after,omitempty"`
	LastScannedBefore *string  `json:"last_scanned_before,omitempty"`
	WAFInterference   *bool    `json:"waf_interference,omitempty"`
}

func (i TargetsInput) filters() intruder.TargetFilters {
	return intruder.TargetFilters{
		Address:           i.Address,
		TagNames:          i.TagNames,
		Status:            i.Status,
		Type:              i.Type,
		Ordering:          i.Ordering,
		LastScannedAfter:  i.LastScannedAfter,
		LastScannedBefore: i.LastScannedBefore,
		WAFInterference:   i.WAFInterference,
	}
}

// OccurrenceInput has no severity: that belongs to the issue, not the occurrence.
type OccurrenceInput struct {
	IssueID               int64    `json:"issue_id"`
	TargetAddresses       []string `json:"target_addresses,omitempty"`
	TagNames              []string `json:"tag_names,omitempty"`
	Snoozed               *bool    `json:"snoozed,omitempty"`
	Since                 *string  `json:"since,omitempty"`
	ExcludeDeletedTargets *bool    `json:"exclude_deleted_targets,omitempty"`
}

type ScannerInput struct {
	IssueID      int64 `json:"issue_id"`
	OccurrenceID int64 `json:"occurrence_id"`
}

type ScanIDInput struct {
	ScanID int64 `json:"scan_id"`
}

type ScanFiltersInput struct {
	Status         *string  `json:"status,omitempty"`
	Type           *string  `json:"scan_type,omitempty"`
	SchedulePeriod *string  `json:"schedule_period,omitempty"`
	TagNames       []string `json:"tag_names,omitempty"`
}

func (i ScanFiltersInput) filters() intruder.ScanFilters {
	return intruder.ScanFilters{
		Status:         i.Status,
		Type:           i.Type,
		SchedulePeriod: i.SchedulePeriod,
		TagNames:       i.TagNames,
	}
}

type TagsInput struct {
	TargetAddress *string `json:"target_address,omitempty"`
}

func issueProperties() map[string]any {
	return map[string]any{
		"target_addresses": optional(array(stringField("Target address"), "Filter by target addresses")),
		"tag_names":        optional(array(stringField("Tag name"), "Filter by tag names")),
		"snoozed":          optional(boolField("Filter by snoozed status")),
		"severity":         optional(enum("Filter by severity", "critical", "high", "medium", "low")),
		"exploit_likelihood": optional(enum("Filter by exploit likelihood",
			"known", "very_likely", "likely", "unlikely", "rare", "unknown")),
		"vulnerability_categories": optional(array(stringField("Vulnerability category"),
			"Filter by vulnerability category, e.g. 'Attack Surface Reduction'")),
		"issue_ids": optional(array(id("Issue ID"), "Filter by specific issue IDs")),
		"since": optional(stringField(
			"RFC 3339 timestamp; show only issues with new occurrences since then")),
		"exclude_deleted_targets": optional(boolField(
			"Exclude issues found only on deleted targets")),
	}
}

func targetProperties() map[string]any {
	return map[string]any{
		"address":   optional(stringField("Filter by target address or display address")),
		"tag_names": optional(array(stringField("Tag name"), "Filter by tag names")),
		"target_status": optional(enum("Filter by target status",
			"live", "license_exceeded", "unscanned", "unresponsive", "agent_uninstalled")),
		"target_type": optional(enum("Filter by target type",
			"external", "internal", "cloud", "container_image")),
		"ordering": optional(enum("Order by last scanned date; unscanned targets come first",
			"last_scanned", "-last_scanned")),
		"last_scanned_after":  optional(stringField("Only targets last scanned on or after this date (YYYY-MM-DD)")),
		"last_scanned_before": optional(stringField("Only targets last scanned on or before this date (YYYY-MM-DD)")),
		"waf_interference":    optional(boolField("Filter by whether WAF interference was detected")),
	}
}

func occurrenceProperties() map[string]any {
	properties := issueProperties()
	for _, field := range []string{"severity", "exploit_likelihood", "vulnerability_categories", "issue_ids"} {
		delete(properties, field)
	}
	properties["issue_id"] = id("Issue ID")
	properties["since"] = optional(stringField(
		"RFC 3339 timestamp; show only occurrences first seen since then"))
	return properties
}

func (s *server) registerReads() {
	const read = readOnly | idempotent

	add(s, "get_user", "Get the authenticated Intruder user.",
		read, object(nil), s.getUser)

	add(s, "get_status", "Get the Intruder API status.",
		read, object(nil), s.getStatus)

	add(s, "list_targets", "List target IDs, addresses, and status, with optional filters.",
		read, object(targetProperties()), s.listTargets)

	add(s, "list_issues", "List issues with optional filters.",
		read, object(issueProperties()), s.listIssues)

	add(s, "list_occurrences", "List occurrences for an issue with optional filters.",
		read, object(occurrenceProperties(), "issue_id"), s.listOccurrences)

	add(s, "get_scanner_output", "Get scanner output for an issue occurrence.",
		read, object(map[string]any{
			"issue_id":      id("Issue ID"),
			"occurrence_id": id("Occurrence ID"),
		}, "issue_id", "occurrence_id"), s.getScannerOutput)

	add(s, "list_scans", "List scans with optional status and scan type filters.",
		read, object(map[string]any{
			"status": optional(enum("Scan status",
				"in_progress", "completed", "cancelled", "cancelled_no_active_targets",
				"cancelled_no_valid_targets", "analysing_results",
			)),
			"scan_type": optional(enum("Scan type",
				"assessment_schedule", "new_service", "cloudbot_new_target",
				"rapid_remediation", "advisory", "cloud_security", "container_image",
			)),
			"schedule_period": optional(enum("Schedule period",
				"daily", "weekly", "monthly", "quarterly", "one_off",
			)),
			"tag_names": optional(array(stringField("Tag name"),
				"Only scans that ran against at least one target with these tags")),
		}), s.listScans)

	add(s, "get_scan", "Get scan details.",
		read, object(map[string]any{"scan_id": id("Scan ID")}, "scan_id"), s.getScan)

	add(s, "list_tags", "List account tags, optionally filtered by target address.",
		read, object(map[string]any{
			"target_address": optional(stringField("Filter by target address")),
		}), s.listTags)

	add(s, "list_licenses", "List infrastructure and application license usage and limits.",
		read, object(nil), s.listLicenses)

	add(s, "list_scan_schedules", "List scan schedules and their details.",
		read, object(nil), s.listScanSchedules)
}

func (s *server) getUser(ctx context.Context, _ Empty) (string, error) {
	health, err := s.client.Health(ctx)
	return health.AuthenticatedAs, err
}

func (s *server) getStatus(ctx context.Context, _ Empty) (string, error) {
	health, err := s.client.Health(ctx)
	return health.Status, err
}

func (s *server) listTargets(ctx context.Context, in TargetsInput) (string, error) {
	targets, err := s.client.Targets(ctx, in.filters())
	if err != nil {
		return "", err
	}

	lines := make([]string, 0, len(targets))
	for _, target := range targets {
		lines = append(lines, fmt.Sprintf("%d - %s (%s)", target.ID, target.Address, target.Status))
	}
	return strings.Join(lines, "\n"), nil
}

func (s *server) listIssues(ctx context.Context, in IssueInput) (string, error) {
	issues, err := s.client.Issues(ctx, in.filters())
	if err != nil {
		return "", err
	}

	lines := make([]string, 0, len(issues))
	for _, issue := range issues {
		lines = append(lines, fmt.Sprintf("%d - %s (%s)", issue.ID, issue.Title, issue.Severity))
	}
	return strings.Join(lines, "\n"), nil
}

func (s *server) listOccurrences(ctx context.Context, in OccurrenceInput) (string, error) {
	filters := IssueInput{
		TargetAddresses:       in.TargetAddresses,
		TagNames:              in.TagNames,
		Snoozed:               in.Snoozed,
		Since:                 in.Since,
		ExcludeDeletedTargets: in.ExcludeDeletedTargets,
	}.filters()

	occurrences, err := s.client.Occurrences(ctx, in.IssueID, filters)
	if err != nil {
		return "", err
	}

	lines := make([]string, 0, len(occurrences))
	for _, occurrence := range occurrences {
		port := string(occurrence.Port)
		if port == "" {
			port = "None" // As the Python server rendered it.
		}
		lines = append(lines, fmt.Sprintf("%d - %s:%s/%s", occurrence.ID, occurrence.Target, port, occurrence.Protocol))
	}
	return strings.Join(lines, "\n"), nil
}

func (s *server) getScannerOutput(ctx context.Context, in ScannerInput) (string, error) {
	outputs, err := s.client.ScannerOutput(ctx, in.IssueID, in.OccurrenceID)
	if err != nil {
		return "", err
	}

	var lines []string
	for _, output := range outputs {
		plugin := "Plugin: " + output.Plugin.Name
		if len(output.Plugin.CVE) > 0 {
			cves := make([]string, 0, len(output.Plugin.CVE))
			for _, cve := range output.Plugin.CVE {
				cves = append(cves, jsonText(cve))
			}
			plugin += " (CVEs: " + strings.Join(cves, ", ") + ")"
		}

		lines = append(lines, plugin, "Output:")
		for _, line := range output.Lines {
			lines = append(lines, jsonText(line))
		}
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n"), nil
}

func (s *server) listScans(ctx context.Context, in ScanFiltersInput) (string, error) {
	scans, err := s.client.Scans(ctx, in.filters())
	if err != nil {
		return "", err
	}

	lines := make([]string, 0, len(scans))
	for _, scan := range scans {
		lines = append(lines, fmt.Sprintf("%d - %s (%s)", scan.ID, scan.Type, scan.Status))
	}
	return strings.Join(lines, "\n"), nil
}

func (s *server) getScan(ctx context.Context, in ScanIDInput) (string, error) {
	scan, err := s.client.Scan(ctx, in.ScanID)
	if err != nil {
		return "", err
	}

	lines := []string{
		fmt.Sprintf("Scan %d (%s)", scan.ID, scan.Type),
		"Status: " + scan.Status,
		"Schedule: " + nullableString(scan.SchedulePeriod),
		"Created: " + timestamp(scan.CreatedAt),
		"Type: " + scan.Type,
	}
	if scan.Throttled != nil {
		lines = append(lines, fmt.Sprintf("Throttled: %t", *scan.Throttled))
	}
	if scan.WebPortsOnly != nil {
		lines = append(lines, fmt.Sprintf("Web ports only: %t", *scan.WebPortsOnly))
	}
	if scan.StartTime != nil {
		lines = append(lines, "Started: "+timestamp(*scan.StartTime))
	}
	if scan.CompletedTime != nil {
		lines = append(lines, "Completed: "+timestamp(*scan.CompletedTime))
	}
	if len(scan.TargetAddresses) > 0 {
		lines = append(lines, "\nTargets:")
		for _, address := range scan.TargetAddresses {
			lines = append(lines, "- "+address)
		}
	}
	return strings.Join(lines, "\n"), nil
}

// listTags derives the set from one target when an address is given: the tag
// endpoint has no address filter.
func (s *server) listTags(ctx context.Context, in TagsInput) (string, error) {
	var names []string

	if in.TargetAddress == nil || *in.TargetAddress == "" {
		tags, err := s.client.Tags(ctx)
		if err != nil {
			return "", err
		}
		for _, tag := range tags {
			names = append(names, tag.Name)
		}
	} else {
		targets, err := s.client.Targets(ctx, intruder.TargetFilters{Address: in.TargetAddress})
		if err != nil {
			return "", err
		}
		for _, target := range targets {
			for _, tag := range target.Tags {
				if tag != nil {
					names = append(names, *tag)
				}
			}
		}
	}

	slices.Sort(names)
	return strings.Join(slices.Compact(names), "\n"), nil
}

func (s *server) listLicenses(ctx context.Context, _ Empty) (string, error) {
	licenses, err := s.client.Licenses(ctx)
	if err != nil {
		return "", err
	}

	var lines []string
	for _, license := range licenses {
		lines = append(lines,
			"Infrastructure Licenses:",
			fmt.Sprintf("  Total: %d", license.TotalInfrastructure),
			fmt.Sprintf("  Available: %d", license.AvailableInfrastructure),
			fmt.Sprintf("  Consumed: %d", license.ConsumedInfrastructure),
			"",
			"Application Licenses:",
			fmt.Sprintf("  Total: %d", license.TotalApplication),
			fmt.Sprintf("  Available: %d", license.AvailableApplication),
			fmt.Sprintf("  Consumed: %d", license.ConsumedApplication),
			"",
		)
	}
	return strings.Join(lines, "\n"), nil
}

func (s *server) listScanSchedules(ctx context.Context, _ Empty) (string, error) {
	schedules, err := s.client.Schedules(ctx)
	if err != nil {
		return "", err
	}
	if len(schedules) == 0 {
		return "No scan schedules found.", nil
	}

	blocks := make([]string, 0, len(schedules))
	for _, schedule := range schedules {
		blocks = append(blocks, formatSchedule(schedule))
	}
	return strings.Join(blocks, "\n\n"), nil
}

func formatSchedule(schedule intruder.Schedule) string {
	targets := make([]string, 0, len(schedule.Targets))
	for _, target := range schedule.Targets {
		targets = append(targets, strconv.FormatInt(target, 10))
	}

	latestScanID := "None"
	if schedule.LatestScanID != nil {
		latestScanID = strconv.FormatInt(*schedule.LatestScanID, 10)
	}

	lines := []string{
		fmt.Sprintf("%d - %s", schedule.ID, schedule.Name),
		"  schedule_period: " + schedule.SchedulePeriod,
		"  status: " + schedule.Status,
		"  first_scan_time: " + nullableTime(schedule.FirstScanTime),
		"  next_scan_date: " + nullableTime(schedule.NextScanDate),
		fmt.Sprintf("  throttled: %t", schedule.Throttled),
		fmt.Sprintf("  web_ports_only: %t", schedule.WebPortsOnly),
		fmt.Sprintf("  upload_to_drata: %t", schedule.UploadToDrata),
		fmt.Sprintf("  upload_to_vanta: %t", schedule.UploadToVanta),
		"  latest_scan_id: " + latestScanID,
		"  latest_scan_status: " + nullableString(schedule.LatestScanStatus),
		"  last_scan_start_time: " + nullableTime(schedule.LastScanStartTime),
		"  last_scan_end_time: " + nullableTime(schedule.LastScanEndTime),
		fmt.Sprintf("  scan_all_targets: %t", schedule.ScanAllTargets),
		"  targets: " + scheduleTargets(targets, schedule.ScanAllTargets),
		"  target_tags: " + scheduleTargets(schedule.TargetTags, schedule.ScanAllTargets),
	}
	return strings.Join(lines, "\n")
}

// jsonText unquotes strings and compacts anything else.
func jsonText(raw json.RawMessage) string {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "null"
	}

	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}

	var compact bytes.Buffer
	if json.Compact(&compact, raw) == nil {
		return compact.String()
	}
	return string(raw)
}

func timestamp(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func nullableString(value *string) string {
	if value == nil {
		return "None"
	}
	return *value
}

func nullableTime(value *time.Time) string {
	if value == nil {
		return "None"
	}
	return timestamp(*value)
}

// scheduleTargets avoids reporting "(none)" for a schedule covering everything.
func scheduleTargets(values []string, all bool) string {
	if len(values) == 0 && all {
		return "(all targets)"
	}
	return joinOrNone(values)
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}
