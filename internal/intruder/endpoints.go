package intruder

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// setList writes a multi-value filter as one comma-separated parameter.
//
// Repeating the parameter is not equivalent: the API keeps only the last
// occurrence and discards the rest, so ?tag_names=a&tag_names=b filters on b
// alone and answers wrongly without erroring. A value containing a comma has
// no documented escape, so it is rejected rather than mis-split.
func setList(query url.Values, field string, values []string) error {
	if len(values) == 0 {
		return nil
	}
	for _, value := range values {
		if strings.Contains(value, ",") {
			return fmt.Errorf("%s cannot filter on a value containing a comma; the API separates values by commas", field)
		}
	}

	query.Set(field, strings.Join(values, ","))
	return nil
}

func setInts(query url.Values, field string, values []int64) {
	if len(values) == 0 {
		return
	}

	text := make([]string, len(values))
	for i, value := range values {
		text[i] = strconv.FormatInt(value, 10)
	}
	query.Set(field, strings.Join(text, ","))
}

func setString(query url.Values, field string, value *string) {
	if value != nil {
		query.Set(field, *value)
	}
}

func setBool(query url.Values, field string, value *bool) {
	if value != nil {
		query.Set(field, strconv.FormatBool(*value))
	}
}

func (c *Client) Health(ctx context.Context) (Health, error) {
	var health Health
	err := c.do(ctx, http.MethodGet, "health/", nil, nil, &health)
	return health, err
}

type TargetFilters struct {
	Address           *string
	TagNames          []string
	Status            *string
	Type              *string
	Ordering          *string
	LastScannedAfter  *string
	LastScannedBefore *string
	WAFInterference   *bool
}

func targetQuery(filters TargetFilters) (url.Values, error) {
	query := url.Values{}
	setString(query, "address", filters.Address)
	setString(query, "target_status", filters.Status)
	setString(query, "target_type", filters.Type)
	setString(query, "ordering", filters.Ordering)
	setString(query, "last_scanned_after", filters.LastScannedAfter)
	setString(query, "last_scanned_before", filters.LastScannedBefore)
	setBool(query, "waf_interference", filters.WAFInterference)

	if err := setList(query, "tag_names", filters.TagNames); err != nil {
		return nil, err
	}
	return query, nil
}

func (c *Client) Targets(ctx context.Context, filters TargetFilters) ([]Target, error) {
	query, err := targetQuery(filters)
	if err != nil {
		return nil, err
	}
	return listAll(ctx, c, "targets/", query, func(t Target) error { return positiveID(t.ID) })
}

// IssueFilters covers both listings; Occurrences drops what it cannot accept.
type IssueFilters struct {
	TargetAddresses         []string
	TagNames                []string
	IssueIDs                []int64
	VulnerabilityCategories []string
	Snoozed                 *bool
	SnoozedOnly             *bool
	Severity                *string
	ExploitLikelihood       *string
	Since                   *string
	ExcludeDeletedTargets   *bool
}

func issueQuery(filters IssueFilters, occurrence bool) (url.Values, error) {
	query := url.Values{}
	setBool(query, "snoozed", filters.Snoozed)
	setBool(query, "snoozed_only", filters.SnoozedOnly)
	setBool(query, "exclude_deleted_targets", filters.ExcludeDeletedTargets)
	setString(query, "since", filters.Since)

	if err := setList(query, "target_addresses", filters.TargetAddresses); err != nil {
		return nil, err
	}
	if err := setList(query, "tag_names", filters.TagNames); err != nil {
		return nil, err
	}

	// The occurrence endpoint accepts none of the filters below.
	if occurrence {
		return query, nil
	}
	setString(query, "severity", filters.Severity)
	setString(query, "exploit_likelihood", filters.ExploitLikelihood)
	setInts(query, "issue_ids", filters.IssueIDs)

	if err := setList(query, "vulnerability_categories", filters.VulnerabilityCategories); err != nil {
		return nil, err
	}
	return query, nil
}

func (c *Client) Issues(ctx context.Context, filters IssueFilters) ([]Issue, error) {
	query, err := issueQuery(filters, false)
	if err != nil {
		return nil, err
	}
	return listAll(ctx, c, "issues/", query, func(i Issue) error { return positiveID(i.ID) })
}

func (c *Client) Occurrences(ctx context.Context, issueID int64, filters IssueFilters) ([]Occurrence, error) {
	query, err := issueQuery(filters, true)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("issues/%d/occurrences/", issueID)
	return listAll(ctx, c, path, query, func(o Occurrence) error { return positiveID(o.ID) })
}

func (c *Client) ScannerOutput(ctx context.Context, issueID, occurrenceID int64) ([]ScannerOutput, error) {
	path := fmt.Sprintf("issues/%d/occurrences/%d/scanner_output/", issueID, occurrenceID)
	return listAll(ctx, c, path, nil, func(s ScannerOutput) error { return positiveID(s.ID) })
}

type ScanFilters struct {
	Status         *string
	Type           *string
	SchedulePeriod *string
	TagNames       []string
}

func (c *Client) Scans(ctx context.Context, filters ScanFilters) ([]Scan, error) {
	query := url.Values{}
	setString(query, "status", filters.Status)
	setString(query, "scan_type", filters.Type)
	setString(query, "schedule_period", filters.SchedulePeriod)

	if err := setList(query, "tag_names", filters.TagNames); err != nil {
		return nil, err
	}
	return listAll(ctx, c, "scans/", query, func(s Scan) error { return positiveID(s.ID) })
}

func (c *Client) Scan(ctx context.Context, id int64) (Scan, error) {
	var scan Scan
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("scans/%d/", id), nil, nil, &scan)
	if err == nil {
		err = positiveID(scan.ID)
	}
	return scan, err
}

// CreateScan with an empty request scans the whole account.
func (c *Client) CreateScan(ctx context.Context, request ScanRequest) (Scan, error) {
	var scan Scan
	err := c.do(ctx, http.MethodPost, "scans/", nil, request, &scan)
	if err == nil {
		err = positiveID(scan.ID)
	}
	return scan, err
}

func (c *Client) CancelScan(ctx context.Context, id int64) (string, error) {
	var result string
	err := c.do(ctx, http.MethodPost, fmt.Sprintf("scans/%d/cancel/", id), nil, nil, &result)
	return result, err
}

func (c *Client) DeleteTarget(ctx context.Context, id int64) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("targets/%d/", id), nil, nil, nil)
}

func (c *Client) CreateTargetTag(ctx context.Context, id int64, name string) (Tag, error) {
	var tag Tag
	err := c.do(ctx, http.MethodPost, fmt.Sprintf("targets/%d/tags/", id), nil, Tag{Name: name}, &tag)
	return tag, err
}

func (c *Client) DeleteTargetTag(ctx context.Context, id int64, name string) error {
	path := fmt.Sprintf("targets/%d/tags/%s/", id, url.PathEscape(name))
	return c.do(ctx, http.MethodDelete, path, nil, nil, nil)
}

func (c *Client) Tags(ctx context.Context) ([]Tag, error) {
	return listAll(ctx, c, "tags/", nil, func(t Tag) error {
		if t.Name == "" {
			return errors.New("API returned an empty tag name")
		}
		return nil
	})
}

func (c *Client) Licenses(ctx context.Context) ([]Licenses, error) {
	return listAll(ctx, c, "licenses/", nil, func(Licenses) error { return nil })
}

// Schedules does not paginate: the endpoint returns everything at once.
func (c *Client) Schedules(ctx context.Context) ([]Schedule, error) {
	return listAll(ctx, c, "scans/schedules/", nil, func(s Schedule) error { return positiveID(s.ID) })
}

func (c *Client) CreateSchedule(ctx context.Context, request ScheduleRequest) (MutationResult, error) {
	var result MutationResult
	err := c.do(ctx, http.MethodPost, "scans/schedules/", nil, request, &result)
	return result, err
}

// UpdateSchedule leaves fields that are nil in request untouched.
func (c *Client) UpdateSchedule(ctx context.Context, id int64, request ScheduleRequest) (MutationResult, error) {
	var result MutationResult
	err := c.do(ctx, http.MethodPatch, fmt.Sprintf("scans/schedules/%d/", id), nil, request, &result)
	return result, err
}

func (c *Client) DeleteSchedule(ctx context.Context, id int64) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("scans/schedules/%d/", id), nil, nil, nil)
}

func (c *Client) SnoozeOccurrence(ctx context.Context, issueID, occurrenceID int64, request SnoozeRequest) (MutationResult, error) {
	var result MutationResult
	path := fmt.Sprintf("issues/%d/occurrences/%d/snooze/", issueID, occurrenceID)
	err := c.do(ctx, http.MethodPost, path, nil, request, &result)
	return result, err
}

type BulkResult struct {
	Created  int
	Existing int
}

// CreateTargets adds addresses the account does not already have.
//
// The bulk endpoint has no upsert, so this reads the inventory first and posts
// only what is new. The read and write are serialized against other calls on
// this client, so two of them cannot both claim the same address.
func (c *Client) CreateTargets(ctx context.Context, addresses []string) (BulkResult, error) {
	select {
	case c.inventory <- struct{}{}:
	case <-ctx.Done():
		return BulkResult{}, ctx.Err()
	}
	defer func() { <-c.inventory }()

	existing, err := c.Targets(ctx, TargetFilters{})
	if err != nil {
		return BulkResult{}, err
	}
	known := make(map[string]bool, len(existing))
	for _, target := range existing {
		known[target.Address] = true
	}

	var result BulkResult
	requested := make(map[string]bool, len(addresses))
	wanted := make([]TargetRequest, 0, len(addresses))
	for _, address := range addresses {
		if requested[address] {
			continue // Duplicate within this call.
		}
		requested[address] = true

		if known[address] {
			result.Existing++
			continue
		}
		wanted = append(wanted, TargetRequest{Address: address})
	}
	if len(wanted) == 0 {
		return result, nil
	}

	var created []Target
	if err := c.do(ctx, http.MethodPost, "targets/bulk/", nil, wanted, &created); err != nil {
		return BulkResult{}, err
	}

	// A mismatch means the reported counts would be wrong.
	outstanding := make(map[string]bool, len(wanted))
	for _, target := range wanted {
		outstanding[target.Address] = true
	}
	for _, target := range created {
		if positiveID(target.ID) != nil || !outstanding[target.Address] {
			return BulkResult{}, errors.New("API returned an unexpected bulk creation result; inspect inventory before retrying")
		}
		delete(outstanding, target.Address)
	}
	if len(outstanding) != 0 {
		return BulkResult{}, errors.New("API returned a partial bulk creation result; inspect inventory before retrying")
	}

	result.Created = len(created)
	return result, nil
}
