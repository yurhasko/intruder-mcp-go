// Package intruder implements the Intruder v1 REST operations used by MCP tools.
package intruder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

// BaseURL is the production Intruder API root.
const BaseURL = "https://api.intruder.io/v1"

// Options controls resource limits. Zero values select defaults, except
// Interval (zero disables pacing) and Retries (zero disables retries).
type Options struct {
	// For tests; the executable always uses the production origin.
	BaseURL    string
	HTTPClient *http.Client
	UserAgent  string

	RequestTimeout time.Duration
	Interval       time.Duration
	Retries        int
	MaxConcurrent  int

	MaxResponseBytes int64
	MaxListBytes     int64
	MaxPages         int
	MaxItems         int
}

// Client is safe for concurrent use.
type Client struct {
	base *url.URL
	key  string
	http *http.Client
	opts Options

	slots chan struct{}

	// paceLock guards next, the earliest time a request may start.
	paceLock chan struct{}
	next     time.Time

	// Serializes the read-then-write in CreateTargets.
	inventory chan struct{}
}

func New(key string, opts Options) (*Client, error) {
	if strings.TrimSpace(key) == "" || strings.ContainsAny(key, "\r\n") {
		return nil, errors.New("INTRUDER_API_KEY must be set to a nonempty API key")
	}

	if opts.BaseURL == "" {
		opts.BaseURL = BaseURL
	}
	// The trailing slash keeps ResolveReference from replacing the last segment.
	base, err := url.Parse(strings.TrimRight(opts.BaseURL, "/") + "/")
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" ||
		(base.Scheme != "https" && base.Scheme != "http") {
		return nil, errors.New("invalid API base URL")
	}

	if opts.RequestTimeout == 0 {
		opts.RequestTimeout = 30 * time.Second
	}
	if opts.MaxConcurrent == 0 {
		opts.MaxConcurrent = 4
	}
	if opts.MaxResponseBytes == 0 {
		opts.MaxResponseBytes = 8 << 20
	}
	if opts.MaxListBytes == 0 {
		opts.MaxListBytes = 64 << 20
	}
	if opts.MaxPages == 0 {
		opts.MaxPages = 1000
	}
	if opts.MaxItems == 0 {
		opts.MaxItems = 100000
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "Intruder-MCP-Go/dev"
	}

	// MaxInt64 is rejected because send reads one byte past the limit.
	if opts.RequestTimeout < 0 || opts.MaxConcurrent < 1 ||
		opts.MaxResponseBytes < 1 || opts.MaxResponseBytes == math.MaxInt64 ||
		opts.MaxPages < 1 || opts.MaxItems < 1 || opts.MaxListBytes < 1 ||
		opts.Interval < 0 || opts.Retries < 0 || opts.Retries > 5 {
		return nil, errors.New("invalid HTTP client resource limits")
	}

	return &Client{
		base:      base,
		key:       key,
		http:      newHTTPClient(opts),
		opts:      opts,
		slots:     make(chan struct{}, opts.MaxConcurrent),
		paceLock:  make(chan struct{}, 1),
		inventory: make(chan struct{}, 1),
	}, nil
}

func newHTTPClient(opts Options) *http.Client {
	var hc http.Client
	switch {
	case opts.HTTPClient != nil:
		hc = *opts.HTTPClient
	default:
		transport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			hc.Transport = http.DefaultTransport
			break
		}
		transport = transport.Clone()
		transport.MaxConnsPerHost = opts.MaxConcurrent
		transport.MaxIdleConnsPerHost = opts.MaxConcurrent
		hc.Transport = transport
	}

	hc.Timeout = 0 // send owns request deadlines.
	// Never follow a redirect while carrying the API key.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &hc
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

// APIError carries the status and request ID only, so response bodies and
// URLs never reach the MCP client.
type APIError struct {
	Status    int
	RequestID string
}

func (e *APIError) Error() string {
	message := fmt.Sprintf("Intruder API returned HTTP %d (%s)", e.Status, http.StatusText(e.Status))
	if e.RequestID != "" {
		message += "; request ID: " + e.RequestID
	}
	return message
}

// TransportError is a request that never produced a response. Only these are retried.
type TransportError struct{ cause error }

func (e *TransportError) Error() string {
	return "Intruder API request failed; check network connectivity and request timeout"
}

func (e *TransportError) Unwrap() error { return e.cause }

func wait(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// pace blocks until Interval has elapsed since the last request started.
func (c *Client) pace(ctx context.Context) error {
	if c.opts.Interval == 0 {
		return ctx.Err()
	}

	select {
	case c.paceLock <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-c.paceLock }()

	if err := wait(ctx, time.Until(c.next)); err != nil {
		return err
	}
	c.next = time.Now().Add(c.opts.Interval)
	return nil
}

// endpoint rejects anything escaping the configured origin or path prefix.
// Pagination links pass through here before the key is attached.
func (c *Client) endpoint(reference string) (*url.URL, error) {
	ref, err := url.Parse(reference)
	if err != nil {
		return nil, errors.New("invalid API endpoint")
	}

	u := c.base.ResolveReference(ref)
	if u.Scheme != c.base.Scheme || u.Host != c.base.Host || u.User != nil || u.Fragment != "" ||
		!strings.HasPrefix(path.Clean(u.Path)+"/", c.base.Path) {
		return nil, errors.New("API pagination or endpoint escaped the configured origin or prefix")
	}
	return u, nil
}

// do decodes into out, which may be nil to discard or a *string for the raw body.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	_, err := c.doJSON(ctx, method, path, query, body, out)
	return err
}

// doJSON also reports the body size, so the paginator can bound a whole list.
func (c *Client) doJSON(ctx context.Context, method, path string, query url.Values, body, out any) (int64, error) {
	u, err := c.endpoint(path)
	if err != nil {
		return 0, err
	}
	if query != nil {
		u.RawQuery = query.Encode()
	}

	var payload []byte
	if body != nil {
		if payload, err = json.Marshal(body); err != nil {
			return 0, fmt.Errorf("encode API request: %w", err)
		}
	}

	for attempt := 0; ; attempt++ {
		req, err := c.newRequest(ctx, method, u.String(), payload, body != nil)
		if err != nil {
			return 0, err
		}

		data, resp, err := c.send(req)
		if err != nil {
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			var transportErr *TransportError
			if c.shouldRetry(method, attempt) && errors.As(err, &transportErr) {
				if err := wait(ctx, backoff(attempt)); err != nil {
					return 0, err
				}
				continue
			}
			return 0, err
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if c.shouldRetry(method, attempt) && retryable(resp.StatusCode) {
				if err := wait(ctx, retryDelay(resp, attempt)); err != nil {
					return 0, err
				}
				continue
			}
			return 0, &APIError{Status: resp.StatusCode, RequestID: safeID(resp.Header.Get("X-Request-ID"))}
		}

		size, err := decode(data, out)
		return size, err
	}
}

func (c *Client) newRequest(ctx context.Context, method, u string, payload []byte, hasBody bool) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(payload))
	if err != nil {
		return nil, errors.New("could not construct API request")
	}

	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("User-Agent", c.opts.UserAgent)
	req.Header.Set("Accept", "application/json")
	if hasBody {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// shouldRetry is GET only: a failed write may already have been applied.
func (c *Client) shouldRetry(method string, attempt int) bool {
	return method == http.MethodGet && attempt < c.opts.Retries
}

func decode(data []byte, out any) (int64, error) {
	size := int64(len(data))
	switch out := out.(type) {
	case nil:
		return size, nil
	case *string:
		*out = string(data)
		return size, nil
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return 0, errors.New("API returned an empty JSON result")
	}
	if err := json.Unmarshal(data, out); err != nil {
		return 0, errors.New("API returned invalid JSON or an unexpected response shape")
	}
	return size, nil
}

// send runs one attempt, holding a concurrency slot only for its duration.
func (c *Client) send(req *http.Request) ([]byte, *http.Response, error) {
	ctx := req.Context()
	select {
	case c.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	defer func() { <-c.slots }()

	if err := c.pace(ctx); err != nil {
		return nil, nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, c.opts.RequestTimeout)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, &TransportError{cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Drain a bounded prefix so the connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, min(c.opts.MaxResponseBytes, 32<<10)))
		if err := ctx.Err(); err != nil {
			return nil, nil, &TransportError{cause: err}
		}
		return nil, resp, nil
	}

	// One byte past the limit, so an oversized body is detected not truncated.
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.opts.MaxResponseBytes+1))
	if ctx.Err() != nil {
		// A deadline can land between the final read and its error.
		return nil, nil, &TransportError{cause: ctx.Err()}
	}
	if int64(len(data)) > c.opts.MaxResponseBytes {
		return nil, nil, errors.New("API response exceeded the configured byte limit")
	}
	if err != nil {
		return nil, nil, &TransportError{cause: err}
	}
	return data, resp, nil
}

// safeID drops anything that could inject text into an error message.
func safeID(value string) string {
	if len(value) > 128 {
		return ""
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return ""
		}
	}
	return value
}

func retryable(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// backoff doubles from 250ms, with jitter to spread concurrent retries.
func backoff(attempt int) time.Duration {
	return time.Duration(250*(1<<attempt))*time.Millisecond + time.Duration(rand.IntN(100))*time.Millisecond
}

func retryDelay(resp *http.Response, attempt int) time.Duration {
	if value := resp.Header.Get("Retry-After"); value != "" {
		if delay, ok := retryAfter(value, time.Now()); ok {
			return delay
		}
	}
	return backoff(attempt)
}

// retryAfter parses both forms: delay-seconds and HTTP-date.
func retryAfter(value string, now time.Time) (time.Duration, bool) {
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 {
		const maxDelay = time.Duration(math.MaxInt64)
		if seconds > int64(maxDelay/time.Second) {
			return maxDelay, true
		}
		return time.Duration(seconds) * time.Second, true
	}
	if timestamp, err := http.ParseTime(value); err == nil {
		return max(time.Duration(0), timestamp.Sub(now)), true
	}
	return 0, false
}

// page uses pointers so a missing field is distinguishable from a zero one.
type page[T any] struct {
	Count   *int    `json:"count"`
	Next    *string `json:"next"`
	Results *[]T    `json:"results"`
}

// listAll walks every page, validating each item. It fails rather than
// returning a partial list.
func listAll[T any](ctx context.Context, c *Client, path string, query url.Values, validate func(T) error) ([]T, error) {
	// Copy so the caller's query is not mutated by the limit/offset we add.
	next := make(url.Values, len(query))
	for key, values := range query {
		next[key] = append([]string(nil), values...)
	}
	next.Set("limit", "100")
	next.Set("offset", "0")
	query = next

	items := make([]T, 0)
	seen := make(map[string]bool)
	var listBytes int64

	for range c.opts.MaxPages {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		u, err := c.endpoint(path)
		if err != nil {
			return nil, err
		}
		if query != nil {
			u.RawQuery = query.Encode()
		}
		if seen[u.String()] {
			return nil, errors.New("API pagination repeated a page")
		}
		seen[u.String()] = true

		var current page[T]
		pageBytes, err := c.doJSON(ctx, http.MethodGet, path, query, nil, &current)
		if err != nil {
			return nil, err
		}
		if current.Count == nil || *current.Count < 0 || current.Results == nil {
			return nil, errors.New("API returned an invalid paginated response")
		}

		// Subtract rather than add, so a huge page cannot overflow the total.
		if pageBytes > c.opts.MaxListBytes-listBytes {
			return nil, errors.New("API list exceeded the configured byte limit; narrow the filters")
		}
		listBytes += pageBytes

		if len(*current.Results) > c.opts.MaxItems-len(items) {
			return nil, errors.New("API results exceeded the configured item limit; narrow the filters")
		}
		for _, item := range *current.Results {
			if err := validate(item); err != nil {
				return nil, err
			}
			items = append(items, item)
		}

		if current.Next == nil || *current.Next == "" {
			if len(items) < *current.Count {
				return nil, errors.New("API omitted pagination while more results remain")
			}
			return items, nil
		}
		if len(*current.Results) == 0 {
			return nil, errors.New("API returned an empty page with a next link")
		}

		// Resolve relative links against the request that produced them.
		link, err := url.Parse(*current.Next)
		if err != nil {
			return nil, errors.New("invalid API next link")
		}
		path = u.ResolveReference(link).String()
		query = nil
	}

	return nil, errors.New("API pagination exceeded the configured page limit; narrow the filters")
}
