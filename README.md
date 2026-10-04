# Intruder MCP for Go

A stdio [MCP](https://modelcontextprotocol.io/) server for [Intruder](https://www.intruder.io/), written in Go. It's a port of [Intruder's Python server](https://github.com/intruder-io/intruder-mcp) and exposes the same tools.

This is an independent project, not an official Intruder product.

## Setup

Needs Go 1.26 or newer. Built on the [official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk).

```sh
go build -o bin/intruder-mcp ./cmd/intruder-mcp
./bin/intruder-mcp -version
```

Set `INTRUDER_API_KEY` in the server's environment. For clients that use `mcpServers`:

```json
{
  "mcpServers": {
    "intruder": {
      "command": "/absolute/path/to/bin/intruder-mcp",
      "env": { "INTRUDER_API_KEY": "YOUR_API_KEY" }
    }
  }
}
```

Prefer your client's secret storage or an inherited environment variable if it has one. The server speaks over stdin/stdout, logs to stderr, and opens no listening socket.

## Tools

| Purpose | Tools |
|---|---|
| Identity | `get_user`, `get_status` |
| Inventory | `list_targets`, `list_tags`, `list_licenses` |
| Findings | `list_issues`, `list_occurrences`, `get_scanner_output` |
| Scans | `list_scans`, `get_scan`, `create_scan`, `cancel_scan` |
| Targets and tags | `create_targets`, `delete_target`, `create_target_tag`, `delete_target_tag` |
| Snoozing | `snooze_occurrence`, `snooze_issue` (retired) |
| Schedules | `list_scan_schedules`, `create_scan_schedule`, `update_scan_schedule`, `delete_scan_schedule` |

Tool discovery carries argument schemas and read/write annotations. Results are plain text and failures come back as MCP tool errors. `delete_target` takes `target_id` as a decimal string because the Python tool did; every other ID is an integer.

The listing tools accept every filter the API documents, which is more than the Python server exposed. See each tool's schema for the full set.

Intruder [removed the issue-level snooze endpoint](https://developers.intruder.io/changelog/issue-snooze-endpoint-removed), so `snooze_issue` returns an error without calling the API. Use `snooze_occurrence` instead — note that it does not snooze occurrences found by later scans.

## Configuration

Everything has a default; run `intruder-mcp -help` for the full list.

| Flag | Default | Effect |
|---|---|---|
| `-request-timeout` | `30s` | Timeout per HTTP request |
| `-tool-timeout` | `2m` | Deadline for a complete tool call |
| `-max-concurrent` | `4` | Maximum simultaneous HTTP requests |
| `-request-interval` | `750ms` | Minimum gap between request starts; `0` disables pacing |
| `-read-retries` | `2` | Retries for eligible GET failures, 0 to 5 |
| `-max-response-bytes` | `8388608` | Bytes per response body |
| `-max-list-bytes` | `67108864` | Response bytes across all pages of one list |
| `-max-output-bytes` | `8388608` | Tool result bytes after JSON escaping |
| `-max-pages` | `1000` | Pages per list call |
| `-max-items` | `100000` | Records per list call |

Intruder allows [5,000 requests/hour, and 1 request/second on trials](https://developers.intruder.io/docs/rate-limiting). Set `-request-interval=1s` on a trial account. Anything else using the same token shares that budget. GET retries honor `Retry-After`; writes are never retried, since a failed write may well have landed.

The limits apply per call. A list that can't be completed fails rather than returning a partial answer, so narrow the filters on a large account or raise the limits to suit your client.

## Notes

- Redirects are never followed while the API key is attached, and a pagination link that points outside the API origin or path prefix is rejected.
- `create_targets` reads the inventory first and skips addresses that already exist, then reports both counts.
- `create_scan` with neither selector scans the whole account. An explicitly empty selector array is rejected rather than read as "everything".
- Schedule updates only touch the fields you pass. An explicit `false` or `[]` is sent; omitting a field leaves it alone. Start times must be in the future, on a whole UTC hour.
- Multi-value filters go out as one comma-separated parameter. Repeating the parameter is not equivalent — the API keeps only the last occurrence — so a filter value containing a comma is rejected rather than mis-split.
- A schedule with `scan_all_targets` set covers the account and comes back with both selection lists empty, so those print as `(all targets)`, not `(none)`.
- Unknown response fields and new enum values are accepted; documented-required fields are checked.
- Output matches the Python server where it reasonably can. Timestamps are UTC RFC 3339.

## Docker

Published images are at `ghcr.io/yurhasko/intruder-mcp-go`:

```sh
docker run --rm -i -e INTRUDER_API_KEY ghcr.io/yurhasko/intruder-mcp-go:latest
```

Or build it yourself:

```sh
docker build --build-arg VERSION=dev -t intruder-mcp-go .
docker run --rm -i -e INTRUDER_API_KEY intruder-mcp-go
```

`-i` matters: without it stdin closes and the server exits immediately. The image runs as a nonroot user on distroless with CA certificates. `GO_IMAGE` and `RUNTIME_IMAGE` accept digests if you want a reproducible build.

Prebuilt binaries for macOS, Linux and Windows (amd64 and arm64) are attached to each [release](https://github.com/yurhasko/intruder-mcp-go/releases), with SHA-256 checksums.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[BSD-3-Clause](LICENSE.md), keeping the upstream copyright and license terms. The binary is statically linked, so the release archives and the image also carry [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
