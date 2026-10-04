# Contributing

Keep changes focused, and add a test for anything that changes behavior.

```sh
go mod tidy
go mod verify
gofmt -l cmd internal
go vet ./...
go test -race -shuffle=on -cover ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Commit `go.mod` and `go.sum` together when dependencies move. The tests run entirely against local fixtures, so you don't need an Intruder account to work on this. Don't commit credentials or real customer data.

## Layout

`internal/intruder` is the API client: HTTP, pagination, retries, and the response models. `internal/tools` is the MCP surface: input schemas, handlers, and output formatting. `cmd/intruder-mcp` wires the two together and owns the flags.

A few things to preserve when editing:

- stdout belongs to the MCP transport. Diagnostics go to stderr.
- Thread the request context through to the API so a canceled tool call actually cancels the HTTP request.
- Mutation payloads distinguish "omitted" from "false" and from "empty array". The pointer fields in `ScheduleRequest` exist for that reason — don't flatten them.
- Errors must not carry API response bodies. `APIError` deliberately exposes only the status and request ID.
- Multi-value query filters go through `setList`, which joins them with commas. Do not switch back to repeated parameters: the API honors only the last one, so the failure is silently wrong results rather than an error.

## Benchmarks

```sh
go test ./internal/intruder -run '^$' -bench . -benchmem
```

These measure request construction and fixture decoding only. They say nothing about how fast Intruder scans.

The output size accounting in `internal/tools/output.go` has a fuzz target, since it reimplements JSON escaping rules:

```sh
go test ./internal/tools -run '^$' -fuzz FuzzOutputSize -fuzztime=60s
```

## Release builds

```sh
bash scripts/build-release.sh v0.1.0
docker build --build-arg VERSION=v0.1.0 -t intruder-mcp-go:v0.1.0 .
docker run --rm intruder-mcp-go:v0.1.0 -version
```

The script writes six platform archives plus SHA-256 checksums to `dist/`. The `Go checks` workflow runs the same checks on every push, cross-builds, and smoke-tests the container, but publishes nothing.

Releases are cut by pushing a tag:

```sh
git tag -a v0.1.0 -m v0.1.0
git push origin v0.1.0
```

That runs the `Release` workflow, which tests the tag, then publishes a GitHub release with the six archives and checksums, and a multi-arch image to `ghcr.io/yurhasko/intruder-mcp-go` tagged `v0.1.0` and `latest`. A tag containing a hyphen (`v0.1.0-rc1`) is published as a pre-release and does not move `latest`.
