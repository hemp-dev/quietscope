## Summary

## Security/privacy impact

- [ ] No telemetry, analytics, auto-update, or remote report upload added.
- [ ] No secret contents are read or printed.
- [ ] Discovered commands, MCP commands, and project scripts are not executed.
- [ ] Cleanup remains allowlist-only and confirmation-gated.
- [ ] HTML output remains self-contained with no external CDN/assets.

## Testing performed

- [ ] `go test ./...`
- [ ] `go build ./cmd/quietscope`
- [ ] `sh tests/smoke_test.sh`

## Notes for reviewers
