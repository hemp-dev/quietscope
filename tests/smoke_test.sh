#!/bin/sh
set -eu

export GOCACHE="${TMPDIR:-/tmp}/quietscope-go-build-cache"

go test ./...
go build -o quietscope ./cmd/quietscope
./quietscope --help >/dev/null

OUTDIR="$(mktemp -d "${TMPDIR:-/tmp}/test-audit.XXXXXX")"
./quietscope --text --json --no-sudo --output "$OUTDIR" >/dev/null

test -f "$OUTDIR/report.txt"
test -f "$OUTDIR/report.json"
first_char="$(head -c 1 "$OUTDIR/report.json")"
test "$first_char" = "{"

echo "smoke test passed"
