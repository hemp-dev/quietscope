#!/bin/sh
set -eu

if [ "$(uname -s)" != "Linux" ]; then
  echo "linux smoke test skipped on non-Linux host"
  exit 0
fi

export GOCACHE="${TMPDIR:-/tmp}/quietscope-go-build-cache"

go test ./...
go build -o quietscope ./cmd/quietscope

OUTDIR="$(mktemp -d "${TMPDIR:-/tmp}/linux-audit.XXXXXX")"
./quietscope --text --json --html --no-sudo --output "$OUTDIR" >/dev/null

test -f "$OUTDIR/report.txt"
test -f "$OUTDIR/report.json"
test -f "$OUTDIR/report.html"
first_char="$(head -c 1 "$OUTDIR/report.json")"
test "$first_char" = "{"
grep -q "linux-" "$OUTDIR/report.json"

echo "linux smoke test passed"
