#!/usr/bin/env bash
#
# go-containerregistry/mayhem/test.sh — RUN go-containerregistry's OWN Go test suite over a
# SELF-CONTAINED (no-network, no-registry) subset of packages and emit a CTRF summary.
# exit 0 iff no test failed.
#
# PATCH-grade oracle: these are REAL known-answer / golden-output suites — pkg/name asserts the
# parsed registry/repo/tag/digest of hundreds of image references (the exact surface the fuzzer
# drives via name.ParseReference), and the pkg/v1 parsing suites assert decoded config/manifest
# values, content-addressable hashes, media types and tarball round-trips. They assert BEHAVIOUR,
# not "exits 0", so a no-op / `return nil` patch that breaks parsing FAILS this oracle.
#
# We deliberately SKIP the network/registry-dependent packages (pkg/v1/remote, pkg/v1/google,
# pkg/v1/daemon, pkg/registry, crane/gcrane, authn ...) which need a live registry / docker daemon
# and are not part of the fuzzed parsing surface. The chosen subset is hermetic and deterministic.
#
# Anti-reward-hacking behavioral probe (§6.3): after running go test (statically linked, immune to
# LD_PRELOAD sabotage), this script also executes /mayhem/fuzz_parse_reference (dynamically linked
# via clang+ASan) against a known seed and asserts that libFuzzer emits "Executed". The LD_PRELOAD
# sabotage neuters fuzz_parse_reference (not in /usr/bin etc.), causing it to exit silently →
# the grep fails → FAILED increments → the oracle is NOT reward-hackable.
#
# This script only RUNS the suite (go test compiles+runs in one step, with the project's normal
# flags — no sanitizer/fuzz build here).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

export PATH="/opt/toolchains/go/bin:/opt/toolchains/go-path/bin:/usr/local/go/bin:/root/go/bin:$PATH"
export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"
export GOMODCACHE="${GOMODCACHE:-/opt/toolchains/go-path/pkg/mod}"
export GOPROXY="${GOPROXY:-file://$(go env GOMODCACHE 2>/dev/null || echo /opt/toolchains/go-path/pkg/mod)/cache/download,off}"
: "${SRC:=/mayhem}"
cd "$SRC"

# Self-contained, network-free parsing/encoding packages (the fuzzed surface + adjacent parsers).
PKGS=(
  ./pkg/name/...
  ./pkg/v1
  ./pkg/v1/types/...
  ./pkg/v1/empty/...
  ./pkg/v1/random/...
  ./pkg/v1/tarball/...
  ./pkg/v1/static/...
  ./pkg/v1/match/...
  ./pkg/v1/partial/...
  ./pkg/v1/stream/...
  ./pkg/v1/layout/...
  ./pkg/compression/...
  ./pkg/logs/...
)

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if ! command -v go >/dev/null 2>&1; then
  echo "go not available — cannot run the test suite" >&2
  emit_ctrf "go-test" 0 1 0; exit 2
fi

echo "=== running: go test -json ${PKGS[*]} ==="
JSON="$SRC/mayhem-build/gotest.json"
mkdir -p "$SRC/mayhem-build"
go test -json "${PKGS[@]}" > "$JSON" 2>"$SRC/mayhem-build/gotest.err"; rc=$?

# Show package-level summary + any build/test errors for humans.
go test "${PKGS[@]}" 2>&1 | tail -40 || true
[ -s "$SRC/mayhem-build/gotest.err" ] && { echo "--- stderr ---"; tail -20 "$SRC/mayhem-build/gotest.err"; }

# Count test-level events (lines that carry a non-empty "Test" field). Subtests included — they are
# real asserted cases. Package-level pass/fail lines have no "Test" field and are excluded.
count_act() { grep "\"Action\":\"$1\"" "$JSON" 2>/dev/null | grep -c "\"Test\":"; }
PASSED=$(count_act pass); FAILED=$(count_act fail); SKIPPED=$(count_act skip)
: "${PASSED:=0}" "${FAILED:=0}" "${SKIPPED:=0}"

# Build failures / no-tests-compiled: go test exits non-zero but may emit no test events.
if [ "$(( PASSED + FAILED + SKIPPED ))" -eq 0 ]; then
  echo "no test events parsed; using go exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "go-test" 1 0 0; exit 0; }
  emit_ctrf "go-test" 0 1 0; exit 1
fi

# Trust the parsed failures; if go reported a non-zero exit but we counted 0 failures (e.g. a
# package build error), force a failure so the oracle is honest.
if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then FAILED=1; fi

# ── Behavioral probe via the dynamically-linked fuzz_parse_reference binary (anti-reward-hacking, §6.3) ──
# Go test binaries are statically linked, so the LD_PRELOAD sabotage mechanism cannot neuter them.
# /mayhem/fuzz_parse_reference IS dynamically linked (built with clang+ASan). Run it single-shot
# against a known seed and assert that libFuzzer emits "Executed" — proving it actually processed
# the input. The sabotage LD_PRELOAD neuters fuzz_parse_reference (not in /usr/bin etc.), causing
# it to exit silently → the grep fails → FAILED increments → the oracle is NOT reward-hackable.
PROBE_INPUT="$SRC/mayhem/testsuite/fuzz_parse_reference/seed_000"
if [ -x /mayhem/fuzz_parse_reference ] && [ -f "$PROBE_INPUT" ]; then
  echo "=== behavioral probe: fuzz_parse_reference single-shot on known seed ==="
  PROBE_OUT=$(/mayhem/fuzz_parse_reference "$PROBE_INPUT" 2>&1 || true)
  if echo "$PROBE_OUT" | grep -q "Executed"; then
    echo "PROBE PASS: fuzz_parse_reference executed the seed input (parser active)"
    PASSED=$(( PASSED + 1 ))
  else
    echo "PROBE FAIL: fuzz_parse_reference produced no 'Executed' output (engine inactive or sabotaged)"
    echo "Output was: $PROBE_OUT"
    FAILED=$(( FAILED + 1 ))
  fi
fi

emit_ctrf "go-test" "$PASSED" "$FAILED" "$SKIPPED"
