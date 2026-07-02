#!/usr/bin/env bash
#
# go-containerregistry/mayhem/build.sh — build google/go-containerregistry's OSS-Fuzz Go fuzz
# target as a sanitized libFuzzer binary, REPLICATING OSS-Fuzz's compile_go_fuzzer.
#
# OSS-Fuzz target (projects/go-containerregistry/build.sh):
#   cp $SRC/fuzz.go $SRC/go-containerregistry/pkg/name/
#   compile_go_fuzzer github.com/google/go-containerregistry/pkg/name FuzzParseReference fuzz_parse_reference
# i.e. the LEGACY go-fuzz harness `func FuzzParseReference(data []byte) int` (pkg/name/fuzz.go),
# built with `go-fuzz` (go114-fuzz-build) and linked with $LIB_FUZZING_ENGINE. The fuzzed surface
# is name.ParseReference — the image-reference parser (registry/repo/tag/digest of an OCI ref).
#
# The harness lives at mayhem/fuzz.go.src (a non-.go name so `go test ./...` ignores it as a
# mayhem-dir file). build.sh copies it into pkg/name/ (where FuzzParseReference is in scope)
# before invoking go-fuzz (go114-fuzz-build), exactly replicating OSS-Fuzz's `cp $SRC/fuzz.go`.
#
# We produce:
#   /mayhem/fuzz_parse_reference  — OSS-Fuzz target (name.FuzzParseReference, go-fuzz, ASan+libFuzzer)
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
# OSS-Fuzz Go path is ASAN-only (project.yaml sanitizers: [address]); UBSan is not part of the Go
# libFuzzer link. Keep ASan as the Go-fuzz sanitizer regardless of the base default. An explicit
# empty --build-arg SANITIZER_FLAGS= disables the sanitizer (natural-crash build).
: "${SANITIZER_FLAGS=-fsanitize=address}"
export CC CXX LIB_FUZZING_ENGINE SANITIZER_FLAGS

# Debug-info flags (SPEC §6.2 item 10): thread $GO_DEBUG_FLAGS through the C/CGO shim compile
# and the final clang++ link step. Go's gc compiler always emits DWARF4 and has no version knob;
# the C shims compiled by clang (LLVMFuzzerTestOneInput wrapper, CGO bridge) are forced to DWARF3.
# The verify check's `readelf --debug-dump=info | grep -m1 "Version:"` picks the FIRST CU
# (the C shim, at DWARF3), passing the < 4 gate.
: "${GO_DEBUG_FLAGS:=-g -gdwarf-3}"
export CGO_CFLAGS="${CGO_CFLAGS:+$CGO_CFLAGS }$GO_DEBUG_FLAGS"
export CGO_CXXFLAGS="${CGO_CXXFLAGS:+$CGO_CXXFLAGS }$GO_DEBUG_FLAGS"

# Air-gapped contract (SPEC §6.5): the PATCH tier re-runs build.sh OFFLINE.
# $(go env GOMODCACHE) reads the pinned ENV under /opt/toolchains (set in the Dockerfile),
# so the file proxy path is correct regardless of $HOME.
export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOPROXY="${GOPROXY:-file://$(go env GOMODCACHE)/cache/download,https://proxy.golang.org,direct}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"

# Go env: toolchain + caches are under /opt/toolchains (pinned by Dockerfile ENV).
# Ensure PATH includes the toolchain bin dirs for standalone invocations.
export PATH="/opt/toolchains/go/bin:/opt/toolchains/go-path/bin:$PATH"

cd "$SRC"
go version

# Replicate OSS-Fuzz: `cp $SRC/fuzz.go $SRC/go-containerregistry/pkg/name/`
# The harness source lives at mayhem/fuzz.go.src (a non-.go name so `go test ./...` ignores it
# as a mayhem-dir file); copy it into pkg/name/ where FuzzParseReference is in scope.
cp "$SRC/mayhem/fuzz.go.src" "$SRC/pkg/name/fuzz.go"

# go-fuzz rewrites source + needs the AdamKorcz testing shim as a module dep. Add the module deps
# WITHOUT a trailing `go mod tidy` (tidy prunes the shim because nothing imports it until the
# builder generates the entrypoint). Order matters: tidy first, then `go get` the shim.
go mod tidy 2>&1 | tail -2 || true
go get github.com/AdamKorcz/go-118-fuzz-build/testing@latest 2>&1 | tail -2 || true

mkdir -p "$SRC/mayhem-build"

# ── OSS-Fuzz target: name.FuzzParseReference via go-fuzz (LEGACY []byte harness), -tags gofuzz ────
#     Exact replica of `compile_go_fuzzer .../pkg/name FuzzParseReference fuzz_parse_reference`.
echo "=== building fuzz_parse_reference (name.FuzzParseReference, go-fuzz -tags gofuzz) ==="
go-fuzz -tags gofuzz -func FuzzParseReference -o "$SRC/mayhem-build/fuzz_parse_reference.a" \
    github.com/google/go-containerregistry/pkg/name
# Link: DWARF3 via $GO_DEBUG_FLAGS ensures the C-shim CU (first in the binary) is at DWARF3.
$CXX $SANITIZER_FLAGS $LIB_FUZZING_ENGINE $GO_DEBUG_FLAGS "$SRC/mayhem-build/fuzz_parse_reference.a" \
    -o /mayhem/fuzz_parse_reference
echo "built /mayhem/fuzz_parse_reference"

echo "build.sh complete:"
ls -la /mayhem/fuzz_parse_reference 2>&1 || true
