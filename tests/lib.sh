#!/usr/bin/env bash

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
KK_BIN=${KK_BIN:-"$ROOT_DIR/kk"}
PYTHON_BIN=${PYTHON_BIN:-python3}

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
RESULTS_FILE=
LOG_DIR=
TMP_ROOT=
LAST_CASE_FILE=
CURRENT_CASE_DIR=

fail_note() {
    printf '%s\n' "$*" >&2
}

init_harness() {
    TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/kk-tests.XXXXXX")
    LOG_DIR="$TMP_ROOT/logs"
    RESULTS_FILE="$TMP_ROOT/results.tsv"
    mkdir -p "$LOG_DIR"
    : > "$RESULTS_FILE"
    LAST_CASE_FILE="$TMP_ROOT/last_case_dir"
    : > "$LAST_CASE_FILE"
}

cleanup_harness() {
    if [[ -n ${KEEP_TEST_ARTIFACTS:-} ]]; then
        printf 'Keeping test artifacts at %s\n' "$TMP_ROOT"
    elif [[ -n ${TMP_ROOT:-} && -d ${TMP_ROOT:-} ]]; then
        rm -rf "$TMP_ROOT"
    fi
}

new_case_dir() {
    local dir
    dir=$(mktemp -d "$TMP_ROOT/case_XXXXXX")
    printf '%s' "$dir" > "$LAST_CASE_FILE"
    printf '%s\n' "$dir"
}

record_result() {
    local status=$1
    local name=$2
    local detail=${3:-}
    printf '%s\t%s\t%s\n' "$status" "$name" "$detail" >> "$RESULTS_FILE"
    case "$status" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)); printf 'PASS %s\n' "$name" ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)); printf 'FAIL %s\n' "$name"; [[ -n $detail ]] && printf '  %s\n' "$detail" ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)); printf 'SKIP %s\n' "$name"; [[ -n $detail ]] && printf '  %s\n' "$detail" ;;
    esac
}

run_test() {
    local name=$1
    shift
    set +e
    (
        set +e
        "$@"
    )
    local rc=$?
    set -e
    if [[ $rc -eq 0 ]]; then
        record_result PASS "$name"
    else
        local last_case=""
        if [[ -f "$LAST_CASE_FILE" ]]; then last_case=$(cat "$LAST_CASE_FILE"); fi
        record_result FAIL "$name" "See artifacts under $last_case"
    fi
}

skip_test() {
    local name=$1
    local detail=$2
    record_result SKIP "$name" "$detail"
}

capture_cmd() {
    local label=$1
    shift
    local stdout_file="$CURRENT_CASE_DIR/${label}.out"
    local stderr_file="$CURRENT_CASE_DIR/${label}.err"
    set +e
    "$@" >"$stdout_file" 2>"$stderr_file"
    local rc=$?
    set -e
    printf '%s' "$rc" > "$CURRENT_CASE_DIR/${label}.exit"
    return 0
}

cmd_exit() {
    local label=$1
    cat "$CURRENT_CASE_DIR/${label}.exit"
}

assert_exit() {
    local label=$1
    local expected=$2
    local actual
    actual=$(cmd_exit "$label")
    if [[ "$actual" != "$expected" ]]; then
        fail_note "Expected exit $expected for $label, got $actual"
        fail_note "stdout:"; sed 's/^/  /' "$CURRENT_CASE_DIR/${label}.out" >&2 || true
        fail_note "stderr:"; sed 's/^/  /' "$CURRENT_CASE_DIR/${label}.err" >&2 || true
        return 1
    fi
}

assert_contains() {
    local file=$1
    local needle=$2
    if ! grep -Fq -- "$needle" "$file"; then
        fail_note "Expected to find '$needle' in $file"
        sed 's/^/  /' "$file" >&2 || true
        return 1
    fi
}

assert_not_contains() {
    local file=$1
    local needle=$2
    if grep -Fq -- "$needle" "$file"; then
        fail_note "Did not expect to find '$needle' in $file"
        sed 's/^/  /' "$file" >&2 || true
        return 1
    fi
}

assert_file_exists() {
    local path=$1
    [[ -f "$path" ]] || { fail_note "Missing file $path"; return 1; }
}

assert_json() {
    "$PYTHON_BIN" "$ROOT_DIR/tests/json_assert.py" "$@"
}

compile_kernel() {
    (cd "$ROOT_DIR" && cc -std=c11 -Wall -Wextra -O2 -o kk kk.c -lsqlite3 -lm)
}

print_summary() {
    printf '\nSummary: passed=%d failed=%d skipped=%d\n' "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"
    printf 'Artifacts: %s\n' "$TMP_ROOT"
}
