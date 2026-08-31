#!/usr/bin/env bash
# scripts/check_no_raw_fs_write.sh — §4.36 preventive lint.
#
# Catches the regression class flagged by §4.28 b9 closure-note
# meta-finding: a developer reaches for the convenient `std::fs::write`
# helper to put bytes onto a config-bearing path, bypassing the
# §4.31 hardening (mode preservation, fsync, validation-then-rename).
# Two real-world regressions of this shape already happened on this
# repo:
#
#   - cli/commands/init.rs:155 used `fs::write(CONFIG_PATH, body)` for
#     the first-boot scaffold (fixed during §4.31 closure).
#   - cli/commands/config/edit.rs:19 used `fs::write(config_path,
#     DEFAULT_CONFIG)` for the same scaffold on the `config edit`
#     fresh-file path (fixed during §4.35 / cli-h1 sprint).
#
# Both of those leave a `0o644` race window between the write and the
# follow-up `set_permissions`, so the lint is structurally about
# correctness, not just style.
#
# The grep pattern is intentionally narrow — only catches calls whose
# FIRST argument is one of the canonical config-path identifiers:
#
#   CONFIG_PATH | config_path | master_path | MASTER_PATH
#
# False-negatives are accepted: a developer can still write
# `fs::write(my_renamed_thing, ...)` and bypass the lint. The
# expectation is that anyone touching a config-path will reach for
# the obvious identifier name, and code review catches the rest. The
# narrow pattern keeps the script noise-free.
#
# CONCRETE CONSEQUENCE — do not read this script's green as coverage of a
# write it cannot see. `Catalog::save_to_disk` (src/lists/catalog.rs) puts
# bytes onto `<lists_dir>/catalog.json` and is OUTSIDE the pattern by
# construction: its path is a `dir.join(Self::DISK_FILENAME)` expression,
# not one of the four identifiers above. That write IS correct today — it
# routes through `hardened_atomic_write` — but this script did not verify
# it and would stay green if a later edit swapped in `std::fs::write`.
# A sprint report cited this gate's green as evidence for that path; it
# was not evidence. Any new config-bearing or state-bearing write on a
# joined path needs eyes, not this lint.
#
# In-file unit tests routinely bind a temp-dir fixture path to a
# local variable also named `config_path` (it IS a config path, just
# not the production master) — see e.g. `load_fixture()` in
# `src/cli/commands/start.rs`. A raw `fs::write` there is fine: it's
# a throwaway temp file, not the hardened production master, and
# there's no concurrent reader racing the 0o644 window. So hits whose
# nearest enclosing top-level item is a `#[cfg(test)] mod ... {`
# block are excluded — see `in_test_module()` below. This narrows by
# STRUCTURE (test module or not), never by relaxing the identifier
# pattern itself, so a genuine production `fs::write(CONFIG_PATH, …)`
# is still caught regardless of which file it's added to.
#
# Prefers ripgrep; falls back to `grep -r` when `rg` isn't installed
# (the canonical CT has no ripgrep). Fails CLOSED — exit 2 — only
# when NEITHER scanner is available: a guard that silently passes
# because its tool is missing is worse than no guard.
#
# Exit codes:
#   0 — clean (no offending fs::write)
#   1 — at least one offending fs::write detected
#   2 — no usable scanner (neither rg nor grep on PATH), or the
#       chosen scanner fails its regex self-test (see probe below)

set -euo pipefail

cd "$(dirname "$0")/.."

# Match `fs::write(IDENT,` where IDENT is one of the canonical
# config-path names. `\b` boundaries ensure `_config_path` and
# `someconfig_path` don't accidentally match. Written in ERE form —
# valid unescaped for `rg` and passed to `grep -E` in the fallback.
PATTERN='\bfs::write\(\s*&?\s*(CONFIG_PATH|config_path|master_path|MASTER_PATH)\b'

if command -v rg >/dev/null 2>&1; then
    scanner=rg
elif command -v grep >/dev/null 2>&1; then
    scanner=grep
else
    echo "check_no_raw_fs_write.sh: neither ripgrep (rg) nor grep found on PATH" >&2
    echo "  Install ripgrep (apt install ripgrep), or ensure grep is available." >&2
    exit 2
fi

# Self-test: prove $scanner's regex dialect actually matches PATTERN
# against a known-positive line before trusting a clean result from
# it. `\s` degrades harmlessly where unsupported (still matches via
# `*`-on-nothing), but `\b` does not — an unsupported `\b` makes the
# WHOLE pattern unmatchable, and an unmatchable pattern reports
# exactly the same "clean" as a genuinely clean tree. This has only
# ever been verified against `rg` and a local non-GNU grep, never the
# canonical CT's grep — so verify at runtime instead of assuming it,
# same fail-closed spirit as the missing-scanner case above.
probe='    std::fs::write(&config_path, body).unwrap();'
probe_matches() {
    if [ "$scanner" = rg ]; then
        printf '%s\n' "$probe" | rg -q "$PATTERN"
    else
        printf '%s\n' "$probe" | grep -qE "$PATTERN"
    fi
}
if ! probe_matches; then
    echo "check_no_raw_fs_write.sh: $scanner self-test failed — PATTERN does not" >&2
    echo "  match a known-positive line under this scanner's regex dialect." >&2
    echo "  Refusing to report clean from a scanner that can't scan." >&2
    exit 2
fi

# `src/config/atomic_write.rs` legitimately calls fs::write inside
# the implementation of the hardened helper. Skip it.
if [ "$scanner" = rg ]; then
    raw_hits=$(rg -n --type rust "$PATTERN" src/ \
            -g '!src/config/atomic_write.rs' \
            || true)
else
    raw_hits=$(grep -rnE "$PATTERN" --include='*.rs' src/ \
            | grep -v '^src/config/atomic_write\.rs:' \
            || true)
fi

# True if $2 (a line number in file $1) falls inside a top-level
# `#[cfg(test)] mod ... {` block. Single pass, no AST: tracks the
# most recent column-0 `}` (closes whatever top-level item preceded)
# against the most recent column-0 `mod NAME {` whose run of
# immediately-preceding attribute lines includes `#[cfg(test)]`.
# Relies on the repo being rustfmt-clean (own gate #3): nested code
# is never at column 0, so a bare `}` there can only be a top-level
# item closing, never a match arm or block return.
in_test_module() {
    local file="$1" target="$2"
    local result
    result=$(awk -v target="$target" '
        /^}/ { last_close = NR }
        /^#\[cfg\(test\)\]/ { pending_test = 1 }
        /^mod [A-Za-z_][A-Za-z0-9_]*[[:space:]]*\{/ {
            if (pending_test) { last_test_open = NR }
            pending_test = 0
        }
        /^#\[/ { next }
        { pending_test = 0 }
        NR == target {
            print (last_test_open > last_close) ? "yes" : "no"
            exit
        }
    ' "$file" 2>/dev/null)
    [ "$result" = "yes" ]
}

hits=""
while IFS= read -r rawline; do
    [ -z "$rawline" ] && continue
    file=${rawline%%:*}
    rest=${rawline#*:}
    lineno=${rest%%:*}
    if in_test_module "$file" "$lineno"; then
        continue
    fi
    hits="${hits}${rawline}"$'\n'
done <<< "$raw_hits"
hits=${hits%$'\n'}

if [ -n "$hits" ]; then
    echo "ERROR: raw fs::write detected on a config-path identifier." >&2
    echo "  Use crate::config::atomic_write::hardened_atomic_write or" >&2
    echo "  atomic_write_and_validate; never std::fs::write on a config" >&2
    echo "  master / CONFIG_PATH." >&2
    echo "" >&2
    echo "$hits" >&2
    exit 1
fi

echo "check_no_raw_fs_write: ok"
