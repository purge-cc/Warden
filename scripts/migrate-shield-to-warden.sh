#!/usr/bin/env bash
#
# migrate-shield-to-warden.sh — convert an existing `purge-shield` install
# to the new `purge-warden` naming (v0.21.0 product rename).
#
# What it does (idempotent; safe to run when there is nothing to migrate):
#   1. stop + disable the old purge-shield units
#   2. rename the unix user + group in place (usermod -l / groupmod -n) so
#      UID/GID — and therefore every file's ownership — survive the move
#   3. mv /etc, /var/lib, /run data dirs purge-shield → purge-warden
#      (handles both the /etc master and the legacy /var/lib master)
#   4. re-own the moved trees to purge-warden (covers the usermod-failed path)
#   5. remove old units + old binary + old aux files (wrapper, resolved drop-in)
#
# It does NOT install the new binary or the new units — run install.sh for
# that. install.sh invokes this script automatically when it detects an old
# install, then proceeds with its normal (now warden-named) steps, which
# recreate the wrapper, the resolved drop-in, the units, and start the daemon.
#
# Ordering matters: units are stopped BEFORE the user rename (usermod refuses
# a user with live processes) and BEFORE the dir moves (release the socket +
# PID file). daemon-reload happens last so a partially-renamed unit set is
# never reloaded.
#
# Usage:
#   sudo ./scripts/migrate-shield-to-warden.sh           # migrate
#   sudo ./scripts/migrate-shield-to-warden.sh --dry-run # preview only

set -euo pipefail

OLD="purge-shield"
NEW="purge-warden"
OLD_BIN="/usr/local/bin/shield"

DRY_RUN="false"
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN="true"

if [[ $DRY_RUN == "true" ]]; then
	run() { printf '  [dry] %s\n' "$*"; }
else
	run() { "$@"; }
fi

log() { printf '▸ %s\n' "$*"; }
ok() { printf '✓ %s\n' "$*"; }
warn() { printf '⚠ %s\n' "$*" >&2; }

# ── Config-path rewriting ─────────────────────────────────────────────
#
# Moving the directories is not enough: absolute paths written INSIDE the
# config point at the tree that no longer exists. The observed failure was
# `[socket] path = /run/purge-shield/control.sock` — the daemon bound :53,
# loaded the full corpus, then died `Permission denied` on the dead socket
# path (not in the unit's ReadWritePaths) and crash-looped at 16 s CPU and
# 1.2 GB RAM per loop. Every early success signal fired before it.
#
# The rewrite must be narrow BY CONSTRUCTION, because `shield` is also an
# ordinary word in operator data — `display_name = "Nvidia Shield"`,
# `id = "shield-tv"` — living in these same files. A blind
# `sed s/shield/warden/g` corrupts the operator's own records while fixing
# the paths. Two conditions must BOTH hold before a byte changes:
#
#   a) the line's key is one of CONFIG_PATH_KEYS — the closed set of keys
#      whose values are ours (see src/config/settings.rs + schema/backup.rs);
#   b) the value STARTS (opening quote anchored) with one of our three FHS
#      prefixes followed by the old product dir.
#
# (b) alone already excludes free-text names; (a) is the second lock. A
# relative value like the shipped default `path = "./control.sock"` fails
# (b) and is left alone.
#
# Anything still naming the old tree after the pass — a multi-line
# `includes` array, a key added after this script was written, an operator
# note — is REPORTED as `unhandled` rather than skipped silently. Silent
# truncation reads as "covered everything".

# Keys whose values are our filesystem paths. Everything else in a config
# file is operator data and is never touched.
CONFIG_PATH_KEYS=(path query_log_path cache_dir dir tls_cert tls_key includes)

# The only prefixes we own. A path anywhere else is the operator's.
CONFIG_PATH_PREFIXES=(/etc /var/lib /run)

# Subdirectories of a moved tree that hold data, not config. `backups/`
# is deliberate: those are archives of past state, and rewriting one
# silently mutates a historical artifact. They are named in the output
# instead, so an operator restoring a pre-migration backup knows it still
# carries old paths.
CONFIG_SKIP_DIRS=(backups lists data)

# Rewrite one file. Emits `rewrite` / `unhandled` report records on stdout;
# writes nothing when DRY_RUN is true.
rewrite_config_file() {
	local file="$1" tmpf outfile report n
	# Declared here so the report loop below does not leak them — `path` in
	# particular is a name worth keeping out of the enclosing scope.
	local kind path lineno before after

	if [[ $DRY_RUN == "true" ]]; then
		# A dry run must not create so much as a temp file in the operator's
		# config dir, so the rewritten content goes nowhere.
		tmpf=""
		outfile=/dev/null
	else
		# Temp in the SAME directory: `mv` is only atomic within one
		# filesystem. mktemp creates it 0600, so there is no loose-permission
		# window even before the mode is copied across.
		tmpf=$(mktemp "$(dirname "$file")/.migrate-XXXXXX") || return 1
		outfile="$tmpf"
	fi

	report=$(awk \
		-v outfile="$outfile" \
		-v fname="$file" \
		-v keys="${CONFIG_PATH_KEYS[*]}" \
		-v prefixes="${CONFIG_PATH_PREFIXES[*]}" \
		-v old="$OLD" \
		-v newname="$NEW" '
		# Display-only (awk passes scalars by value, so the line actually
		# written is untouched). Interior tabs become spaces because the
		# report is tab-separated and the shell splits it on tabs — a tab
		# inside a config value would otherwise garble the preview.
		function trim(s) {
			gsub(/^[ \t]+|[ \t]+$/, "", s)
			gsub(/\t/, " ", s)
			return s
		}
		BEGIN {
			nk = split(keys, K, " ")
			for (i = 1; i <= nk; i++) KEYS[K[i]] = 1
			np = split(prefixes, PRE, " ")
			for (i = 1; i <= np; i++)
				stale = stale (i > 1 ? "|" : "") PRE[i] "/" old
			stale = "(" stale ")"
		}
		{
			line = $0
			outln = line
			# The key is the text before the first "=", trimmed. A line with
			# no "=" (table header, comment, blank) has no key and is inert.
			eq = index(line, "=")
			key = (eq > 0) ? trim(substr(line, 1, eq - 1)) : ""
			hits = 0
			if (key in KEYS) {
				for (i = 1; i <= np; i++) {
					# Anchored on the opening quote so only a value that
					# BEGINS with our path matches. Two forms: the path
					# continues ("/run/purge-shield/x") or the value is the
					# bare directory ("/var/lib/purge-shield").
					hits += gsub("\"" PRE[i] "/" old "/", "\"" PRE[i] "/" newname "/", outln)
					hits += gsub("\"" PRE[i] "/" old "\"", "\"" PRE[i] "/" newname "\"", outln)
				}
			}
			if (hits > 0)
				printf "rewrite\t%s\t%d\t%s\t%s\n", fname, FNR, trim(line), trim(outln)
			# Checked AFTER substitution, so it also catches a line that was
			# only partially rewritten.
			if (outln ~ stale)
				printf "unhandled\t%s\t%d\t%s\n", fname, FNR, trim(line)
			print outln > outfile
		}
	' "$file")

	n=$(printf '%s' "$report" | grep -c '^rewrite' || true)

	if [[ -n $report ]]; then
		while IFS=$'\t' read -r kind path lineno before after; do
			case $kind in
				rewrite)
					if [[ $DRY_RUN == "true" ]]; then
						printf '  [dry] rewrite %s:%s\n          %s\n       → %s\n' \
							"$path" "$lineno" "$before" "$after"
					else
						printf '  rewrote %s:%s  %s → %s\n' "$path" "$lineno" "$before" "$after"
					fi
					;;
				unhandled)
					warn "left as-is (not a recognised path value) $path:$lineno: $before"
					;;
			esac
		done <<<"$report"
	fi

	if [[ $DRY_RUN != "true" ]]; then
		if [[ $n -gt 0 ]]; then
			# Carry the original mode across before the rename, so the
			# published file never exists with the wrong permissions.
			# Ownership self-heals: step 4's `chown -R` runs straight after.
			chmod --reference="$file" "$tmpf"
			mv "$tmpf" "$file"
		else
			rm -f "$tmpf"
		fi
	fi
}

# NUL-separated list of the config files under a tree, minus the data and
# archive directories. Shared by the rewrite and the staleness detector so
# the two can never disagree about what counts as config.
find_config_files() {
	local root="$1" d prune=()
	for d in "${CONFIG_SKIP_DIRS[@]}"; do
		prune+=(-path "$root/$d" -o)
	done
	unset "prune[${#prune[@]}-1]" # drop the trailing -o
	find "$root" \( "${prune[@]}" \) -prune -o -type f -name '*.toml' -print0
}

# ERE matching any of our path prefixes followed by the old product dir.
# Built with an explicit numeric test, not `${i:+|}`: that expands on a
# non-empty STRING, and "0" is non-empty, so it emits a leading `|` — an
# empty alternative, which matches every line and turns the detector below
# into a needle that finds anything.
stale_path_re() {
	local p re=""
	for p in "${CONFIG_PATH_PREFIXES[@]}"; do
		[[ -n $re ]] && re+="|"
		re+="$p/$OLD"
	done
	printf '(%s)' "$re"
}

# True when a config under an ALREADY-MIGRATED tree still names the old one.
#
# This is the detection case the three signals below cannot see. A host
# migrated by an earlier version of this script has no old unit, no old user
# and no old directories — they were renamed or removed — yet its config can
# still point into the dead tree. That is precisely the population this
# rewrite exists for (the CT on 2026-06-01), so it is detected by content.
#
# Deliberately permissive: it fires on a stale path anywhere, including
# operator free text that the rewrite will report rather than change. The
# cost of a false positive is one idempotent no-op pass — every other step
# is already guarded, and step 1 only ever stops OLD-named units, so a
# running purge-warden.service is never interrupted.
has_stale_config_paths() {
	local base root f re
	re=$(stale_path_re)
	for base in "$@"; do
		root="$base/$NEW"
		[[ -d $root ]] || continue
		while IFS= read -r -d '' f; do
			if grep -qE "$re" "$f" 2>/dev/null; then
				return 0
			fi
		done < <(find_config_files "$root")
	done
	return 1
}

rewrite_config_paths_in_tree() {
	local root="$1" f d

	while IFS= read -r -d '' f; do
		rewrite_config_file "$f"
	done < <(find_config_files "$root")

	# Name the archives we deliberately did not rewrite.
	for d in "${CONFIG_SKIP_DIRS[@]}"; do
		if [[ -d $root/$d ]] && compgen -G "$root/$d/*.toml" >/dev/null; then
			log "not rewritten (archive/data, review before restoring): $root/$d/*.toml"
		fi
	done
}

# Rewrite the config trees under each given base (/etc, /var/lib …).
migrate_config_paths() {
	local base root
	for base in "$@"; do
		# In a real run step 3 has already moved $base/$OLD → $base/$NEW, so
		# the files live at the NEW path. In a dry run that `mv` was only
		# printed — the files are still at the OLD path, and scanning the new
		# one would find nothing, report nothing and exit 0: a preview that
		# looks clean precisely because it looked in an empty place.
		if [[ $DRY_RUN == "true" ]]; then
			root="$base/$OLD"
		else
			root="$base/$NEW"
		fi
		[[ -d $root ]] || continue
		rewrite_config_paths_in_tree "$root"
	done
}

# Sourcing hook for scripts/check_migrate_config_paths.sh: loads the helpers
# above without running a migration. Nothing below this line is a pure
# function definition.
[[ ${MIGRATE_SOURCE_ONLY:-} == "1" ]] && return 0

# ── Root check ────────────────────────────────────────────────────────
if [[ $DRY_RUN != "true" && $EUID -ne 0 ]]; then
	warn "must run as root (try: sudo $0)"
	exit 1
fi

# ── Detection — exit 0 quietly when there is nothing to migrate ───────
need_migrate="false"
[[ -f /etc/systemd/system/${OLD}.service ]] && need_migrate="true"
id "$OLD" >/dev/null 2>&1 && need_migrate="true"
[[ -d /var/lib/$OLD || -d /etc/$OLD || -d /run/$OLD ]] && need_migrate="true"
# Fourth signal: a host an earlier version of this script already migrated
# shows none of the three above, but may still carry stale paths in config.
has_stale_config_paths /etc /var/lib && need_migrate="true"

if [[ $need_migrate != "true" ]]; then
	ok "no $OLD install detected — nothing to migrate"
	exit 0
fi

log "migrating existing $OLD install → $NEW"

# ── 1. Stop + disable the old units (release socket / PID first) ──────
for unit in "${OLD}.service" "${OLD}-backup.timer" "${OLD}-backup.service"; do
	if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
		run systemctl stop "$unit" 2>/dev/null || true
		run systemctl disable "$unit" 2>/dev/null || true
	fi
done
ok "old units stopped + disabled"

# ── 2. Rename unix user + group in place (preserve UID/GID) ───────────
# usermod -l keeps the numeric UID, so files owned by the old user are still
# owned (by number) after the rename — the chown in step 4 then re-labels
# them by the new name and also covers the fallback path where the rename
# could not happen and a fresh user gets created by `warden init` later.
if id "$OLD" >/dev/null 2>&1 && ! id "$NEW" >/dev/null 2>&1; then
	if run usermod -l "$NEW" "$OLD"; then
		ok "renamed user $OLD → $NEW (UID preserved)"
	else
		warn "usermod rename failed — install.sh will create $NEW; chown re-owns files"
	fi
fi
if getent group "$OLD" >/dev/null 2>&1 && ! getent group "$NEW" >/dev/null 2>&1; then
	run groupmod -n "$NEW" "$OLD" || warn "groupmod rename failed (non-fatal)"
fi

# ── 3. Move the data / config / runtime directories ───────────────────
for base in /etc /var/lib /run; do
	if [[ -e $base/$OLD && ! -e $base/$NEW ]]; then
		run mv "$base/$OLD" "$base/$NEW"
		ok "moved $base/$OLD → $base/$NEW"
	elif [[ -e $base/$OLD && -e $base/$NEW ]]; then
		warn "$base/$NEW already exists — leaving $base/$OLD in place (manual review)"
	fi
done

# PID file lived at /run/<name>/<name>.pid — rename inside the moved dir.
if [[ -f /run/$NEW/${OLD}.pid ]]; then
	run mv "/run/$NEW/${OLD}.pid" "/run/$NEW/${NEW}.pid"
fi

# ── 3b. Rewrite absolute paths inside the moved config ────────────────
# Must run AFTER the move (the files are edited at their new location) and
# BEFORE the chown, which re-owns whatever this step rewrote. /run holds no
# config — only the socket and PID file — so it is not scanned.
log "rewriting config paths $OLD → $NEW"
migrate_config_paths /etc /var/lib
ok "config path values rewritten"

# ── 4. Re-own the moved trees to the (renamed or fresh) user/group ────
# `-h` (`--no-dereference`) so a symlink met during the recursive walk has
# ITS OWN ownership changed, never the target's. These trees hold
# daemon-written `lists/` and `data/`, so a symlink planted there by a
# compromised daemon user must not let `chown -R` follow it and hand an
# arbitrary file to the service account. GNU coreutils already defaults to
# no-follow (`-P`), but busybox/BSD differ, so force it explicitly.
#
# src/cli/commands/init/mod.rs:967 does the identical operation and has
# carried this defence since roundup-01; this site did not, which is the
# only reason it is written out twice.
for dir in /etc/$NEW /var/lib/$NEW /run/$NEW; do
	[[ -e $dir ]] && run chown -R -h "$NEW:$NEW" "$dir" || true
done
ok "re-owned config/state/runtime trees to $NEW"

# ── 5. Remove old units, old binary, old aux files ────────────────────
# install.sh installs the warden-named units + binary and rewrites the
# wrapper; the resolved drop-in is rewritten too. Remove the old-named
# artefacts so no purge-shield files linger.
for unit in "${OLD}.service" "${OLD}-backup.service" "${OLD}-backup.timer"; do
	run rm -f "/etc/systemd/system/$unit"
done
run rm -f "$OLD_BIN"
run rm -f "/etc/profile.d/${OLD}-wrapper.sh"
run rm -f "/etc/systemd/resolved.conf.d/${OLD}-no-stub.conf"
ok "removed old units, $OLD_BIN, wrapper + resolved drop-in"

# ── 6. Reload systemd so the removed units leave the live set ─────────
run systemctl daemon-reload

ok "migration complete: $OLD → $NEW"
log "run install.sh to install the warden binary + units and start the daemon"
