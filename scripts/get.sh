#!/bin/sh
# get.sh — one-command bootstrap installer for purge-warden.
#
#     curl -fsSL https://get.purge.cc | sudo sh
#
# Resolves the published version, downloads the release bundle for this
# machine's architecture, verifies its SHA-256 against the published manifest,
# unpacks it, and hands off to the real installer inside it.
#
# This script is deliberately small. It does NOT install anything itself:
# scripts/install.sh in the bundle owns port 53, systemd-resolved, the
# firewall, SELinux labelling, `warden init` and the unit. Duplicating any of
# that here would create a second implementation to drift from the first.
#
# ── STRUCTURE: read this before editing ──────────────────────────────
# Every statement lives inside a function and the only top-level call is
# `main "$@"` on the LAST line. A `curl | sh` pipeline is executed as it
# arrives, so a connection cut halfway through a flat script runs the prefix
# and leaves a half-install behind. With the body in functions, a truncated
# download defines a few functions and calls nothing.
#
# POSIX sh, not bash: this is piped into whatever /bin/sh the host ships
# (dash on Debian/Ubuntu). No arrays, no `[[ ]]`, no `local`, no `pipefail`.
# Those parse fine under bash and fail at runtime under dash — the class of
# bug a syntax check cannot see. The INSTALLER is bash; this wrapper is not,
# which is the entire reason the wrapper exists.
#
# ── Environment knobs (a pipeline cannot take positional flags) ───────
#   PURGE_VERSION=v0.39.0     pin a version instead of reading /stable
#   PURGE_BASE_URL=https://…  alternate artifact host. Must be https — every
#                             fetch runs with --proto '=https', so a plain-http
#                             host is refused rather than silently downgraded
#   PURGE_INSTALL_DIR=…       where the bundle is unpacked
#                             (default /usr/local/lib/purge-warden)
#   PURGE_ALLOW_PACKAGE_OVERLAP=1
#                             proceed even though the distro package is
#                             installed — read the refusal text first
#   PURGE_DRY_RUN=1           validate a staged bundle and pass --dry-run;
#                             leave an existing bundle untouched
#
# Anything else on the command line is forwarded to the installer verbatim:
#   curl -fsSL https://get.purge.cc | sudo sh -s -- --yes --upstream 10.0.0.1:53

set -eu

# ── Constants ────────────────────────────────────────────────────────
BASE_URL="${PURGE_BASE_URL:-https://get.purge.cc}"
WANT_VERSION="${PURGE_VERSION:-}"
INSTALL_DIR="${PURGE_INSTALL_DIR:-/usr/local/lib/purge-warden}"
ALLOW_PACKAGE_OVERLAP="${PURGE_ALLOW_PACKAGE_OVERLAP:-}"
DRY_RUN="${PURGE_DRY_RUN:-}"

# Set by the resolve/detect functions, read by everything after them.
TARGET=""
VERSION=""
ARTIFACT=""
WORKDIR=""
STAGING_DIR=""
BACKUP_DIR=""

# ── Output ───────────────────────────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
	C_R=$(printf '\033[0m')
	C_B=$(printf '\033[1;34m')
	C_G=$(printf '\033[1;32m')
	C_Y=$(printf '\033[1;33m')
	C_E=$(printf '\033[1;31m')
else
	C_R='' C_B='' C_G='' C_Y='' C_E=''
fi

log() { printf '%s▸%s %s\n' "$C_B" "$C_R" "$*"; }
ok() { printf '%s✓%s %s\n' "$C_G" "$C_R" "$*"; }
warn() { printf '%s⚠%s %s\n' "$C_Y" "$C_R" "$*" >&2; }
step() { printf '\n%s── %s ──%s\n' "$C_B" "$*" "$C_R"; }
die() {
	printf '\n%s✗%s %s\n\n' "$C_E" "$C_R" "$*" >&2
	exit 1
}

cleanup() {
	# A failed replacement must not strand the previous bundle under a hidden
	# sibling name. This only runs while the hand-off has not happened.
	if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
		if [ ! -e "$INSTALL_DIR" ]; then
			mv "$BACKUP_DIR" "$INSTALL_DIR" 2>/dev/null ||
				warn "cannot restore the previous bundle from $BACKUP_DIR"
		else
			rm -rf "$BACKUP_DIR" 2>/dev/null ||
				warn "cannot remove the previous bundle at $BACKUP_DIR"
		fi
	fi
	[ -n "$STAGING_DIR" ] && [ -d "$STAGING_DIR" ] && rm -rf "$STAGING_DIR"
	[ -n "$WORKDIR" ] && [ -d "$WORKDIR" ] && rm -rf "$WORKDIR"
	return 0
}

have() { command -v "$1" >/dev/null 2>&1; }

# ── Preconditions ────────────────────────────────────────────────────
require_root() {
	[ "$(id -u)" -eq 0 ] || die "this installer must run as root.

    curl -fsSL $BASE_URL | sudo sh"
}

require_tools() {
	# bash is checked first and named explicitly: the installer this script
	# hands off to is 2300 lines of bash and cannot run under sh. A host
	# without it fails here with one sentence instead of a page of syntax
	# errors from a half-parsed script.
	have bash || die "bash is required — the installer is a bash program.

    Debian/Ubuntu:  apt-get install -y bash
    Fedora/RHEL:    dnf install -y bash"

	have tar || die "tar is required to unpack the release bundle."

	have curl || have wget ||
		die "neither curl nor wget is available — cannot download anything."

	have sha256sum || have shasum ||
		die "no SHA-256 tool found (sha256sum or shasum). The download cannot be
verified, and an unverified install is not offered."
}

# The bundle installs to /usr/local; a distro package installs to /usr. Both
# can be present at once, and the result is not a merge — it is a machine
# where two different warden versions are half-live:
#
#   /usr/local/bin/warden          beats  /usr/bin/warden          on PATH
#   /etc/systemd/system/….service  beats  /usr/lib/systemd/…       in systemd
#
# so the bundle's binary answers the operator's commands while the package's
# files sit unused, and an `apt-get upgrade` moves the one nobody is running.
# Refuse rather than produce that, and name the two ways out.
check_no_distro_package() {
	pkg=""
	if have dpkg-query && dpkg-query -W -f='${Status}' purge-warden 2>/dev/null |
		grep -q 'install ok installed'; then
		pkg="deb"
	elif have rpm && rpm -q purge-warden >/dev/null 2>&1; then
		pkg="rpm"
	fi
	[ -z "$pkg" ] && return 0

	[ -n "$ALLOW_PACKAGE_OVERLAP" ] && {
		warn "the purge-warden distro package is installed and you asked to
    proceed anyway. /usr/local will shadow it on PATH and in systemd."
		return 0
	}

	if [ "$pkg" = deb ]; then
		die "the purge-warden .deb is already installed.

Installing the bundle on top would leave two versions half-live: the bundle's
/usr/local/bin/warden shadows the package's /usr/bin/warden, and its unit in
/etc/systemd/system shadows the package's. Pick one.

    Keep the package:  it is already installed — nothing to do here.
    Switch to this:    sudo apt-get purge purge-warden, then re-run.
    Override:          PURGE_ALLOW_PACKAGE_OVERLAP=1 (you own the result)"
	fi
	die "the purge-warden .rpm is already installed.

Installing the bundle on top would leave two versions half-live: the bundle's
/usr/local/bin/warden shadows the package's /usr/bin/warden, and its unit in
/etc/systemd/system shadows the package's. Pick one.

    Keep the package:  it is already installed — nothing to do here.
    Switch to this:    sudo dnf remove purge-warden, then re-run.
    Override:          PURGE_ALLOW_PACKAGE_OVERLAP=1 (you own the result)"
}

# ── Host detection ───────────────────────────────────────────────────
# Maps `uname -m` to the target triple in the published artifact name. The
# two triples differ in libc on purpose: x86_64 is glibc-dynamic (built on an
# old enough base that its floor covers every claimed distribution), aarch64
# is musl-static (no ARM base to pin, so the dependency is removed instead).
detect_target() {
	m=$(uname -m 2>/dev/null || echo unknown)
	case "$m" in
	x86_64 | amd64) TARGET=x86_64-unknown-linux-gnu ;;
	aarch64 | arm64) TARGET=aarch64-unknown-linux-musl ;;
	*) die "unsupported architecture: $m

purge-warden publishes x86_64 and aarch64 builds. Build from source instead:
    https://git.purge.cc — see BUILDING.md" ;;
	esac
	[ "$(uname -s 2>/dev/null)" = Linux ] ||
		die "purge-warden is a Linux systemd service; this host is not Linux."
}

# ── Version resolution ───────────────────────────────────────────────
fetch() {
	# fetch <url> <dest>
	if have curl; then
		curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
	else
		wget -q --https-only -O "$2" "$1"
	fi
}

# The version reaches a URL path and a filename, so it is validated before use
# rather than trusted because the host returned it.
#
# Two stages, and the first is not redundant: `grep -E '^…$'` anchors per LINE,
# so a two-line value whose FIRST line is well-formed satisfies `grep -q`.
# Shell `case` has no line semantics, so the character-class rejection catches
# an embedded newline; the regex then checks the shape.
#
# The leading `v` is part of the version token, not a path prefix: the pointer
# file holds `v0.39.0`, the directory is `/v0.39.0/` and the tarball is named
# `warden-v0.39.0-…`. One representation, threaded through unchanged.
validate_version() {
	case "$1" in
	'' | *[!0-9A-Za-z.-]*) return 1 ;;
	esac
	printf '%s' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'
}

resolve_version() {
	if [ -n "$WANT_VERSION" ]; then
		VERSION="$WANT_VERSION"
	else
		# Deliberately NOT `$(fetch … | tr …)`. POSIX sh has no `pipefail`, so a
		# pipeline's status is the LAST stage's — `tr` succeeds on empty input,
		# which swallows a failed download and reports it downstream as a
		# malformed version string. Fetch, check, then trim.
		resolve_version_raw=$(fetch "$BASE_URL/stable" /dev/stdout) ||
			die "cannot reach $BASE_URL/stable — check network/DNS, or pin a
version with PURGE_VERSION=vX.Y.Z"
		VERSION=$(printf '%s' "$resolve_version_raw" | tr -d ' \t\r\n')
	fi

	validate_version "$VERSION" ||
		die "'$VERSION' is not a valid version string. Expected vX.Y.Z."
}

artifact_name() {
	ARTIFACT="warden-$VERSION-$TARGET.tar.gz"
}

# ── Download + verify ────────────────────────────────────────────────
select_expected_sum() {
	# select_expected_sum <manifest> <artifact> <out-file>
	awk -v want="$2" '$2 == want { print }' "$1" >"$3"
	[ -s "$3" ]
}

sha_check() {
	# sha_check <dir> <manifest-line-file>
	if have sha256sum; then
		(cd "$1" && sha256sum -c "$2" >/dev/null 2>&1)
	else
		(cd "$1" && shasum -a 256 -c "$2" >/dev/null 2>&1)
	fi
}

download_and_verify() {
	step "Downloading purge-warden $VERSION"
	WORKDIR=$(mktemp -d) || die "cannot create a temporary directory"
	trap cleanup EXIT
	trap 'cleanup; exit 1' INT TERM

	log "$ARTIFACT"
	fetch "$BASE_URL/$VERSION/$ARTIFACT" "$WORKDIR/$ARTIFACT" ||
		die "download failed: $BASE_URL/$VERSION/$ARTIFACT

If this version exists, the build for $TARGET may not be published."
	log "SHA256SUMS"
	fetch "$BASE_URL/$VERSION/SHA256SUMS" "$WORKDIR/SHA256SUMS" ||
		die "cannot fetch the checksum manifest — refusing to install an
unverified bundle"

	select_expected_sum "$WORKDIR/SHA256SUMS" "$ARTIFACT" \
		"$WORKDIR/expected.sha256" ||
		die "$ARTIFACT is not listed in SHA256SUMS for $VERSION — the release
is incomplete or the artifact name changed. Not installing."

	sha_check "$WORKDIR" expected.sha256 ||
		die "CHECKSUM MISMATCH for $ARTIFACT.

The downloaded file does not match the published manifest. This is either a
corrupted download or a tampered artifact. Nothing was installed."
	ok "Checksum verified"

	warn "Signature verification is not available yet — the manifest is not
    signed. The checksum above proves the file matches the manifest, not that
    the manifest itself is authentic. See https://purge.cc/security"
}

# ── Unpack ───────────────────────────────────────────────────────────
# Unpacked to a STABLE directory, never to the mktemp dir the download landed
# in. The installer derives REPO_ROOT from its own location and prints
# `sudo $REPO_ROOT/scripts/uninstall.sh` as the removal command; from a temp
# directory that path is dead before the operator finishes reading it. It also
# reads the three systemd units by that path at install time.
validate_install_dir() {
	# This path is later moved aside and removed as a whole. Refuse paths that
	# could name a filesystem root, a conventional broad directory, or a path
	# with lexical aliases that make the target hard to reason about.
	case "$INSTALL_DIR" in
	'' | / | */ | *//* | */./* | */../* | */. | */..)
		die "PURGE_INSTALL_DIR must be a specific absolute directory, not '$INSTALL_DIR'"
		;;
	esac
	case "$INSTALL_DIR" in
	/*) ;;
	*) die "PURGE_INSTALL_DIR must be an absolute path, not '$INSTALL_DIR'" ;;
	esac
	case "$INSTALL_DIR" in
	/bin | /boot | /dev | /etc | /home | /lib | /lib64 | /media | /mnt | /opt | \
	/proc | /root | /run | /sbin | /srv | /sys | /tmp | /usr | /usr/bin | /usr/lib | \
	/usr/lib64 | /usr/local | /usr/local/bin | /usr/local/lib | /usr/local/share | \
	/usr/sbin | /usr/share | /var | /var/cache | /var/lib | /var/log | /var/spool | /var/tmp)
		die "PURGE_INSTALL_DIR names a broad system directory: $INSTALL_DIR"
		;;
	esac
}

validate_bundle_archive() {
	listing="$WORKDIR/archive.list"
	tar -tzf "$WORKDIR/$ARTIFACT" >"$listing" ||
		die "cannot inspect $ARTIFACT — the archive is corrupt."

	# The bundle is an executable plus the exact installer support files. An
	# unexpected member is a packaging error and could also be a traversal or
	# link that escapes the private staging directory.
	while IFS= read -r member; do
		case "$member" in
		./ | ./warden | ./scripts/ | ./scripts/install.sh | \
		./scripts/uninstall.sh | ./scripts/upgrade_config_gate.sh | \
		./scripts/migrate-shield-to-warden.sh | ./systemd/ | \
		./systemd/purge-warden.service | ./systemd/purge-warden-backup.service | \
		./systemd/purge-warden-backup.timer) ;;
		*) die "the bundle contains an unexpected path: $member" ;;
		esac
	done <"$listing"
	awk 'seen[$0]++ { exit 1 }' "$listing" ||
		die "the bundle contains a duplicate archive member"
	tar -tvzf "$WORKDIR/$ARTIFACT" |
		awk 'substr($0, 1, 1) != "-" && substr($0, 1, 1) != "d" { exit 1 }' ||
		die "the bundle contains a link or unsupported archive member"
}

unpack_bundle() {
	validate_install_dir
	step "Unpacking to $INSTALL_DIR"
	validate_bundle_archive

	parent=${INSTALL_DIR%/*}
	leaf=${INSTALL_DIR##*/}
	[ -n "$parent" ] || parent=/
	mkdir -p "$parent" || die "cannot create parent directory for $INSTALL_DIR"

	# Extract and inspect a complete candidate before touching the active tree.
	# A sibling makes the later rename atomic on the same filesystem.
	STAGING_DIR=$(mktemp -d "$parent/.${leaf}.staging.XXXXXX") ||
		die "cannot create a staging directory beside $INSTALL_DIR"
	tar -xzf "$WORKDIR/$ARTIFACT" -C "$STAGING_DIR" ||
		die "cannot unpack $ARTIFACT — the archive is corrupt."

	[ -f "$STAGING_DIR/warden" ] && [ ! -L "$STAGING_DIR/warden" ] &&
		[ -x "$STAGING_DIR/warden" ] ||
		die "the bundle does not contain an executable ./warden.
This is a broken release, not a broken host. Nothing was installed."
	for required in \
		scripts/install.sh \
		scripts/uninstall.sh \
		scripts/upgrade_config_gate.sh \
		scripts/migrate-shield-to-warden.sh
	do
		[ -f "$STAGING_DIR/$required" ] && [ ! -L "$STAGING_DIR/$required" ] &&
			[ -x "$STAGING_DIR/$required" ] ||
			die "the bundle lacks executable $required. Nothing was installed."
	done
	for required in \
		systemd/purge-warden.service \
		systemd/purge-warden-backup.service \
		systemd/purge-warden-backup.timer
	do
		[ -f "$STAGING_DIR/$required" ] && [ ! -L "$STAGING_DIR/$required" ] ||
			die "the bundle lacks regular file $required. Nothing was installed."
	done

	# A dry run may inspect the downloaded bundle, but it must leave the active
	# bundle untouched. run_installer uses this candidate directly below.
	[ -n "$DRY_RUN" ] && {
		ok "Bundle checked (dry run)"
		return 0
	}

	if [ -e "$INSTALL_DIR" ] || [ -L "$INSTALL_DIR" ]; then
		[ -d "$INSTALL_DIR" ] && [ ! -L "$INSTALL_DIR" ] ||
			die "$INSTALL_DIR exists but is not a real directory; refusing to replace it"
		BACKUP_DIR=$(mktemp -d "$parent/.${leaf}.previous.XXXXXX") ||
			die "cannot reserve a backup path beside $INSTALL_DIR"
		rmdir "$BACKUP_DIR" || die "cannot prepare a backup path beside $INSTALL_DIR"
		mv "$INSTALL_DIR" "$BACKUP_DIR" || die "cannot move the previous bundle aside"
		if ! mv "$STAGING_DIR" "$INSTALL_DIR"; then
			mv "$BACKUP_DIR" "$INSTALL_DIR" ||
				die "cannot activate the new bundle or restore the previous one"
			BACKUP_DIR=""
			die "cannot activate the new bundle; the previous bundle was restored"
		fi
	else
		mv "$STAGING_DIR" "$INSTALL_DIR" || die "cannot activate the new bundle"
	fi
	STAGING_DIR=""

	if [ -n "$BACKUP_DIR" ]; then
		rm -rf "$BACKUP_DIR" || warn "could not remove previous bundle at $BACKUP_DIR"
		BACKUP_DIR=""
	fi
	ok "Bundle unpacked"
}

# ── Hand off ─────────────────────────────────────────────────────────
# `exec`, not a call: the installer becomes this process. Its exit status is
# the one-liner's exit status with nothing in between to swallow or reinterpret
# it, and nothing after this line can run and contradict what it printed.
run_installer() {
	installer_root=$INSTALL_DIR
	[ -n "$DRY_RUN" ] && installer_root=$STAGING_DIR
	step "Handing off to the installer"
	set -- --binary "$installer_root/warden" "$@"
	[ -n "$DRY_RUN" ] && set -- "$@" --dry-run
	log "bash $installer_root/scripts/install.sh $*"
	[ -n "$DRY_RUN" ] && {
		bash "$installer_root/scripts/install.sh" "$@"
		return $?
	}
	[ -z "$WORKDIR" ] || rm -rf "$WORKDIR" || warn "could not remove download workspace"
	WORKDIR=""
	trap - EXIT INT TERM
	exec bash "$installer_root/scripts/install.sh" "$@"
}

main() {
	require_root
	require_tools
	check_no_distro_package
	detect_target
	resolve_version
	artifact_name
	download_and_verify
	unpack_bundle
	run_installer "$@"
}

main "$@"
