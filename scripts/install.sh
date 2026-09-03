#!/usr/bin/env bash
#
# install.sh — purge-warden installer for Debian/Ubuntu and Fedora/RHEL
#
# Takes a fresh machine to a running, LAN-filtering DNS server in one step.
# Run as root from a git clone of the purge-warden repo.
#
# Quick start:
#   sudo ./scripts/install.sh                      # auto-detect everything
#   sudo ./scripts/install.sh --yes                # no prompts
#   sudo ./scripts/install.sh --build-from-source  # build here instead of --binary
#   sudo ./scripts/install.sh --dry-run            # preview without changes
#   sudo ./scripts/install.sh --upgrade            # update an existing install

set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
UNIT_SRC="$REPO_ROOT/systemd/purge-warden.service"
UNIT_DEST="/etc/systemd/system/purge-warden.service"
# Sprint 4 — auto-backup oneshot + timer (v0.20.0-auto-backup-cli).
BACKUP_UNIT_SRC="$REPO_ROOT/systemd/purge-warden-backup.service"
BACKUP_UNIT_DEST="/etc/systemd/system/purge-warden-backup.service"
BACKUP_TIMER_SRC="$REPO_ROOT/systemd/purge-warden-backup.timer"
BACKUP_TIMER_DEST="/etc/systemd/system/purge-warden-backup.timer"
# The operator types `warden`; the daemon execs a different file. That split
# is the whole point of §4.40-exec:
#
#   WRAPPER_DEST  /usr/local/bin/warden — on PATH, an executable POSIX sh
#                 script that routes the caller to the daemon user.
#   BINARY_DEST   the real ELF, deliberately NOT on PATH so nothing reaches it
#                 by accident. /usr/local/libexec is the FHS home for programs
#                 that are executed by other programs rather than by users.
#
# Everything that must run the REAL binary — `warden init`, `token generate`,
# `--version`, both systemd units — names BINARY_DEST. Routing the installer
# or the daemon through the wrapper would make them re-enter the routing
# logic they exist to set up.
LIBEXEC_DIR="/usr/local/libexec/purge-warden"
BINARY_DEST="$LIBEXEC_DIR/warden"
WRAPPER_DEST="/usr/local/bin/warden"
# The shell FUNCTION this wrapper replaces. Removed on fresh install and on
# upgrade: left behind it is sourced into every login shell and shadows the
# executable, so the operator keeps running the old routing while believing
# they run the new one.
LEGACY_PROFILED_WRAPPER="/etc/profile.d/purge-warden-wrapper.sh"
CONFIG_PATH="/var/lib/purge-warden/config.toml"
RESOLVED_DROPIN="/etc/systemd/resolved.conf.d/purge-warden-no-stub.conf"
# systemd-resolved publishes two resolv.conf files. `stub-resolv.conf`
# names only the 127.0.0.53 stub; `resolv.conf` names the real uplink
# servers. Silencing the stub makes the first one a dead end — see
# repoint_resolv_conf_off_stub.
RESOLVED_STUB_RESOLV="/run/systemd/resolve/stub-resolv.conf"
RESOLVED_UPLINK_RESOLV="/run/systemd/resolve/resolv.conf"
# Overridable so repoint_resolv_conf_off_stub can be exercised against a
# scratch tree instead of the live host's resolver. A function that can
# only be tested by breaking the machine it runs on does not get tested.
SYSTEM_RESOLV_CONF="${SYSTEM_RESOLV_CONF:-/etc/resolv.conf}"

# Set by preflight, read by every phase that touches packages or the
# host's security surface. Declared here so a phase invoked out of order
# fails on an empty value rather than on an unbound variable under set -u.
DISTRO_FAMILY=""
PKG_MGR=""

# Recorded by preflight, read by Phase 7.5, and it MUST be sampled before
# Phase 4 creates the libexec binary. It is the only thing that tells a
# MIGRATION from a CLOBBER:
#
#   migration  this host predates the wrapper split, so /usr/local/bin holds
#              the old binary because that is where it always lived. Nobody
#              copied anything. True of every host that exists today.
#   clobber    libexec was already populated, so the ELF at the wrapper path
#              got there by someone streaming a binary over the wrapper.
#
# After install_binary the two look identical, and treating them the same
# means accusing the operator of a mistake they did not make on 100% of
# upgrades — advice that cannot fix the box it is given for, which is the
# exact defect the half-install branch of this file exists to remove.
LIBEXEC_BINARY_PREEXISTED=""

DEFAULT_LISTEN="0.0.0.0:53"
DEFAULT_LISTS="security/malicious,privacy/ads,privacy/tracking"
# Phase 8 bound for the first blocklist download + ingest (the default
# trio is ~hundreds of MB). Override for slow links:
#   BLOCK_VERIFY_TIMEOUT_SECS=1200 ./scripts/install.sh …
BLOCK_VERIFY_TIMEOUT_SECS="${BLOCK_VERIFY_TIMEOUT_SECS:-600}"

# ── Terminal detection (runs at script load, before any redirect) ─────
# IS_TTY gates progress animations that use \r to overwrite the same line —
# those only work on a real terminal. The color table is NO_COLOR-aware and
# independent (you can have a color-capable terminal with NO_COLOR=1 set).
if [[ -t 1 ]]; then
	IS_TTY=true
else
	IS_TTY=false
fi

if [[ $IS_TTY == "true" && -z "${NO_COLOR:-}" ]]; then
	C_R=$'\033[0m'
	C_B=$'\033[1;34m'
	C_G=$'\033[1;32m'
	C_Y=$'\033[1;33m'
	C_E=$'\033[1;31m'
	C_D=$'\033[2m'
else
	C_R='' C_B='' C_G='' C_Y='' C_E='' C_D=''
fi

log() { printf '%s▸%s %s\n' "$C_B" "$C_R" "$*"; }
ok() { printf '%s✓%s %s\n' "$C_G" "$C_R" "$*"; }
warn() { printf '%s⚠%s %s\n' "$C_Y" "$C_R" "$*" >&2; }
err() { printf '%s✗%s %s\n' "$C_E" "$C_R" "$*" >&2; }
step() { printf '\n%s── %s ──%s\n' "$C_B" "$*" "$C_R"; }
die() {
	err "$*"
	exit 1
}

# Guard the space-separated form of a value-taking flag.
#
# `FOO="$2"` with nothing in $2 dies under `set -u` with bash's own
# "$2: unbound variable" — which names a positional parameter, not the
# flag, and is not an installer message at all. Measured 2026-08-16 on
# the lab host: `install.sh --upgrade --binary` reached a real upgrade
# with the path missing, sudo's session opened and closed in the same
# second, and the operator had nothing on screen to act on. They
# reasonably concluded the install had run.
#
# The `*)` arm in main() already refuses an UNKNOWN flag in our own
# voice. This is the same refusal for a KNOWN flag with a missing value —
# the arm that was missing.
#
# Also rejects a value that is itself a `--flag`. Checked against
# print_help rather than assumed: --lan-cidr takes a CIDR, --listen an
# addr:port, --lists a name CSV, --binary a path, and --upstream is
# documented there as addr:port CSV and explicitly NOT a URL (DoH/DoT are
# configured post-install via [upstream].mode). None can begin with `--`,
# so a `--`-leading value is always a dropped argument, never a real one.
#
# Call as `require_value "$1" "$@"` from inside the case arm.
require_value() {
	local flag=$1
	shift
	if [[ $# -lt 2 ]]; then
		err "$flag requires a value"
		printf '\n  Either: %s%s <value>%s\n  or:     %s%s=<value>%s\n\n  Run: %s --help\n\n' \
			"$C_B" "$flag" "$C_R" "$C_B" "$flag" "$C_R" "$0"
		exit 2
	fi
	if [[ $2 == --* ]]; then
		err "$flag requires a value, but the next argument is another flag: $2"
		printf '\n  Its value was dropped. Use %s%s=<value>%s to keep flag and\n  value in one argument.\n\n  Run: %s --help\n\n' \
			"$C_B" "$flag" "$C_R" "$0"
		exit 2
	fi
}

# ── Runtime flags ─────────────────────────────────────────────────────
LAN_CIDR=""
LISTEN="$DEFAULT_LISTEN"
# neutrality-09: no default. Empty means "let warden detect it" — the
# binary reads this machine's own resolver, which its network chose and
# we did not. --upstream still overrides.
UPSTREAM=""
LISTS="$DEFAULT_LISTS"
MODE=""
BINARY_PATH=""
UPGRADE="false"
DRY_RUN="false"
YES="false"

LOG_FILE=""
LOG_TEE_PID=""

# ── Traps ─────────────────────────────────────────────────────────────
# ERR: surface the failing line + what command ran.
# INT/QUIT/TERM: clean Ctrl-C without a bash stack trace.
trap 'rc=$?; err "installer failed at line ${BASH_LINENO[0]} (exit $rc)"; printf "\n  Last command: %s\n" "${BASH_COMMAND}" >&2; [[ -n $LOG_FILE ]] && printf "  Full log: %s\n" "$LOG_FILE" >&2; printf "  If reproducible, run with --dry-run first and share:\n    journalctl -u purge-warden -n 50 --no-pager\n\n" >&2; exit $rc' ERR
trap 'err "interrupted by user (signal)"; exit 130' INT QUIT TERM

# ── Helpers ───────────────────────────────────────────────────────────

print_help() {
	cat <<EOF
Usage: sudo $0 [OPTIONS]

Install purge-warden on Debian 12+ / Ubuntu 22.04+ / Fedora 40+ / RHEL 9+.
Must be run as root from a git clone of the purge-warden repo.

OPTIONS:
  --lan-cidr <cidr[,cidr...]>
                          Subnet(s) allowed to query this resolver.
                          Example: --lan-cidr 10.10.1.0/24
                          Dual-homed (LAN + VPN), comma-separated:
                            --lan-cidr 10.10.1.0/24,100.64.0.0/10
                          Auto-detected from the default route if omitted.

  --listen <addr:port>    Address purge-warden binds to.
                          Default: $DEFAULT_LISTEN

  --upstream <csv>        Comma-separated upstream resolvers, as plain-DNS
                          addr:port — e.g. 192.0.2.53:53,192.0.2.54:53
                          NOT a URL: DoH/DoT are configured after the
                          install via [upstream].mode + .servers.
                          Default: detected from this machine — warden
                          reads the resolver your network already uses
                          and never picks a provider for you.

  --lists <csv>           Comma-separated blocklist names to subscribe to.
                          Default: $DEFAULT_LISTS

  --build-from-source     Install build toolchain + rustup and run
                          'cargo build --release' on this machine.
                          Requires ~2 GB disk and internet.

  --binary <path>         Use a pre-built binary from this path.
                          If neither flag is given, ./target/release/warden
                          is auto-detected when running from a repo clone.

  --upgrade               Update an existing install: stop, replace binary
                          and unit file, re-apply config patches, restart.
                          Leaves your edits to config.toml alone.

  --dry-run               Show all actions without making changes.

  --yes, -y               Non-interactive; accept prompts with default answer.

  --help, -h              Show this help and exit.

EXAMPLES:
  # Simplest: auto-detect LAN + use pre-built binary at target/release/warden
  sudo $0 --yes

  # Build from source on the target, explicit LAN CIDR
  sudo $0 --build-from-source --lan-cidr 192.168.1.0/24 --yes

  # Upgrade an existing install (after git pull + cargo build --release)
  sudo $0 --upgrade

  # Preview without touching anything
  sudo $0 --dry-run
EOF
}

confirm() {
	local prompt="$1" ans
	printf '%s [y/N] ' "$prompt"
	read -r ans </dev/tty || return 1
	[[ $ans =~ ^[Yy] ]]
}

run() {
	if [[ $DRY_RUN == "true" ]]; then
		printf '  %s[dry]%s %s\n' "$C_Y" "$C_R" "$*"
	else
		"$@"
	fi
}

detect_distro() {
	[[ -f /etc/os-release ]] || {
		echo unknown
		return
	}
	# shellcheck disable=SC1091
	. /etc/os-release
	echo "${ID:-unknown}"
}

detect_distro_version() {
	[[ -f /etc/os-release ]] || {
		echo 0
		return
	}
	# shellcheck disable=SC1091
	. /etc/os-release
	echo "${VERSION_ID:-0}"
}

# Which package-manager dialect this host speaks. Everything downstream
# branches on the FAMILY, never on the distro id, so adding a derivative
# (Linux Mint, AlmaLinux, …) is one entry in the case below rather than a
# new branch in every phase.
#
# ID_LIKE is consulted second: derivatives set ID to their own name and
# ID_LIKE to the parent, so `ubuntu` is matched by name while a downstream
# respin nobody enumerated still lands in the right family.
detect_distro_family() {
	local id like
	[[ -f /etc/os-release ]] || {
		echo unknown
		return
	}
	# shellcheck disable=SC1091
	. /etc/os-release
	id="${ID:-unknown}"
	like="${ID_LIKE:-}"
	case "$id" in
		debian | ubuntu | raspbian | linuxmint | pop)
			echo debian
			return
			;;
		fedora | rhel | centos | rocky | almalinux)
			echo rhel
			return
			;;
	esac
	case " $like " in
		*" debian "* | *" ubuntu "*)
			echo debian
			return
			;;
		*" rhel "* | *" fedora "* | *" centos "*)
			echo rhel
			return
			;;
	esac
	echo unknown
}

detect_lan_iface() {
	ip -4 route show default 2>/dev/null | awk '{print $5; exit}'
}

detect_lan_cidr() {
	# The "proto kernel scope link" route is the network CIDR for
	# the interface carrying the default route — no bitwise math needed.
	local iface
	iface=$(detect_lan_iface) || return 1
	[[ -n $iface ]] || return 1
	ip -4 route show dev "$iface" 2>/dev/null |
		awk '/proto kernel.*scope link/ {print $1; exit}'
}

detect_lan_ip() {
	local iface
	iface=$(detect_lan_iface) || return 1
	[[ -n $iface ]] || return 1
	ip -4 addr show dev "$iface" 2>/dev/null |
		awk '/inet /{print $2; exit}' |
		cut -d/ -f1
}

port_53_holder() {
	# Returns the ss line for whatever is listening on :53, or empty.
	ss -tulnp 2>/dev/null | awk '$5 ~ /:53$/ {print; exit}'
}

# The needle must tolerate the INTERFACE SCOPE. `ss` renders a loopback
# listener as `127.0.0.53%lo:53`, not `127.0.0.53:53` — measured on
# the lab host (Fedora 44, systemd 259, iproute2 6.17.0), where the
# literal form matched zero lines while resolved was demonstrably active and
# holding the port. The installer then fell through to the generic
# "port 53 is already in use" refusal and told the operator to stop
# dnsmasq/bind9/pihole, none of which was the holder. A hard install blocker
# on stock Fedora, which is a supported target.
#
# It had never fired, and the comment below already predicted why: the
# Debian CT has no systemd-resolved at all. the lab host looked like a
# working precedent and was not — its stub was disabled by a HAND-written
# /etc/systemd/resolved.conf.d/99-no-stub.conf, so this function returned
# false for the right reason and the broken branch stayed unvisited.
#
# 127.0.0.54 is matched too: `DNSStubListener=` governs the proxy stub on
# .54 as well as the stub on .53, so either address being bound means the
# same setting is the thing holding port 53.
resolved_stub_active() {
	systemctl is-active --quiet systemd-resolved.service 2>/dev/null || return 1
	ss -tulnp 2>/dev/null | grep -qE '127\.0\.0\.5[34](%[^:[:space:]]+)?:53'
}

# Silencing the stub listener frees port 53, but it also kills the only
# nameserver `/etc/resolv.conf` knows about when that file is the symlink
# systemd-resolved installs by default:
#
#     /etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf
#     nameserver 127.0.0.53          <- nothing listens here any more
#
# Whether that breaks the host depends entirely on nsswitch, which is why
# it has stayed invisible:
#
#     Fedora 44        hosts: files myhostname resolve [!UNAVAIL=return] dns
#                      `resolve` = nss-resolve, which reaches resolved over
#                      D-Bus and never reads resolv.conf. Nothing breaks.
#     Debian / Ubuntu  hosts: files dns
#                      glibc reads resolv.conf and queries a dead address.
#                      DNS is gone for the whole host.
#
# Measured 2026-08-08: `ubuntu:24.04` ships `files dns`, and Ubuntu runs
# systemd-resolved by default — so on a target this installer claims to
# support, Phase 1 could leave the machine with no resolver and Phase 2's
# `apt-get update` would be the first thing to trip over it. (The Debian CT
# in the lab never hit this: it has no systemd-resolved at all, so
# `resolved_stub_active` returns false and this path never runs. Latent on
# Debian, live on Ubuntu.)
#
# The repoint is deliberately narrow. It fires only when resolv.conf is a
# symlink to the stub file — a hand-authored `/etc/resolv.conf` is the
# operator's, and we do not touch it — and only when the uplink file
# actually names a server, because swapping one empty resolver for another
# is the same dead end by a different path.
repoint_resolv_conf_off_stub() {
	local target
	target=$(readlink -f "$SYSTEM_RESOLV_CONF" 2>/dev/null || true)
	# Not the stub symlink → operator-managed, or already pointed elsewhere.
	[[ $target == "$RESOLVED_STUB_RESOLV" ]] || return 0

	if ! grep -qE '^[[:space:]]*nameserver[[:space:]]+[^[:space:]]' \
		"$RESOLVED_UPLINK_RESOLV" 2>/dev/null; then
		warn "$SYSTEM_RESOLV_CONF points at the stub we just silenced, and"
		warn "$RESOLVED_UPLINK_RESOLV names no server — leaving it alone."
		warn "This host may have no DNS until purge-warden is listening."
		return 0
	fi

	if [[ $DRY_RUN == "true" ]]; then
		printf '  %s[dry]%s relink %s → %s\n' \
			"$C_Y" "$C_R" "$SYSTEM_RESOLV_CONF" "$RESOLVED_UPLINK_RESOLV"
		return 0
	fi
	ln -sf "$RESOLVED_UPLINK_RESOLV" "$SYSTEM_RESOLV_CONF"
	ok "repointed $SYSTEM_RESOLV_CONF at the uplink servers (was the silenced stub)"
}

disable_resolved_stub() {
	if [[ $DRY_RUN == "true" ]]; then
		printf '  %s[dry]%s write %s (DNSStubListener=no)\n' "$C_Y" "$C_R" "$RESOLVED_DROPIN"
		printf '  %s[dry]%s systemctl restart systemd-resolved\n' "$C_Y" "$C_R"
		repoint_resolv_conf_off_stub
		return
	fi
	install -m 0755 -d "$(dirname "$RESOLVED_DROPIN")"
	cat >"$RESOLVED_DROPIN" <<-EOF
		# Installed by purge-warden install.sh
		# Disables the 127.0.0.53:53 stub listener so purge-warden can bind port 53.
		[Resolve]
		DNSStubListener=no
	EOF
	systemctl restart systemd-resolved.service
	# Order matters: resolved must have reloaded before we trust the uplink
	# file, and the symlink must be correct before Phase 2 resolves anything.
	repoint_resolv_conf_off_stub
}

# On an SELinux host a file's security context is derived from policy for
# its PATH, and `install` copying out of a build tree does not apply it —
# the copy inherits the context of wherever it came from. systemd refuses
# to execute a unit file whose context it does not recognise, so a unit
# dropped in with the wrong label fails to start with a message that says
# nothing about SELinux.
#
# restorecon just asks the policy what the label should be and sets it. It
# is a no-op on a host where SELinux is disabled, so there is no need to
# check enforcement state — only that the tool exists (policycoreutils is
# not guaranteed on a minimal image).
restore_selinux_context() {
	[[ $DISTRO_FAMILY == "rhel" ]] || return 0
	command -v restorecon >/dev/null 2>&1 || return 0
	local p
	for p in "$@"; do
		[[ -e $p ]] || continue
		run restorecon -F "$p"
	done
}

# Debian ships no firewall enabled by default; Fedora and RHEL ship
# firewalld active, and its default zone does NOT permit DNS. Without this
# the daemon comes up healthy, answers itself, and is unreachable from the
# LAN it was installed to serve — a failure that looks like a warden bug
# and is not.
#
# --add-service=dns covers 53/tcp and 53/udp together, so it stays correct
# if the listen port ever gains a transport.
open_dns_in_firewall() {
	[[ $DISTRO_FAMILY == "rhel" ]] || return 0
	command -v firewall-cmd >/dev/null 2>&1 || return 0
	systemctl is-active --quiet firewalld 2>/dev/null || {
		log "firewalld installed but not running — nothing to open"
		return 0
	}
	if firewall-cmd --quiet --query-service=dns 2>/dev/null; then
		ok "firewalld already permits DNS"
		return 0
	fi
	run firewall-cmd --permanent --add-service=dns
	run firewall-cmd --reload
	ok "firewalld: opened 53/tcp + 53/udp in the default zone"
}

validate_cidr() {
	# Loose check: octets.octets.octets.octets/prefix, not a full validator.
	[[ $1 =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]
}

# A comma-separated list of them, for --lan-cidr.
#
# Kept SEPARATE from validate_cidr rather than teaching that function to
# accept lists: its name promises one CIDR, and a predicate that quietly
# starts accepting more is how a validator stops validating.
#
# The list form exists because a dual-homed host is the normal case, not the
# exotic one — the lab host answers on 10.10.1.5/24 (LAN) and
# 192.0.2.3/32 (tailnet), and with only the LAN range every query arriving
# over the VPN is REFUSED. `warden init --allow-from` has always taken a
# comma-separated list; it was only this flag that could not express one.
#
# An empty element fails rather than being skipped: "10.0.0.0/8," is a typo,
# and accepting it would install a narrower policy than the operator wrote
# while reporting success.
#
# Split by hand, NOT with `local IFS=,` + `for part in $1`. That was the
# first version and it passed the trailing-comma case: word splitting drops
# trailing empty fields, so "10.0.0.0/8," is one valid element and the
# paragraph above was describing behaviour the code did not have. The gate
# arm caught it, which is the whole argument for writing the arm before
# trusting the comment.
validate_cidr_list() {
	local list="$1" part
	[[ -n $list ]] || return 1
	while [[ $list == *,* ]]; do
		part="${list%%,*}"
		list="${list#*,}"
		validate_cidr "$part" || return 1
	done
	validate_cidr "$list"
}

# Returns free space in MB on the filesystem holding $1, or 0 if the path
# doesn't exist (in which case we fall back to the parent directory).
avail_mb() {
	local path="$1"
	while [[ -n $path && ! -e $path ]]; do
		path=$(dirname "$path")
	done
	df -BM --output=avail "$path" 2>/dev/null | awk 'NR==2 {gsub("M",""); print $1}'
}

check_disk_space() {
	# Minimums are conservative: a release binary is ~10 MB, the initial
	# on-disk list cache settles around 200 MB for the three default lists,
	# and cargo's target/ for a clean release build hits ~1.8 GB.
	local need_install_mb=50 need_state_mb=300 need_build_mb=2000
	local avail

	avail=$(avail_mb "$BINARY_DEST")
	[[ -z $avail ]] && avail=0
	if ((avail < need_install_mb)); then
		die "need ${need_install_mb}M free for $BINARY_DEST, have ${avail}M"
	fi

	avail=$(avail_mb /var/lib/purge-warden)
	[[ -z $avail ]] && avail=0
	if ((avail < need_state_mb)); then
		warn "only ${avail}M free in /var/lib — recommend ${need_state_mb}M+ for list cache"
	fi

	if [[ $MODE == "build" ]]; then
		avail=$(avail_mb "$REPO_ROOT/target")
		[[ -z $avail ]] && avail=0
		if ((avail < need_build_mb)); then
			die "need ${need_build_mb}M free in $REPO_ROOT for cargo build, have ${avail}M"
		fi
	fi

	ok "disk space sufficient"
}

# ── Phase 1: Preflight ────────────────────────────────────────────────

preflight() {
	step "Phase 1: Preflight"

	if [[ $EUID -eq 0 ]]; then
		ok "running as root (uid 0)"
	else
		# Only reachable in --dry-run (non-dry runs are escalated in main).
		warn "running as uid $EUID — a real install would need root"
	fi

	# systemd is required — we install a .service unit and use systemctl.
	if ! command -v systemctl >/dev/null 2>&1; then
		err "systemctl not found"
		printf '\n  purge-warden is shipped as a systemd unit. Your system appears to use\n'
		printf '  a different init (OpenRC, runit, sysvinit, s6…).\n'
		printf '  Supported: systemd (default on Debian 12+, Ubuntu 16+, modern RHEL/Fedora).\n\n'
		exit 1
	fi
	ok "systemd detected"

	local distro ver
	distro=$(detect_distro)
	ver=$(detect_distro_version)
	DISTRO_FAMILY=$(detect_distro_family)
	case "$DISTRO_FAMILY" in
		debian)
			PKG_MGR="apt-get"
			ok "distro: $distro $ver (debian family)"
			;;
		rhel)
			PKG_MGR="dnf"
			command -v dnf >/dev/null 2>&1 || die "dnf not found on a $distro host"
			ok "distro: $distro $ver (rhel family)"
			;;
		*)
			err "unsupported distro: $distro $ver"
			printf '\n  Supported: Debian 12+, Ubuntu 22.04+, Raspberry Pi OS,\n'
			printf '             Fedora 40+, RHEL 9+ and rebuilds (Rocky, Alma)\n'
			printf '  For anything else (Arch, NixOS, …), install manually — see BUILDING.md.\n\n'
			exit 1
			;;
	esac

	# Network reachability — catches air-gapped hosts and broken DNS before
	# the package manager wastes 30 seconds on a doomed download. getent uses
	# the system resolver (pre-installed everywhere) so we don't depend on
	# curl/dig yet. The host is the one whose packages we are about to fetch:
	# probing a Debian mirror on Fedora would test a name this install never
	# resolves again, and pass or fail for the wrong reason.
	local connectivity_host
	if [[ $DISTRO_FAMILY == "rhel" ]]; then
		connectivity_host="mirrors.fedoraproject.org"
	else
		connectivity_host="deb.debian.org"
	fi
	if ! timeout 5 getent hosts "$connectivity_host" >/dev/null 2>&1; then
		err "cannot resolve $connectivity_host"
		printf '\n  The installer needs internet to fetch %s packages and blocklist catalogs.\n' "$PKG_MGR"
		printf '  Check your network: %sip -4 route show%s, %sip -4 addr show%s\n' "$C_D" "$C_R" "$C_D" "$C_R"
		printf '  Check DNS:          %scat /etc/resolv.conf%s\n\n' "$C_D" "$C_R"
		exit 1
	fi
	ok "DNS and network reachable ($connectivity_host)"

	# Detect + resolve port 53 conflict
	if [[ $UPGRADE != "true" ]]; then
		local p53
		p53=$(port_53_holder)
		if [[ -n $p53 ]]; then
			if resolved_stub_active; then
				warn "systemd-resolved is holding 127.0.0.53:53 (stub listener)"
				if [[ $YES == "true" ]] || confirm "Disable the stub listener so purge-warden can bind port 53?"; then
					disable_resolved_stub
					ok "disabled systemd-resolved stub listener"
				else
					die "cannot proceed while another service holds port 53"
				fi
			else
				err "port 53 is already in use:"
				printf '\n  %s\n\n' "$p53"
				printf '  Stop the other service before running this installer.\n'
				printf '  Common offenders: dnsmasq, bind9, named, pihole, unbound.\n'
				# systemd-resolved belongs on this list even though the branch
				# above is supposed to catch it: it is the DEFAULT holder on
				# Fedora, RHEL and Ubuntu, and the one time this message was
				# actually read by an operator, resolved was the holder and the
				# detector had missed it. A message that omits the most likely
				# culprit sends the reader hunting for daemons that are not
				# installed.
				if systemctl is-active --quiet systemd-resolved.service 2>/dev/null; then
					printf '  systemd-resolved is ACTIVE here and is the likely holder —\n'
					printf '  check with: %sss -tulnp | grep :53%s\n' "$C_D" "$C_R"
				fi
				printf '\n'
				exit 1
			fi
		else
			ok "port 53 is free"
		fi
	fi

	# Resolve LAN CIDR
	if [[ -z $LAN_CIDR ]]; then
		local detected
		detected=$(detect_lan_cidr || true)
		if [[ -n $detected ]]; then
			LAN_CIDR="$detected"
			ok "LAN CIDR auto-detected from default route: $LAN_CIDR"
		else
			err "could not auto-detect LAN CIDR"
			printf '\n  Pass --lan-cidr <cidr>, e.g. --lan-cidr 10.0.0.0/24\n'
			printf '  You can find your LAN with: ip -4 route show\n\n'
			exit 1
		fi
	fi
	# `warden init --upstream` takes plain-DNS addr:port and nothing else; DoH
	# and DoT are configured afterwards, by setting [upstream].mode and
	# rewriting [upstream].servers. An operator mirroring a working config
	# from another box copies THAT form — the URLs — and the installer used to
	# forward them verbatim, install the binary, and only then die inside
	# Phase 5 with the binary already replaced.
	#
	# Refused here, before anything is written, for the same reason the config
	# resolution moved: fail before you mutate, not after.
	#
	# The needle is `://` rather than a full addr:port validator. The binary
	# already does the real validation and does it better; the job here is to
	# catch the ONE mistake that is both common and silent until Phase 5,
	# without inventing a second parser that would reject valid IPv6 forms
	# like [2001:db8::1]:53.
	if [[ $UPSTREAM == *"://"* ]]; then
		err "--upstream takes plain DNS addr:port, not a URL"
		printf '\n  Got:      %s\n' "$UPSTREAM"
		printf '  Expected: %s192.0.2.53:53,192.0.2.54:53%s (addr:port)\n\n' "$C_B" "$C_R"
		printf '  DoH and DoT are configured AFTER the install, by setting\n'
		printf '  %s[upstream].mode%s and rewriting %s[upstream].servers%s in the config.\n' \
			"$C_D" "$C_R" "$C_D" "$C_R"
		printf '  `warden init` only ever writes plain-DNS upstreams.\n\n'
		exit 1
	fi

	validate_cidr_list "$LAN_CIDR" ||
		die "invalid CIDR: $LAN_CIDR (expected a.b.c.d/prefix, or several comma-separated)"

	# Resolve binary source
	if [[ -z $MODE ]]; then
		local default_bin="$REPO_ROOT/target/release/warden"
		if [[ -x $default_bin ]]; then
			MODE="binary"
			BINARY_PATH="$default_bin"
			ok "found pre-built binary: $BINARY_PATH"
		else
			err "no binary available"
			printf '\n  Either pass --build-from-source to build here,\n'
			printf '  or build first with: %scd %s && cargo build --release%s\n\n' "$C_D" "$REPO_ROOT" "$C_R"
			exit 1
		fi
	elif [[ $MODE == "binary" ]]; then
		[[ -x $BINARY_PATH ]] || die "binary not found or not executable: $BINARY_PATH"
		ok "binary: $BINARY_PATH"
	elif [[ $MODE == "build" ]]; then
		ok "will build from source"
	fi

	[[ -f $UNIT_SRC ]] || die "systemd unit not found at $UNIT_SRC. Run from a purge-warden git checkout."
	ok "unit file template: $UNIT_SRC"

	check_disk_space

	# Sampled here because preflight is the last phase that runs before
	# install_binary populates $LIBEXEC_DIR. See the declaration for what
	# depends on it.
	if [[ -f $BINARY_DEST ]]; then
		LIBEXEC_BINARY_PREEXISTED=true
	else
		LIBEXEC_BINARY_PREEXISTED=false
	fi

	check_existing_install
}

# Is there an install here, and is it a WHOLE one? Echoes none | half | full.
#
# `-x $BINARY_DEST || -x $WRAPPER_DEST` because the binary has lived at both:
# pre-§4.40-exec hosts hold the raw ELF at $WRAPPER_DEST, and a detector that
# only looks in libexec calls such a box empty and walks into it silently.
#
# HALF is the binary and nothing else — no unit, no config at either path, no
# daemon user. That is precisely what an installer that died after Phase 4
# leaves behind, and it is the ONE combination where a fresh install is the
# repair. Every other combination is a real install and keeps the refusal:
# each of the three other terms is state a fresh run would overwrite.
classify_existing_install() {
	local binary=false unit=false config=false user=false

	[[ -x $BINARY_DEST || -x $WRAPPER_DEST ]] && binary=true
	[[ -f $UNIT_DEST ]] && unit=true
	# Through resolve_installed_config, never a second candidate loop: two
	# copies of the precedence drift, and install.sh carried exactly that bug
	# until it was found announcing /var/lib while /etc had been linted.
	resolve_installed_config >/dev/null && config=true
	# A CONDITION, not `x=$(getent …)`. getent exits 2 on a missing key, and
	# under `set -euo pipefail` an assignment carrying that status kills the
	# script — the bug that made every --dry-run die at Phase 5.4.
	getent passwd purge-warden >/dev/null 2>&1 && user=true

	if [[ $unit == "true" || $config == "true" || $user == "true" ]]; then
		printf 'full'
	elif [[ $binary == "true" ]]; then
		printf 'half'
	else
		printf 'none'
	fi
}

# Decide whether this run may proceed. Split out of preflight so it can be
# exercised: preflight also detects the distro, resolves a binary source and
# measures disk, none of which a gate can stand up.
check_existing_install() {
	local state
	state=$(classify_existing_install)

	if [[ $UPGRADE == "true" ]]; then
		if [[ $state == "none" ]]; then
			die "--upgrade requested but no existing install found (no $BINARY_DEST and no $UNIT_DEST)"
		fi
		ok "upgrade mode: existing install detected"
		return 0
	fi

	case $state in
	none)
		return 0
		;;
	half)
		# NOT an error. Measured on the lab host 2026-08-14: a run that
		# died after Phase 4 left only the binary, and the next run refused
		# with "an existing install was detected" and sent the operator to
		# --upgrade — which replaces a binary and never creates the config
		# that was missing. The advice could not fix the box it was given
		# for. Say what is actually here and repair it.
		warn "half-installed box: the binary is present, but nothing else is"
		printf '\n  Binary:  %s\n' "$(installed_binary_path)"
		printf '  Unit:    (missing)\n'
		printf '  Config:  (missing at both /etc and %s)\n' "$CONFIG_PATH"
		printf '  User:    (missing)\n'
		printf '\n  A previous install almost certainly died partway through.\n'
		printf '  Continuing as a FRESH install — that is what repairs this state.\n'
		printf '  (%s--upgrade%s would not: it replaces the binary and creates no config.)\n\n' \
			"$C_B" "$C_R"
		return 0
		;;
	esac

	err "an existing purge-warden install was detected"
	printf '\n  Binary:  %s\n' "$(installed_binary_path)"
	printf '  Unit:    %s\n' "$([[ -f $UNIT_DEST ]] && echo "$UNIT_DEST" || echo "(missing)")"
	printf '  Config:  %s\n' "$(resolve_installed_config || echo "(missing)")"
	printf '\n  To update it, re-run with --upgrade:\n'
	printf '    %ssudo %s --upgrade%s\n\n' "$C_B" "$0" "$C_R"
	printf '  To start fresh, run %s%s/scripts/uninstall.sh%s first.\n\n' "$C_B" "$REPO_ROOT" "$C_R"
	exit 1
}

# Where the binary actually is — the two paths it has lived at, in the order
# a current install uses them.
installed_binary_path() {
	if [[ -x $BINARY_DEST ]]; then
		printf '%s' "$BINARY_DEST"
	elif is_elf_binary "$WRAPPER_DEST"; then
		printf '%s (raw binary — the pre-libexec layout)' "$WRAPPER_DEST"
	elif [[ -x $WRAPPER_DEST ]]; then
		printf '%s (wrapper only — no binary in %s)' "$WRAPPER_DEST" "$LIBEXEC_DIR"
	else
		printf '(missing)'
	fi
}

# Terms the operator must see before anything is changed on the host.
# Printed unconditionally — including under --yes and on a headless run —
# so the acceptance is always in the install log. The interactive gate
# that follows in main() is what turns it from a notice into consent.
show_disclaimer() {
	step "Before you continue"
	cat <<EOF
  purge-warden is free and open-source software, released under the GNU
  Affero General Public License, version 3 or later.

  It is provided "as is", WITHOUT WARRANTY OF ANY KIND, either express or
  implied. Sections 15 and 16 of that licence set out the full disclaimer
  of warranty and limitation of liability, and they apply to this
  installation.

  purge-warden becomes the DNS resolver for every device you point at it.
  You alone are responsible for how you configure it: which blocklists you
  load, which upstream resolvers you trust, and which clients you permit.
  A mistake in that configuration can block legitimate traffic, or leave
  your network unable to resolve names at all.

  The authors and contributors accept no liability for any loss, damage,
  or disruption arising from the use or misuse of this software. If you do
  not accept these terms, do not install it.
EOF
	printf '\n'
}

show_plan() {
	local distro ver
	distro=$(detect_distro)
	ver=$(detect_distro_version)

	step "Install plan"
	printf '  Host:        %s %s (%s)\n' "$distro" "$ver" "$(uname -m)"
	printf '  Mode:        %s\n' "$([[ $UPGRADE == "true" ]] && echo upgrade || echo fresh-install)"
	printf '  Binary src:  %s\n' "$([[ $MODE == "build" ]] && echo "build here via cargo --release" || echo "$BINARY_PATH")"
	printf '  Binary dst:  %s\n' "$BINARY_DEST"
	printf '  Unit file:   %s → %s\n' "$UNIT_SRC" "$UNIT_DEST"
	# Resolve, do not assume. This line used to print $CONFIG_PATH
	# unconditionally, on the argument that show_plan runs BEFORE
	# migrate_existing_install and a resolution here could disagree with the
	# later one.
	#
	# Measured in an /etc-master container 2026-08-14, that argument was
	# backwards: the plan announced /var/lib while Phase 3.5 in the SAME run
	# linted /etc. The disagreement it was meant to avoid was already
	# happening, in the common upgrade case, and it is the very defect the
	# rest of this work removes — telling the operator about a file the
	# installer did not look at.
	#
	# Resolving here is right for the /etc-master upgrade and falls back to
	# $CONFIG_PATH when no config exists yet, which on a fresh install is
	# exactly where `warden init` will write one. The shield-era window —
	# after show_plan, before the migrate relocates the config — is the only
	# case left where the two can differ, and there NOTHING is at either
	# warden path yet, so no resolution could have been better informed.
	local plan_cfg
	plan_cfg=$(resolve_installed_config) || plan_cfg="$CONFIG_PATH"
	printf '  Config file: %s\n' "$plan_cfg"
	printf '  LAN CIDR:    %s (→ server.allow_from)\n' "$LAN_CIDR"
	printf '  Listen on:   %s\n' "$LISTEN"
	printf '  Upstream:    %s\n' "$UPSTREAM"
	printf '  Lists:       %s\n' "$LISTS"
	printf '  Run user:    purge-warden (system user, created by warden init)\n'
	printf '\n'
}

# ── Phase 2: System dependencies ──────────────────────────────────────

install_runtime_deps() {
	step "Phase 2: Install runtime dependencies"
	# No libssl on either family: the TLS stack is rustls + ring end-to-end
	# (DoH/DoT and the list fetcher), roots from embedded webpki-roots.
	# ca-certificates is for curl/rustup in the build path; dig comes from
	# dnsutils on Debian and bind-utils on RHEL — same binary, and the
	# verify phase is the only thing that needs it.
	if [[ $DISTRO_FAMILY == "rhel" ]]; then
		run dnf install -y ca-certificates bind-utils
	else
		export DEBIAN_FRONTEND=noninteractive
		run apt-get update
		run apt-get install -y ca-certificates dnsutils
	fi
	ok "runtime dependencies installed"
}

install_build_deps() {
	step "Phase 2b: Install build toolchain"
	# No libssl-dev on either family: nothing in the dependency tree links
	# system OpenSSL (reqwest is built with rustls-tls).
	#
	# RHEL has no build-essential, so its bundle is spelled out. Measured in
	# a clean fedora:44 container 2026-08-08: `gcc gcc-c++ make git curl
	# pkgconf-pkg-config` alone builds warden --release in 3m18s. cmake is
	# NOT required for x86_64 and an earlier version of this comment claiming
	# otherwise was wrong.
	#
	# cmake is installed anyway, as insurance rather than a dependency:
	# aws-lc-sys picks cc_builder when the target has pregenerated bindings
	# and falls back to its cmake builder otherwise — and that fallback ends
	# in `check_dependencies().unwrap()`, i.e. a panic mid-build, not a
	# readable error. x86_64-linux has the bindings; the aarch64-musl cross
	# target is not covered by that measurement. One package is a cheaper
	# hedge than a panic on a target nobody tested.
	#
	# perl is deliberately NOT listed. ring's build.rs only shells out to it
	# when `.git` is present, which is the crate-packaging path, never a
	# crates.io consumer — and Fedora pulls perl in as a dependency of other
	# base packages regardless, which is why its absence was never tested.
	if [[ $DISTRO_FAMILY == "rhel" ]]; then
		run dnf install -y gcc gcc-c++ make cmake git curl pkgconf-pkg-config
	else
		export DEBIAN_FRONTEND=noninteractive
		run apt-get install -y build-essential pkg-config git curl cmake
	fi
	if command -v cargo >/dev/null 2>&1; then
		ok "cargo already available ($(cargo --version))"
	elif [[ -x "$HOME/.cargo/bin/cargo" ]]; then
		export PATH="$HOME/.cargo/bin:$PATH"
		ok "cargo found at $HOME/.cargo/bin"
	else
		log "installing rustup (stable toolchain)"
		if [[ $DRY_RUN == "true" ]]; then
			printf '  %s[dry]%s curl sh.rustup.rs | sh -s -- -y --default-toolchain stable\n' "$C_Y" "$C_R"
		else
			curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
				sh -s -- -y --default-toolchain stable --profile default >&2
			export PATH="$HOME/.cargo/bin:$PATH"
		fi
		ok "rustup installed"
	fi
}

# ── Phase 3: Build (optional) ─────────────────────────────────────────

build_binary() {
	step "Phase 3: Build release binary"
	log "running cargo build --release (3-5 min on typical hardware)"
	if [[ $DRY_RUN == "true" ]]; then
		printf '  %s[dry]%s cd %s && cargo build --release\n' "$C_Y" "$C_R" "$REPO_ROOT"
		BINARY_PATH="$REPO_ROOT/target/release/warden"
		return
	fi
	(cd "$REPO_ROOT" && cargo build --release)
	BINARY_PATH="$REPO_ROOT/target/release/warden"
	[[ -x $BINARY_PATH ]] || die "build succeeded but binary missing at $BINARY_PATH"
	ok "built $BINARY_PATH ($(du -h "$BINARY_PATH" | awk '{print $1}'))"
}

# ── Phase 4: Install binary ───────────────────────────────────────────

install_binary() {
	step "Phase 4: Install binary to $BINARY_DEST"
	if systemctl is-active --quiet purge-warden.service 2>/dev/null; then
		log "stopping running purge-warden before replacing binary"
		run systemctl stop purge-warden.service
	fi
	# -D creates $LIBEXEC_DIR: unlike /usr/local/bin it does not exist on a
	# stock Debian or Fedora, so a plain `install` would fail on every fresh
	# machine. install(1) makes the parents 0755, which is what we want — the
	# binary is world-executable, only the config it reads is not.
	run install -D -m 0755 "$BINARY_PATH" "$BINARY_DEST"
	restore_selinux_context "$LIBEXEC_DIR" "$BINARY_DEST"
	if [[ $DRY_RUN != "true" ]]; then
		ok "installed: $("$BINARY_DEST" --version)"
	else
		ok "would install $BINARY_PATH → $BINARY_DEST"
	fi
}

# ── Phase 3.5: Validate any pre-existing config ───────────────────────

# rev-2606 install-03/install-05: the old flow sed-patched pre-existing
# configs (a v0 `lists =` shape the v2 loader hard-rejects, plus silent
# no-op anchors). Replaced by an honest gate: lint the existing config
# with the NEW binary BEFORE the running service is stopped, so a
# config the new daemon would refuse aborts the install while LAN DNS
# is still up. Fresh installs (no config) skip straight through —
# warden init writes a complete config in Phase 5.
# The candidate MUST come from resolve_installed_config, never from
# $CONFIG_PATH alone. The daemon prefers /etc/purge-warden/config.toml and
# only falls back to /var/lib, so a guard on $CONFIG_PATH returns early on
# every /etc-master host — this gate lints NOTHING there, while Phase 5
# then prints "keeping it (validated in Phase 3.5)" about a file it never
# opened. A gate that reports green on the file it did not read is worse
# than no gate: the operator stops the service on its word.
#
# Resolution happens BEFORE the --dry-run branch so the preview names the
# file that would actually be linted (same principle as ensure_daemon_home).
# NAME IS NARROWER THAN THE JOB, and deliberately kept — read this before
# grepping for a "migrate" phase and concluding there isn't one.
#
# Since plp-s3b (R7) this does lint AND, when the lint fails, migrate v2->v3
# and re-lint, via `upgrade_config_gate.sh`. Renaming it to match would touch
# seventeen references in `check_install_config_resolution.sh` — a fence over
# behaviour this change did not alter — so the rename is left for S4 and the
# truth is written here instead.
#
# It still runs BEFORE `install_binary`, which is what stops the service, so
# a refusal at any point leaves the running daemon and LAN DNS untouched.
#
# The migration writes `<config parent>/backups/pre-migration-*.toml` as
# root, creating `backups/` at root's umask if it is absent. That is safe
# only because Phase 6 (`prepare_backup_dir`) runs later and unconditionally
# re-asserts `purge-warden:purge-warden` + 0750 on that directory — its own
# comment says it exists to repair exactly this. The ORDER is what makes it
# safe, and it is pinned by arm H of `check_upgrade_config_gate.sh`.
lint_existing_config() {
	local cfg
	if ! cfg=$(resolve_installed_config); then
		# Neither path holds a config: fresh install. warden init writes a
		# complete one in Phase 5 — there is nothing to validate yet.
		return 0
	fi
	step "Phase 3.5: Validate existing config against the new binary"
	if [[ $DRY_RUN == "true" ]]; then
		"$SCRIPT_DIR/upgrade_config_gate.sh" --binary "$BINARY_PATH" --config "$cfg" --dry-run
		return
	fi
	# The gate lints, and MIGRATES v2 -> v3 if the lint fails, then re-lints.
	#
	# It used to lint only, and print a `warden migrate ...` line for the
	# operator to run. That form is one this repo has already paid for
	# ("the installer verified the product and printed a command nobody
	# ever ran"), and after the `SCHEMA_VERSION_V1` 2 -> 3 bump it stops
	# being merely useless: EVERY config on disk fails the lint, so every
	# upgrade would abort at Phase 3.5 with an instruction instead of an
	# install. R7, `_docs/features/profile_list_policy.md` §6.1.
	#
	# Position is load-bearing and unchanged: this runs before
	# `install_binary`, which is what stops the service. A refusal here
	# leaves the running daemon — and LAN DNS — completely untouched.
	#
	# One implementation, shared with `make upgrade`, so the config-path
	# resolution and the ordering exist once. `--config` is passed
	# explicitly because `resolve_installed_config` has already run above:
	# letting the gate resolve again could pick a different file than the
	# one this function reported on, which is the exact defect the
	# single-resolver rule was written for.
	if "$SCRIPT_DIR/upgrade_config_gate.sh" --binary "$BINARY_PATH" --config "$cfg"; then
		ok "existing config loads under the new binary: $cfg"
	else
		err "existing config at $cfg cannot be made loadable by the new binary"
		printf '\n  The running service has NOT been touched, and the config was\n'
		printf '  left unchanged unless the migration succeeded. Fix it first:\n'
		printf '    - follow the suggestions printed above, or\n'
		printf '    - pre-v2 configs: %swarden migrate v1-to-v3 --from-config %s --target %s --force%s\n' \
			"$C_D" "$cfg" "$cfg" "$C_R"
		printf '  then re-run this installer.\n\n'
		exit 6
	fi
}

# ── Phase 5: warden init (user + dirs + default config) ───────────────

run_warden_init() {
	step "Phase 5: Create system user, directories, default config"
	# Both paths, not just $CONFIG_PATH. The daemon's discovery prefers
	# /etc/purge-warden/config.toml on migrated/FHS hosts and only falls
	# back to /var/lib (see systemd/purge-warden.service and
	# src/cli/config_discovery.rs) — so a migrated host has a live config
	# that this guard could not see. It then ran `warden init` during an
	# --upgrade, AFTER the service was stopped. While the installer always
	# forwarded a hardcoded --upstream that was merely pointless; now that
	# init can legitimately refuse (no resolver detectable on this host),
	# it is a path that leaves the household with no DNS.
	#
	# This used to carry its OWN candidate loop, and it listed $CONFIG_PATH
	# BEFORE /etc — the opposite precedence to the daemon's. It saw a config
	# on both layouts, so the no-DNS path above stayed closed, but on a host
	# holding both files it named /var/lib while Phase 3.5 had linted /etc:
	# the line below claims "validated in Phase 3.5" about a different file
	# than the one that was validated. One resolver, one precedence.
	local existing=""
	existing=$(resolve_installed_config) || existing=""
	if [[ -n $existing ]]; then
		# Existing config (upgrade / re-run): linted in Phase 3.5, keep
		# it untouched. init would bail on it (and a --force overwrite
		# is exactly what an upgrade must never do).
		#
		# The dry-run takes this branch TOO, and that is the fix rather
		# than an oversight. The guard used to read
		# `[[ -n $existing && $DRY_RUN != "true" ]]`, so a preview on a
		# host that already had a config skipped it and printed the
		# `init` line below — an action the real run would never take.
		# Measured on the lab host 2026-08-15: the preview announced
		# `init --lists security/malicious,privacy/ads,privacy/tracking`
		# on a box carrying FOURTEEN lists, reading as "your config is
		# about to be rebuilt with three". A preview exists to decide
		# whether to proceed; one that overstates the damage stops a safe
		# upgrade just as effectively as one that hides real damage.
		if [[ $DRY_RUN == "true" ]]; then
			printf '  %s[dry]%s keep existing config %s (no init)\n' \
				"$C_Y" "$C_R" "$existing"
		else
			ok "config already present at $existing — keeping it (validated in Phase 3.5)"
		fi
		return
	fi

	# No config VISIBLE — which is not the same as no config. Say which,
	# rather than previewing an init the real run would never perform.
	if [[ $DRY_RUN == "true" ]] && config_may_be_hidden; then
		printf '  %s[dry]%s cannot read %s as uid %s — a config may be present\n' \
			"$C_Y" "$C_R" "$(dirname "$CONFIG_PATH")" "$EUID"
		printf '        and this preview cannot see it. The real run is root and\n'
		printf '        WOULD keep it. Re-run with sudo for a preview that can tell.\n'
		return
	fi
	# Fresh install: init runs fully specified — the installer already
	# collected every answer (flags or defaults), so init never prompts
	# regardless of TTY (rev-2606 install-01/install-02). allow_from =
	# detected/passed LAN CIDR + loopback.
	# neutrality-09: --upstream is passed ONLY when the operator gave
	# one. With it omitted, `init --yes` adopts the resolver this
	# machine already uses and prints what it chose. The installer no
	# longer carries a provider, and there is no second detection
	# implementation in shell to drift from the binary's.
	local upstream_arg=()
	if [[ -n $UPSTREAM ]]; then
		upstream_arg=(--upstream "$UPSTREAM")
	fi
	if [[ $DRY_RUN == "true" ]]; then
		printf '  %s[dry]%s %s init --yes --listen %s %s--lists %s --allow-from %s,127.0.0.0/8\n' \
			"$C_Y" "$C_R" "$BINARY_DEST" "$LISTEN" \
			"${UPSTREAM:+--upstream $UPSTREAM }" "$LISTS" "$LAN_CIDR"
		return
	fi
	"$BINARY_DEST" init --yes \
		--listen "$LISTEN" \
		"${upstream_arg[@]}" \
		--lists "$LISTS" \
		--allow-from "${LAN_CIDR},127.0.0.0/8"
}

# ── Phase 5.5: §4.40 admin-token XDG→FHS migration ────────────────────

# Move a legacy admin token from `$HOME/.config/purge-warden/token` (XDG
# spec, pre-§4.40 default) to `/var/lib/purge-warden/token` (FHS canonical,
# post-§4.40 default). Must run from install.sh — the daemon process is
# hardened with systemd `ProtectHome=yes`, so a boot-time migration
# inside the daemon never sees `/home/purge-warden/`. Root running
# install.sh has full filesystem visibility.
#
# Idempotent — re-runs are no-ops:
#   - FHS file already exists → skip (do NOT overwrite a fresh token).
#   - XDG file missing → skip.
#   - Otherwise → copy + chown + chmod + unlink legacy.
migrate_admin_token_to_fhs() {
	step "Phase 5.5: Migrate admin token to FHS canonical path (§4.40)"

	local XDG_TOKEN=/home/purge-warden/.config/purge-warden/token
	local FHS_TOKEN=/var/lib/purge-warden/token

	if [[ -f $FHS_TOKEN ]]; then
		ok "FHS token already present at $FHS_TOKEN — skipping"
		return
	fi
	if [[ ! -f $XDG_TOKEN ]]; then
		ok "no legacy XDG token at $XDG_TOKEN — fresh install, nothing to migrate"
		return
	fi

	if [[ $DRY_RUN == "true" ]]; then
		printf '  %s[dry]%s copy %s → %s, chown purge-warden, chmod 0600, unlink legacy\n' \
			"$C_Y" "$C_R" "$XDG_TOKEN" "$FHS_TOKEN"
		return
	fi

	cp -p "$XDG_TOKEN" "$FHS_TOKEN"
	chown purge-warden:purge-warden "$FHS_TOKEN"
	chmod 0600 "$FHS_TOKEN"
	rm -f "$XDG_TOKEN"
	ok "migrated admin token: $XDG_TOKEN → $FHS_TOKEN (mode 0600, owner purge-warden)"
}

# ── Phase 5.6: Daemon-user home directory ─────────────────────────────

# `warden init` creates purge-warden as a system user, and `useradd
# --system` does NOT create a home directory — but /etc/passwd still names
# one (/home/purge-warden). Anything the CLI or TUI writes under $HOME
# therefore fails: the directory is absent and /home is root-owned, so
# create_dir_all cannot make it.
#
# §4.40 already paid for this once — the admin token lived under $HOME,
# resolved nowhere, and Admin-tier IPC verbs auth-failed into an empty TUI.
# The token moved to FHS, but the CLASS of bug did not go away: the welcome
# banner's `seen_versions` still lives under $HOME, so on a fresh install
# the banner reappears at every single launch, its dismissal silently
# swallowed (welcome_banner::dismiss is best-effort by design).
#
# Creating the directory is cheaper than auditing every future $HOME writer.
# The daemon itself never sees it (the unit sets ProtectHome=yes) — this is
# for the CLI and TUI, which run outside that sandbox.
# The home path comes from /etc/passwd, NOT from a literal: it is whatever
# $HOME will actually expand to for that user at runtime, which is the only
# thing that matters here. On hosts migrated from the purge-shield era the
# field still reads /home/purge-shield — creating that is correct, however
# odd it looks, because that is where the CLI will try to write. (Phase 5.5
# hardcodes /home/purge-warden for its legacy-token probe and is therefore
# blind on those same hosts; pre-§4.40 only, left alone here.)
ensure_daemon_home() {
	step "Phase 5.4: Daemon-user home directory"

	# `|| home=""` is load-bearing, not defensive noise. `getent` exits 2 when
	# the key is absent, and under `set -euo pipefail` that becomes the exit
	# status of the assignment and kills the script — so the `warn` below was
	# UNREACHABLE code guarding a case that aborted the installer instead.
	#
	# A real install never showed it: Phase 5 creates the user, so by the time
	# this runs `getent` succeeds. Under --dry-run Phase 5 only prints, so the
	# user never exists and every preview on a clean machine died right here,
	# at Phase 5.4, with no message.
	local home=""
	home=$(getent passwd purge-warden | cut -d: -f6) || home=""
	if [[ -z $home ]]; then
		warn "user purge-warden not found — skipping (warden init should have created it)"
		return 0
	fi

	# Existence is checked BEFORE the dry-run branch, not after: a dry run
	# that announces an action it would not actually take is misinformation,
	# and the whole point of --dry-run is to be believed.
	if [[ -d $home ]]; then
		ok "daemon home already present: $home"
		return
	fi

	if [[ $DRY_RUN == "true" ]]; then
		printf '  %s[dry]%s install -d -o purge-warden -g purge-warden -m 0700 %s\n' \
			"$C_Y" "$C_R" "$home"
		return
	fi

	install -d -o purge-warden -g purge-warden -m 0700 "$home"
	ok "daemon home created: $home (owner purge-warden, mode 0700)"
}

# ── Phase 5.7: Admin token ────────────────────────────────────────────

# Resolve the config the daemon will actually load, in the daemon's own
# discovery order (/etc first, /var/lib second — see
# src/cli/config_discovery.rs). Phase 5's own probe checks $CONFIG_PATH
# first; that order is wrong for anything that must agree with the binary.
resolve_installed_config() {
	local candidate
	for candidate in /etc/purge-warden/config.toml "$CONFIG_PATH"; do
		if [[ -f $candidate ]]; then
			printf '%s' "$candidate"
			return 0
		fi
	done
	return 1
}

# Could a config be there that this process simply cannot SEE?
#
# `[[ -f x ]]` is false for "no such file" AND for "permission denied on the
# path", and warden's state directory is `0750 purge-warden:purge-warden` —
# so every candidate reads absent to any user that is not root or the daemon.
# The real install runs as root and is unaffected. `--dry-run` deliberately
# does NOT escalate ("a preview doesn't need real privileges"), so the
# preview is exactly where this bites.
#
# Measured on the lab host 2026-08-15: `bash install.sh --dry-run --upgrade`
# as an ordinary user announced `init --lists security/malicious,privacy/ads,
# privacy/tracking` on a box carrying FOURTEEN lists and a healthy config —
# it had concluded "fresh install" from a permission error. Same shape as
# `Path::exists()` hiding EACCES in the daemon's own discovery: an absence
# and a refusal are different facts, and code that cannot tell them apart
# reports the wrong one with total confidence.
#
# True only when a state directory EXISTS but its contents are unreadable —
# i.e. there is something there we are being kept out of. On a genuinely
# clean machine the directories are absent and this is false, so a fresh
# install still previews as a fresh install.
config_may_be_hidden() {
	[[ $EUID -eq 0 ]] && return 1
	local dir
	for dir in /etc/purge-warden "$(dirname "$CONFIG_PATH")"; do
		[[ -d $dir && ! -r $dir ]] && return 0
	done
	return 1
}

# Generate the admin token when the install does not have one.
#
# Without it the box installs, filters, and answers DNS perfectly — and
# every mutating action refuses with "run `warden token generate`". The
# installer used to MIGRATE a legacy token (Phase 5.5) but never create
# one, so a clean install shipped a dashboard whose every write failed.
#
# Runs as purge-warden so the config mutation and the 0600 token file land
# with the right ownership. The plaintext is deliberately NOT echoed: the
# installer tees its whole output to $LOG_FILE, and a credential in an
# install log is a credential leak. It is saved to /var/lib/purge-warden/
# token, where every `warden` command on this host finds it automatically.
#
# No restart. If the daemon is already up (upgrade path) the new hash needs
# a config reload, and `ExecReload=/bin/kill -HUP $MAINPID` reaches
# `api_token_hash.store(...)` in signal_loop. A restart would stop answering
# DNS until the blocklists finish loading — minutes on a large corpus.
ensure_admin_token() {
	step "Phase 5.7: Admin token"

	local cfg
	if ! cfg=$(resolve_installed_config); then
		warn "no config found — skipping token generation"
		return 0
	fi

	if [[ $DRY_RUN == "true" ]]; then
		printf '  %s[dry]%s warden --config %s token generate (as purge-warden, output suppressed)\n' \
			"$C_Y" "$C_R" "$cfg"
		return
	fi

	local out rc=0
	# `--config` goes BEFORE the subcommand. It is a GLOBAL flag on the
	# warden CLI; `token generate` itself takes no options but -h, so the
	# trailing form is rejected by clap:
	#
	#     unexpected argument '--config' found
	#     Usage: warden token generate
	#
	# Measured on the lab host: a fresh install completed with NO admin
	# token, and every mutating command would have refused. The failure was
	# non-fatal by design — the branch below warns and continues — so it
	# scrolled past in a wall of successful phases and the box looked
	# installed.
	out=$(su -s /bin/bash purge-warden -c \
		"$BINARY_DEST --config $(printf '%q' "$cfg") token generate" 2>&1) || rc=$?

	if [[ $rc -eq 0 ]]; then
		ok "admin token generated (saved to /var/lib/purge-warden/token, mode 0600)"
	elif [[ $out == *"token already exists"* ]]; then
		ok "admin token already configured — left untouched"
		return 0
	else
		warn "could not generate the admin token — mutating commands will refuse"
		printf '  %s\n' "$out"
		printf '  Generate it later with: %swarden token generate%s\n' "$C_D" "$C_R"
		return 0
	fi

	# Only reached when a token was just created. A daemon that is already
	# running holds no hash in memory yet; SIGHUP loads it without downtime.
	if systemctl is-active --quiet purge-warden.service 2>/dev/null; then
		run systemctl reload purge-warden.service
		ok "daemon reloaded (SIGHUP) — token active, DNS never stopped answering"
	fi
}

# ── Phase 6: Prepare backup directory ─────────────────────────────────

# rev-2606 install-03/install-05: the config-patching half of the old
# Phase 6 is gone. warden init now writes a complete config (allow_from
# included) on fresh installs, and pre-existing configs are lint-gated
# in Phase 3.5 instead of sed-patched — no more silent no-op anchors,
# no more v0 `lists =` shape the v2 loader rejects.
prepare_backup_dir() {
	step "Phase 6: Prepare backup directory"

	# Resolved like the daemon does, NOT from $CONFIG_PATH. On an
	# /etc-master host $CONFIG_PATH does not exist, so the old guard
	# `die`d here — AFTER install_binary stopped the service and BEFORE
	# install_unit restarts it, i.e. the installer aborted leaving LAN DNS
	# down. The die survives for the genuine "no config anywhere" case,
	# which after Phase 5 is a real error.
	#
	# Resolved before the --dry-run branch: the preview must name the same
	# directory the real run would create. The dry branch must NOT die when
	# nothing resolves — a preview of a fresh install runs before Phase 5
	# has written any config, and `--dry-run` on a clean machine has to
	# work. There the real run would create $CONFIG_PATH, so that is the
	# parent to show.
	local cfg
	if ! cfg=$(resolve_installed_config); then
		if [[ $DRY_RUN == "true" ]]; then
			cfg="$CONFIG_PATH"
		else
			die "config.toml not found at /etc/purge-warden/ or $CONFIG_PATH (warden init should have created it)"
		fi
	fi

	if [[ $DRY_RUN == "true" ]]; then
		printf '  %s[dry]%s mkdir -p %s/backups (owner purge-warden, mode 0750)\n' \
			"$C_Y" "$C_R" "$(dirname "$cfg")"
		return
	fi

	# §backup-restore-tui: ensure <config-parent>/backups/ exists owned by
	# purge-warden so the TUI Settings `b` action and the `warden config
	# backup` CLI can write archives without root. Default per
	# `BackupConfig::resolve_dir` is `<config-parent>/backups`. If the
	# operator points `[backup] dir` elsewhere via TOML they own that
	# path's perms (see CONFIG_GUIDE §15.13). chown is idempotent so a
	# pre-existing root-owned dir from earlier root-run testing is fixed.
	# Mode 0750, NOT 0755 — backup archives capture the master config
	# (api.token_hash) plus the device inventory; the engine creates
	# this dir 0750 on purpose (src/cli/commands/config/backup.rs) and
	# the installer must not re-loosen it (rev-2606 backup-01).
	local BACKUP_DIR
	BACKUP_DIR="$(dirname "$cfg")/backups"
	mkdir -p "$BACKUP_DIR"
	chown purge-warden:purge-warden "$BACKUP_DIR"
	chmod 0750 "$BACKUP_DIR"
	ok "backup dir prepared: $BACKUP_DIR (owner purge-warden, mode 0750)"
}

# ── Phase 7: Install systemd unit + enable + start ────────────────────

install_unit() {
	step "Phase 7: Install systemd unit and start service"

	# Sprint 27 lesson: a unit-file edit (ProcSubset=pid hiding
	# /proc/net/) silently broke ARP for a whole session because a
	# manual deploy replaced the binary but not the unit. Surface
	# every unit mutation explicitly in upgrade mode so the operator
	# sees what's changing — even if nothing visibly breaks, the diff
	# tells them what to look for in journalctl afterwards.
	if [[ $UPGRADE == "true" && -f $UNIT_DEST && -f $UNIT_SRC ]]; then
		if cmp -s "$UNIT_SRC" "$UNIT_DEST"; then
			ok "unit file unchanged — no update needed"
		else
			warn "unit file differs from repo copy — will replace"
			if command -v diff >/dev/null 2>&1; then
				printf '\n  %s── unit diff (installed → repo) ──%s\n' "$C_D" "$C_R"
				diff -u "$UNIT_DEST" "$UNIT_SRC" | head -40 | sed 's/^/  /' || true
				printf '\n'
			fi
		fi
	fi

	run install -m 0644 "$UNIT_SRC" "$UNIT_DEST"
	restore_selinux_context "$UNIT_DEST"
	# Before the service starts, not after: a daemon that binds :53 and is
	# then unreachable reads as a warden failure, and the operator debugs
	# the wrong layer.
	open_dns_in_firewall
	run systemctl daemon-reload
	if [[ $DRY_RUN != "true" ]]; then
		systemctl reset-failed purge-warden.service 2>/dev/null || true
	fi

	# Upgrade path: the service was stopped in install_binary before
	# the replacement, so `enable --now` restarts it. But if
	# install_binary decided the service wasn't running, we'd leave
	# it stopped after a unit change — surface that explicitly.
	if [[ $UPGRADE == "true" && $DRY_RUN != "true" ]]; then
		run systemctl restart purge-warden.service
	else
		run systemctl enable --now purge-warden.service
	fi
	ok "purge-warden.service enabled and started"

	# ── Auto-backup oneshot + timer (Sprint 4, v0.20.0) ─────────────
	# The .timer fires every hour; the .service runs `warden config
	# backup --auto`, which honours `[backup] auto_interval` and exits
	# 0 cleanly when not due / disabled / unset. Editing the TOML
	# takes effect on the next hourly tick — no daemon-reload needed.
	run install -m 0644 "$BACKUP_UNIT_SRC" "$BACKUP_UNIT_DEST"
	run install -m 0644 "$BACKUP_TIMER_SRC" "$BACKUP_TIMER_DEST"
	run systemctl daemon-reload
	run systemctl enable --now purge-warden-backup.timer
	ok "purge-warden-backup.timer enabled (hourly wakeup, gated by [backup] auto_interval)"
}

# ── Phase 7.5: Install the operator wrapper (§4.40) ───────────────────

# Write /usr/local/bin/warden as an EXECUTABLE that routes to the daemon
# user (purge-warden). After §4.32 the IPC socket is peer-uid-gated 0600 —
# only the daemon user can talk to it — and /var/lib/purge-warden/ is 0750,
# so the config is unreadable too.
#
# 2026-08-08: the wrapper used to route ONLY uid 0, sending every other
# user down the `else` branch to a direct exec. That branch is the broken
# one: a non-root admin gets "no config file found", a fallback to
# ./control.sock, and a dashboard whose System panel sits on STARTING
# forever. A sudoer is already root-equivalent, so routing them grants no
# capability they could not take — it only removes the incantation.
#
# 2026-08-14: it stopped being a shell function. As a function in
# /etc/profile.d it existed only inside a LOGIN shell, and `warden` on PATH
# still resolved to the raw binary for everyone else — measured on
# the lab host:
#
#     env -i /bin/sh -c 'command -v warden'   ->   /usr/local/bin/warden
#
# From cron, from `ssh host warden status`, from any non-shell caller, that
# binary RAN, could not read the config, and reported what looks like a
# broken install. Worse than "not found", and unreachable by any amount of
# work on the function. The real binary moved to $BINARY_DEST (off PATH) and
# this path became the executable, so there is no longer an unrouted `warden`
# for a non-shell caller to find.
# True when $1 starts with the four-byte ELF magic (7f 45 4c 46).
#
# `file` is not installed on a minimal Debian or Fedora, so read the magic
# directly — od is coreutils and always there. Deliberately NOT a check for
# "is it a script": a truncated wrapper, or a wrapper from a future version,
# must not be reported as a stray binary.
is_elf_binary() {
	[[ -f $1 ]] || return 1
	local magic
	magic=$(od -An -tx1 -N4 -- "$1" 2>/dev/null | tr -d ' \n')
	[[ $magic == "7f454c46" ]]
}

install_operator_wrapper() {
	step "Phase 7.5: Install operator wrapper at $WRAPPER_DEST"

	# The operator's standing habit is to stream a fresh binary straight onto
	# /usr/local/bin/warden. Before §4.40-exec that WAS the binary and the copy
	# was the update; now it is the wrapper, so the same muscle memory silently
	# destroys the routing — and the copied binary is not even what the daemon
	# runs, because both units ExecStart $BINARY_DEST. Nothing breaks loudly:
	# `warden` still executes, just unrouted, and reports the config as missing
	# days later.
	#
	# Detect it and say so. The wrapper is rewritten below either way, so this
	# branch owns the REPORT, and the report is the point: an operator who is
	# told nothing repeats the copy.
	#
	# But an ELF here is NOT evidence of a copy on its own. On every host that
	# predates this split it is simply the old binary, sitting where the old
	# installer put it — and that is the common case, not the rare one. The
	# two are told apart by whether libexec was already populated when this
	# run started; see $LIBEXEC_BINARY_PREEXISTED.
	local clobbered=false migrated=false
	if [[ $DRY_RUN != "true" ]] && is_elf_binary "$WRAPPER_DEST"; then
		if [[ $LIBEXEC_BINARY_PREEXISTED == "true" ]]; then
			clobbered=true
		else
			migrated=true
		fi
	fi

	if [[ $DRY_RUN == "true" ]]; then
		printf '  %s[dry]%s write %s (chmod 0755)\n' "$C_Y" "$C_R" "$WRAPPER_DEST"
		printf '  %s[dry]%s remove superseded %s\n' "$C_Y" "$C_R" "$LEGACY_PROFILED_WRAPPER"
		return
	fi

	# Written beside the target and moved into place, never `cat >` onto the
	# target itself. Two reasons, one of them measured:
	#
	#   - The file being replaced may be UNWRITABLE. A binary copied from a
	#     read-only store lands 0555, and `cat >` on it fails. Root normally
	#     bypasses that, but the failure mode is silent and total: the ELF
	#     survives, the `chmod 0755` below still runs, and the install reports
	#     an installed wrapper that was never written. Caught by the gate,
	#     which does not run as root.
	#   - A truncated write leaves every `warden` on the box broken. Replacing
	#     by rename means the path holds the old file or the new one, never
	#     half of either.
	#
	# The heredoc body is single-quoted so the install-time shell does NOT
	# expand $* / $@ — those expand when the operator runs the wrapper.
	local staged="$WRAPPER_DEST.new-$$"
	cat >"$staged" <<'WRAPEOF'
#!/bin/sh
# purge-warden operator wrapper (installed by scripts/install.sh §4.40).
#
# Why this exists: the IPC socket is peer-uid-gated 0600 owned
# purge-warden:purge-warden (§4.32) and /var/lib/purge-warden/ is 0750, so
# a shell that is not the daemon user can neither read the config nor talk
# to the daemon. It silently falls back to ./config.toml and ./control.sock
# and reports "no config file found" with a System panel stuck on STARTING.
#
# Why an EXECUTABLE and not a shell function: a function in /etc/profile.d is
# defined only inside a LOGIN shell. Everywhere else — cron, `ssh host warden
# status`, any non-shell caller — `warden` on PATH resolved to the raw binary,
# which ran, could not read the config, and reported a working install as
# broken. A file on PATH is visible to every caller a function is invisible to.
#
# Routing rules, in order:
#   1. An explicit --config, or a ./config.toml in the CWD, means the caller
#      is driving their own install (the dev workflow). Never route those —
#      routing would run a dev command against the system config.
#   2. The daemon user itself: nothing to route.
#   3. root: must DROP to the daemon user, because the peer-uid gate rejects
#      uid 0 outright (Connection reset by peer).
#   4. Any other user, when sudo is available: route through it. Someone who
#      can sudo is already root-equivalent, so this grants no capability they
#      could not take anyway — it only removes the incantation.
#   5. No sudo: run directly and let the binary report its own error.
#
# Known limit of routing: the CWD is NOT changed, so a relative path argument
# is resolved by the daemon user, who may not be able to read the caller's
# directory. That surfaces as a plain permission error, which is honest.
#
# `exec` IS correct here, and that inverts the old note. As a sourced FUNCTION
# `exec` would have replaced the operator's login shell with the warden process
# and killed the session when the command exited (rev-2606 wrapper-01). This is
# a separate PROCESS, so `exec` replaces only the wrapper: one less process in
# the chain, signals and exit status pass straight through, and nothing is left
# waiting to mangle them.
#
# POSIX sh, not bash: this runs from cron and from whatever /bin/sh the host
# ships (dash on Debian). `local` outside a function and `printf '%q'` are both
# bash extensions that PARSE fine and fail at runtime — the two bugs a syntax
# check cannot see, which is why the gate executes this file instead.

BIN=/usr/local/libexec/purge-warden/warden

if [ ! -x "$BIN" ]; then
	echo "warden: $BIN not found or not executable" >&2
	exit 127
fi

# Quote one argument for re-parsing by an inner shell: wrap it in single
# quotes, writing each embedded quote as '\''. This replaces `printf '%q '`,
# which is a bash builtin extension. Pure parameter expansion — no fork, and
# unlike a $(… | sed …) round-trip it cannot eat an argument's trailing
# newlines.
sq() {
	sq_rest=$1
	sq_out=''
	while :; do
		case $sq_rest in
		*"'"*)
			sq_out="$sq_out${sq_rest%%\'*}'\\''"
			sq_rest=${sq_rest#*\'}
			;;
		*)
			printf "'%s'" "$sq_out$sq_rest"
			return
			;;
		esac
	done
}

# 1 — the caller drives their own install.
for a in "$@"; do
	case "$a" in
	--config | --config=*)
		exec "$BIN" "$@"
		;;
	esac
done
# -e, NOT -r. The two differ on exactly one input: a ./config.toml that
# EXISTS but the caller cannot read. Under -r that fails the guard, so
# the wrapper routes to purge-warden — which does not change directory
# (see the note above), and whose non-root discovery ranks ./config.toml
# FIRST, ahead of /etc. The file the caller could not read then silently
# outranks the system master. The readability test and the identity that
# ends up reading are two different subjects.
#
# Rule 1 is about a dev config being PRESENT here, not about who can
# read it. Under -e that case runs unrouted and reports a plain
# permission error, which is honest — the same trade the CWD note above
# already makes.
if [ -e ./config.toml ]; then
	exec "$BIN" "$@"
fi

# 2 — already the daemon user.
if [ "$(id -un)" = purge-warden ]; then
	exec "$BIN" "$@"
fi

# 3 — root drops to the daemon user.
if [ "$(id -u)" -eq 0 ]; then
	# The `exec` inside the -c string replaces su's child shell, so the
	# chain is wrapper → su → warden with nothing idling in between.
	cmd=$(sq "$BIN")
	for a in "$@"; do
		cmd="$cmd $(sq "$a")"
	done
	exec su -s /bin/sh purge-warden -c "exec $cmd"
fi

# 4 — non-root admin routes through sudo.
if command -v sudo >/dev/null 2>&1; then
	exec sudo -u purge-warden "$BIN" "$@"
fi

# 5 — nothing to route with.
exec "$BIN" "$@"
WRAPEOF
	chmod 0755 "$staged"
	mv -f "$staged" "$WRAPPER_DEST"
	restore_selinux_context "$WRAPPER_DEST"
	ok "installed $WRAPPER_DEST"

	if [[ $migrated == "true" ]]; then
		# Not a warning. Nothing went wrong: this is what upgrading a
		# pre-split host looks like, and the operator only needs to know
		# that the two paths now mean different things.
		ok "migrated: $WRAPPER_DEST held the binary and is now the wrapper"
		printf '  The daemon runs %s%s%s from here on.\n' "$C_D" "$BINARY_DEST" "$C_R"
		printf '  Do not copy a binary onto %s%s%s again — that is the wrapper\n' \
			"$C_D" "$WRAPPER_DEST" "$C_R"
		printf '  now, and overwriting it breaks `warden` for every caller.\n'
	elif [[ $clobbered == "true" ]]; then
		warn "a raw binary had been copied over $WRAPPER_DEST — wrapper restored"
		printf '  That file is the routing wrapper, not the daemon binary. The daemon\n'
		printf '  runs %s%s%s, which this installer just replaced.\n' "$C_D" "$BINARY_DEST" "$C_R"
		printf '  To update warden, re-run this installer with %s--upgrade%s\n' "$C_B" "$C_R"
		printf '  instead of copying a binary onto %s%s%s.\n' "$C_D" "$WRAPPER_DEST" "$C_R"
	fi

	# The function is superseded, not merely redundant: /etc/profile.d is
	# sourced AFTER PATH is set, so a surviving `warden()` shadows the
	# executable in exactly the shell the operator uses interactively. They
	# would then be testing the old routing while reading the new install's
	# output.
	if [[ -f $LEGACY_PROFILED_WRAPPER ]]; then
		rm -f "$LEGACY_PROFILED_WRAPPER"
		ok "removed superseded shell function $LEGACY_PROFILED_WRAPPER"
	fi
}

# ── Phase 8: Verify ───────────────────────────────────────────────────

verify() {
	step "Phase 8: Verify DNS resolution and filtering"

	if [[ $DRY_RUN == "true" ]]; then
		printf '  %s[dry]%s dig @127.0.0.1 google.com (expect A record)\n' "$C_Y" "$C_R"
		printf '  %s[dry]%s dig @127.0.0.1 doubleclick.net (expect 0.0.0.0)\n' "$C_Y" "$C_R"
		return
	fi

	# Poll the actual DNS listener until it responds. Probing dig directly
	# is more reliable than grep'ing journalctl for a "DNS server listening"
	# log line, which can match a stale entry from a previous run within
	# the journal time window. We don't care about the answer — only that
	# something replied (dig returns 9 = "no reply from server" until then).
	log "waiting for DNS listener to accept queries (up to 30s)"
	local waited=0 listening=false
	while ((waited < 30)); do
		if dig @127.0.0.1 +time=1 +tries=1 +norec localhost >/dev/null 2>&1; then
			listening=true
			break
		fi
		if [[ $IS_TTY == "true" ]]; then
			printf '\r  %swaiting…%s %ds' "$C_D" "$C_R" "$waited"
		fi
		sleep 1
		waited=$((waited + 1))
	done
	if [[ $IS_TTY == "true" ]]; then printf '\r\033[K'; fi
	if [[ $listening == "true" ]]; then
		ok "DNS listener ready (after ${waited}s)"
	else
		warn "DNS listener not ready after 30s — verification may fail"
	fi

	local allow_result
	allow_result=$(dig @127.0.0.1 google.com +short +time=3 2>&1 | head -1)
	if [[ -z $allow_result || $allow_result == "0.0.0.0" ]]; then
		err "google.com did NOT resolve to a real IP (got: '${allow_result:-<empty>}')"
		printf '\n  Upstream resolution is broken. Check:\n'
		printf '    - Upstream reachability: %sdig @<the address in upstream.servers> example.com%s\n' "$C_D" "$C_R"
		printf '    - See it with:           %swarden config show%s\n' "$C_D" "$C_R"
		printf '    - Recent errors:         %sjournalctl -u purge-warden -n 30%s\n\n' "$C_D" "$C_R"
		exit 5
	fi
	ok "google.com → $allow_result (resolved via upstream)"

	# rev-2606: the blocked-domain check must POLL, not one-shot. On a
	# fresh install the first blocklist download (~hundreds of MB for the
	# default trio) takes minutes; an immediate dig forwards the real IP
	# and a one-shot check false-fails a perfectly correct install. The
	# bound stays a HARD failure — a daemon that still forwards a
	# known-listed domain after the window is a non-filtering install,
	# which is exactly what this phase exists to catch.
	log "waiting for first blocklist download + ingest (up to ${BLOCK_VERIFY_TIMEOUT_SECS}s)"
	local block_result="" block_waited=0 blocked=false
	while ((block_waited < BLOCK_VERIFY_TIMEOUT_SECS)); do
		block_result=$(dig @127.0.0.1 doubleclick.net +short +time=3 2>&1 | head -1)
		if [[ $block_result == "0.0.0.0" ]]; then
			blocked=true
			break
		fi
		if [[ $IS_TTY == "true" ]]; then
			printf '\r  %slists downloading…%s %ds (doubleclick.net → %s)' \
				"$C_D" "$C_R" "$block_waited" "${block_result:-<no answer>}"
		fi
		sleep 5
		block_waited=$((block_waited + 5))
	done
	if [[ $IS_TTY == "true" ]]; then printf '\r\033[K'; fi
	if [[ $blocked != "true" ]]; then
		err "doubleclick.net was NOT blocked after ${BLOCK_VERIFY_TIMEOUT_SECS}s (got: '$block_result')"
		printf '\n  The daemon is up but filtering nothing — this install is NOT protecting you.\n'
		printf '  Diagnose:\n'
		printf '    - List download progress: %sjournalctl -u purge-warden -n 50 | grep -i list%s\n' "$C_D" "$C_R"
		printf '    - Re-check later:         %sdig @127.0.0.1 doubleclick.net%s\n' "$C_D" "$C_R"
		# Name the config the daemon actually loaded, not $CONFIG_PATH: on an
		# /etc-master host the latter does not exist and the operator greps a
		# missing file while diagnosing a live failure. Falls back to
		# $CONFIG_PATH only if nothing resolves, which cannot happen here
		# (Phase 5 ran) but keeps the printf total.
		local cfg_hint
		cfg_hint=$(resolve_installed_config) || cfg_hint="$CONFIG_PATH"
		printf '    - Subscriptions:          %sgrep -A3 blocklists %s%s\n\n' "$C_D" "$cfg_hint" "$C_R"
		exit 5
	fi
	ok "doubleclick.net → 0.0.0.0 (blocked, after ${block_waited}s)"
}

# ── Phase 8.5: Operator path ──────────────────────────────────────────

# Verify the human can actually drive the thing we just installed.
#
# This phase exists because Phase 8 is careful about the wrong half. It
# polls upstream resolution, then polls for a blocked domain with a
# minutes-long budget — genuinely thorough about whether the PRODUCT works.
# It then hands off to print_next_steps, which tells the operator to run
# `warden dashboard`: the one command nothing in this script has ever run.
#
# On 2026-08-08 that gap cost an evening. Every metric the installer
# measures was green — daemon active, 3/3 lists, 11.9M domains, blocking
# correct — and `warden dashboard` as a normal user reported "no config
# file found (os error 2)" with a System panel frozen on STARTING. The
# installer verified the product and printed an instruction it had never
# verified.
#
# WARN, never exit: DNS filtering works with or without the operator path,
# and failing the install here would mark a filtering box as failed. The
# hard failures stay with the DNS checks that already own them.
verify_operator_path() {
	step "Phase 8.5: Verify the operator path"

	local target="${SUDO_USER:-}"
	if [[ -z $target || $target == "root" ]]; then
		warn "no non-root invoker to test (SUDO_USER unset — direct root login?)"
		printf '  Log in as your normal user and run %swarden status%s to confirm.\n' \
			"$C_D" "$C_R"
		return 0
	fi

	if [[ $DRY_RUN == "true" ]]; then
		printf '  %s[dry]%s su - %s -c '"'"'warden status'"'"'\n' "$C_Y" "$C_R" "$target"
		return
	fi

	# ── 8.5a — PATH resolution, as $target, WITHOUT sudo ──────────────
	#
	# `command -v` resolves a name; it does not run the wrapper, so it never
	# reaches the wrapper's `sudo -u purge-warden` branch and never prompts.
	# That makes this measurable on every host, including the password-sudo
	# majority the phase used to skip entirely.
	#
	# Two distinct failures, and the message has to tell them apart:
	#   - resolves to nothing: $WRAPPER_DEST is not on $target's PATH.
	#   - resolves to the bare word `warden`: something is shadowing the file
	#     with a shell FUNCTION. That was warden's own pre-§4.40 layout, so a
	#     stale /etc/profile.d file surviving the upgrade lands here — and the
	#     function is invisible to cron, which is the bug the executable fixed.
	local path_out path_rc=0
	path_out=$(su - "$target" -c 'command -v warden' 2>&1) || path_rc=$?
	if [[ $path_rc -eq 0 && $path_out == "$WRAPPER_DEST" ]]; then
		ok "wrapper resolves on '$target' PATH: $WRAPPER_DEST"
	else
		warn "'$target' does not resolve \`warden\` to $WRAPPER_DEST"
		printf '\n  What their shell resolved: %s\n' "${path_out:-<nothing>}"
		if [[ $path_out == "warden" ]]; then
			printf '  That is a shell FUNCTION shadowing the file — cron and ssh\n'
			printf '  will not see it. Look for a stray %s/etc/profile.d/*warden*%s\n' \
				"$C_D" "$C_R"
		fi
		printf '\n'
	fi

	# The wrapper must be the script, not the raw ELF. Phase 7.5 guarantees
	# it; this asserts the guarantee held rather than assuming it. A host
	# still carrying the pre-libexec layout runs the binary unrouted, which
	# starts and then fails to read the config — worse than absent, because
	# it looks like a product fault.
	if is_elf_binary "$WRAPPER_DEST"; then
		warn "$WRAPPER_DEST is a raw binary, not the wrapper"
		printf '\n  Phase 7.5 should have replaced it. Routing will not happen.\n\n'
	fi

	# ── 8.5b — the product itself, as the daemon user, WITHOUT sudo ────
	#
	# THE check the 2026-08-08 incident called for: `os error 2` was config
	# discovery failing for purge-warden, and that is measurable here with no
	# password at all — root switches user without one. Everything below this
	# point needs $target's sudo; this does not, so it runs first and always.
	#
	# Through $WRAPPER_DEST rather than $BINARY_DEST: as purge-warden the
	# wrapper takes branch 2 ("the daemon user itself: nothing to route") and
	# execs the same binary, so one extra link is verified at zero cost.
	#
	# `su -s /bin/bash`, NOT `su -`. The dash form resets $HOME, and config
	# discovery is the property under test — verify the invocation the
	# wrapper's own root branch makes, not a neighbouring one.
	local svc_out svc_rc=0
	svc_out=$(su -s /bin/bash purge-warden -c "exec $WRAPPER_DEST status" 2>&1) || svc_rc=$?
	if [[ $svc_rc -eq 0 && $svc_out == *"is running"* ]]; then
		ok "the daemon user can read its own config and reach the socket"
	else
		warn "purge-warden cannot drive warden — the operator path cannot work"
		printf '\n  This is the half that does NOT depend on your sudo rules, so a\n'
		printf '  failure here is the product, not the plumbing.\n'
		printf '  What warden said:\n'
		printf '    %s\n' "${svc_out:-<no output>}" | head -5
		printf '\n'
	fi

	# ── 8.5c — the sudo hop, only where measuring it is free ───────────
	#
	# The wrapper's non-root branch is `sudo -u purge-warden`, so the checks
	# below run sudo AS $target. On a host where sudo asks for a password —
	# the Fedora and Debian default; measured on the lab host — that
	# surfaces as a bare `[sudo] password for <user>:` in the middle of an
	# install, with nothing on screen explaining who wants it. Worse in a
	# non-interactive run: sudo fails, and this reports that the operator
	# path is broken when it is merely password-protected.
	#
	# Needing a password is CORRECT behaviour, not a fault, so probe for it
	# first and report it as its own outcome. `-n` never prompts.
	#
	# Probed through `su -` rather than directly, because $target's sudo
	# rules can differ from root's view of them (NOPASSWD is per-user), and
	# because it is the same shell shape the real check uses.
	#
	# Deliberately NOT `ok`, and deliberately NOT `warn`. `sudo -n` fails
	# for two different reasons — a password is required, or $target may not
	# run sudo at all — and nothing short of parsing sudo's error text tells
	# them apart. That text is LOCALISED (the probe host answers in Italian:
	# "è necessaria una password"), so matching it is a detector a language
	# setting defeats. `ok` would be a false all-clear on the non-sudoer;
	# `warn` would be a false alarm on the password host, which is the very
	# noise this branch exists to remove. So: state what was not measured,
	# and claim neither outcome.
	#
	# What this branch may NO LONGER say is "operator path NOT exercised".
	# It said exactly that until 2026-08-15, and it was the whole defect:
	# password-sudo is the default on both target distros, so the phase
	# built after the 2026-08-08 incident skipped on nearly every host and
	# printed an instruction it had never run — the very thing it existed to
	# stop. 8.5a and 8.5b above are measured unconditionally, so the honest
	# claim is narrow: one hop of three is unmeasured.
	if ! su - "$target" -c 'sudo -n true' >/dev/null 2>&1; then
		printf '%s·%s the sudo hop was not measured: sudo needs a password for '"'"'%s'"'"'\n' \
			"$C_B" "$C_R" "$target"
		printf '  Testing it would prompt for a password mid-install. PATH resolution\n'
		printf '  and the daemon user'"'"'s own access ARE verified above.\n'
		printf '  Confirm the last hop after logging in: %swarden status%s\n' "$C_D" "$C_R"
		printf '  If that fails, %s'"'"'%s'"'"' may not be a sudoer%s — check with %ssudo -l%s\n' \
			"$C_D" "$target" "$C_R" "$C_D" "$C_R"
		return 0
	fi

	# A LOGIN shell (`su -`). That used to be the ONLY shape worth testing,
	# because the wrapper was a function in /etc/profile.d and nothing else
	# sourced it. It is now an executable on PATH, so this measures PATH
	# resolution plus routing, and the login shell is merely the shape an
	# operator most often uses.
	#
	# Do not reword this invocation lightly: arm J of
	# check_install_config_resolution.sh pins the literal string, because the
	# property it guards is that the `sudo -n` probe above runs BEFORE the
	# call that can prompt.
	local out rc=0
	out=$(su - "$target" -c 'warden status' 2>&1) || rc=$?

	# The needle is POSITIVE — real daemon data in the output — and not a
	# list of error phrasings to reject. Both would pass today (measured on
	# home-warden: working rc=0 with "is running"; broken rc=2 without it),
	# but they rot in opposite directions. A negative match fails OPEN: the
	# day someone rewords the discovery warning, this reports a working
	# operator path that is broken. A positive match fails CLOSED: the same
	# rewording produces a spurious warning, which is noisy and harmless.
	# For a warn-only check, pick the needle whose failure mode is a false
	# alarm rather than a false all-clear.
	#
	# Safe here because Phase 8 already hard-failed unless the daemon was
	# answering, so "not running" at this point cannot mean a legitimately
	# stopped daemon.
	if [[ $rc -eq 0 && $out == *"is running"* ]]; then
		ok "operator path works: '$target' can run \`warden status\`"
	else
		warn "'$target' cannot drive warden from a login shell"
		printf '\n  The daemon is fine — this is the operator path only.\n'
		printf '  What warden said:\n'
		printf '    %s\n' "${out:-<no output>}" | head -5
		printf '\n  Check the wrapper is present and executable:\n'
		printf '    %sls -l %s%s\n' "$C_D" "$WRAPPER_DEST" "$C_R"
		printf '    %ssu - %s -c '"'"'command -v warden'"'"'%s\n' "$C_D" "$target" "$C_R"
		printf '  Meanwhile this always works:\n'
		printf '    %ssudo -u purge-warden warden status%s\n\n' "$C_D" "$C_R"
		return 0
	fi

	# The NON-login half, and the reason this phase grew a second test.
	# print_next_steps now tells the operator that cron, ssh and scripts all
	# reach warden. That claim was false for the entire life of the shell
	# function, and printing an unverified instruction is precisely the defect
	# this phase was created to stop — it verified the product and printed a
	# command it had never run.
	#
	# Absolute path, not `warden`: PATH containing /usr/local/bin is a distro
	# guarantee, not a property of ours, and testing it here would fail on
	# someone's stripped PATH for a reason that is not our bug. What IS ours is
	# that the file works with no profile sourced at all — the cron shape.
	#
	# `cd /` first, and it is load-bearing. A non-login `su` does NOT change
	# directory, so the child inherits the CWD this installer was invoked
	# from — a git checkout, which in the documented dev layout holds a
	# ./config.toml. That trips wrapper rule 1, the call runs unrouted, and
	# this reports a broken non-login path on a host where it is fine. The
	# login check above is immune only because `su -` chdirs to $HOME.
	local nl_out nl_rc=0
	nl_out=$(su -s /bin/sh "$target" -c "cd / && $WRAPPER_DEST status" 2>&1) || nl_rc=$?
	if [[ $nl_rc -eq 0 && $nl_out == *"is running"* ]]; then
		ok "non-login path works: cron/ssh/scripts reach $WRAPPER_DEST"
		return 0
	fi

	warn "the non-login path is broken — cron and \`ssh host warden …\` will fail"
	printf '\n  A login shell works, so the wrapper is installed and routes.\n'
	printf '  What %s said without a login shell:\n' "$WRAPPER_DEST"
	printf '    %s\n' "${nl_out:-<no output>}" | head -5
	printf '\n'
}

# ── Phase 9: Next steps ───────────────────────────────────────────────

print_next_steps() {
	step "Install complete"
	local ip
	ip=$(detect_lan_ip || echo "<this-host>")

	printf '\n'
	printf '%s✓%s purge-warden is running on %s%s:53%s\n\n' "$C_G" "$C_R" "$C_B" "$ip" "$C_R"
	printf '%sNext steps:%s\n' "$C_B" "$C_R"
	printf '  1. Point your router'"'"'s DHCP at %s%s%s as primary DNS\n' "$C_B" "$ip" "$C_R"
	printf '     (or configure individual LAN devices directly)\n'
	printf '  2. Watch live logs: %sjournalctl -fu purge-warden%s\n' "$C_D" "$C_R"
	printf '  3. Top blocked / queried domains: %swarden stats%s\n' "$C_D" "$C_R"
	printf '  4. Per-device profiles: %swarden device add <id> --mac <mac> --profile <profile>%s\n' "$C_D" "$C_R"
	printf '  5. Interactive dashboard: %swarden dashboard%s\n' "$C_D" "$C_R"
	printf '\n%sAbout running `warden` as yourself:%s\n' "$C_B" "$C_R"
	printf '  The daemon owns its config and its control socket, so `warden` has to run\n'
	printf '  as the %spurge-warden%s user. %s%s%s does that for you — it is an\n' \
		"$C_B" "$C_R" "$C_B" "$WRAPPER_DEST" "$C_R"
	printf '  executable on your PATH, so every caller finds it: an interactive shell,\n'
	printf '  %sssh host warden status%s, cron, a script, a systemd unit.\n' "$C_D" "$C_R"
	printf '  The daemon itself runs %s%s%s,\n' "$C_D" "$BINARY_DEST" "$C_R"
	printf '  which is deliberately NOT on PATH.\n'
	printf '  Always works too: %ssudo -u purge-warden warden status%s\n' "$C_D" "$C_R"
	# The shell function is removed by Phase 7.5, but a shell that was ALREADY
	# open when this ran still carries it in memory, where it shadows the
	# executable. Harmless — the old function calls this same path, which now
	# routes — but the extra hop is invisible and confusing to debug.
	printf '  Upgrading from a %s/etc/profile.d%s wrapper? Shells already open still hold\n' "$C_D" "$C_R"
	printf '  the old function: run %sunset -f warden%s in them, or just log in again.\n' "$C_D" "$C_R"
	printf '\n%sTest from another LAN host:%s\n' "$C_B" "$C_R"
	printf '  %sdig @%s doubleclick.net    # expect 0.0.0.0 (blocked)%s\n' "$C_D" "$ip" "$C_R"
	printf '  %sdig @%s google.com         # expect a real IP%s\n' "$C_D" "$ip" "$C_R"
	printf '\n%sTo uninstall:%s\n' "$C_B" "$C_R"
	printf '  %ssudo %s/scripts/uninstall.sh%s\n' "$C_D" "$REPO_ROOT" "$C_R"

	if [[ -n $LOG_FILE ]]; then
		printf '\n%sFull install log:%s %s\n' "$C_B" "$C_R" "$LOG_FILE"
	fi
	printf '\n'
}

# ── Pre-step: migrate an existing purge-shield install ────────────────

# Detect a legacy purge-shield install and convert it to purge-warden
# BEFORE the normal install steps run (v0.21.0 rename, Decision A).
# Delegates to scripts/migrate-shield-to-warden.sh, which is idempotent
# and a clean no-op on a fresh machine. Runs ahead of install_binary /
# run_warden_init / install_unit so the rest of the flow operates on the
# already-renamed user + directories; install.sh then recreates the
# wrapper, resolved drop-in, units, and starts the daemon (warden-named).
migrate_existing_install() {
	local migrate_script="$SCRIPT_DIR/migrate-shield-to-warden.sh"
	[[ -f $migrate_script ]] || return 0
	# Detection is the migrate script's own job — duplicating it here made
	# this hook blind to the host it matters most on: one an earlier version
	# of the script already migrated has no old unit, user or directory, yet
	# can still carry paths into the dead tree in its config. The script is
	# idempotent and exits 0 with "nothing to migrate" on a fresh machine.
	step "Pre-step: migrate an existing purge-shield install → purge-warden"
	if [[ $DRY_RUN == "true" ]]; then
		bash "$migrate_script" --dry-run
	else
		bash "$migrate_script"
	fi
}

# ── Main ──────────────────────────────────────────────────────────────

main() {
	ORIG_ARGS="$*"
	ORIG_ARGV=("$@")

	while [[ $# -gt 0 ]]; do
		case $1 in
			--lan-cidr)
				require_value "$1" "$@"
				LAN_CIDR="$2"
				shift 2
				;;
			--lan-cidr=*)
				LAN_CIDR="${1#*=}"
				shift
				;;
			--listen)
				require_value "$1" "$@"
				LISTEN="$2"
				shift 2
				;;
			--listen=*)
				LISTEN="${1#*=}"
				shift
				;;
			--upstream)
				require_value "$1" "$@"
				UPSTREAM="$2"
				shift 2
				;;
			--upstream=*)
				UPSTREAM="${1#*=}"
				shift
				;;
			--lists)
				require_value "$1" "$@"
				LISTS="$2"
				shift 2
				;;
			--lists=*)
				LISTS="${1#*=}"
				shift
				;;
			--build-from-source)
				MODE="build"
				shift
				;;
			--binary)
				require_value "$1" "$@"
				MODE="binary"
				BINARY_PATH="$2"
				shift 2
				;;
			--binary=*)
				MODE="binary"
				BINARY_PATH="${1#*=}"
				shift
				;;
			--upgrade)
				UPGRADE="true"
				shift
				;;
			--dry-run)
				DRY_RUN="true"
				shift
				;;
			--yes | -y)
				YES="true"
				shift
				;;
			--help | -h)
				print_help
				exit 0
				;;
			*)
				err "unknown argument: $1"
				printf '\nRun: %s --help\n\n' "$0"
				exit 2
				;;
		esac
	done

	# Auto-escalate to root via sudo (smoother than "re-run with sudo").
	# Re-exec with the ORIGINAL argv so the second pass parses the same flags.
	# NO_COLOR is preserved via sudo -E so output stays consistent.
	# Skipped in --dry-run: a preview doesn't need real privileges, and
	# making the user type a sudo password just to see what WOULD happen
	# defeats the purpose of the flag.
	if [[ $EUID -ne 0 && $DRY_RUN != "true" ]]; then
		if command -v sudo >/dev/null 2>&1; then
			printf '%s▸%s not running as root — re-executing via sudo\n' "$C_B" "$C_R"
			exec sudo -E bash "$0" "${ORIG_ARGV[@]}"
		fi
		err "this installer must run as root, and sudo is not available"
		printf '\n  Re-run from a root shell: %sbash %s %s%s\n\n' "$C_B" "$0" "$ORIG_ARGS" "$C_R"
		exit 1
	fi

	# Tee stdout+stderr to a log file for real runs. Color escapes are already
	# baked into the format strings (evaluated at script-load while stdout was
	# still a TTY), so the terminal still shows color and the log captures
	# everything — ANSI and all. Users can strip with `sed 's/\x1b\[[0-9;]*m//g'`.
	if [[ $DRY_RUN != "true" ]]; then
		LOG_FILE="/var/log/purge-warden-install-$(date +%Y%m%d-%H%M%S).log"
		install -m 0755 -d /var/log 2>/dev/null || true
		# Tee stdout+stderr to a log file. $! captures the tee PID so we
		# can wait on it at exit — otherwise the parent's exit races the
		# tee subprocess and the last ~20 lines get lost before the FIFO
		# flushes.
		exec > >(tee -a "$LOG_FILE") 2>&1
		LOG_TEE_PID=$!
		log "logging to $LOG_FILE"
	else
		warn "DRY RUN — no changes will be made"
	fi

	preflight
	show_plan
	show_disclaimer

	# Ask for confirmation unless --yes, --dry-run, or no TTY at all.
	# /dev/tty lets the prompt work even when stdin is piped (curl | bash).
	if [[ $YES != "true" && $DRY_RUN != "true" ]]; then
		if [[ ! -t 0 && ! -r /dev/tty ]]; then
			warn "no TTY detected — proceeding with defaults (use --yes to silence)"
		elif ! confirm "Accept these terms and proceed with the install?"; then
			log "aborted by user"
			exit 0
		fi
	fi

	migrate_existing_install
	install_runtime_deps
	if [[ $MODE == "build" ]]; then
		install_build_deps
		build_binary
	fi
	# Lint any pre-existing config with the NEW binary BEFORE
	# install_binary stops the running service — a refused config must
	# abort the upgrade while LAN DNS is still answering.
	lint_existing_config
	install_binary
	run_warden_init
	ensure_daemon_home
	migrate_admin_token_to_fhs
	ensure_admin_token
	prepare_backup_dir
	install_unit
	install_operator_wrapper
	verify
	verify_operator_path
	print_next_steps

	# Drain the tee subprocess so the log captures every byte we wrote.
	# Closing fd 1/2 sends EOF to the FIFO; wait joins on tee's exit.
	if [[ -n ${LOG_TEE_PID:-} ]]; then
		exec 1>&- 2>&-
		wait "$LOG_TEE_PID" 2>/dev/null || true
	fi
}

main "$@"
