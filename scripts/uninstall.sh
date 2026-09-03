#!/usr/bin/env bash
#
# uninstall.sh — remove purge-warden from a Debian/Ubuntu host.
#
# By default, leaves /var/lib/purge-warden/ intact (config, lists cache,
# stats data) so a re-install preserves state. Pass --purge to wipe it.
#
# Safe to run on partial installs — each step checks before acting.

set -euo pipefail

# Mirrors install.sh: the real binary lives off PATH in libexec, and
# /usr/local/bin/warden is the operator wrapper that routes to it. Both go.
# WRAPPER_DEST is also where PRE-§4.40-exec installs put the raw binary, so
# removing it covers the old layout without a version check.
LIBEXEC_DIR="/usr/local/libexec/purge-warden"
BINARY_DEST="$LIBEXEC_DIR/warden"
WRAPPER_DEST="/usr/local/bin/warden"
LEGACY_PROFILED_WRAPPER="/etc/profile.d/purge-warden-wrapper.sh"
UNIT_DEST="/etc/systemd/system/purge-warden.service"
BACKUP_UNIT_DEST="/etc/systemd/system/purge-warden-backup.service"
BACKUP_TIMER_DEST="/etc/systemd/system/purge-warden-backup.timer"
STATE_DIR="/var/lib/purge-warden"
ETC_DIR="/etc/purge-warden"
RUN_DIR="/run/purge-warden"
RESOLVED_DROPIN="/etc/systemd/resolved.conf.d/purge-warden-no-stub.conf"
SERVICE_USER="purge-warden"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
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

PURGE="false"
YES="false"
DRY_RUN="false"
RESTORE_RESOLVED="false"

print_help() {
	cat <<EOF
Usage: sudo $0 [OPTIONS]

Remove purge-warden from this host.

OPTIONS:
  --purge              Also delete /var/lib/purge-warden/ (config, lists,
                       stats) and /etc/purge-warden/ (master config +
                       tokens on FHS/migrated layouts). Without this,
                       both are preserved for a future re-install.

  --restore-resolved   Remove the systemd-resolved drop-in that disabled
                       the 127.0.0.53:53 stub listener, and restart
                       systemd-resolved. Only needed if the install.sh
                       previously disabled it.

  --dry-run            Show actions without making changes.

  --yes, -y            Non-interactive; accept prompts.

  --help, -h           Show this help.
EOF
}

# Returns 1 for BOTH "the operator declined" and "the read failed". Callers
# cannot tell those apart, so every caller must establish that /dev/tty is
# openable before getting here.
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

main() {
	while [[ $# -gt 0 ]]; do
		case $1 in
			--purge)
				PURGE="true"
				shift
				;;
			--restore-resolved)
				RESTORE_RESOLVED="true"
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
				exit 2
				;;
		esac
	done

	[[ $EUID -eq 0 ]] || die "must run as root. Try: sudo $0 $*"
	[[ $DRY_RUN == "true" ]] && warn "DRY RUN — no changes will be made"

	step "Uninstall plan"
	printf '  Stop + disable service:   %s\n' "$UNIT_DEST"
	printf '  Stop + remove backup timer: %s + .service\n' "$BACKUP_TIMER_DEST"
	printf '  Remove binary:            %s\n' "$BINARY_DEST"
	printf '  Remove unit file:         %s\n' "$UNIT_DEST"
	printf '  Remove operator wrapper:  %s\n' "$WRAPPER_DEST"
	printf '  Remove legacy shell function: %s\n' "$LEGACY_PROFILED_WRAPPER"
	printf '  Remove system user:       %s\n' "$SERVICE_USER"
	printf '  Remove runtime dir:       %s\n' "$RUN_DIR"
	printf '  Keep state dir:           %s (%s)\n' "$STATE_DIR" \
		"$([[ $PURGE == "true" ]] && echo 'NO — --purge set, will be deleted' || echo 'yes — preserves config + list cache')"
	printf '  Keep config dir:          %s (%s)\n' "$ETC_DIR" \
		"$([[ $PURGE == "true" ]] && echo 'NO — --purge set, will be deleted' || echo 'yes — preserves master config + tokens')"
	printf '  Restore systemd-resolved: %s\n' \
		"$([[ $RESTORE_RESOLVED == "true" ]] && echo 'yes — re-enable stub listener' || echo 'no')"
	printf '\n'

	if [[ $YES != "true" && $DRY_RUN != "true" ]]; then
		# confirm() reads /dev/tty, which exists as a mode-0666 node even where
		# the process has no controlling terminal — so `[[ -r /dev/tty ]]`
		# would answer true and the read would then fail with ENXIO. Attempt
		# the open instead, and refuse rather than proceed: this removes a
		# resolver, and consent that could not be given must not be assumed.
		#
		# Non-zero, not `exit 0`. An uninstall that removed nothing and
		# reported success is indistinguishable from one that worked, and a
		# script driving this would carry on as though the box were clean.
		if ! (: </dev/tty) 2>/dev/null; then
			err "no terminal available to confirm the uninstall, and --yes was
    not given. Nothing has been removed.

    Re-run non-interactively:
      sudo $0 --yes"
			exit 1
		fi
		confirm "Proceed with uninstall?" || {
			log "aborted"
			exit 0
		}
	fi

	step "Phase 1: Stop and disable service"
	if systemctl is-active --quiet purge-warden.service 2>/dev/null; then
		run systemctl stop purge-warden.service
		ok "service stopped"
	else
		ok "service was not running"
	fi
	if systemctl is-enabled --quiet purge-warden.service 2>/dev/null; then
		run systemctl disable purge-warden.service
		ok "service disabled"
	else
		ok "service was not enabled"
	fi

	# rev-2606 uninstall-01: install.sh enables purge-warden-backup.timer
	# (hourly, Persistent=true). Left behind, it fires `warden config
	# backup --auto` against a deleted binary forever — a permanently
	# failing unit and journal spam. Own block, deliberately NOT nested
	# in the main-unit removal: a partial install (backup units present,
	# main unit already gone) must still be cleaned up.
	step "Phase 1.5: Stop and remove auto-backup timer"
	if systemctl is-active --quiet purge-warden-backup.timer 2>/dev/null; then
		run systemctl stop purge-warden-backup.timer
		ok "backup timer stopped"
	else
		ok "backup timer was not running"
	fi
	if systemctl is-enabled --quiet purge-warden-backup.timer 2>/dev/null; then
		run systemctl disable purge-warden-backup.timer
		ok "backup timer disabled"
	else
		ok "backup timer was not enabled"
	fi
	if [[ -f $BACKUP_TIMER_DEST || -f $BACKUP_UNIT_DEST ]]; then
		run rm -f "$BACKUP_TIMER_DEST" "$BACKUP_UNIT_DEST"
		run systemctl daemon-reload
		run systemctl reset-failed purge-warden-backup.service 2>/dev/null || true
		ok "backup units removed"
	else
		ok "backup units already absent"
	fi

	step "Phase 2: Remove unit file"
	if [[ -f $UNIT_DEST ]]; then
		run rm -f "$UNIT_DEST"
		run systemctl daemon-reload
		run systemctl reset-failed purge-warden.service 2>/dev/null || true
		ok "unit file removed"
	else
		ok "unit file already absent"
	fi

	step "Phase 3: Remove binary"
	if [[ -e $BINARY_DEST ]]; then
		run rm -f "$BINARY_DEST"
		ok "binary removed from $BINARY_DEST"
	else
		ok "binary already absent"
	fi
	# rmdir, not rm -rf: the directory is ours and holds one file, so an
	# empty-check failure means something else put a file there and a
	# recursive delete would take it with us.
	# Its own dry branch rather than `run`: the status of rmdir decides what
	# is reported, and `run` swallows it in dry mode — which would delete the
	# directory during a preview.
	if [[ -d $LIBEXEC_DIR ]]; then
		if [[ $DRY_RUN == "true" ]]; then
			printf '  %s[dry]%s rmdir %s\n' "$C_Y" "$C_R" "$LIBEXEC_DIR"
		elif rmdir "$LIBEXEC_DIR" 2>/dev/null; then
			ok "$LIBEXEC_DIR removed"
		else
			warn "$LIBEXEC_DIR not empty — left in place"
		fi
	fi

	# §4.40 DISC-5: mirror the install-time wrapper drop. The wrapper
	# routes `warden` invocations through the daemon user; leaving it
	# behind after the binary is gone means every `warden` on the box
	# reports "not found or not executable" from a file that still exists
	# — a worse error than the shell's own.
	step "Phase 3.5: Remove the operator wrapper"
	if [[ -e $WRAPPER_DEST ]]; then
		run rm -f "$WRAPPER_DEST"
		ok "operator wrapper removed from $WRAPPER_DEST"
	else
		ok "operator wrapper already absent"
	fi
	# Pre-§4.40-exec hosts carry the shell FUNCTION this replaced. It is
	# sourced by every login shell, so leaving it behind after uninstall
	# gives the operator a `warden` that still exists and does nothing.
	if [[ -f $LEGACY_PROFILED_WRAPPER ]]; then
		run rm -f "$LEGACY_PROFILED_WRAPPER"
		ok "legacy shell function removed from $LEGACY_PROFILED_WRAPPER"
	else
		ok "legacy shell function already absent"
	fi

	step "Phase 4: Remove runtime directory"
	if [[ -d $RUN_DIR ]]; then
		run rm -rf "$RUN_DIR"
		ok "$RUN_DIR removed"
	else
		ok "$RUN_DIR already absent"
	fi

	step "Phase 5: State + config directories"
	if [[ $PURGE == "true" ]]; then
		if [[ -d $STATE_DIR ]]; then
			run rm -rf "$STATE_DIR"
			ok "$STATE_DIR removed (--purge)"
		else
			ok "$STATE_DIR already absent"
		fi
	else
		if [[ -d $STATE_DIR ]]; then
			ok "$STATE_DIR preserved (pass --purge to delete)"
		else
			ok "$STATE_DIR already absent"
		fi
	fi
	# rev-2606 uninstall-02: on FHS/migrated layouts the master config
	# tree lives under /etc/purge-warden — api.token_hash, the device
	# MAC/IP/owner inventory, possibly backups/ archives. "Remove
	# everything" must not leave the most sensitive tree behind.
	if [[ $PURGE == "true" ]]; then
		if [[ -d $ETC_DIR ]]; then
			run rm -rf "$ETC_DIR"
			ok "$ETC_DIR removed (--purge)"
		else
			ok "$ETC_DIR already absent"
		fi
	else
		if [[ -d $ETC_DIR ]]; then
			ok "$ETC_DIR preserved (pass --purge to delete)"
		else
			ok "$ETC_DIR already absent"
		fi
	fi

	step "Phase 6: Remove system user"
	if id "$SERVICE_USER" &>/dev/null; then
		if [[ $PURGE == "true" ]]; then
			run userdel "$SERVICE_USER"
			ok "user $SERVICE_USER removed"
		else
			warn "user $SERVICE_USER still exists (pass --purge to remove)"
		fi
	else
		ok "user $SERVICE_USER already absent"
	fi

	if [[ $RESTORE_RESOLVED == "true" ]]; then
		step "Phase 7: Restore systemd-resolved"
		if [[ -f $RESOLVED_DROPIN ]]; then
			run rm -f "$RESOLVED_DROPIN"
			run systemctl restart systemd-resolved.service
			ok "stub listener re-enabled"
		else
			ok "no drop-in found at $RESOLVED_DROPIN"
		fi
	fi

	step "Uninstall complete"
	printf '\n'
	if [[ $PURGE != "true" ]]; then
		local kept=()
		[[ -d $STATE_DIR ]] && kept+=("$STATE_DIR")
		[[ -d $ETC_DIR ]] && kept+=("$ETC_DIR")
		if ((${#kept[@]} > 0)); then
			printf '%s%s%s preserved. A re-install will pick up the existing config and list cache.\n' \
				"$C_B" "${kept[*]}" "$C_R"
			printf 'To delete later: %ssudo rm -rf %s && sudo userdel %s%s\n' \
				"$C_D" "${kept[*]}" "$SERVICE_USER" "$C_R"
		fi
	fi
	printf '\n'
}

main "$@"
