#!/usr/bin/env bash
# Narrow S6 v3-to-v4 release transaction. SIGKILL/power loss leave .s6-old
# siblings as manual recovery evidence; automatic resume is out of scope.
set -Eeuo pipefail

BINARY=""; MASTER=""; DRY_RUN=false
BIN_DEST=${WARDEN_UPGRADE_BINARY_DEST:-/usr/local/libexec/purge-warden/warden}
UNIT_SOURCE=${WARDEN_UPGRADE_UNIT_SOURCE:-"$(cd "$(dirname "$0")/.." && pwd)/systemd/purge-warden.service"}
UNIT_DEST=${WARDEN_UPGRADE_UNIT_DEST:-/etc/systemd/system/purge-warden.service}
SERVICE=${WARDEN_UPGRADE_SERVICE:-purge-warden.service}
BACKUP_SERVICE=${WARDEN_UPGRADE_BACKUP_SERVICE:-purge-warden-backup.service}
BACKUP_TIMER=${WARDEN_UPGRADE_BACKUP_TIMER:-purge-warden-backup.timer}
PROC_ROOT=${WARDEN_UPGRADE_PROC_ROOT:-/proc}
DNS_SERVER=${WARDEN_UPGRADE_DNS_SERVER:-127.0.0.1}
ALLOW_NAME_EXPLICIT=${WARDEN_UPGRADE_ALLOW_NAME+x}
BLOCK_NAME_EXPLICIT=${WARDEN_UPGRADE_BLOCK_NAME+x}
BLOCK_RESPONSE_EXPLICIT=${WARDEN_UPGRADE_BLOCK_RESPONSE+x}
HEALTH_CONTRACT_EXPLICIT=${WARDEN_UPGRADE_HEALTH_CONTRACT+x}
# Do not use :- here: an explicitly empty probe name is unsafe and must be
# refused before maintenance, rather than silently falling back to a default.
ALLOW_NAME=${WARDEN_UPGRADE_ALLOW_NAME-google.com}
BLOCK_NAME=${WARDEN_UPGRADE_BLOCK_NAME-doubleclick.net}
BLOCK_RESPONSE=${WARDEN_UPGRADE_BLOCK_RESPONSE-zero}
HEALTH_CONTRACT=${WARDEN_UPGRADE_HEALTH_CONTRACT-allow_and_block}
HEALTH_TIMEOUT=${WARDEN_UPGRADE_HEALTH_TIMEOUT_SECS:-300}
HEALTH_INTERVAL=${WARDEN_UPGRADE_HEALTH_INTERVAL_SECS:-1}
FORWARD_TIMEOUT=${WARDEN_UPGRADE_FORWARD_TIMEOUT_SECS:-300}
RECOVERY_TIMEOUT=${WARDEN_UPGRADE_RECOVERY_TIMEOUT_SECS:-15}
RECOVERY_INTERVAL=${WARDEN_UPGRADE_RECOVERY_INTERVAL_SECS:-1}
BIN_BACKUP="${BIN_DEST}.s6-old"; UNIT_BACKUP="${UNIT_DEST}.s6-old"
transaction_started=false; healthy=false; finalized=false; cleanup_running=false
timer_was_active=false; old_elf_saved=false; old_unit_saved=false
old_elf_id=""; old_unit_id=""
critical_rename=false; pending_signal_rc=0
TRANSACTION_PID=$$
export TRANSACTION_PID

usage() { cat <<'USAGE'
usage: upgrade_config_gate.sh --binary <candidate-elf> --config <master> [--dry-run]
  --binary  required executable candidate ELF
  --config  required installed schema-3 master config
  --dry-run validate inputs and print the transaction without mutating

Custom health probes require WARDEN_UPGRADE_BLOCK_RESPONSE=zero|nxdomain|refused|soa_nodata.
By default the allow name must prove a positive answer and the block name must prove the exact
expected block response for the loopback client. Fully restrictive profiles must explicitly set
WARDEN_UPGRADE_HEALTH_CONTRACT=block_all; that contract skips only the positive allow proof.
USAGE
}
die() { echo "upgrade-gate: $*" >&2; exit 1; }
is_uint() { [[ $1 =~ ^[0-9]{1,9}$ ]]; }
regular_file() { [[ -f $1 && ! -L $1 ]]; }
executable_file() { regular_file "$1" && [[ -x $1 ]]; }
file_id() { stat -Lc '%d:%i' "$1"; }

# Return active (0), inactive (1), or unable to confirm state (2).
unit_active() {
	local rc
	set +e
	systemctl is-active --quiet "$1"
	rc=$?
	set -e
	case $rc in 0) return 0 ;; 3) return 1 ;; *) return 2 ;; esac
}

# Limit a command to one absolute deadline. A command that never returns is
# killed by timeout, so the EXIT handler can enter recovery.
before_deadline() { (( SECONDS <= $1 )); }
before_health_deadline() { (( HEALTH_TIMEOUT > 0 && SECONDS < $1 )); }
bounded() {
	local deadline=$1 remaining
	shift
	remaining=$((deadline - SECONDS))
	(( remaining > 0 )) || return 124
	timeout -k 1s "${remaining}s" "$@"
}
sync_parent_by() {
	local deadline=$1 path=$2 parent
	parent=${path%/*}; [[ $parent != "$path" && -n $parent ]] || parent=.
	bounded "$deadline" sync "$parent"
}
file_id_by() { bounded "$1" stat -Lc '%d:%i' "$2"; }
forward() { bounded "$forward_deadline" "$@"; }
# restorecon/reset-failed remain best-effort, but a consumed deadline is fatal.
optional_forward() {
	local rc
	if forward "$@"; then return 0; fi
	rc=$?
	(( SECONDS < forward_deadline )) && return 0
	return "$rc"
}
unit_active_by() {
	local deadline=$1 unit=$2 rc
	before_deadline "$deadline" || return 2
	set +e
	bounded "$deadline" systemctl is-active --quiet "$unit"
	rc=$?
	set -e
	before_deadline "$deadline" || return 2
	case $rc in 0) return 0 ;; 3) return 1 ;; *) return 2 ;; esac
}
unit_active_health_by() {
	local deadline=$1 unit=$2 rc
	before_health_deadline "$deadline" || return 2
	set +e
	bounded "$deadline" systemctl is-active --quiet "$unit"
	rc=$?
	set -e
	before_health_deadline "$deadline" || return 2
	case $rc in 0) return 0 ;; 3) return 1 ;; *) return 2 ;; esac
}
wait_active() {
	local deadline=$1 unit=$2 state sleep_for remaining
	while :; do
		if unit_active_by "$deadline" "$unit"; then return 0; else state=$?; fi
		[[ $state -eq 1 ]] || return 1
		remaining=$((deadline - SECONDS)); (( remaining > 0 )) || return 1
		sleep_for=$RECOVERY_INTERVAL
		(( sleep_for > remaining )) && sleep_for=$remaining
		bounded "$deadline" sleep "$sleep_for" || return 1
	done
}
stop_and_confirm_by() {
	local deadline=$1 unit=$2 state
	bounded "$deadline" systemctl stop "$unit" || :
	if unit_active_by "$deadline" "$unit"; then return 1; else state=$?; fi
	[[ $state -eq 1 ]]
}
contain_participants_by() {
	local deadline=$1 unit
	for unit in "$BACKUP_TIMER" "$BACKUP_SERVICE" "$SERVICE"; do
		stop_and_confirm_by "$deadline" "$unit" || return 1
	done
}
contain_participants() {
	local deadline=$((SECONDS + RECOVERY_TIMEOUT))
	contain_participants_by "$deadline"
}
artifact_matches_by() {
	local deadline=$1 path=$2 expected=$3 observed
	regular_file "$path" || return 1
	if observed=$(file_id_by "$deadline" "$path"); then [[ $observed == "$expected" ]]; else return 1; fi
}
restore_one_artifact_by() {
	local deadline=$1 dest=$2 backup=$3 expected=$4
	if artifact_matches_by "$deadline" "$dest" "$expected"; then
		[[ ! -e $backup && ! -L $backup ]] && return 0
		return 1
	fi
	artifact_matches_by "$deadline" "$backup" "$expected" || return 1
	if ! bounded "$deadline" mv "$backup" "$dest"; then
		# mv may have completed before reporting an error; accept only exact state.
		artifact_matches_by "$deadline" "$dest" "$expected" && [[ ! -e $backup && ! -L $backup ]] || return 1
	fi
	sync_parent_by "$deadline" "$dest" || return 1
	artifact_matches_by "$deadline" "$dest" "$expected" && [[ ! -e $backup && ! -L $backup ]]
}
restore_old_artifacts_by() {
	local deadline=$1 restore_ok=true
	# Reconcile destination/backup identities even if a timed mv reported failure.
	restore_one_artifact_by "$deadline" "$UNIT_DEST" "$UNIT_BACKUP" "$old_unit_id" || restore_ok=false
	restore_one_artifact_by "$deadline" "$BIN_DEST" "$BIN_BACKUP" "$old_elf_id" || restore_ok=false
	executable_file "$BIN_DEST" && regular_file "$UNIT_DEST" || restore_ok=false
	"$restore_ok"
}

recover() {
	local original_rc=$1 rollback_ok=true restore_ok=true old_started=false containment_deadline rollback_deadline restore_deadline
	set +e
	containment_deadline=$((SECONDS + RECOVERY_TIMEOUT))
	if ! contain_participants_by "$containment_deadline"; then
		echo "upgrade-gate: RECOVERY REQUIRED: participant containment was not confirmed; config and recovery artifacts were not modified." >&2
		return 75
	fi
	# Rollback and artifact restoration have separate finite windows: a hung
	# rollback cannot consume the chance to put exact old files back on disk.
	rollback_deadline=$((SECONDS + RECOVERY_TIMEOUT))
	bounded "$rollback_deadline" "$BINARY" migrate v3-to-v4 --from-config "$MASTER" --rollback || rollback_ok=false
	restore_deadline=$((SECONDS + RECOVERY_TIMEOUT))
	restore_old_artifacts_by "$restore_deadline" || restore_ok=false
	# Never start the old daemon until candidate rollback has proved v3.
	if ! "$rollback_ok"; then
		if ! "$restore_ok"; then
			echo "upgrade-gate: RECOVERY REQUIRED: candidate rollback was not confirmed and exact old artifacts could not be restored; backup timer remains stopped and config evidence is preserved." >&2
		else
			echo "upgrade-gate: RECOVERY REQUIRED: candidate rollback was not confirmed; exact old artifacts were restored, but the backup timer remains stopped and config evidence is preserved." >&2
		fi
		return 75
	fi
	bounded "$restore_deadline" systemctl daemon-reload || restore_ok=false
	if "$restore_ok"; then
		bounded "$restore_deadline" systemctl reset-failed "$SERVICE" || true
		if bounded "$restore_deadline" systemctl start "$SERVICE" && wait_active "$restore_deadline" "$SERVICE"; then old_started=true; fi
	fi
	if ! "$old_started"; then
		echo "upgrade-gate: RECOVERY REQUIRED: participant containment, rollback, restore, reload, or old-daemon restart was not confirmed; backup timer was not resumed and evidence is preserved." >&2
		return 75
	fi
	if "$timer_was_active"; then
		restore_deadline=$((SECONDS + RECOVERY_TIMEOUT))
		if ! bounded "$restore_deadline" systemctl start "$BACKUP_TIMER" || ! wait_active "$restore_deadline" "$BACKUP_TIMER"; then
		echo "upgrade-gate: RECOVERY REQUIRED: old daemon recovered but backup timer could not be restored." >&2
		return 75
		fi
	fi
	echo "upgrade-gate: transaction failed; complete v3 state and old daemon were restored." >&2
	return "$original_rc"
}
on_exit() {
	local rc=$?
	trap - EXIT HUP INT TERM
	if "$transaction_started" && ! "$healthy" && ! "$finalized" && ! "$cleanup_running"; then
		cleanup_running=true
		recover "$rc"; exit $?
	fi
	exit "$rc"
}
on_signal() {
	local rc=$1
	if "$critical_rename"; then pending_signal_rc=$rc; return 0; fi
	exit "$rc"
}
finish_pending_signal() {
	local rc=$pending_signal_rc
	pending_signal_rc=0
	[[ $rc -eq 0 ]] || exit "$rc"
}
trap on_exit EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

while [[ $# -gt 0 ]]; do
	case $1 in
		--binary) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; BINARY=$2; shift 2 ;;
		--binary=*) BINARY=${1#*=}; shift ;;
		--config) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; MASTER=$2; shift 2 ;;
		--config=*) MASTER=${1#*=}; shift ;;
		--dry-run) DRY_RUN=true; shift ;;
		--help|-h) usage; exit 0 ;;
		*) echo "upgrade-gate: unknown argument: $1" >&2; usage >&2; exit 2 ;;
	esac
done
[[ -n $BINARY && -n $MASTER ]] || { echo "upgrade-gate: --binary and --config are required" >&2; exit 2; }
executable_file "$BINARY" || { echo "upgrade-gate: candidate is not an executable regular file" >&2; exit 2; }
regular_file "$MASTER" || { echo "upgrade-gate: master is not a regular file" >&2; exit 2; }
executable_file "$BIN_DEST" || { echo "upgrade-gate: installed old ELF is not an executable regular file" >&2; exit 2; }
regular_file "$UNIT_SOURCE" && regular_file "$UNIT_DEST" || { echo "upgrade-gate: unit source or installed unit is not a regular file" >&2; exit 2; }
[[ -d $PROC_ROOT ]] || { echo "upgrade-gate: proc root is not a directory" >&2; exit 2; }
[[ -n $SERVICE && -n $BACKUP_SERVICE && -n $BACKUP_TIMER && -n $DNS_SERVER && -n $ALLOW_NAME && -n $BLOCK_NAME ]] || die "empty transaction override"
is_uint "$HEALTH_TIMEOUT" && is_uint "$HEALTH_INTERVAL" && is_uint "$FORWARD_TIMEOUT" && is_uint "$RECOVERY_TIMEOUT" && is_uint "$RECOVERY_INTERVAL" || { echo "upgrade-gate: timeout and interval overrides must be non-negative bounded integers" >&2; exit 2; }
HEALTH_TIMEOUT=$((10#$HEALTH_TIMEOUT)); HEALTH_INTERVAL=$((10#$HEALTH_INTERVAL))
FORWARD_TIMEOUT=$((10#$FORWARD_TIMEOUT)); RECOVERY_TIMEOUT=$((10#$RECOVERY_TIMEOUT)); RECOVERY_INTERVAL=$((10#$RECOVERY_INTERVAL))
(( FORWARD_TIMEOUT > 0 && RECOVERY_TIMEOUT > 0 )) || { echo "upgrade-gate: forward and recovery timeouts must be greater than zero" >&2; exit 2; }
case $BLOCK_RESPONSE in zero|nxdomain|refused|soa_nodata) ;; *) echo "upgrade-gate: WARDEN_UPGRADE_BLOCK_RESPONSE must be zero, nxdomain, refused, or soa_nodata" >&2; exit 2 ;; esac
case $HEALTH_CONTRACT in allow_and_block|block_all) ;; *) echo "upgrade-gate: WARDEN_UPGRADE_HEALTH_CONTRACT must be allow_and_block or block_all" >&2; exit 2 ;; esac
if [[ -n $ALLOW_NAME_EXPLICIT || -n $BLOCK_NAME_EXPLICIT ]] && [[ -z $BLOCK_RESPONSE_EXPLICIT ]]; then
	echo "upgrade-gate: custom health probes require explicit WARDEN_UPGRADE_BLOCK_RESPONSE; the effective resolver profile cannot be inferred safely" >&2
	exit 2
fi
command -v timeout >/dev/null 2>&1 && timeout -k 1s 1s true >/dev/null 2>&1 || { echo "upgrade-gate: usable timeout command is required before maintenance" >&2; exit 2; }
if ! candidate_id=$(file_id "$BINARY") || ! installed_id=$(file_id "$BIN_DEST") || ! old_unit_id=$(file_id "$UNIT_DEST") || [[ ! $candidate_id =~ ^[0-9]+:[0-9]+$ || ! $installed_id =~ ^[0-9]+:[0-9]+$ || ! $old_unit_id =~ ^[0-9]+:[0-9]+$ ]]; then
	echo "upgrade-gate: cannot determine executable identities" >&2; exit 2
fi
old_elf_id=$installed_id
[[ $candidate_id != "$installed_id" ]] || { echo "upgrade-gate: candidate and installed ELF must differ" >&2; exit 2; }
[[ ! -e $BIN_BACKUP && ! -L $BIN_BACKUP && ! -e $UNIT_BACKUP && ! -L $UNIT_BACKUP ]] || { echo "upgrade-gate: refusing pre-existing .s6-old recovery evidence" >&2; exit 2; }
if "$DRY_RUN"; then echo "upgrade-gate: [dry] candidate check, quiesce, preserve, migrate, lint, install, health, finalize"; exit 0; fi

if ! check_output=$("$BINARY" migrate v3-to-v4 --from-config "$MASTER" --check); then
	echo "upgrade-gate: candidate check refused; v2 requires a separately reviewed/manual upgrade." >&2; exit 3
fi
if [[ $check_output == *$'\n'* || ! $check_output =~ ^schema-3\ config\ is\ ready\ for\ v3-to-v4\ migration\ \([0-9]+\ members\)$ ]]; then
	echo "upgrade-gate: S6 transaction not applicable: candidate check did not report exact v3-ready status." >&2; exit 3
fi
printf '%s\n' "$check_output"

# Entry refusal is non-mutating; capture timer policy before maintenance begins.
if unit_active "$SERVICE"; then :; else
	state=$?; [[ $state -eq 1 ]] && die "old daemon must be active before S6 cutover" || die "cannot confirm old daemon state"
fi
if unit_active "$BACKUP_TIMER"; then timer_was_active=true; else
	state=$?; [[ $state -eq 1 ]] || die "cannot confirm backup timer state"
fi
transaction_started=true
contain_participants || die "failed to quiesce every managed participant"
forward_deadline=$((SECONDS + FORWARD_TIMEOUT))
if old_inode=$(file_id_by "$forward_deadline" "$BIN_DEST"); then
	[[ $old_inode =~ ^[0-9]+:[0-9]+$ && $old_inode == "$old_elf_id" ]] || die "installed old ELF changed before process audit"
else
	rc=$?
	echo "upgrade-gate: cannot determine installed old ELF identity for process audit" >&2
	exit "$rc"
fi
printf 'process-audit:begin\n' >&2
for pid_dir in "$PROC_ROOT"/[0-9]*; do
	[[ -d $pid_dir ]] || continue
	exe="$pid_dir/exe"
	[[ -e $exe || -L $exe ]] || continue
	if exe_inode=$(file_id_by "$forward_deadline" "$exe" 2>/dev/null); then
		[[ $exe_inode != "$old_inode" ]] || die "legacy process remains: PID ${pid_dir#"$PROC_ROOT"/}; close it before retrying"
	else
		rc=$?
		if [[ -d $pid_dir && ( -e $exe || -L $exe ) ]]; then
			[[ $rc -eq 124 ]] && { echo "upgrade-gate: process audit deadline expired" >&2; exit "$rc"; }
			die "cannot audit legacy process: PID ${pid_dir#"$PROC_ROOT"/}"
		fi
		continue
	fi
done
printf 'process-audit:complete\n' >&2
if current_unit_id=$(file_id_by "$forward_deadline" "$UNIT_DEST"); then
	[[ $current_unit_id == "$old_unit_id" ]] || die "installed old daemon unit changed before preservation"
else
	rc=$?
	echo "upgrade-gate: cannot determine installed old daemon unit identity" >&2
	exit "$rc"
fi
critical_rename=true
if forward mv "$BIN_DEST" "$BIN_BACKUP"; then old_elf_saved=true; else
	rc=$?; critical_rename=false; finish_pending_signal; exit "$rc"
fi
critical_rename=false
sync_parent_by "$forward_deadline" "$BIN_DEST"
finish_pending_signal
critical_rename=true
if forward mv "$UNIT_DEST" "$UNIT_BACKUP"; then old_unit_saved=true; else
	rc=$?; critical_rename=false; finish_pending_signal; exit "$rc"
fi
critical_rename=false
sync_parent_by "$forward_deadline" "$UNIT_DEST"
finish_pending_signal
# No candidate config mutation may begin until this invocation has durably
# preserved both exact old artifacts. Recovery can still reconcile an
# ambiguous failed rename from inode evidence, but the forward path may not
# proceed on a merely attempted preservation.
if ! "$old_elf_saved" || ! "$old_unit_saved"; then
	die "old ELF and daemon unit were not both preserved before migration"
fi
forward "$BINARY" migrate v3-to-v4 --from-config "$MASTER"
forward "$BINARY" --config "$MASTER" config lint
forward install -m 0755 "$BINARY" "$BIN_DEST"
if command -v restorecon >/dev/null 2>&1; then optional_forward restorecon -F "$BIN_DEST"; fi
forward install -m 0644 "$UNIT_SOURCE" "$UNIT_DEST"
if command -v restorecon >/dev/null 2>&1; then optional_forward restorecon -F "$UNIT_DEST"; fi
forward systemctl daemon-reload
optional_forward systemctl reset-failed "$SERVICE"
forward systemctl start "$SERVICE"

valid_ipv4() {
	local ip=$1 a b c d part
	[[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
	IFS=. read -r a b c d <<<"$ip"
	for part in "$a" "$b" "$c" "$d"; do (( 10#$part <= 255 )) || return 1; done
}
dns_status_is() {
	local response=$1 expected=$2 pattern
	pattern="status:[[:space:]]*${expected},"
	[[ $response =~ $pattern ]]
}
dns_has_answer() { [[ $1 =~ ANSWER:[[:space:]]*[1-9][0-9]*, ]]; }
dns_has_no_answer() { [[ $1 =~ ANSWER:[[:space:]]*0, ]]; }
dns_has_authority() { [[ $1 =~ AUTHORITY:[[:space:]]*[1-9][0-9]*, ]]; }
allow_response_ok() {
	local response=$1 line owner= ttl= class= type= value= rest= positive=false zero=false
	dns_status_is "$response" NOERROR && dns_has_answer "$response" || return 1
	while IFS= read -r line; do
		read -r owner ttl class type value rest <<<"$line"
		[[ $class == IN && $type == A ]] || continue
		valid_ipv4 "$value" || return 1
		[[ $value == 0.0.0.0 ]] && zero=true || positive=true
	done <<<"$response"
	[[ $positive == true && $zero == false ]]
}
zero_response_ok() {
	local response=$1 line owner= ttl= class= type= value= rest= zero=false routable=false
	dns_status_is "$response" NOERROR && dns_has_answer "$response" || return 1
	while IFS= read -r line; do
		read -r owner ttl class type value rest <<<"$line"
		[[ $class == IN && $type == A ]] || continue
		valid_ipv4 "$value" || return 1
		[[ $value == 0.0.0.0 ]] && zero=true || routable=true
	done <<<"$response"
	[[ $zero == true && $routable == false ]]
}
block_response_ok() {
	local response=$1
	case $BLOCK_RESPONSE in
		zero) zero_response_ok "$response" ;;
		nxdomain) dns_status_is "$response" NXDOMAIN && dns_has_no_answer "$response" ;;
		refused) dns_status_is "$response" REFUSED && dns_has_no_answer "$response" ;;
		soa_nodata)
			dns_status_is "$response" NOERROR && dns_has_no_answer "$response" && dns_has_authority "$response" &&
				[[ $response == *"AUTHORITY SECTION:"* && $response =~ [[:space:]]IN[[:space:]]SOA[[:space:]] ]]
			;;
	esac
}
health_probe() {
	local deadline=$1 output
	shift
	before_health_deadline "$deadline" || return 2
	if output=$(bounded "$deadline" "$@" 2>/dev/null); then :; else return 1; fi
	before_health_deadline "$deadline" || return 2
	printf '%s' "$output"
}
deadline=$((SECONDS + HEALTH_TIMEOUT))
while :; do
	before_health_deadline "$deadline" || die "candidate health deadline expired"
	unit_active_health_by "$deadline" "$SERVICE" || die "candidate daemon became inactive or could not be confirmed during health gate"
	listener_ok=false; allow_ok=false; block_ok=false
	if health_probe "$deadline" dig "@$DNS_SERVER" +time=1 +tries=1 +norec localhost >/dev/null; then
		listener_ok=true
		if [[ $HEALTH_CONTRACT == block_all ]]; then
			# This is deliberately narrow: a fully restrictive profile still has
			# to answer locally and prove the configured block response exactly.
			allow_ok=true
		elif allow=$(health_probe "$deadline" dig "@$DNS_SERVER" +time=1 +tries=1 "$ALLOW_NAME" A); then
			allow_response_ok "$allow" && allow_ok=true
		fi
		if block=$(health_probe "$deadline" dig "@$DNS_SERVER" +time=1 +tries=1 "$BLOCK_NAME" A); then block_response_ok "$block" && block_ok=true; fi
	fi
	if "$listener_ok" && "$allow_ok" && "$block_ok"; then
		before_health_deadline "$deadline" || die "candidate health deadline expired"
		unit_active_health_by "$deadline" "$SERVICE" || die "candidate daemon became inactive or could not be confirmed during health gate"
		before_health_deadline "$deadline" || die "candidate health deadline expired"
		healthy=true
		break
	fi
	remaining=$((deadline - SECONDS))
	(( remaining > 0 )) || die "candidate health deadline expired"
	sleep_for=$HEALTH_INTERVAL
	(( sleep_for > remaining )) && sleep_for=$remaining
	bounded "$deadline" sleep "$sleep_for" || die "candidate health deadline expired"
done
finalize_deadline=$((SECONDS + FORWARD_TIMEOUT))
if ! bounded "$finalize_deadline" "$BINARY" migrate v3-to-v4 --from-config "$MASTER" --finalize; then
	echo "upgrade-gate: finalize failed after health; candidate remains running. Inspect evidence and rerun candidate --finalize." >&2; exit 1
fi
finalized=true
post_health_deadline=$((SECONDS + RECOVERY_TIMEOUT))
if "$timer_was_active"; then
	if ! bounded "$post_health_deadline" systemctl start "$BACKUP_TIMER" || ! wait_active "$post_health_deadline" "$BACKUP_TIMER"; then
		echo "upgrade-gate: finalized candidate remains running; backup timer was not confirmed active and old backups were retained." >&2
		exit 75
	fi
fi
if ! bounded "$post_health_deadline" rm -f "$BIN_BACKUP" "$UNIT_BACKUP" || ! sync_parent_by "$post_health_deadline" "$BIN_DEST" || ! sync_parent_by "$post_health_deadline" "$UNIT_DEST"; then
	echo "upgrade-gate: finalized candidate remains running; old backup cleanup did not complete. Inspect remaining evidence." >&2
	exit 75
fi
echo "upgrade-gate: S6 v3-to-v4 transaction completed"
