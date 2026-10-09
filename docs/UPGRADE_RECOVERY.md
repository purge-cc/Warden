# Upgrade recovery

This reference covers `install.sh --upgrade`: how the upgrade transaction runs,
what its exit statuses mean, and how to recover by hand when it ends with
`RECOVERY REQUIRED` or is killed. Some installer and gate messages name the
section to read; after any other `RECOVERY REQUIRED`, start at
[End states after exit 75](#end-states-after-exit-75).

The file ships in the release bundle as `docs/UPGRADE_RECOVERY.md`, beside the
`scripts/` directory that holds `install.sh`. A bundle installed with `get.sh`
is unpacked to `/usr/local/lib/purge-warden` by default. A source checkout has
the file at the same relative path. Below, `<bundle>` is the directory that
holds the unpacked bundle, `<candidate-elf>` is the `warden` executable in it,
and `<master>` is the installed master configuration file.

## How the upgrade runs

The supported upgrade is `sudo ./scripts/install.sh --upgrade`, which hands the
cutover to
`scripts/upgrade_config_gate.sh --binary <candidate-elf> --config <master>`. The
candidate reads the installed tree and decides its schema before anything changes.
An unknown or unreadable schema is refused with nothing changed. The gate then
quiesces the daemon and backup service/timer, refuses while any process still
executes the old ELF, and preserves that ELF and its unit. Next it runs the
forward steps for that schema and lints. It then installs one candidate
generation, starts it, proves listener/allow/block health, and only then
finalizes. Do not restart any old or new reader between migration phases.

| Installed schema | Forward steps | Finalize |
|------------------|---------------|----------|
| 3 | `migrate v3-to-v4` | `migrate v3-to-v4 --finalize` with the candidate running |
| 4 | `migrate v4-to-v5 --check` before quiescing, then `--plan`, then `--apply-plan` | stop the healthy candidate, `migrate v4-to-v5 --finalize`, start it again |
| 5 | none | none; health alone commits the swap |

For schema 4, the gate refuses before quiescing when `--check` fails or reports
`apply blocked: true`. Review those findings with
`<candidate-elf> --config <master> migrate v4-to-v5 --check --json`, resolve them,
and run the upgrade again. The plan and the apply receipt are written to a new
root-only directory, `/var/tmp/purge-warden-v4-to-v5.XXXXXX`, whose path the gate
prints. `/var/tmp` survives a reboot, so the receipt is still there for a manual
rollback. `WARDEN_UPGRADE_WORK_ROOT` replaces `/var/tmp`; `TMPDIR` is ignored. Before
any change, the gate refuses a root that is not an absolute path of real directories,
each owned by root and, if group or others can write it, sticky. The directory is
removed only after a completed transaction. The
v4-to-v5 apply, rollback and finalize take the daemon's offline PID lease, so
the daemon is always stopped while they run.

The default health contract requires all three proofs against the loopback
resolver: a responding listener, a positive IPv4 answer for `google.com`, and a
zero-address block answer for `doubleclick.net`. Sites using different probe
names, or a non-zero response with the default names, must set
`WARDEN_UPGRADE_BLOCK_RESPONSE` explicitly to `zero`, `nxdomain`, `refused`, or
`soa_nodata`; the gate does not infer policy from the installed configuration.
A fully restrictive profile may set
`WARDEN_UPGRADE_HEALTH_CONTRACT=block_all`. That explicit contract skips only
the positive allow proof and still requires both the listener and the exact
configured block response. Empty probe names and unknown contracts are refused
before maintenance begins.

Forward work and post-health finalization each have a finite 300-second window
by default (`WARDEN_UPGRADE_FORWARD_TIMEOUT_SECS`). Health has its own
300-second window (`WARDEN_UPGRADE_HEALTH_TIMEOUT_SECS`). Each recovery phase is
bounded independently by `WARDEN_UPGRADE_RECOVERY_TIMEOUT_SECS`, 15 seconds by
default, so a hung rollback cannot consume the opportunity to restore the exact
old ELF and unit from inode-verified backups. These values may be raised for a
known slow host, but must remain positive integers.

## Schema 3

The schema-3 migration CLI phases are below. The gate runs `--check` before it
quiesces anything, as the read-only probe that decides the schema; the migration
and the lint run with every old participant quiesced:

```bash
<candidate-elf> migrate v3-to-v4 --from-config <master> --check
<candidate-elf> migrate v3-to-v4 --from-config <master>
<candidate-elf> --config <master> config lint
```

The normal migration retains a journaled schema-3 rollback snapshot. Before
finalization, a failed candidate is recovered under the same quiescence boundary
with:

```bash
<candidate-elf> migrate v3-to-v4 --from-config <master> --rollback
```

After that succeeds, restore the preserved old unit and ELF before restarting the
old daemon. If candidate health succeeds, commit the new side and discard the
migration rollback snapshot with:

```bash
<candidate-elf> migrate v3-to-v4 --from-config <master> --finalize
```

Finalization is the rollback cliff: after it, the migration CLI has no retained
schema-3 snapshot to restore. A finalize failure after health is not permission to
start the old daemon; keep the healthy candidate running, inspect the retained
evidence, and retry `--finalize`. Never delete `.warden-migration` or
`.warden-migration.cleanup-*` by hand. Directory flock and directory fsync require
supported local Linux filesystem semantics; network filesystem behavior is not
certified.

## Schema 4 and exit 75

For schema 4, a failure or signal at any point before a confirmed finalize rolls
back with the apply receipt. If apply never returned a receipt, the gate accepts
the tree only when `--check` still reports the source revision it recorded
before any change: the one it read again after stopping the daemon or, if that
read failed, the one it read before. Any other state is left for the operator.
Do not change the configuration while `install.sh --upgrade` runs: the
migration can roll back only a tree that is unchanged since apply.

After a confirmed v4-to-v5 finalize there is no rollback: if the candidate then
fails to restart, the gate exits 75 and leaves the backup timer and `.s6-old`
evidence in place. From the start of finalize the gate ignores HUP, INT and
TERM, so a signal cannot cut the transaction short. If finalize itself fails,
the gate asks for a rollback with the receipt. The answer `"not_found"` means
finalize did commit; `"not_applicable"` means the schema-5 tree changed after
apply. Either way there is nothing to roll back and the old binary cannot read
schema 5, so the gate exits 75 without restoring the old ELF and unit. The
candidate ELF and unit stay installed, the old ones stay as `.s6-old`, and
recovery is end state b in [End states after exit 75](#end-states-after-exit-75).

If rollback fails or times out, the gate may still restore the exact old ELF and
unit when their recorded identities prove the result. It deliberately does not
start that binary until config rollback has also been confirmed. It then exits 75
with `RECOVERY REQUIRED` and keeps the service and backup timer stopped for
operator recovery; retained migration evidence must not be discarded.

## Manual schema-4 recovery

Use these commands only to recover from exit 75 or from a killed upgrade, never
as a replacement for `install.sh --upgrade`. Run them as root, with the daemon,
the backup service and the backup timer stopped. Use the unpacked candidate ELF
from the release bundle, not `/usr/local/bin/warden`, and give the installed
master with `--config`:

```bash
<candidate-elf> --config <master> migrate v4-to-v5 --check
<candidate-elf> --config <master> migrate v4-to-v5 --plan <new-file>
<candidate-elf> --config <master> migrate v4-to-v5 --apply-plan <plan> --expect-plan-hash <hash>
<candidate-elf> --config <master> migrate v4-to-v5 --rollback <receipt_id> --expect-revision <candidate_config_revision>
<candidate-elf> --config <master> migrate v4-to-v5 --finalize <receipt_id>
```

`receipt_id` and `candidate_config_revision` are in `receipt.json` in the
directory the gate printed. If that file is missing or empty, first check, as
the gate does without a receipt, whether apply changed anything: if `--check`
prints `source revision:` followed by the `source_config_revision` field of the
retained `plan.json` from that directory, the configuration is still the one
the plan was made from, so there is nothing to roll back; continue as after a
confirmed `--rollback` below. Otherwise run the same `--apply-plan` again with
that `plan.json`, giving its `plan_hash` field as `<hash>`. After a committed
apply, the replay returns the existing receipt and changes nothing. If the apply
did not commit, the replay applies the plan now, if the master still matches
it, and returns its new receipt. Either way, run `--rollback` with the receipt
it returns.

`--rollback` is confirmed only when it answers `"restored"` or
`"already_restored"`. After `"not_found"` (finalize had committed) or
`"not_applicable"` (the configuration changed after apply), follow end state b
in [End states after exit 75](#end-states-after-exit-75) instead. After a
confirmed `--rollback`, move each of
`/usr/local/libexec/purge-warden/warden.s6-old` and
`/etc/systemd/system/purge-warden.service.s6-old` that exists back over the
installed binary or unit, run `systemctl daemon-reload` and
`systemctl reset-failed purge-warden.service`, then start
`purge-warden.service` and, if it is enabled, `purge-warden-backup.timer`.

## End states after exit 75

Before it exits 75, the gate prints one of the messages below. Earlier lines of
its output, also kept in the install log, give the schema it found as
`candidate reports config schema <N>` and, for schema 4 once it has created it,
the plan and receipt directory, a new `/var/tmp/purge-warden-v4-to-v5.*`
directory, as `v4-to-v5 plan and receipt: <dir>`. The gate stops the backup
timer before it changes anything, so `systemctl is-active` no longer shows
whether the timer ran before the upgrade. "If it is enabled" below means
`systemctl is-enabled purge-warden-backup.timer` prints `enabled`. The old ELF,
`<old-elf>` below, is `/usr/local/libexec/purge-warden/warden.s6-old` if that
file exists, and otherwise the installed `/usr/local/libexec/purge-warden/warden`.

- `is finalized and has no rollback` or `finalized candidate remains running`,
  any schema: the upgrade is committed and cannot be rolled back, and the
  candidate ELF and unit are installed. If `purge-warden.service` is not
  running, run `systemctl daemon-reload` and
  `systemctl reset-failed purge-warden.service`, and start it (its journal
  shows why it did not restart). Once it runs, start the backup timer if it
  is enabled and delete the `.s6-old` files that remain.
  `install.sh` skipped its post-upgrade steps; run the same
  `install.sh --upgrade` again to finish them.
- `v4-to-v5 cannot roll back`: end state b.
- `old daemon recovered but backup timer could not be restored`: the old
  version runs on the configuration it had before the upgrade. Start the backup
  timer if it is enabled.
- Any other message, any schema: end state a. These messages can follow a
  failure at any point of the upgrade, so its checks find the state instead of
  the message. A `.s6-old` refusal whose lint fails, and the refusal to
  upgrade a schema-5 master while the old daemon is inactive, also lead here.

a. Restore the old version:
   1. Stop `purge-warden-backup.timer`, `purge-warden-backup.service` and
      `purge-warden.service`, and check that `systemctl is-active` reports none
      of them active.
   2. Make sure the old version reads the configuration. If `warden.s6-old`
      does not exist and
      `cmp <candidate-elf> /usr/local/libexec/purge-warden/warden` prints
      nothing, the candidate is installed and the upgrade was committed: follow
      the first entry above instead. Otherwise take the first case that applies:
      - The plan and receipt directory of the failed upgrade holds a non-empty
        `receipt.json`: run `--rollback` with it as in
        [Manual schema-4 recovery](#manual-schema-4-recovery). Go on once it
        answers `"restored"` or `"already_restored"`. After `"not_found"` or
        `"not_applicable"`, follow b instead. If it fails, fix the cause its
        error names and run it again.
      - The failed upgrade found schema 3: run
        `<candidate-elf> migrate v3-to-v4 --from-config <master> --rollback`
        (see [Schema 3](#schema-3)), and go on only once it prints
        `schema-3 config restored and valid` or
        `schema-3 config is already valid; no rollback snapshot found`.
      - The directory holds a `plan.json`: follow
        [Manual schema-4 recovery](#manual-schema-4-recovery) for a missing or
        empty `receipt.json`.
      - `<old-elf> --config <master> config lint` passes: the old version reads
        the configuration as it is. Go on.
      - Otherwise start neither version: keep every file as it is and find out
        why the old ELF fails lint.
   3. Move each `.s6-old` file that remains back over the installed binary or
      unit, run `systemctl daemon-reload` even if no file moved (the gate may
      have loaded the candidate unit) and
      `systemctl reset-failed purge-warden.service`, and start
      `purge-warden.service`.
   4. Start the backup timer if it is enabled.

b. Keep the candidate: the configuration is schema 5, which the old binary
   cannot read, and `--rollback` answered `"not_found"` (finalize had committed)
   or `"not_applicable"` (the configuration changed after apply). To go back
   instead after `"not_applicable"`, undo the configuration change made during
   the upgrade so that `--rollback` answers `"restored"`, then finish as in a.
   Otherwise, with the daemon, the backup service and the backup timer stopped:
   1. Check that `<candidate-elf> --config <master> config lint` passes: the
      candidate reads only schema 5. If it fails while
      `<old-elf> --config <master> config lint` passes, continue with step 3 of
      a instead. If both fail, start neither version and keep every file as it
      is.
   2. If `warden.s6-old` does not exist, rename the installed
      `/usr/local/libexec/purge-warden/warden` to it; do the same for
      `purge-warden.service.s6-old` and the installed unit. The old files stay
      as `.s6-old`.
   3. Install the candidate:
      `install -m 0755 <candidate-elf> /usr/local/libexec/purge-warden/warden`,
      `install -m 0644 <bundle>/systemd/purge-warden.service /etc/systemd/system/`,
      `restorecon -F` on both paths where SELinux is enabled, then
      `systemctl daemon-reload`.
   4. Run `systemctl reset-failed purge-warden.service`, start
      `purge-warden.service`, and check that `systemctl is-active` reports it
      active and that it answers the health probes described in
      [How the upgrade runs](#how-the-upgrade-runs). Do not finalize a
      candidate that fails them; read its journal. After `"not_applicable"`,
      stop it: you can then fix the cause and repeat this step, or go back as
      described above, which needs it stopped. After `"not_found"`, finalize
      has committed and stopping it only leaves the resolver down: keep it
      running while you find the cause.
   5. Stop `purge-warden.service`, check that `systemctl is-active` no longer
      reports it active, and run
      `<candidate-elf> --config <master> migrate v4-to-v5 --finalize <receipt_id>`,
      with the `receipt_id` you gave `--rollback`: the one in `receipt.json`
      in the plan and receipt directory, or the one the replayed `--apply-plan`
      returned. It answers `"finalized"`, `"already_finalized"` if finalize
      had committed, or `"not_found"` if the receipt has expired together with
      its undo data; go on after any of these. If it fails, run
      `systemctl reset-failed purge-warden.service`, start the candidate again,
      fix the cause its error names and repeat this step. Then run
      `systemctl reset-failed purge-warden.service`, start the daemon again and
      check that `systemctl is-active` reports it active.
   6. Start the backup timer if it is enabled, delete the two `.s6-old` files,
      and run the same `install.sh --upgrade` again to finish the post-upgrade
      steps.

## Signals

Ctrl-C, a `kill` of the process group, or a terminal hangup reaches
`install.sh`, its log `tee` and the gate together when `install.sh` runs from
an interactive shell, directly or under `sudo`, or under `sudo` with `use_pty`,
the default from sudo 1.9.14. Before the transaction is committed, the gate
then restores the old version as for any other failure. Once recovery has
started it ignores further HUP, INT and TERM; each recovery phase is bounded.
Once the transaction is committed it ignores them as well and completes: for
schema 3 and 5 from the moment the health gate passes, for schema 4 from the
start of the v4-to-v5 finalize. The log `tee` ignores these signals too. The
gate ignores SIGPIPE, and a report it cannot write neither stops its recovery
nor changes its exit status, so the recovery report still reaches the install
log and, if it is still open, the terminal.

Ctrl-\ (QUIT) does not stop the gate: the transaction runs to its end, and
`install.sh` then stops with one of the statuses below, 4 if the transaction
completed.

A signal sent to the `install.sh` PID alone reaches only `install.sh`. So does
a hangup when `install.sh` itself leads the terminal session (for example
`ssh -tt root@host bash install.sh --upgrade`), or when `sudo` without
`use_pty`, the sudoers default before sudo 1.9.14, leads it (for example
`ssh -t admin@host sudo bash install.sh --upgrade`). The gate is not signalled
and runs to its end. `install.sh` then
stops with one of the statuses below, 4 if the transaction completed.

If the log `tee` itself is killed, later reports reach neither the install log
nor the terminal. A failed gate still sets the exit status of `install.sh`.
After a completed transaction, `install.sh` then exits 1 before its
post-upgrade steps; rerun `install.sh --upgrade` to finish them.

`install.sh --upgrade` exits with one of these statuses after a signal:

- 130: interrupted. Without a gate message, the signal came before the
  transaction started and nothing was changed. Otherwise follow the gate
  message above it. It says that the old version was restored, or, when a
  schema-3 finalize failed after the health gate, that the candidate remains
  running and needs `--finalize`. If `install.sh` says instead that the state
  of the upgrade is unknown, run the checks it names.
- 75: `RECOVERY REQUIRED`. Use [End states after exit 75](#end-states-after-exit-75).
- 4: the upgrade transaction completed before the signal stopped the installer:
  `install.sh` found the candidate ELF installed and no `.s6-old` file. The new
  version is installed and running, but the post-upgrade steps were skipped.
  Run the same `install.sh --upgrade` command again to finish them.

## Killed or crashed upgrades

Only SIGKILL, a power loss or a crash can leave a host outside these statuses.
It can stop the gate at any point. The old ELF and unit can then remain only as
`.s6-old`, and the installed ELF or unit can be missing. The gate and
`install.sh --upgrade` refuse to start while a `.s6-old` file exists, and their
refusals give the manual recovery steps: with a v4-to-v5 receipt from that
upgrade, use [Manual schema-4 recovery](#manual-schema-4-recovery); otherwise
move the old files back if the old ELF still lints the master. If the gate was
killed after the health gate passed for schema 3 or 5, the candidate is already
running and can be kept instead: for schema 3 first run
`<candidate-elf> migrate v3-to-v4 --from-config <master> --finalize`; then start
the backup timer if it is enabled, delete the two `.s6-old` files and run the
same `install.sh --upgrade` again to finish the post-upgrade steps.

## Evidence kept after a rollback

A v4-to-v5 rollback keeps evidence for later inspection. The first two
directories are in the node state directory, `/var/lib/purge-warden` on a
standard install:

- `.warden-policy-receipts/<namespace>/<key>.json` is the receipt of the rolled
  back transaction.
- `.warden-policy-transactions/<namespace>/<key>` is its finished journal and
  undo data.
- `/var/tmp/purge-warden-v4-to-v5.*` holds the plan and the apply receipt.

The receipt and its journal are kept for at least 24 hours. A later policy
transaction then removes them. The gate removes the `/var/tmp` directory only
after a completed transaction; after a rollback, remove it by hand once you no
longer need it.

A candidate that refuses to start, for example on a schema-4 master, first runs
its startup recovery. That creates lock files and private state directories such
as `.warden-node-lifecycle` and `.warden-policy-receipts` in the node state
directory, with an empty lifecycle index. They hold no policy or configuration.
The old version starts with them in place, and the next upgrade reuses them, so
leave them.
