BINARY   := warden
PREFIX   := /usr/local
# The real binary lives off PATH; $(PREFIX)/bin/warden is the operator
# wrapper written by scripts/install.sh, and the systemd units ExecStart the
# libexec path. Installing the ELF to $(PREFIX)/bin would destroy the wrapper
# AND leave the daemon on the old libexec binary — a box that looks upgraded
# and is not.
LIBEXEC  := $(PREFIX)/libexec/purge-warden
SYSTEMD  := /etc/systemd/system
STATE    := /var/lib/purge-warden
ARM_TARGET := aarch64-unknown-linux-musl

.PHONY: build build-arm test install upgrade uninstall clean

build:
	cargo build --release

build-arm:
	cargo build --release --target $(ARM_TARGET)

test:
	./scripts/check_no_raw_fs_write.sh
	cargo fmt --check
	cargo clippy --all-targets
	cargo test

# First-time install: places the binary in $(LIBEXEC), the units and an
# example config, and reloads systemd. It does not start the service or
# write the `warden` wrapper. Next, run `$(LIBEXEC)/warden init`, then
# `systemctl enable --now purge-warden`. `sudo ./scripts/install.sh` does
# the whole install, including the LAN CIDR allow-list.
install: build
	install -Dm755 target/release/$(BINARY)           $(LIBEXEC)/$(BINARY)
	install -Dm644 systemd/purge-warden.service        $(SYSTEMD)/purge-warden.service
	install -Dm644 systemd/purge-warden-backup.service $(SYSTEMD)/purge-warden-backup.service
	install -Dm644 systemd/purge-warden-backup.timer   $(SYSTEMD)/purge-warden-backup.timer
	install -Dm644 config/default.toml                 $(STATE)/config.toml.example
	systemctl daemon-reload
	@echo "Installed the binary + unit. This target does NOT write the operator"
	@echo "wrapper at $(PREFIX)/bin/$(BINARY), so \`warden\` is not on PATH yet —"
	@echo "run 'sudo ./scripts/install.sh' for the end-to-end install."
	@echo "Then: '$(LIBEXEC)/$(BINARY) init' to create the system user + directories."

# Upgrade from this tree: build, then run scripts/upgrade_config_gate.sh with
# the new binary and the installed config. It checks the config and migrates
# a schema-3 or schema-4 config, swaps the binary and unit, and puts the old
# ones back on failure. It does not refresh
# the `warden` wrapper or the backup units; `sudo ./scripts/install.sh
# --upgrade` does.
upgrade: build
	@set -eu; \
	if [ -e /etc/purge-warden/config.toml ] || [ -L /etc/purge-warden/config.toml ]; then \
		if [ ! -f /etc/purge-warden/config.toml ] || [ -L /etc/purge-warden/config.toml ]; then echo "REFUSING: unsupported /etc/purge-warden/config.toml master (must be a regular non-symlink file)."; exit 1; fi; cfg=/etc/purge-warden/config.toml; \
	elif [ -e $(STATE)/config.toml ] || [ -L $(STATE)/config.toml ]; then \
		if [ ! -f $(STATE)/config.toml ] || [ -L $(STATE)/config.toml ]; then echo "REFUSING: unsupported $(STATE)/config.toml master (must be a regular non-symlink file)."; exit 1; fi; cfg=$(STATE)/config.toml; \
	else echo "REFUSING: no installed regular master config found in /etc/purge-warden or $(STATE)."; exit 1; fi; \
	if [ -f "$(PREFIX)/bin/$(BINARY)" ] && head -c4 "$(PREFIX)/bin/$(BINARY)" 2>/dev/null | grep -q 'ELF'; then \
		if [ -f "$(LIBEXEC)/$(BINARY)" ] && [ ! -L "$(LIBEXEC)/$(BINARY)" ] && [ -x "$(LIBEXEC)/$(BINARY)" ] && head -c4 "$(LIBEXEC)/$(BINARY)" 2>/dev/null | grep -q 'ELF'; then \
			echo "REFUSING: $(PREFIX)/bin/$(BINARY) is a raw binary, not the warden wrapper. Nothing was changed."; \
			echo "  Run 'sudo ./scripts/install.sh --upgrade' instead: it upgrades the daemon and puts the wrapper back."; \
		else \
			echo "REFUSING: $(PREFIX)/bin/$(BINARY) is a raw binary and $(LIBEXEC)/$(BINARY) is missing or not a regular executable: an old layout that no upgrade converts in place. Nothing was changed."; \
		fi; exit 1; \
	fi; \
	./scripts/upgrade_config_gate.sh --binary target/release/$(BINARY) --config "$$cfg"; \
	echo "Upgrade finished."

uninstall:
	-systemctl disable --now purge-warden.service purge-warden-backup.timer
	rm -f $(LIBEXEC)/$(BINARY)
	rm -f $(PREFIX)/bin/$(BINARY)
	rm -f $(SYSTEMD)/purge-warden.service
	rm -f $(SYSTEMD)/purge-warden-backup.service $(SYSTEMD)/purge-warden-backup.timer
	systemctl daemon-reload

clean:
	cargo clean
