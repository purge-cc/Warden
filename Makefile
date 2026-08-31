BINARY   := warden
PREFIX   := /usr/local
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

# First-time install: places binary + unit + example config, reloads
# systemd. Does NOT start the service — fresh installs need
# `warden init` first to create the system user + config.toml, then
# `systemctl enable --now purge-warden`. See `scripts/install.sh` for
# the end-to-end path that also fills in the LAN CIDR allow-list.
install: build
	install -Dm755 target/release/$(BINARY)           $(PREFIX)/bin/$(BINARY)
	install -Dm644 systemd/purge-warden.service        $(SYSTEMD)/purge-warden.service
	install -Dm644 config/default.toml                 $(STATE)/config.toml.example
	systemctl daemon-reload
	@echo "Installed. Run 'warden init' to create system user and directories."

# Upgrade an already-running install: build, stop, replace binary +
# unit file, reload systemd, restart.
upgrade: build
	@if ! systemctl is-active --quiet purge-warden.service 2>/dev/null; then \
		echo "No running purge-warden service found — run 'make install' for a fresh install."; \
		exit 1; \
	fi
	install -m 0755 target/release/$(BINARY)                  $(PREFIX)/bin/$(BINARY)
	install -m 0644 systemd/purge-warden.service              $(SYSTEMD)/purge-warden.service
	systemctl daemon-reload
	systemctl restart purge-warden.service
	@echo "Upgraded. Verify with: systemctl status purge-warden && dig @127.0.0.1 example.com"

uninstall:
	rm -f $(PREFIX)/bin/$(BINARY)
	rm -f $(SYSTEMD)/purge-warden.service
	systemctl daemon-reload

clean:
	cargo clean
