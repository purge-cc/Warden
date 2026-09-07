# Release notes

`unreleased.md` collects changes that have not been published yet. During a
release, rename it to `<version>.md`, change its title to the same version, and
create a new `unreleased.md` for later work.

The Git tag must be `v<version>`, and `<version>` must match `Cargo.toml`. The
release workflow refuses a tag when any of these three values disagree.
