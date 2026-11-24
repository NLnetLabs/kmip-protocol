# Prepare
- determine the next version number, obey SEMVER.
- update `Changelog.md` with the release date, version X.Y.Z[-NNN] and release summary

# Make a release branch and test packaging
- `git checkout main`
- `git pull`
- `git checkout -b release-vX.Y.Z[-xxx]`
- `cargo update`
- bump application version in `Cargo.toml` to X.Y.Z[-xxx]
- `cargo check` (to bump the application version in Cargo.lock)
- `git add Cargo.toml Cargo.lock Changelog.md`
- `git commit`
- `git push`
- `cargo publish --dry-run`
- make a PR for the branch
- review the PR and ensure the CI workflow succeeds
- merge the release branch to main

# Release
- `git checkout main`
- `git tag -a -m "vX.Y.Z[-xxx]" vX.Y.Z[-xxx]`
- Verify that the release tag version is the same as the Cargo.toml version but with a `v` prefix
- `git push --tags`
- create a GH release with tag vX.Y.Z[-NNN] and title 'X.Y.Z[-NNN] <NAME>"
- `cargo publish`

# Prepare for development
- `git checkout -b prep-for-dev`
- bump application version in `Cargo.toml` to next minor version with suffix `-dev`
- `cargo check` (to also bump the application version in `Cargo.lock`)
- Add 'Unreleased new version' in `Changelog.md`
- `git add Cargo.toml Cargo.lock Changelog.md`
- `git commit`
- `git push`
- make a PR for the branch
- review the PR and ensure the CI workflow succeeds
- merge the `prep-for-dev` branch to main

