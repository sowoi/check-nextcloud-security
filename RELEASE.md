## check-nextcloud-security 1.6.2

### Fixed

- **Release date in `CHANGELOG.md`.** The date of a release section was set
  when the release pull request was opened and never changed again. The
  release-notes workflow now sets it on every push to the pull request
  (`scripts/release_notes.py --refresh-date`), so it matches the day of the
  last change before the merge.

### Changed

- **Release notes are written in the release pull request.** `main` is
  protected, so the publish workflow no longer pushes to it. A new
  `release-notes` workflow commits `CHANGELOG.md`, `RELEASE.md` and
  `supported_versions.json` to the pull request; if they are out of date at
  release time, the publish workflow opens a follow-up pull request.
