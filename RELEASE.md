## check-nextcloud-security 1.6.0

### Added

- **PHP version check.** The PHP version reported by the `serverinfo` app is
  compared with a bundled list of critical PHP advisories
  (`nextcloud_local_scan/data/php_advisories.json`). The first entry is
  **PHP2Shell** (CVE-2026-109618, CVE-2026-109619), an unauthenticated remote
  code execution fixed in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12.
  - The serverinfo API reports the PHP that serves web requests
    (PHP-FPM / mod_php). The `occ` transport falls back to the command line
    PHP and says so in the output.
  - An affected version, or a branch without an upstream fix (PHP 8.1 and
    older), is `CRITICAL`. A Debian/Ubuntu build that may carry a backport,
    or an end-of-life branch, is `WARNING`. A PHP finding never lowers the
    state.
- **`--php-ignore ID`** (`CNS_PHP_IGNORE`, `php_ignore:`) acknowledges an
  advisory by id or CVE after a distribution backport has been verified, for
  example on RHEL or AlmaLinux. **`--no-php-check`** (`CNS_NO_PHP_CHECK`)
  disables the check.
- **`php_advisories`** performance metric, a `php` block in the webhook
  payload, and `phpVersion` / `phpSource` in the update information of the
  local scanner.

### Changed

- `--version` / the webhook `plugin_version` now report the current release;
  `__version__` had been left at 1.4.0.

### Notes

- The PHP check needs the `serverinfo` lookup (API token or `occ`). Without it
  the output says `PHP check: version not available`.
- CVE-2026-115560 has no fixed PHP release yet and is not covered. The
  mitigation is `session.upload_progress.enabled=0`.
