# `nextcloud_local_scan`

The local scan engine behind `--scan-backend local` and the
`check-nextcloud-scanner` service. It reproduces the checks of
[scan.nextcloud.com](https://scan.nextcloud.com) without contacting it, and
adds a number of checks the public scanner does not perform.

It is a **re-implementation, not a mirror**. The public scanner's source and
its exact rating algorithm are not published, so the two will not always agree.
This document explains where and why they differ - read it before you switch a
production check over.

| Module | Purpose |
|:-------|:--------|
| `scanner.py` | The scan engine; produces the Scan-API-compatible result document |
| `serverinfo.py` | Update check against the local instance (OCS API or `occ`) |
| `vulndb.py`, `data/` | Advisory database and version-range matching |
| `versions.py` | Version parsing, comparison and the hardening matrix |
| `config.py`, `secrets.py` | YAML / environment / secret-provider configuration |
| `service.py`, `cli.py` | The HTTP service that speaks the Scan API |
| `factory.py` | Builds settings objects from a `Configuration` |

## Why the ratings can differ

The two backends answer the same question from different evidence:

| | scan.nextcloud.com | local scanner |
|:--|:--|:--|
| Version | `status.php` | `status.php` (identical) |
| Known vulnerabilities | Nextcloud's own, continuously maintained advisory database | The local advisory database, **empty unless you fill it** |
| End of life | Nextcloud's internal release/EOL calendar | The release schedule bundled with the package - see below |
| Update available | Nextcloud's release index | Your instance via `serverinfo`, or the updater server |
| Hardenings | Not observable externally, derived from the version | Same approach (`versions.HARDENING_MATRIX`) |
| Extra checks | none | TLS, exposed paths, headers, WebDAV, ... (can cap the rating) |

### End-of-life detection

Nextcloud's release calendar is not published in machine-readable form, and the
public updater server is no help: it answers with an **empty document** both
when a release is current *and* when its branch is no longer served. A scanner
relying on it alone cannot tell those two apart. That used to produce a
confusing split verdict for the same instance - `F` remotely, `C` locally.

The package therefore ships `data/supported_versions.json`, scraped from the
[maintenance and release schedule][schedule] by
`scripts/update_supported_versions.py`:

```json
{
  "supported": [34, 33, 32],
  "oldest_supported": 32
}
```

Every major release **below** `oldest_supported` is end of life, gets `EOL:
true` and rating `F`, matching the remote backend:

```console
$ check-nextcloud-security --host nextcloud.example.com --scan-backend local
CRITICAL: This server version is end-of-life and has no security fixes.
Nextcloud 29.0.2.2 on nextcloud.example.com, rating: F, ...
```

A release *newer* than anything on the schedule (a release candidate, say) is
not treated as end of life. The updater server remains a secondary signal: if
it does report an EOL branch, that verdict still stands.

[schedule]: https://github.com/nextcloud/server/wiki/Maintenance-and-Release-Schedule

#### Keeping the schedule current

The file is refreshed automatically by two workflows - on every release, and
monthly via a pull request - so an installed release is at most one Nextcloud
release cycle behind. Two knobs let you take over:

```yaml
scanner:
  use_release_schedule: true       # set to false to skip the EOL check entirely
  supported_majors: [34, 33, 32]   # override the bundled list
```

The override is what you want for a distribution- or vendor-maintained build
that receives backported fixes past the upstream end-of-life date. Turning the
check off entirely restores the old behaviour, where only the updater server
and `serverinfo` are consulted.

The list that was applied is reported as `supportedMajorVersions` in the result
document, so a stale or overridden schedule is visible rather than silent.

### Vulnerabilities

`data/vulnerabilities.json` **ships empty on purpose.** Publishing a CVE list
that is only updated with the plugin would be worse than shipping none - it
would look authoritative while quietly going stale. `vulnerabilities: []` from
the local scanner therefore means *"nothing in the database you configured"*,
not *"this instance has no known vulnerabilities"*.

Point it at a real source before you rely on it:

```yaml
scanner:
  vulnerability_db: /etc/check-nextcloud-security/advisories.json
  vulnerability_feed: https://example.com/nextcloud-advisories.json
```

Both the native format and the GitHub Advisory API format are accepted; entries
match on the half-open version range `[introduced, fixed)`. The sources that
were actually loaded appear as `advisorySources` in the result document, so a
misconfigured path is visible rather than silent.

### Hardenings

Whether an instance enables brute-force protection or CSPv3 cannot be observed
from the outside. Both scanners therefore infer it from the release that
introduced the measure - a *capability*, not a confirmation that it is switched
on. `HARDENING_MATRIX` in `versions.py` holds the mapping.

### Additional checks change the rating

The extra checks have no counterpart upstream, and by default a failure caps
the rating: `critical` -> at most `2` (D), `high` -> `3` (C), `medium` -> `4`
(A). That is why a locally scanned instance can score lower than the same
instance on scan.nextcloud.com even when both agree on version, updates and
vulnerabilities. To report the findings without touching the rating:

```yaml
scanner:
  extra_checks_rating: false
```

Or drop the additional checks entirely with `--no-extra-checks`.

### Rating algorithm

An approximation of the published 0-5 scale, evaluated in this order:

| Rating | Grade | Condition |
|:------:|:-----:|:----------|
| 0 | F | End of life |
| 1 | E | Vulnerability with severity critical or high |
| 2 | D | Any other known vulnerability |
| 3 | C | A whole major release behind |
| 4 | A | Update available within the branch |
| 5 | A+ | Up to date |

then capped by the worst failed additional check. Upstream may weigh the same
evidence differently, so treat a one-grade difference as normal and compare
findings, not grades.

### Smaller differences

- **No queue, no rate limit.** The public API queues scans and refuses too many
  in a row; the local scanner scans immediately, so `--rescan` is meaningless
  (the container caches per host for `service.cache_ttl` seconds instead).
- **IP addresses and ports work.** `--host 192.0.2.10:8443` is fine locally and
  rejected by the public API.
- **HTTP-only instances are scanned**, with a `critical` `httpsAvailable`
  finding, instead of failing outright.
- **`scannedAt` is the moment you asked.** The public API may return a cached
  result from hours ago - visible in your monitoring as an unchanging timestamp.
- **Extra fields.** The result adds `scanner`, `updates`, `extraChecks` and
  `advisorySources`; every field the public API returns keeps its name and
  meaning, so downstream tooling continues to work.
- **The scan comes from your host.** Results reflect what your monitoring host
  sees - a reverse proxy, geo-blocking or a WAF rule can make the same instance
  look different to you than to scan.nextcloud.com.

## ownCloud instances

ownCloud exposes the same `status.php` contract (`version`, `versionstring`,
`productname`, `edition`, `maintenance`), so both backends can read it. Verified
against `demo.owncloud.com`, which reports Infinite Scale 10.11.0.0.

Applies unchanged:

- TLS certificate validity and expiry, HTTP-only detection
- Security headers, HSTS
- Exposed paths (including `/data/.ncdata` and `/data/owncloud.log`),
  directory listing, WebDAV authentication
- Maintenance mode and pending database upgrades

Does **not** apply, because it is Nextcloud-specific:

- **End of life.** ownCloud and Infinite Scale version independently of the
  Nextcloud release schedule, so `supported_versions.json` is ignored and no
  product is rated `F` on those grounds.
- **Hardenings.** `HARDENING_MATRIX` maps Nextcloud majors; `hardenings` is
  returned empty rather than misleading.
- **Update check.** The `serverinfo` app and the Nextcloud updater server do not
  serve ownCloud; use `--no-update-check`.
- **Advisories.** Point `vulnerability_db` at an ownCloud advisory source; the
  bundled file is empty anyway.

Infinite Scale is a single-page application that answers **every** path with
HTTP 200 and its app shell. The scanner probes a nonsense path first and
suppresses the exposed-path checks when the instance answers everything alike,
so it does not report five phantom exposures.

```console
$ check-nextcloud-security --host demo.owncloud.com --scan-backend local --no-update-check
OK: Infinite Scale 10.11.0.0 on demo.owncloud.com, rating: A+, ...
```

The public scan.nextcloud.com backend also accepts ownCloud hosts, but rates
them against Nextcloud's calendar - a reason to prefer the local backend here.

## Using it directly

```python
from nextcloud_local_scan import ScannerSettings, scan

result = scan("nextcloud.example.com", settings=ScannerSettings(timeout=10))
print(result["rating"], result["version"], result["extraChecks"])
```

`scan()` raises `ScanError` when the instance cannot be identified as a
Nextcloud. Every setting in `ScannerSettings` and `ServerInfoSettings` can also
come from a YAML file, an environment variable or a secret provider - see
[`config/check-nextcloud-security.example.yml`](../config/check-nextcloud-security.example.yml)
and the [Configuration file and secrets](../README.md#configuration-file-and-secrets)
section of the main README.
