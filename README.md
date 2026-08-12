<!-- TOC -->
* [check-nextcloud-security](#check-nextcloud-security)
* [Quick start](#quick-start)
* [Features](#features)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
  * [Using pipx / uv / pip (recommended)](#using-pipx--uv--pip-recommended)
    * [Updating](#updating)
  * [Docker](#docker)
  * [Icinga2 / Nagios](#icinga2--nagios)
    * [Using the Docker image instead](#using-the-docker-image-instead)
* [CLI Usage](#cli-usage)
  * [Command](#command)
* [Options:](#options)
* [Checking multiple hosts](#checking-multiple-hosts)
* [Environment variables](#environment-variables)
* [Local scanning without scan.nextcloud.com](#local-scanning-without-scannextcloudcom)
  * [1. In-process (`--scan-backend local`)](#1-in-process---scan-backend-local)
  * [2. Self-hosted scanner container (`--scan-url`)](#2-self-hosted-scanner-container---scan-url)
  * [End-of-life detection](#end-of-life-detection)
  * [ownCloud](#owncloud)
  * [What the local scanner checks](#what-the-local-scanner-checks)
  * [Advisory database](#advisory-database)
* [Update check via the local instance (`serverinfo`)](#update-check-via-the-local-instance-serverinfo)
* [Configuration file and secrets](#configuration-file-and-secrets)
* [Rating thresholds](#rating-thresholds)
* [Hardening checks](#hardening-checks)
* [Webhook notifications](#webhook-notifications)
* [Retries and backoff](#retries-and-backoff)
* [Performance data](#performance-data)
* [Rescan](#rescan)
* [Example output](#example-output)
* [Icinga Director](#icinga-director)
  * [Automated deployment with Ansible](#automated-deployment-with-ansible)
* [Scheduling without Icinga2 / Nagios (systemd timer / cron)](#scheduling-without-icinga2--nagios-systemd-timer--cron)
  * [systemd timer](#systemd-timer)
  * [cron](#cron)
* [Troubleshooting](#troubleshooting)
* [Contributing](#contributing)
* [License](#license)
* [More](#more)
<!-- TOC -->

# check-nextcloud-security
Check the security level of your Nextcloud instance with the Nextcloud Security API

By default this check uses Nextcloud's own security scan at scan.nextcloud.com
to find out whether your instance has any known vulnerabilities or risks.

**You no longer have to.** The very same checks can run entirely **locally** -
either in-process (`--scan-backend local`) or in a self-hosted scanner
container (`--scan-url`) - so that nothing about your instance is ever sent to
a third party, IP addresses and internal hostnames work, and there are no rate
limits. The local scanner also performs a number of
[additional checks](#what-the-local-scanner-checks) the public scanner does
not, and takes update information straight from your instance via the
`serverinfo` app. See
[Local scanning without scan.nextcloud.com](#local-scanning-without-scannextcloudcom).

# Quick start
Install the plugin and run a check - one command each:

```shell
pipx install check-nextcloud-security     # or: uv tool install / pip install
check-nextcloud-security --host nextcloud.example.com
```

Want to keep everything in your own network? Add `--scan-backend local` and the
identical checks run on your machine, without contacting scan.nextcloud.com:

```shell
check-nextcloud-security --host nextcloud.example.com --scan-backend local
```

For a permanent setup (Icinga2, systemd timer, cron, Docker, ...) see
[Installation](#installation) below.

# Features
- **Scan locally instead of via scan.nextcloud.com** - in-process
  (`--scan-backend local`) or through your own scanner container
  (`--scan-url`). No data leaves your network, no rate limits, IP addresses
  and custom ports supported
- **Additional security checks** the public scanner does not perform: TLS
  certificate and protocol state, publicly readable paths, directory
  listings, unauthenticated WebDAV, modern security headers
- **Update check against the local instance** via the Nextcloud `serverinfo`
  app - no dependency on an external service
- Configuration from a YAML file, environment variables or a secret provider
  (Docker/Kubernetes secrets, files, environment, commands)
- Standard Nagios/Icinga exit codes (OK, WARNING, CRITICAL, UNKNOWN) and
  performance data (rating, vulnerability count, scan duration)
- Configurable rating thresholds for WARNING and CRITICAL
- Optional hardening and security-header checks (`--check-hardening`)
- Optional webhook notification when a check turns critical
- Automatic retry with exponential backoff on transient network errors
- Web proxy support, debugging, on-demand rescan
- Installable with pipx/uv/pip - or as a ready-to-use Docker image


# Prerequisites
- Python 3.10 or newer - or Docker, if you prefer the containerised route.
- `requests` and `PyYAML`, installed automatically by pipx/uv/pip.

# Installation
Installing with pipx, uv or pip is the recommended route; Docker is available
as an alternative if you don't want Python on the host.

## Using pipx / uv / pip (recommended)
The package is published on
[PyPI](https://pypi.org/project/check-nextcloud-security/) and installs two
commands onto your `PATH`: `check-nextcloud-security` (the check itself) and
`check-nextcloud-scanner` (the optional local scan service).

**[pipx](https://pipx.pypa.io/) - recommended for CLI tools**, keeps the plugin
in its own virtualenv:
```shell
pipx install check-nextcloud-security
```

**[uv](https://docs.astral.sh/uv/)** - same idea, faster:
```shell
uv tool install check-nextcloud-security
```

**pip** - into the system or an existing virtualenv:
```shell
pip install check-nextcloud-security
```

To install the latest unreleased changes, point any of them at the repository
instead: `pipx install git+https://github.com/sowoi/check-nextcloud-security.git`
(likewise `uv tool install git+https://...` and `pip install git+https://...`).

### Updating
```shell
pipx upgrade check-nextcloud-security          # pipx
pipx upgrade-all                               # ... or every pipx tool at once

uv tool upgrade check-nextcloud-security       # uv
uv tool upgrade --all                          # ... or every uv tool at once

pip install --upgrade check-nextcloud-security # pip
```

Check what you are running with `check-nextcloud-security --version`, and see
[CHANGELOG.md](CHANGELOG.md) for what changed. A git installation is updated by
re-running the same `install` command with `--force` (pipx/uv) or
`--upgrade --force-reinstall` (pip).

To remove the plugin again: `pipx uninstall check-nextcloud-security`,
`uv tool uninstall check-nextcloud-security` or
`pip uninstall check-nextcloud-security`.

**From a checkout (development or air-gapped install):**

The project uses [uv](https://docs.astral.sh/uv/) as its dependency manager;
`uv.lock` pins every dependency, so an install is reproducible:

```shell
git clone https://github.com/sowoi/check-nextcloud-security.git
cd check-nextcloud-security

uv sync                                       # create .venv from uv.lock
uv run check-nextcloud-security --host nextcloud.example.com
```

Without `uv`, install the checkout with pip - the dependencies are declared in
`pyproject.toml`, no separate requirements file is needed:

```shell
pip install .
# or, without installing, run the script in place:
pip install requests PyYAML
python3 check_nextcloud_security.py --host nextcloud.example.com
```

If some deployment tool of yours insists on a `requirements.txt`, generate one
from the lock file instead of maintaining it by hand:

```shell
uv export --no-dev --no-emit-project --format requirements.txt -o requirements.txt

# without the hashes, if your tooling cannot handle them:
uv export --no-dev --no-emit-project --no-hashes --format requirements.txt -o requirements.txt

# including the development and test dependencies:
uv export --no-emit-project --format requirements.txt -o requirements-dev.txt
```

Older uv versions call the same command `uv pip compile pyproject.toml -o requirements.txt`.
Such a file is a build artefact - do not commit it, it goes stale the moment
`uv.lock` changes.

## Docker
Use this if you would rather not install anything on the host. The image also
ships the local scan service (see
[Local scanning](#local-scanning-without-scannextcloudcom)).

Build the image once from a local checkout of this repository:
```shell
git clone https://github.com/sowoi/check-nextcloud-security.git
cd check-nextcloud-security
docker build -t check-nextcloud-security .
```

Run a check:
```shell
docker run --rm check-nextcloud-security --host nextcloud.example.com
```

Or configure it entirely through [environment variables](#environment-variables)
(handy since you don't need to edit the `docker run` command per host):
```shell
docker run --rm -e CNS_HOST=nextcloud.example.com check-nextcloud-security
```

The check container needs no network ports and, with the default backend, only
outbound HTTPS access to `scan.nextcloud.com`; with `--scan-backend local` it
talks to your instance instead. It runs as an unprivileged `nagios` user and exits with
the same Nagios-style codes (`0`/`1`/`2`/`3`) as the native script, so it can
be dropped straight into any monitoring pipeline that already understands
`docker run` as a check command (see [Icinga2 / Nagios](#icinga2--nagios) and
[Icinga Director](#icinga-director) below).

If you'd rather not build locally, push the built image to your own registry
(e.g. `docker tag check-nextcloud-security registry.example.com/check-nextcloud-security` followed by `docker push ...`) and reference that image on your monitoring host(s) instead.

## Icinga2 / Nagios
- If you installed the package with pipx/uv/pip, locate the installed `check-nextcloud-security` executable (e.g. `which check-nextcloud-security`) and reference that path in `PluginDir`, or copy/symlink it into your plugin folder (usually `/usr/lib/nagios/plugins/`).
- If you're running the script manually, put `check_nextcloud_security.py` into your plugin folder instead.
- Create a new command custom command:

```
object CheckCommand "check_nextcloud_security" {
    import "plugin-check-command"
    command = [ PluginDir + "/check-nextcloud-security" ]

    arguments += {
        "--host" = {
            description = "Nextcloud hostname or URL"
            required = true
            value = "$address$"
        }

        "--proxy" = {
            description = "HTTP/HTTPS proxy (optional)"
            required = false
        }

        "--rescan" = {
            description = "Trigger a new scan on each check (optional)"
            set_if = "$nextcloud_rescan$"
        }

        "--debug" = {
            description = "Enable debugging output (optional)"
            set_if = "$nextcloud_debug$"
        }

        "--warning" = {
            description = "Rating (0-5) at or below which the check warns (optional)"
            value = "$nextcloud_warning$"
        }

        "--critical" = {
            description = "Rating (0-5) at or below which the check is critical (optional)"
            value = "$nextcloud_critical$"
        }

        "--check-hardening" = {
            description = "Also check hardening measures and security headers (optional)"
            set_if = "$nextcloud_check_hardening$"
        }
    }
}
```

- Create a new Service object.
- Please do not run the query too often, or you will be banned. In the template below 24 hours are given. Normally, one check every 24 hours is sufficient. 

```
object Service "Service: Nextcloud Security Scan" {
   import               "generic-service"
   host_name =          "YOUR NEXTCLOUD HOST"
   check_command =      "check_nextcloud_security"
   check_interval = 24h
}
```

### Using the Docker image instead

If you installed via [Docker](#docker), point the `CheckCommand` at `docker`
and let it run the container on demand instead of a local binary:

```
object CheckCommand "check_nextcloud_security_docker" {
    import "plugin-check-command"
    command = [ "/usr/bin/docker" ]

    arguments += {
        "run" = {
            order = -5
            value = "run"
        }
        "--rm" = {
            order = -4
            value = "--rm"
        }
        "image" = {
            order = -3
            skip_key = true
            value = "check-nextcloud-security"
        }
        "--host" = {
            description = "Nextcloud hostname or URL"
            required = true
            value = "$address$"
        }
        "--proxy" = {
            description = "HTTP/HTTPS proxy (optional)"
            required = false
        }
        "--rescan" = {
            description = "Trigger a new scan on each check (optional)"
            set_if = "$nextcloud_rescan$"
        }
        "--debug" = {
            description = "Enable debugging output (optional)"
            set_if = "$nextcloud_debug$"
        }

        "--warning" = {
            description = "Rating (0-5) at or below which the check warns (optional)"
            value = "$nextcloud_warning$"
        }

        "--critical" = {
            description = "Rating (0-5) at or below which the check is critical (optional)"
            value = "$nextcloud_critical$"
        }

        "--check-hardening" = {
            description = "Also check hardening measures and security headers (optional)"
            set_if = "$nextcloud_check_hardening$"
        }
    }
}
```

This assumes the `check-nextcloud-security` image has already been built (or
pulled) on the Icinga2 host, and that the user running the Icinga2 daemon has
permission to talk to the Docker socket.


# CLI Usage
- `check-nextcloud-security -h` will show you a manual.

## Command
```shell
check-nextcloud-security --host <Hostname> --rescan
```

# Options:
| Option              | Description                                            | Default      | Environment variable |
|:--------------------|:--------------------------------------------------------|:-------------|:----------------------|
| `-H, --host`        | Nextcloud server address(es) (hostname or URL). Accepts a comma-separated list to check multiple hosts in one run | **required** | `CNS_HOST`            |
| `-P, --proxy`       | Proxy server address                                   | *None*       | `CNS_PROXY`           |
| `-r, --rescan`      | Trigger a fresh scan each time (slower, more accurate) | *False*      | `CNS_RESCAN`          |
| `-d, --debug`       | Enable verbose debugging output                        | *False*      | `CNS_DEBUG`           |
| `-w, --warning`     | Rating (0-5) at or below which the check warns         | `3` (`C`)    | `CNS_WARNING`         |
| `-c, --critical`    | Rating (0-5) at or below which the check is critical   | `1` (`E`)    | `CNS_CRITICAL`        |
| `--check-hardening` | Also report missing hardening measures and security headers | *False* | `CNS_CHECK_HARDENING` |
| `--timeout`         | HTTP timeout in seconds per Scan API call              | `10`         | `CNS_TIMEOUT`         |
| `--webhook-url`     | Optional endpoint notified when the check reaches the configured state | *None* (disabled) | `CNS_WEBHOOK_URL` |
| `--webhook-on`      | Lowest state that triggers the webhook (`critical`, `warning`, `unknown`, `always`) | `critical` | `CNS_WEBHOOK_ON` |
| `--webhook-header`  | Extra header for the webhook request, repeatable      | *None*       | `CNS_WEBHOOK_HEADERS` |
| `--webhook-timeout` | HTTP timeout in seconds for the webhook call          | `10`         | `CNS_WEBHOOK_TIMEOUT` |
| `--retries`         | Retry attempts for transient network errors            | `2`          | `CNS_RETRIES`         |
| `--backoff-factor`  | Exponential backoff factor (seconds) between retries   | `0.5`        | `CNS_BACKOFF_FACTOR`  |
| `--config`          | Path to the YAML configuration file                    | auto-discovered | `CNS_CONFIG_FILE`  |
| `--scan-backend`    | `remote` (Scan API) or `local` (checks run in-process) | `remote`     | `CNS_SCAN_BACKEND`    |
| `--scan-url`        | Base URL of the Scan API, e.g. your scanner container  | `https://scan.nextcloud.com` | `CNS_SCAN_URL` |
| `--scan-token`      | Token sent as `X-Auth-Token` to a self-hosted scanner  | *None*       | `CNS_SCAN_TOKEN`      |
| `--no-extra-checks` | Local backend: skip the additional checks              | *False*      | `CNS_NO_EXTRA_CHECKS` |
| `--insecure`        | Local backend: do not verify the instance's TLS certificate | *False* | `CNS_INSECURE`        |
| `--serverinfo-mode` | Update check transport: `auto`, `api`, `occ`, `off`    | `auto`       | `CNS_SERVERINFO_MODE` |
| `--serverinfo-url`  | Base URL of the instance for the serverinfo API        | `https://<host>` | `CNS_SERVERINFO_URL` |
| `--serverinfo-token`| Monitoring token of the serverinfo app (`NC-Token`)    | *None*       | `CNS_SERVERINFO_TOKEN` |
| `--serverinfo-user` | Admin user for the serverinfo API                      | *None*       | `CNS_SERVERINFO_USER` |
| `--serverinfo-password` | Password / app password for that user              | *None*       | `CNS_SERVERINFO_PASSWORD` |
| `--serverinfo-occ`  | `occ` command used for the update check                | `occ`        | `CNS_SERVERINFO_OCC_COMMAND` |
| `--serverinfo-container` | Run `occ` inside this container via `docker exec` | *None*       | `CNS_SERVERINFO_CONTAINER` |
| `--no-update-check` | Disable the update check against the local instance    | *False*      | `CNS_NO_UPDATE_CHECK` |
| `--update-warning`  | Report WARNING when a server update is pending         | *False*      | `CNS_UPDATE_WARNING`  |
| `-V, --version`     | Show the installed version and exit                    | —            | —                     |
| `-h, --help`        | Show help and exit                                     | —            | —                     |


# Checking multiple hosts
`--host` (and `CNS_HOST`) accepts a comma-separated list of hostnames, e.g.:

```shell
check-nextcloud-security --host nextcloud1.example.com,nextcloud2.example.com
```

Hosts are processed one by one. The output starts with a one-line summary
(e.g. `Checked 2 host(s): overall CRITICAL (1 CRITICAL, 1 OK)`), followed by
one result block per host. The plugin exits with the worst status found
across all hosts, using the usual Nagios/Icinga priority: `CRITICAL` >
`WARNING` > `UNKNOWN` > `OK`. A single host still produces the original,
single-block output and exit code, so existing single-host setups are
unaffected.

Whitespace around each hostname is ignored, and empty entries (e.g. from a
trailing comma) are dropped.

# Environment variables
Every option has a `CNS_`-prefixed environment variable equivalent (see the
table above). This is especially useful for Docker, systemd, and cron, where
setting environment variables is often more convenient than editing a command
line. **An explicit command-line flag always takes precedence over its
environment variable.**

```shell
export CNS_HOST=nextcloud.example.com
export CNS_PROXY=http://proxy.example.com:3128
check-nextcloud-security
```

Boolean variables (`CNS_DEBUG`, `CNS_RESCAN`, `CNS_CHECK_HARDENING`) accept `1`, `true`, `yes`, or
`on` (case-insensitive) to enable the corresponding flag; any other value
(including unset/empty) is treated as disabled.

The same values can also come from a YAML file or a secret provider - see
[Configuration file and secrets](#configuration-file-and-secrets).


# Local scanning without scan.nextcloud.com
By default the plugin queries the public Scan API - that behaviour is
unchanged. If you would rather keep everything inside your own network, the
same checks can run locally in two ways.

## 1. In-process (`--scan-backend local`)
```shell
check-nextcloud-security --host nextcloud.example.com --scan-backend local
```
No scan service is involved at all: the plugin talks to the instance
directly and produces the same result document (product, version, rating,
`hardenings`, `setup.headers`, vulnerabilities) that scan.nextcloud.com
returns, so thresholds, hardening checks, webhooks and performance data keep
working exactly as before. Unlike the public API, the local backend also
accepts IP addresses and non-standard ports (`--host 192.0.2.10:8443`).

## 2. Self-hosted scanner container (`--scan-url`)
The image ships a second entry point, `check-nextcloud-scanner`, which serves
a drop-in replacement for the Scan API:

| Endpoint | Behaviour |
|:---------|:----------|
| `POST /api/queue` (`url=<host>`) | Scan the host, return `{"uuid": ...}` |
| `GET /api/result/<uuid>` | Return the stored result |
| `POST /api/requeue` (`url=<host>`) | Discard the cache and scan again |
| `GET /api/scan?url=<host>` | Convenience: scan and return the document |
| `GET /healthz` | Liveness probe |

```shell
# start the scanner
docker run -d --name nextcloud-scanner -p 8080:8080 \
  --entrypoint check-nextcloud-scanner \
  check-nextcloud-security serve

# point the check at it
check-nextcloud-security --host nextcloud.example.com --scan-url http://localhost:8080
```

If the **check** also runs in a container, both need to be on the same network -
`localhost` inside a container is that container itself:

```shell
# recommended: a shared user-defined network, addressed by container name
docker network create nextcloud-scan
docker run -d --name nextcloud-scanner --network nextcloud-scan \
  --entrypoint check-nextcloud-scanner check-nextcloud-security serve
docker run --rm --network nextcloud-scan check-nextcloud-security \
  --host nextcloud.example.com --scan-url http://nextcloud-scanner:8080

# or, for a scanner running on the Docker host itself. On Linux
# 'host.docker.internal' does not exist unless you map it explicitly:
docker run --rm --add-host host.docker.internal:host-gateway \
  check-nextcloud-security \
  --host nextcloud.example.com --scan-url http://host.docker.internal:8080
```

`--host` accepts a bare hostname as well as a full URL, so
`--host https://nextcloud.example.com/` and `--host nextcloud.example.com` are
equivalent; scheme, path and credentials are stripped.

A ready-made [`docker-compose.yml`](docker-compose.yml) starts the scanner
plus a check container, including a health check and Docker secrets:

```shell
# 1. create the secret files from the templates
cp secrets/scanner_token.example    secrets/scanner_token
cp secrets/serverinfo_token.example secrets/serverinfo_token

# 2. fill them with real values
openssl rand -hex 32 > secrets/scanner_token          # protects the service
printf '%s' '<serverinfo-token>' > secrets/serverinfo_token
chmod 600 secrets/scanner_token secrets/serverinfo_token

# 3. adjust CNS_SERVERINFO_URL / --host in docker-compose.yml, then:
docker compose up -d scanner
docker compose run --rm check
```

| Secret | Mounted at | Purpose |
|:-------|:-----------|:--------|
| `secrets/scanner_token` | `/run/secrets/scanner_token` | Shared token between scanner (`CNS_SERVICE_TOKEN_FILE`) and check (`CNS_SCAN_TOKEN_FILE`). Requests without it are rejected. |
| `secrets/serverinfo_token` | `/run/secrets/serverinfo_token` | `NC-Token` for the serverinfo update check (`secret://serverinfo_token`). |

Everything in `secrets/` except the `*.example` templates is git-ignored - see
[`secrets/README.md`](secrets/README.md). Protect the service with a token
whenever it is reachable by others; without `service.token` the endpoints are
open to anyone who can connect.

Results are cached per host for `service.cache_ttl` seconds (15 minutes by
default), so polling several times a minute does not hammer the instance.

> **Local and remote results are not always identical.** The local scanner is a
> re-implementation of a scanner whose source and rating algorithm are not
> published, so treat a one-grade difference as normal and compare findings
> rather than grades. Read
> [`nextcloud_local_scan/README.md`](nextcloud_local_scan/README.md) for the
> full list of differences before switching a production check over.

### End-of-life detection

Nextcloud's release calendar is not machine-readable, and the public updater
server answers identically for a current and a retired release. The package
therefore ships the supported major releases in
`nextcloud_local_scan/data/supported_versions.json`, scraped from the
[maintenance and release schedule][release-schedule]; anything below the oldest
supported major is rated `F`, just as the remote backend does. The file is
refreshed on every release and monthly by a scheduled workflow.

```yaml
scanner:
  use_release_schedule: true       # false disables the EOL check
  # supported_majors: [34, 33, 32] # override for a vendor-maintained build
```

Or via the environment: `CNS_SCANNER_USE_RELEASE_SCHEDULE`,
`CNS_SCANNER_SUPPORTED_MAJORS`.

[release-schedule]: https://github.com/nextcloud/server/wiki/Maintenance-and-Release-Schedule

### ownCloud

ownCloud and Infinite Scale expose a compatible `status.php`, so both backends
work against them. TLS, header, exposed-path, WebDAV and maintenance checks
apply unchanged; the end-of-life schedule, the hardening matrix and the
`serverinfo` update check are Nextcloud-specific and are skipped automatically
(use `--no-update-check`). See
[`nextcloud_local_scan/README.md`](nextcloud_local_scan/README.md#owncloud-instances).

## What the local scanner checks
Everything the public scanner reports:

- product, version and edition from `status.php`
- `hardenings` derived from the release that introduced each measure
  (brute-force protection, CSPv3, SameSite cookies, password confirmation,
  `__Host-` prefix, app password restrictions and HIBP scanning)
- `setup.https.used` / `setup.https.enforced` and the security headers
  `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`,
  `X-Download-Options`, `X-Permitted-Cross-Domain-Policies`, `X-Robots-Tag`
- known vulnerabilities and the resulting rating (`0`-`5`)

Plus additional checks (`extraChecks` in the JSON, disable with
`--no-extra-checks`):

| Check | Severity | Purpose |
|:------|:---------|:--------|
| `httpsAvailable`, `tlsHandshake`, `tlsProtocol` | critical/high | Instance only reachable over HTTP, broken TLS, or a protocol older than TLS 1.2 |
| `tlsCertificate` | high/medium | Certificate expired or expiring within `scanner.tls_min_days` |
| `header:Strict-Transport-Security`, `header:Content-Security-Policy`, `header:Referrer-Policy` | high/medium | Modern headers the public scanner does not evaluate |
| `exposed:/config/config.php`, `/data/.ocdata`, `/data/nextcloud.log`, `/db_structure.xml`, `/.user.ini`, `/.htaccess`, `/3rdparty/`, `/README.md` | critical - low | Installation internals readable over HTTP |
| `directoryListing` | critical | Directory listing enabled for `/data/` |
| `webdavAuthentication` | critical | `/remote.php/dav/` answers without demanding authentication |
| `versionDisclosure:Server`, `versionDisclosure:X-Powered-By` | low | Web server / PHP versions leaked in responses |
| `maintenanceMode`, `databaseUpgrade` | medium/high | Instance in maintenance mode or waiting for a database upgrade |

A failed additional check caps the rating (critical -> `D`, high -> `C`);
set `scanner.extra_checks_rating: false` to report them without touching the
rating.

## Advisory database
Known vulnerabilities are matched against the version range
`[introduced, fixed)` of a local advisory database. Sources are merged in this
order and de-duplicated by id:

1. the file bundled with the package,
2. every file in `scanner.vulnerability_db`,
3. the JSON feed in `scanner.vulnerability_feed`.

Both the native format (`{"advisories": [{"id": ..., "introduced": ...,
"fixed": ...}]}`) and the GitHub Advisory API format are understood, so an
air-gapped setup can mirror a feed to a file without conversion. A feed that
is unreachable is logged and ignored - it never turns a healthy instance into
`UNKNOWN`. Because the bundled database is empty, `vulnerabilities: []` from a
local scan means "nothing in the database you configured", not "no known
vulnerabilities" - see
[`nextcloud_local_scan/README.md`](nextcloud_local_scan/README.md).

# Update check via the local instance (`serverinfo`)
Update information does not come from scan.nextcloud.com; it is taken from the
Nextcloud instance itself through the
[serverinfo](https://github.com/nextcloud/serverinfo) app. Two transports are
available, selected with `--serverinfo-mode`:

**`api`** - the OCS endpoint
`/ocs/v2.php/apps/serverinfo/api/v1/info?skipUpdate=false`, authenticated with
the monitoring token or with admin credentials:

```shell
# on the Nextcloud server, once:
occ config:app:set serverinfo token --value "$(openssl rand -hex 32)"

check-nextcloud-security --host nextcloud.example.com \
  --serverinfo-mode api \
  --serverinfo-url https://nextcloud.example.com \
  --serverinfo-token "$(cat /run/secrets/serverinfo_token)"
```

**`occ`** - the local command line, optionally inside a container:

```shell
check-nextcloud-security --host nextcloud.example.com \
  --serverinfo-mode occ \
  --serverinfo-occ "php /var/www/html/occ"

# or, when Nextcloud runs in a container:
check-nextcloud-security --host nextcloud.example.com \
  --serverinfo-mode occ --serverinfo-container nextcloud-app
```

`occ serverinfo` is used first; installations whose serverinfo app does not
provide that subcommand fall back to `occ update:check`, which reports the
same update state.

`auto` (the default) picks the API when a URL plus token/credentials are
configured, the command line when an `occ` command or container is
configured, and skips the update check otherwise. To switch the update check
off explicitly - for instance when the plugin has no way to reach the instance
or you already monitor updates elsewhere - use `--no-update-check`
(`CNS_NO_UPDATE_CHECK=true`, or `serverinfo.mode: off` in the configuration
file). The result is reported as
an extra output line and as the `update_available` performance metric; with
`--update-warning` a pending server update turns an otherwise `OK` result
into `WARNING`. A failing update check never aborts the security check.

# Configuration file and secrets
All settings can live in a YAML file instead of the command line. It is read
from `--config`, `CNS_CONFIG_FILE`, `./check-nextcloud-security.yml` or
`/etc/check-nextcloud-security/config.yml` (first match wins). See
[`config/check-nextcloud-security.example.yml`](config/check-nextcloud-security.example.yml)
for a fully commented example.

```yaml
host: nextcloud.example.com
check_hardening: true

scan:
  backend: local

scanner:
  extra_checks: true
  tls_min_days: 21

serverinfo:
  mode: api
  url: https://nextcloud.example.com
  token: secret://serverinfo_token
```

Nested keys map one to one onto the environment variables: `scan.backend` is
`CNS_SCAN_BACKEND`, `serverinfo.token` is `CNS_SERVERINFO_TOKEN`,
`scanner.tls_min_days` is `CNS_SCANNER_TLS_MIN_DAYS`. Precedence is
**command line > environment variable > configuration file > default**.

Secrets never have to be written into the file or the process environment.
Any value may be a reference:

| Reference | Resolves to |
|:----------|:------------|
| `secret://name` | `<secrets.dir>/name`, i.e. `/run/secrets/name` for Docker and Kubernetes secrets |
| `file:///path/to/file` | The contents of that file |
| `env://VARIABLE` | The value of that environment variable |
| `exec://command --arg` | The stdout of that command (requires `secrets.allow_exec: true`) |

Alternatively append `_file` to any key or variable:
`CNS_SERVERINFO_TOKEN_FILE=/run/secrets/token` or `token_file: /run/secrets/token`.
Trailing newlines are stripped, so `echo secret > file` works as expected.

`secret://name` looks below `secrets.dir` (`CNS_SECRETS_DIR`), which defaults to
`/run/secrets` - exactly where Docker and Kubernetes mount their secrets. Outside
a container, point it at your own directory:

```shell
mkdir -p /etc/check-nextcloud-security/secrets
openssl rand -hex 32 > /etc/check-nextcloud-security/secrets/scanner_token
printf '%s' '<serverinfo-token>' > /etc/check-nextcloud-security/secrets/serverinfo_token
chmod 600 /etc/check-nextcloud-security/secrets/*

export CNS_SECRETS_DIR=/etc/check-nextcloud-security/secrets
check-nextcloud-security --host nextcloud.example.com \
  --serverinfo-token 'secret://serverinfo_token'
```

The repository ships templates for both files in
[`secrets/`](secrets/README.md); copy them and replace the placeholder values.

# Rating thresholds
scan.nextcloud.com grades an instance from `A+` (best) down to `F`. The plugin
maps that grade to a numeric rating and compares it against two inclusive
thresholds:

| Rating | 5    | 4   | 3   | 2   | 1   | 0   |
|:-------|:-----|:----|:----|:----|:----|:----|
| Grade  | `A+` | `A` | `C` | `D` | `E` | `F` |

- `-c, --critical` / `CNS_CRITICAL` (default `1`, i.e. `E`) - a rating at or
  below this value is `CRITICAL`.
- `-w, --warning` / `CNS_WARNING` (default `3`, i.e. `C`) - a rating at or
  below this value is `WARNING`.

Two rules always apply on top of the thresholds:

- **Known vulnerabilities raise the state to at least `WARNING`**, even when
  the overall rating still looks acceptable. The reported CVE identifiers are
  listed in the output.
- **An end-of-life version is always `CRITICAL`**, because it receives no
  security fixes at all.

A rating outside the documented `0-5` range yields `UNKNOWN`. `--critical`
must not be higher than `--warning`, and both must be within `0-5`; otherwise
the plugin refuses to run.

```shell
# Only alert once the instance is actually end-of-life
check-nextcloud-security --host nextcloud.example.com --warning 1 --critical 0

# Be strict: anything short of a fully patched A+ instance warns
check-nextcloud-security --host nextcloud.example.com --warning 4 --critical 1
```


# Hardening checks
The Scan API also reports which hardening measures and security headers an
instance has enabled. With `--check-hardening` / `CNS_CHECK_HARDENING` these
are evaluated as well:

- Hardenings such as `bruteforceProtection`, `CSPv3`, `sameSiteCookies` and
  `passwordConfirmation`
- Whether HTTPS is enforced
- Security headers such as `X-Frame-Options` and `X-Content-Type-Options`

Anything reported as missing is listed in the output and exported as the
`hardenings_missing` performance metric. A result that would otherwise be `OK`
is raised to `WARNING`; an existing `WARNING`/`CRITICAL` is never downgraded.

```shell
check-nextcloud-security --host nextcloud.example.com --check-hardening
```


# Webhook notifications
The plugin can post a JSON notification to an HTTP(S) endpoint when a check
reaches a critical level. The feature is **optional and disabled by default** -
it activates only once `--webhook-url` (or `CNS_WEBHOOK_URL`) is set.

```shell
check-nextcloud-security --host nextcloud.example.com \
  --webhook-url https://hooks.example.com/nextcloud
```

- `--webhook-on` / `CNS_WEBHOOK_ON` (default `critical`) selects the lowest
  state that triggers a notification. Each level includes the more severe ones:
  `critical`, `warning` (WARNING + CRITICAL), `unknown` (UNKNOWN + WARNING +
  CRITICAL) and `always`.
- `--webhook-header` / `CNS_WEBHOOK_HEADERS` adds request headers, e.g. for
  authentication. Repeat the flag, or separate entries with `;` in the
  environment variable: `CNS_WEBHOOK_HEADERS="X-Auth-Token: abc; X-Env: prod"`.
- `--webhook-timeout` / `CNS_WEBHOOK_TIMEOUT` (default `10`) limits the
  webhook call; it is independent of the Scan API `--timeout`.

Delivery reuses `--retries` / `--backoff-factor`. **A failing webhook never
changes the check result** - the plugin appends `Webhook delivery failed` to
its output and still exits with the state it measured, so a broken
notification channel cannot hide (or fake) a vulnerable instance.

When several hosts are checked in one run, each host that reaches the
configured state produces its own notification. Scans that fail outright
(unreachable host, throttled API) notify as well when `--webhook-on` is set to
`unknown` or `always`.

Example payload:

```json
{
  "plugin": "check-nextcloud-security",
  "plugin_version": "1.3.0",
  "timestamp": "2026-08-07T10:12:33.123456+00:00",
  "host": "nextcloud.example.com",
  "status": "CRITICAL",
  "exit_code": 2,
  "message": "CRITICAL: This server version is end-of-life and has no security fixes.",
  "rating": 0,
  "rating_label": "F",
  "product": "Nextcloud",
  "product_version": "29.0.2.2",
  "domain": "nextcloud.example.com",
  "scanned_at": "2026-08-07 06:28:56.000000",
  "eol": true,
  "vulnerability_count": 0,
  "vulnerabilities": [],
  "missing_hardenings": [],
  "scan_url": "https://scan.nextcloud.com/api/result/6a1d1bd0-...",
  "scan_uuid": "6a1d1bd0-...",
  "duration_seconds": 1.234
}
```

Notifications sent for a failed scan carry only the common fields (`plugin`,
`plugin_version`, `timestamp`, `host`, `status`, `exit_code`, `message`).

> **Note:** treat the webhook as a supplement to your monitoring system, not a
> replacement. It is fire-and-forget and is not retried beyond the configured
> retry budget.


# Retries and backoff
Transient network errors (timeouts, connection resets, `5xx` responses from
scan.nextcloud.com) are retried automatically with exponential backoff before
the check gives up and reports `UNKNOWN`.

- `--retries` / `CNS_RETRIES` (default `2`) - number of retry attempts after
  the initial try (so the default performs up to 3 attempts total).
- `--backoff-factor` / `CNS_BACKOFF_FACTOR` (default `0.5`) - base delay in
  seconds; the wait before each retry doubles (`backoff_factor * 2^attempt`),
  e.g. `0.5s`, `1s`, `2s`, ...
- `--timeout` / `CNS_TIMEOUT` (default `10`) - how long a single Scan API call
  may take before it counts as a failure. Raise it on slow links or when
  scanning through a proxy.

Set `--retries 0` to disable retries entirely and fail fast.


# Performance data
Output includes standard Nagios/Icinga performance data after a `|`
character, so Icinga2/Grafana/etc. can graph results over time:

```
rating=5;;;0;5 vulnerabilities=0;;;0; time=1.234s;;;0;
```

| Metric            | Meaning                                                         |
|:------------------|:-----------------------------------------------------------------|
| `rating`          | Numeric scan rating, `0`-`5` (`5`=A+ ... `0`=F), `U` if unknown |
| `vulnerabilities` | Number of known vulnerabilities reported for the scanned version |
| `time`            | Time spent on the scan, in seconds                               |
| `hardenings_missing` | Missing hardening measures (only with `--check-hardening`)     |
| `extra_checks_failed` | Failed additional checks (local scanner only)                |
| `update_available` | `1` when the local instance announces a pending server update   |


# Rescan
Too many checks with `--rescan` may lead to no further scans being possible for a certain period of time.  
As a rule, it is sufficient to perform one scan per day.

This limit applies to the public Scan API only. `--scan-backend local` always
produces a fresh result (`--rescan` is a no-op there), and the self-hosted
scanner container serves a cached result for `service.cache_ttl` seconds
before scanning again.

# Example output

```Shell
$ check-nextcloud-security -H nextcloud.example.com
CRITICAL: This server version is end-of-life and has no security fixes.
Nextcloud 24.0.11.1 on nextcloud.example.com, rating: F, last scanned: 2023-05-30 07:48:58.000000 | rating=0;;;0;5 vulnerabilities=0;;;0; time=0.842s;;;0;

$ check-nextcloud-security -H nextcloud.example.com
OK: Server is up to date. No known vulnerabilities.
Nextcloud 26.0.2.1 on nextcloud.example.com, rating: A+, last scanned: 2023-05-29 08:50:58.000000 | rating=5;;;0;5 vulnerabilities=0;;;0; time=0.731s;;;0;
```


# Icinga Director
[Icinga Director](https://icinga.com/docs/icinga-director/latest/) manages
`CheckCommand`, `Service Template`, and `Service` objects through its web UI
instead of hand-written config files. The steps below work for either the
native install or the [Docker](#docker) image.

1. **Create the Command**
   - Navigate to *Icinga Director → Commands → Add*.
   - **Command name:** `check_nextcloud_security`
   - **Command:**
     - Native install: `/usr/lib/nagios/plugins/check-nextcloud-security` (wherever you installed/symlinked it, see [Installation](#installation)).
     - Docker: `/usr/bin/docker` (see the [Docker CheckCommand](#using-the-docker-image-instead) example for the required fixed arguments `run`, `--rm`, and the image name).
   - **Command type:** *Plugin Check Command*.

2. **Add the arguments** on the same Command object (*Fields* tab → *Add argument*):

   | Argument   | Value                       | Description                        |
   |:-----------|:----------------------------|:------------------------------------|
   | `--host`   | `$address$` (or a custom Director Data Field, e.g. `$nextcloud_host$`) | Nextcloud hostname or URL, required |
   | `--proxy`  | Data Field `$nextcloud_proxy$`, optional | HTTP/HTTPS proxy |
   | `--rescan` | Set-if Data Field `$nextcloud_rescan$` (boolean), optional | Trigger a fresh scan on every check |
   | `--debug`  | Set-if Data Field `$nextcloud_debug$` (boolean), optional | Verbose debug output |

   For each optional argument, tick *Skip this argument on empty value* so
   Director omits the flag entirely when the field isn't set.

3. **Expose the fields to services** by defining matching *Data Fields* under
   the Command (*Fields* tab → *Add data field*), e.g. `nextcloud_host`,
   `nextcloud_proxy`, `nextcloud_rescan`, `nextcloud_debug` - then set their
   *Data Type* (`String` or `Boolean`) and *Var Filter* as needed.

4. **Create a Service Template**
   - *Icinga Director → Service Templates → Add*.
   - **Check command:** `check_nextcloud_security`.
   - **Check interval:** `24h` (avoid scanning more often - see [Rescan](#rescan)).
   - Leave the Data Fields empty here so they can be filled in per service/host.

5. **Apply it to a host or host group**
   - *Icinga Director → Services → Add* (or a *Service Apply Rule* for a whole host group).
   - Import the Service Template created above.
   - Fill in `nextcloud_host` (or rely on `$address$` if you didn't override it) and any optional fields.
   - Deploy the configuration from *Icinga Director → Deployments*.

Once deployed, Icinga2 will invoke the command exactly as described in the
[Icinga2 / Nagios](#icinga2--nagios) section, whether that resolves to the
native binary or `docker run` under the hood.

## Automated deployment with Ansible

Prefer not to click through Icinga Director or configure hosts by hand?
[`ansible/`](ansible/README.md) contains ready-to-use playbooks that install
and configure check-nextcloud-security (native or Docker) on one or more
Icinga2 hosts, including the `CheckCommand`/`Service` objects described
above. See [`ansible/README.md`](ansible/README.md) for prerequisites and
usage.


# Scheduling without Icinga2 / Nagios (systemd timer / cron)
If you don't run Icinga2/Nagios, you can still schedule regular scans with
systemd timers or cron. Ready-to-adapt example files live in
[`contrib/`](contrib/):

- [`contrib/systemd/check-nextcloud-security.service`](contrib/systemd/check-nextcloud-security.service)
  and [`.timer`](contrib/systemd/check-nextcloud-security.timer)
- [`contrib/systemd/check-nextcloud-security.env.example`](contrib/systemd/check-nextcloud-security.env.example)
- [`contrib/cron/check-nextcloud-security.cron`](contrib/cron/check-nextcloud-security.cron)

## systemd timer
```shell
sudo mkdir -p /etc/check-nextcloud-security
sudo cp contrib/systemd/check-nextcloud-security.env.example /etc/check-nextcloud-security/env
sudo $EDITOR /etc/check-nextcloud-security/env   # set CNS_HOST (and any other options)

sudo cp contrib/systemd/check-nextcloud-security.service /etc/systemd/system/
sudo cp contrib/systemd/check-nextcloud-security.timer /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now check-nextcloud-security.timer

# Run it once immediately to verify the setup:
sudo systemctl start check-nextcloud-security.service
journalctl -u check-nextcloud-security.service
```

## cron
```shell
sudo cp contrib/cron/check-nextcloud-security.cron /etc/cron.d/check-nextcloud-security
sudo chmod 644 /etc/cron.d/check-nextcloud-security
sudo $EDITOR /etc/cron.d/check-nextcloud-security   # set CNS_HOST (and any other options)
```

Both examples configure the check entirely through [environment
variables](#environment-variables), so the same binary or Docker image can be
reused unmodified across hosts - only the environment file/cron entry changes.


# Troubleshooting

**`IP addresses are not supported by the Scan API.`**
Pass a hostname, not an IP address - scan.nextcloud.com resolves the host
itself and cannot scan a bare IP. Use `--host nextcloud.example.com`, not
`--host 203.0.113.10`.

**`UNKNOWN: ... Scan failed! Either no Nextcloud/ownCloud found or too many scans queued`**
Either the target host isn't a reachable Nextcloud/ownCloud instance, or
scan.nextcloud.com is rate-limiting new scan requests from your IP. Wait a
while before retrying, and avoid scheduling checks more often than once a day
(see [Rescan](#rescan)).

**`UNKNOWN: Scan result unclear. Please verify manually.`**
The API returned a rating this plugin doesn't recognize. Run with `--debug`
(or `CNS_DEBUG=1`) to log the raw API response, and check the result manually
at https://scan.nextcloud.com.

**Requests keep failing / retries exhausted**
- Confirm outbound HTTPS access to `scan.nextcloud.com` from the host (or
  container) running the check, including through any required proxy
  (`--proxy` / `CNS_PROXY`).
- Increase `--retries` / `CNS_RETRIES` and `--backoff-factor` /
  `CNS_BACKOFF_FACTOR` if your network is flaky or high-latency.
- Run with `--debug` to see each retry attempt logged.

**Docker: `permission denied while trying to connect to the Docker socket`**
The user running Icinga2/cron/systemd needs permission to talk to the Docker
daemon - either add it to the `docker` group, or run the check via `sudo`,
depending on your security policy.

**Nothing happens / no output from cron or systemd**
- Cron and systemd units don't have a login shell's `PATH` or environment by
  default - use the full path to `check-nextcloud-security` and set
  `CNS_HOST` explicitly (see [Scheduling](#scheduling-without-icinga2--nagios-systemd-timer--cron)).
- Check logs with `journalctl -u check-nextcloud-security.service` (systemd)
  or your configured log file (cron, see the example cron file).

**Exit code reference**

| Exit code | Meaning    |
|:----------|:-----------|
| `0`       | OK         |
| `1`       | WARNING    |
| `2`       | CRITICAL   |
| `3`       | UNKNOWN    |


# Contributing
Bug reports, feature requests and pull requests are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, the test suite,
the linting rules and how releases are cut.

# License
Licensed under the terms of GNU General Public License v3.0. See LICENSE file.

# More
[Dev-Site okxo.de](https://okxo.de/regularly-check-your-nextcloud-instance-for-vulnerabilities)

![Linting](https://github.com/sowoi/check-nextcloud-security//actions/workflows/run-ruff-check.yml/badge.svg)
![Unittests](https://github.com/sowoi/check-nextcloud-security//actions/workflows/run-tests.yml/badge.svg)
![Type checking](https://github.com/sowoi/check-nextcloud-security//actions/workflows/run-mypy-check.yml/badge.svg)
![Ansible](https://github.com/sowoi/check-nextcloud-security//actions/workflows/run-ansible-check.yml/badge.svg)
