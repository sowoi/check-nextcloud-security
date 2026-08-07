<!-- TOC -->
* [check-nextcloud-security](#check-nextcloud-security)
* [Quick start](#quick-start)
* [Features](#features)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
  * [Docker](#docker)
  * [Icinga2 / Nagios:](#icinga2--nagios-)
* [CLI Usage](#cli-usage)
  * [Command](#command)
* [Options:](#options)
* [Environment variables](#environment-variables)
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
* [Troubleshooting](#troubleshooting)
* [License](#license)
* [More](#more)
<!-- TOC -->

# check-nextcloud-security
Check the security level of your Nextcloud instance with the Nextcloud Security API

This check uses Nextcloud's own security scan at scan.nextcloud.com to check if your Nextcloud instance has any known vulnerabilities/risks.

# Quick start
No clone, no Python, no dependency install - just Docker. This builds the
image straight from the Git repository and runs a single check:

```shell
docker run --rm $(docker build -q https://github.com/sowoi/check-nextcloud-security.git) --host nextcloud.example.com
```

For a permanent setup (Icinga2, systemd timer, cron, ...) see
[Installation](#installation) below.

# Features
- Debugging
- Web proxy support
- Trigger a fresh rescan on demand
- Standard Nagios/Icinga exit codes (OK, WARNING, CRITICAL, UNKNOWN)
- Ready-to-use Docker image - no local Python setup required
- Fully configurable via environment variables (great for Docker, systemd, cron)
- Automatic retry with exponential backoff on transient network errors
- Configurable rating thresholds for WARNING and CRITICAL
- Optional hardening and security-header checks (`--check-hardening`)
- Optional webhook notification when a check turns critical
- Nagios/Icinga performance data (rating, vulnerability count, scan duration)


# Prerequisites
- Either Python 3.10+ **or** Docker - pick whichever installation method you use below.
- `requests` (installed automatically with any of the Python-based methods below)

# Installation
Pick whichever method fits your workflow best.

## Docker
No Python, pip, or dependency management required on the host - only Docker.

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

The container has no network ports and needs only outbound HTTPS access to
`scan.nextcloud.com`. It runs as an unprivileged `nagios` user and exits with
the same Nagios-style codes (`0`/`1`/`2`/`3`) as the native script, so it can
be dropped straight into any monitoring pipeline that already understands
`docker run` as a check command (see [Icinga2 / Nagios](#icinga2--nagios-) and
[Icinga Director](#icinga-director) below).

If you'd rather not build locally, push the built image to your own registry
(e.g. `docker tag check-nextcloud-security registry.example.com/check-nextcloud-security` followed by `docker push ...`) and reference that image on your monitoring host(s) instead.

## Using pipx / uv / pip
All of these expose a `check-nextcloud-security` command on your `PATH`.

The package is published on [PyPI](https://pypi.org/project/check-nextcloud-security/), so a plain
`pip install check-nextcloud-security` (or the pipx/uv equivalents below) is
the quickest way to get started. If you need the latest unreleased changes,
install directly from git instead by using the `git+https://...` URLs shown
below.

**Using [pipx](https://pipx.pypa.io/) (recommended for CLI tools):**
```shell
pipx install check-nextcloud-security
# or, to install the latest unreleased changes from git:
pipx install git+https://github.com/sowoi/check-nextcloud-security.git
```

**Using [uv](https://docs.astral.sh/uv/):**
```shell
uv tool install check-nextcloud-security
# or, to install the latest unreleased changes from git:
uv tool install git+https://github.com/sowoi/check-nextcloud-security.git
```

**Using pip:**
```shell
pip install check-nextcloud-security
# or, to install the latest unreleased changes from git:
pip install git+https://github.com/sowoi/check-nextcloud-security.git
```

Upgrade an existing pip installation with:
```shell
pip install --upgrade check-nextcloud-security
```

**Manual / air-gapped install:**
- Clone or download this repository to your local Nextcloud server (or wherever you want to run the check).
- Install the runtime dependency:
```shell
pip install -r requirements.txt
```
- Run the script directly with `python3 check_nextcloud_security.py ...` instead of the `check-nextcloud-security` command.


## Icinga2 / Nagios: 
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
| `time`            | Time spent querying scan.nextcloud.com, in seconds               |


# Rescan
Too many checks with `--rescan` may lead to no further scans being possible for a certain period of time.  
As a rule, it is sufficient to perform one scan per day.

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
[Icinga2 / Nagios](#icinga2--nagios-) section, whether that resolves to the
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


# License
Licensed under the terms of GNU General Public License v3.0. See LICENSE file.

# More
[Dev-Site okxo.de](https://okxo.de/regularly-check-your-nextcloud-instance-for-vulnerabilities)

![Linting](https://github.com/sowoi/check-nextcloud-security//actions/workflows/run-ruff-check.yml/badge.svg)
![Unittests](https://github.com/sowoi/check-nextcloud-security//actions/workflows/run-tests.yml/badge.svg)
![Type checking](https://github.com/sowoi/check-nextcloud-security//actions/workflows/run-mypy-check.yml/badge.svg)
![Ansible](https://github.com/sowoi/check-nextcloud-security//actions/workflows/run-ansible-check.yml/badge.svg)
