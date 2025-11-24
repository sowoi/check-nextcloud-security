<!-- TOC -->
* [check-nextcloud-security](#check-nextcloud-security)
* [Features](#features)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
  * [Icinga2 / Nagios:](#icinga2--nagios-)
* [CLI Usage](#cli-usage)
  * [Command](#command)
* [Options:](#options)
* [Rescan](#rescan)
* [Example output](#example-output)
* [License](#license)
* [More](#more)
<!-- TOC -->

# check-nextcloud-security
Check the security level of your Nextcloud instance with the Nextcloud Security API

This check uses Nextcloud's own security scan at scan.nextcloud.com to check if your Nextcloud instance has any known vulnerabilities/risks.

# Features
- Debugging
- Web proxy support


# Prerequisites
- Python3.10 or higher
- Python3-requests module

# Installation
- Download check_nextcloud_security.py to your local Nextcloud server or wherever you want to run the check.
- Install requirements using pip
```
pip install -r requirements.txt
```


## Icinga2 / Nagios: 
- Put the Python script to your plugin folder. Usually /usr/lib/nagios/plugins/
- Create a new command custom command:

```
object CheckCommand "check_nextcloud_security" {
    import "plugin-check-command"
    command = [ PluginDir + "/check_nextcloud_security.py" ]

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


# CLI Usage
- `python3 check_nextcloud_security.py -h` will show you a manual.

## Command
```
python3 check_nextcloud_security.py --host <Hostname> --rescan
```

# Options:
| Option         | Description                                            | Default      |
|:---------------|:-------------------------------------------------------|:-------------|
| `-H, --host`   | Nextcloud server address (hostname or URL)             | **required** |
| `-P, --proxy`  | Proxy server address                                   | *None*       |
| `-r, --rescan` | Trigger a fresh scan each time (slower, more accurate) | *False*      |
| `-d, --debug`  | Enable verbose debugging output                        | *False*      |
| `-h, --help`   | Show help and exit                                     | —            |


# Rescan
Too many checks with `--rescan True` may lead to result no further scans being possible for a certain period of time.  
As a rule, it is sufficient to perform one scan per day.

# Example output

```Shell
python3 check_nextcloud_security.py -H nexcloud.example.com
CRITICAL: This server version is end of life and has no security fixes anymore. 
 Nextcloud 24.0.11.1  on  nextcloud.example.com , rating is  F , last scanned:  2023-05-30 07:48:58.000000

python3 check_nextcloud_security.py -H nextcloud.example.com
OK: Server is up to date. No known vulnerabilities 
 Nextcloud 26.0.2.1  on  nextcloud.example.com , rating is  A+ , last scanned:  2023-05-29 08:50:58.000000
 
 
```


# License
Licensed under the terms of GNU General Public License v3.0. See LICENSE file.

# More
[Dev-Site okxo.de](https://okxo.de/regularly-check-your-nextcloud-instance-for-vulnerabilities)

![Linting](https://github.com/sowoi/check-nextcloud-security//actions/workflows/run-ruff-check.yml/badge.svg)
![Unittests](https://github.com/sowoi/check-nextcloud-security//actions/workflows/run-tests.yml/badge.svg)
