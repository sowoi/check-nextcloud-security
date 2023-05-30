# check-nextcloud-security
Check the security level of your Nextcloud instance with the Nextcloud Security API

This check uses Nextcloud's own security scan at scan.nextcloud.com to check if your Nextcloud instance has any known vulnerabilities/risks.

# Features
- Debugging
- Web proxy support


# Prerequisites
- Python3
- Python3-requests module

# Installation
- Download check_nextcloud_security.py to your local Nextcloud server or wherever you want to run the check.

Icinga2 / Nagios: 
- Put the Python script to your Pluginfolder. Usually /usr/lib/nagios/plugins/
- Create a new command custome command:

```
object CheckCommand "check_nextcloud_security" {
    import "plugin-check-command"
    command = [ PluginDir + "/check_nextcloud_security.py" ]
    arguments += {
        "--host" = {
            description = "hostname"
            required = true
            value = "$address$"
        }
        
        "--proxy" = {
            description = "Web Proxy"
            required = false
        }
    }
}

```

- Create a new Service object.
- Please do not run the query too often or you will be banned. In the template below 24 hours are given. I would not have it checked more often than that. 

```
object Service "Service: Nextcloud Security Scan" {
   import               "generic-service"
   host_name =          "YOUR NEXTCLOUD HOST"
   check_command =      "check_nextcloud_security"
   check_interval = 24h
}
```


# CLI Usage
- "python3 check_nextcloud_security.py -h" will show you a manual.

- Usage: check_nextcloud_security.py -h 

# Options:
  -h, --help            show this help message and exit

  Generic options:
    -d, --debug         enable debugging outputs (default: no)

  Host options:
    -H HOST, --host=HOST
                        Nextcloud server adress

  Proxy options:
    -P HOST, --proxy=HOST
                        Nextcloud server adress

# Example output

```Shell
python3 check_nextcloud_security.py -H nexcloud.example.com
CRITICAL: This server version is end of life and has no security fixes anymore. 
 Nextcloud 24.0.11.1  on  nextcloud.example.com , rating is  F , last scanned:  2023-05-30 07:48:58.000000

python3 check_nextcloud_security.py -H ok.nextlcoud.example.com
OK: Server is up to date. No known vulnerabilities 
 Nextcloud 26.0.2.1  on  nextcloud.example.com , rating is  A+ , last scanned:  2023-05-29 08:50:58.000000
```


# License
Licensed under the terms of GNU General Public License v3.0. See LICENSE file.

# More
[Dev-Site okxo.de](https://okxo.de/regularly-check-your-nextcloud-instance-for-vulnerabilities)
