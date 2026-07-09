# Ansible playbooks for check-nextcloud-security

Deploy and configure [check-nextcloud-security](../README.md) on one or
more Icinga2 hosts, using either a **native** (pip/virtualenv) install or a
**Docker**-based install. Both playbooks template the same Icinga2
`CheckCommand`/`Service` objects documented in the main [README](../README.md#icinga2--nagios),
so switching between them just means running a different playbook.

> **Important:** Do not apply both playbooks to the same host. Both roles
> manage an Icinga2 `CheckCommand` object with the same name
> (`check_nextcloud_security`), so running both would create conflicting
> configuration. Each role writes a marker file
> (`/etc/icinga2/conf.d/.check_nextcloud_security_{native,docker}`) and
> will refuse to run if the other deployment's marker is present.

## Contents

- `ansible.cfg` - sane local defaults (inventory path, roles path, `become`).
- `requirements.yml` - Ansible Galaxy collection requirements (only needed
  for the Docker playbook).
- `inventory.example.ini` - example inventory; copy and adapt.
- `group_vars/all.yml` - example shared variables.
- `roles/nextcloud_check_native/` - installs the plugin into a dedicated
  virtualenv via pip and symlinks it into the Nagios plugin directory.
- `roles/nextcloud_check_docker/` - builds the Docker image on the target
  host and runs the check via `docker run`.
- `playbooks/deploy_native.yml` / `playbooks/deploy_docker.yml` - entry
  point playbooks applying the respective role to the `icinga_targets`
  group.

## Prerequisites

- Ansible >= 2.14 on your control node.
- Target hosts already running Icinga2 with an existing `Host` object per
  target (the Service object created by these roles attaches to it).
- SSH access and sudo/become privileges on the target hosts.
- **Docker playbook only:** Docker Engine already installed on the target
  host (this role deliberately does not install Docker itself - use
  [geerlingguy.docker](https://galaxy.ansible.com/geerlingguy/docker) or
  your OS's official instructions first), and the `community.docker`
  collection installed locally:

  ```shell
  cd ansible
  ansible-galaxy collection install -r requirements.yml
  ```

## Quick start

```shell
cd ansible
cp inventory.example.ini inventory.ini
$EDITOR inventory.ini   # set your Icinga2 hosts and nextcloud_check_host

# Native (pip/virtualenv) install:
ansible-playbook -i inventory.ini playbooks/deploy_native.yml

# OR Docker install:
ansible-galaxy collection install -r requirements.yml
ansible-playbook -i inventory.ini playbooks/deploy_docker.yml
```

## Variable reference

Both roles share the same plugin-related variables. Set them per-host in
your inventory (see `inventory.example.ini`) or in `group_vars`/`host_vars`.

| Variable                              | Description                                              | Default                        |
|:---------------------------------------|:----------------------------------------------------------|:--------------------------------|
| `nextcloud_check_host`                 | Nextcloud server to scan (hostname or URL)                | `{{ inventory_hostname }}`      |
| `nextcloud_check_proxy`                | HTTP/HTTPS proxy (optional)                                | `""` (unset)                    |
| `nextcloud_check_rescan`               | Trigger a fresh scan each time                             | `false`                         |
| `nextcloud_check_debug`                | Enable verbose debugging output                            | `false`                         |
| `nextcloud_check_retries`              | Retry attempts for transient network errors                | `2`                             |
| `nextcloud_check_backoff_factor`       | Exponential backoff factor (seconds) between retries       | `0.5`                           |
| `nextcloud_check_interval`             | Icinga2 `check_interval` (please keep >= `24h`)            | `24h`                           |
| `nextcloud_check_service_name`         | Icinga2 `Service` object display name                      | `Nextcloud Security Scan`       |
| `nextcloud_check_command_name`         | Icinga2 `CheckCommand` object name                         | `check_nextcloud_security`      |
| `nextcloud_check_icinga_host_name`     | Existing Icinga2 `Host` object to attach the Service to     | `{{ inventory_hostname }}`      |
| `nextcloud_check_icinga_conf_dir`      | Where to write the `.conf` files                           | `/etc/icinga2/conf.d`           |
| `nextcloud_check_validate_config`      | Run `icinga2 daemon -C` after templating                   | `true`                          |
| `nextcloud_check_manage_icinga_service`| Reload/restart icinga2 automatically via handlers          | `true`                          |

These variables map 1:1 to the `CNS_*` environment variables / CLI flags
documented in the main [README's options table](../README.md#options).

### Native role only

| Variable                        | Description                                       | Default                                |
|:---------------------------------|:----------------------------------------------------|:-----------------------------------------|
| `nextcloud_check_repo_url`        | Git URL installed with pip                          | `https://github.com/sowoi/check-nextcloud-security.git` |
| `nextcloud_check_repo_version`    | Git ref (branch/tag/commit) to install              | `main`                                   |
| `nextcloud_check_venv_path`       | Virtualenv location                                 | `/opt/check-nextcloud-security/venv`     |
| `nextcloud_check_plugin_dir`      | Nagios/Icinga2 plugin directory (symlink target)    | `/usr/lib/nagios/plugins`                |

### Docker role only

| Variable                          | Description                                        | Default                                  |
|:-----------------------------------|:------------------------------------------------------|:--------------------------------------------|
| `nextcloud_check_repo_url`          | Git URL cloned to build the image from                | `https://github.com/sowoi/check-nextcloud-security.git` |
| `nextcloud_check_repo_version`      | Git ref (branch/tag/commit) to build                  | `main`                                     |
| `nextcloud_check_clone_dest`        | Where the repo is cloned on the target host           | `/opt/check-nextcloud-security/src`        |
| `nextcloud_check_docker_image_name` | Docker image name                                     | `check-nextcloud-security`                 |
| `nextcloud_check_docker_image_tag`  | Docker image tag                                      | `latest`                                   |
| `nextcloud_check_force_rebuild`     | Always rebuild the image, even without repo changes   | `false`                                     |
| `nextcloud_check_icinga_user`       | Service account added to the `docker` group           | `icinga`                                    |
| `nextcloud_check_docker_binary`     | Path to the Docker CLI used by the CheckCommand       | `/usr/bin/docker`                           |

## What each role does

### `nextcloud_check_native`

1. Fails early if a Docker deployment marker is already present on the host.
2. Installs OS prerequisites (`python3`, `python3-venv`, `python3-pip`, `git`).
3. Creates a virtualenv and installs `check-nextcloud-security` into it
   with `pip install git+...`.
4. Symlinks the venv's `check-nextcloud-security` executable into the
   Nagios plugin directory.
5. Templates the Icinga2 `CheckCommand` and `Service` objects.
6. Validates the Icinga2 configuration (`icinga2 daemon -C`) and reloads
   the service via a handler.
7. Writes a marker file so a later Docker-role run on the same host is
   refused.

### `nextcloud_check_docker`

1. Fails early if a native deployment marker is already present on the host.
2. Verifies Docker is installed and usable; fails with guidance if not.
3. Clones the repository and builds the Docker image with
   `community.docker.docker_image`.
4. Adds the Icinga2 service account to the `docker` group (this requires
   restarting, not just reloading, the icinga2 service - handled by a
   dedicated `restart icinga2` handler, distinct from the `reload icinga2`
   handler used for config-only changes).
5. Templates the Icinga2 `CheckCommand` (running `docker run --rm ...`)
   and `Service` objects.
6. Validates the Icinga2 configuration and reloads/restarts the service.
7. Writes a marker file so a later native-role run on the same host is
   refused.

## Re-running / updating

Both playbooks are idempotent and safe to re-run, e.g. after bumping
`nextcloud_check_repo_version` to pick up a new release:

```shell
ansible-playbook -i inventory.ini playbooks/deploy_native.yml --limit icinga01.example.com
```

## Uninstalling

These roles don't ship a removal playbook. To roll back manually:

- Remove `{{ nextcloud_check_icinga_conf_dir }}/check_nextcloud_security*.conf`
  and the corresponding marker file, then reload icinga2.
- Native: remove `nextcloud_check_venv_path` and the plugin-directory symlink.
- Docker: remove the built image (`docker rmi check-nextcloud-security`) and
  `nextcloud_check_clone_dest`, and optionally remove the icinga2 user from
  the `docker` group.

## Syntax-checking changes

```shell
cd ansible
ansible-playbook --syntax-check playbooks/deploy_native.yml
ansible-playbook --syntax-check playbooks/deploy_docker.yml
ansible-lint playbooks/ roles/   # optional, if ansible-lint is installed
```

These same checks run automatically in CI on every change under `ansible/`
(see [`.github/workflows/run-ansible-check.yml`](../.github/workflows/run-ansible-check.yml)),
so a pull request will fail if a playbook stops parsing or a role picks up
a lint regression.
