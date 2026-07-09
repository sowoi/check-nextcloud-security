# Scheduling examples

Ready-to-adapt examples for running `check-nextcloud-security` on a
schedule, outside of Icinga2/Nagios. See the "Scheduling without Icinga2 /
Nagios" section in the main [README.md](../README.md) for full instructions.

- `systemd/` - a `.service` + `.timer` pair, plus an example environment file.
- `cron/` - a `cron.d` drop-in file.

Both approaches rely on the `CNS_*` environment variables documented in the
main README instead of command-line flags, so the same plugin binary/image
can be reused unmodified.
