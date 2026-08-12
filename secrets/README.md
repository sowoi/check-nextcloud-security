# Secrets

`docker-compose.yml` mounts the files in this directory as Docker secrets at
`/run/secrets/<name>` inside the containers. The `.example` files are templates:
copy them, put the real value in, and never commit the result - everything in
this directory except `*.example` and this README is git-ignored.

```shell
# Token that protects the scanner service. Any random string will do.
openssl rand -hex 32 > secrets/scanner_token

# Monitoring token of the serverinfo app, created on the Nextcloud server:
#   occ config:app:set serverinfo token --value <token>
printf '%s' '<token>' > secrets/serverinfo_token

chmod 600 secrets/scanner_token secrets/serverinfo_token
```

| File | Used by | Purpose |
|:-----|:--------|:--------|
| `scanner_token` | `scanner` (`CNS_SERVICE_TOKEN_FILE`), `check` (`CNS_SCAN_TOKEN_FILE`) | Shared token for the scan service. Requests without it are rejected. |
| `serverinfo_token` | `scanner` (`CNS_SERVERINFO_TOKEN_FILE`) | `NC-Token` for the serverinfo update check on the Nextcloud instance. |

Trailing newlines are stripped when a secret is read, so `openssl rand -hex 32 >
file` and `echo secret > file` both work.

Outside of Docker the same files can be referenced with `secret://scanner_token`
(resolved below `CNS_SECRETS_DIR`, `/run/secrets` by default), with
`file:///path/to/file`, or with the `_FILE` environment variable convention.
