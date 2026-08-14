# Reviam Beacon

Beacon is Reviam's customer-hosted collector. It gathers and enriches identity, account, access, and billing data inside the customer's infrastructure, then sends minimized observations to Reviam. Vendor credentials never leave the customer environment.

## Why Go

Beacon ships as one cross-platform binary with no language runtime to install. Go fits an always-running collector and keeps the security-sensitive boundary small enough to audit.

## Current foundation

- Interactive terminal interface built with Bubble Tea.
- `configure`, `status`, `run`, and `version` commands.
- Masked in-TUI entry for integration credentials; secret values are never CLI arguments.
- Local XChaCha20-Poly1305 vault using a new data key and nonce per write.
- GCP Cloud KMS envelope encryption with CRC32C integrity validation.
- Application Default Credentials and Workload Identity support—no GCP key file required.
- Atomic vault writes with restrictive local permissions.
- HTTPS enforcement for non-local Reviam control planes.
- Locally generated Ed25519 Beacon identity; only the public key is enrolled with Reviam.
- Single-use enrollment tokens are accepted through masked TUI input or standard input and are never persisted.
- Signed, nonce-protected outbound review-job polling with concurrent per-app uploads.
- Local Google Workspace, GitHub, and Slack account collectors.
- GitHub deploy-key inventory across accessible organization repositories; only non-secret metadata is uploaded, never key material.
- GitHub current-month net billing usage, normalized as USD spend when the organization billing API is available.
- Unit tests for enrollment, request signing, encryption, permissions, freshness, and tamper detection.

`beacon run` is a long-running worker. Install `deploy/beacon.service` as a systemd user service on Linux so it restarts after failures and reboots without requiring an inbound port.

## GCP prerequisites

Create or select a symmetric `ENCRYPT_DECRYPT` CryptoKey, then grant Beacon's workload identity the narrow role below on that key:

```text
roles/cloudkms.cryptoKeyEncrypterDecrypter
```

Beacon accepts the full CryptoKey resource:

```text
projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY
```

Authentication uses Google Application Default Credentials. On GCP, prefer an attached service account through Workload Identity. For local development, use `gcloud auth application-default login`.

## GitHub collection

Store these two values through `beacon secret set` or the bounded stdin importer:

```text
github.token
github.org
```

Use a fine-grained personal access token owned by the organization and select all repositories. Grant read-only access to:

- Repository Metadata, to enumerate repositories.
- Repository Administration, to inventory active deploy keys.
- Organization Members, to inventory members and outside collaborators.
- Organization Administration, to read current-month billing usage.

Beacon enriches each organization account from its GitHub user profile and
includes the profile email when the user has made it public. GitHub does not
expose other members' private email addresses through the authenticated-user
email permission. The optional Account permission **Email addresses: Read**
adds the token owner's verified primary email only; it does not reveal private
addresses for the rest of the organization.

Billing collection requires GitHub's enhanced billing platform. The organization usage-summary endpoint is currently a public preview, so Beacon treats unavailable billing as optional enrichment and still uploads a valid account and deploy-key snapshot.

## Develop

Requires Go 1.24 or newer.

```sh
make check
make build
./beacon
```

Set `BEACON_HOME` to choose a local runtime directory. Otherwise Beacon uses the operating system's user configuration directory.

## Commands

```text
beacon                 Open the interactive terminal interface
beacon configure       Configure GCP KMS and enroll through the interactive TUI
beacon configure --kms-key KEY --control-plane URL --name NAME --enrollment-token-stdin
                       Configure noninteractively, reading the one-time token from stdin
beacon secret set      Enter and encrypt an integration secret
beacon secret import --stdin
                       Atomically import a bounded versioned credential bundle from a pipe
beacon secret list     List configured secret names without revealing values
beacon status          Decrypt and inspect configuration without exposing secrets
beacon run             Start the outbound collection worker
beacon version         Print the build version
```

On a Linux host:

```sh
install -d -m 0700 ~/.config/systemd/user
install -m 0600 deploy/beacon.service ~/.config/systemd/user/beacon.service
systemctl --user daemon-reload
systemctl --user enable --now beacon.service
sudo loginctl enable-linger "$USER"
```

See [the architecture](docs/ARCHITECTURE.md) for the SaaS/Beacon trust boundary.

## License

No license has been selected yet. The distribution and licensing model should be chosen deliberately before publication.
