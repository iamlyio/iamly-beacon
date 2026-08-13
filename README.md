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
- Unit tests for encryption, permissions, freshness, and tamper detection.

The TUI and GCP KMS vault are the first milestone. Vendor adapters and the outbound Reviam job transport are next; `beacon run` currently fails clearly instead of pretending to collect.

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
beacon configure       Configure GCP KMS and create the encrypted local vault
beacon secret set      Enter and encrypt an integration secret
beacon secret list     List configured secret names without revealing values
beacon status          Decrypt and inspect configuration without exposing secrets
beacon run             Start the outbound collection worker
beacon version         Print the build version
```

See [the architecture](docs/ARCHITECTURE.md) for the SaaS/Beacon trust boundary.

## License

No license has been selected yet. The distribution and licensing model should be chosen deliberately before publication.
