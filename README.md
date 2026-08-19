# iamly.io Beacon

[![CI](https://github.com/iamlyio/iamly-beacon/actions/workflows/ci.yml/badge.svg)](https://github.com/iamlyio/iamly-beacon/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Beacon is iamly.io's customer-hosted collector. It gathers and enriches identity, account, access, and billing data inside the customer's infrastructure, then sends minimized observations to iamly.io. Vendor credentials never leave the customer environment.

[Beacon repository](https://github.com/iamlyio/iamly-beacon) ·
[Product domain](https://iamly.io)

The current release candidate connects to the development control plane at
`https://beacon-dev.iamly.io`. It is intended for testing, not production use.
Each signed poll reports the host name, private interface addresses, and Beacon
version; iamly.io observes the public source address at its trusted reverse
proxy. No vendor credential or signing private key is included.

## Download and install

[GitHub Releases](https://github.com/iamlyio/iamly-beacon/releases/tag/v2.2.0-rc.1)
provides ready-to-run binaries with no language runtime to install. Choose the
archive matching the machine that will keep your application credentials:

| Operating system | AMD64 / Intel | ARM64 / Apple silicon |
| --- | --- | --- |
| Linux | `iamly-beacon_linux_amd64.tar.gz` | `iamly-beacon_linux_arm64.tar.gz` |
| macOS | `iamly-beacon_darwin_amd64.tar.gz` | `iamly-beacon_darwin_arm64.tar.gz` |
| Windows | `iamly-beacon_windows_amd64.zip` | `iamly-beacon_windows_arm64.zip` |

### Linux

For a typical Intel/AMD Linux host:

```sh
archive=iamly-beacon_linux_amd64.tar.gz
base=https://github.com/iamlyio/iamly-beacon/releases/download/v2.2.0-rc.1
curl --fail --location --remote-name "$base/$archive"
curl --fail --location --remote-name "$base/SHA256SUMS"
grep " $archive\$" SHA256SUMS > SHA256SUMS.selected
sha256sum --check SHA256SUMS.selected
tar -xzf "$archive"
install -m 0755 beacon "$HOME/.local/bin/beacon"
beacon version
```

Use `iamly-beacon_linux_arm64.tar.gz` instead on an ARM64 host. Ensure
`$HOME/.local/bin` is in `PATH`.

### macOS

Use `darwin_arm64` on Apple silicon or `darwin_amd64` on an Intel Mac:

```sh
archive=iamly-beacon_darwin_arm64.tar.gz
base=https://github.com/iamlyio/iamly-beacon/releases/download/v2.2.0-rc.1
curl --fail --location --remote-name "$base/$archive"
curl --fail --location --remote-name "$base/SHA256SUMS"
grep " $archive\$" SHA256SUMS > SHA256SUMS.selected
shasum -a 256 -c SHA256SUMS.selected
tar -xzf "$archive"
mkdir -p "$HOME/.local/bin"
install -m 0755 beacon "$HOME/.local/bin/beacon"
"$HOME/.local/bin/beacon" version
```

### Windows

In PowerShell, use `windows_amd64` on most PCs or `windows_arm64` on Windows on
ARM:

```powershell
$Archive = "iamly-beacon_windows_amd64.zip"
$Base = "https://github.com/iamlyio/iamly-beacon/releases/download/v2.2.0-rc.1"
Invoke-WebRequest "$Base/$Archive" -OutFile $Archive
Invoke-WebRequest "$Base/SHA256SUMS" -OutFile "SHA256SUMS"
$Expected = ((Select-String -Path "SHA256SUMS" -Pattern " $Archive$").Line -split "\s+")[0]
$Actual = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
if ($Actual -ne $Expected) { throw "Beacon checksum verification failed" }
$InstallDir = Join-Path $env:LOCALAPPDATA "iamly\bin"
New-Item -ItemType Directory -Force $InstallDir | Out-Null
Expand-Archive -Force $Archive $InstallDir
& (Join-Path $InstallDir "beacon.exe") version
```

Add `%LOCALAPPDATA%\iamly\bin` to the user `PATH` if you want to run `beacon`
without its full path.

Release artifacts also include a CycloneDX SBOM and GitHub build provenance.
With the GitHub CLI installed, verify provenance before installation:

```sh
gh attestation verify "$archive" --repo iamlyio/iamly-beacon
```

After installation, continue with [Quick start](#quick-start). Beacon needs
outbound HTTPS access but no inbound port.

## Quick start

1. In iamly.io, open **Integrations → Beacon**, create an enrollment token, and
   keep the single-use token available.
2. Choose local key storage, Google Cloud KMS, or AWS KMS for the encrypted
   vault. Local storage is the simplest default; cloud KMS keeps the wrapping
   key outside the Beacon host.
3. Start the guided setup, then enter the Beacon name, enrollment token, and
   `https://beacon-dev.iamly.io` when prompted:

   ```sh
   beacon configure --local
   ```

   Use `beacon configure --google-kms` or `beacon configure --aws-kms` to
   select a cloud key instead.

4. Add one or more read-only integrations, then confirm the non-secret status:

   ```sh
   beacon secret set google
   beacon status
   ```

5. Start the outbound worker with `beacon run`, or install the included
   [systemd user service](deploy/beacon.service) on Linux.

Beacon requires no inbound port. Keep its vault directory private, and never
paste integration credentials into issues, logs, or command-line arguments.

## Why Go

Beacon ships as one cross-platform binary with no language runtime to install. Go fits an always-running collector and keeps the security-sensitive boundary small enough to audit.

The repository follows Semantic Versioning. Release builds read the current
version from `VERSION`; `make build` stamps that value into `beacon version`.

## Current foundation

- Interactive terminal interface built with Bubble Tea.
- `configure`, `secret`, `status`, `run`, and `version` commands.
- Masked in-TUI entry for integration credentials; secret values are never CLI arguments.
- Local XChaCha20-Poly1305 vault using a new data key and nonce per write.
- Local, Google Cloud KMS, and AWS KMS vault-key providers with authenticated
  envelope encryption and automatic provider discovery for existing vaults.
- Application Default Credentials, AWS's default credential chain, and cloud
  workload identities—no long-lived cloud credential file required.
- Atomic vault writes with restrictive local permissions.
- HTTPS enforcement for non-local iamly.io control planes.
- Locally generated Ed25519 Beacon identity; only the public key is enrolled with iamly.io.
- Single-use enrollment tokens are accepted through masked TUI input or standard input and are never persisted.
- Signed, nonce-protected outbound review-job polling with concurrent per-app uploads.
- Bounded transient retries for vendor APIs and idempotent result uploads; expired jobs resume with only their missing applications.
- Strict vendor-response size and pagination limits; redirects are refused so local authorization headers cannot cross request boundaries.
- Sixteen local, read-only account collectors spanning HR, identity, cloud,
  developer, collaboration, network, and AI platforms.
- GitHub deploy-key inventory across accessible organization repositories; only non-secret metadata is uploaded, never key material.
- GitHub current-month net billing usage, normalized as USD spend when the organization billing API is available.
- Unit tests for enrollment, request signing, encryption, permissions, freshness, and tamper detection.

`beacon run` is a long-running worker. Install `deploy/beacon.service` as a systemd user service on Linux so it restarts after failures and reboots without requiring an inbound port.

## Review workflow

1. A workspace requests a review in iamly.io.
2. Beacon claims the job through signed outbound HTTPS; no inbound port is required.
3. Configured collectors run independently and concurrently inside the customer environment.
4. Each collector completes its application-specific profile, role, activity, credential, and billing enrichment locally.
5. Beacon uploads each normalized application snapshot as soon as it is ready; one failed connector does not block the others.
6. A temporary network interruption is retried in place. If the job lease expires, Beacon reclaims it and reruns only applications whose snapshots were not accepted.
7. iamly.io waits for every requested connector to reach a terminal state, builds the unified access matrix, applies policy analysis, and retains findings and audit evidence.

## Supported collectors

| Application | Beacon vault names | Collected observations |
| --- | --- | --- |
| BambooHR | `bamboohr.companyDomain`, `bamboohr.apiKey` | Complete employee roster, active/inactive lifecycle, work email, job title, department, hire date |
| Google Workspace | `google.clientEmail`, `google.privateKey`, `google.adminEmail` | Directory identities, status, administrator role, creation time, last login |
| GCP | `gcp.clientEmail`, `gcp.resourceScope`, `gcp.privateKey` | Direct IAM users and service accounts, lifecycle, and granted roles in one project, folder, or organization |
| GitHub | `github.token`, `github.org` | Members, outside collaborators, roles, public profile enrichment, deploy keys, available billing usage |
| Slack | `slack.userToken` | Members, guest types, status, last-seen activity, billable-seat facts |
| Tailscale | `tailscale.clientId`, `tailscale.clientSecret` | Tailnet users, roles, lifecycle status, and activity |
| Twingate | `twingate.network`, `twingate.apiToken` | Network users, roles, types, and lifecycle status |
| Notion | `notion.token` | Workspace people and bots visible to an internal integration |
| Zoom | `zoom.accountId`, `zoom.clientId`, `zoom.clientSecret` | Active, inactive, and pending users, roles, license type, last login |
| Figma | `figma.token`, `figma.tenantId` | SCIM-provisioned users, lifecycle, administrator flag, and seat type |
| OpenAI | `openai.adminApiKey` | API Platform organization users and roles |
| Anthropic | `anthropic.adminApiKey` | Console organization users and roles |
| Linear | `linear.apiKey` | Active and disabled workspace users, roles, and activity |
| Vercel | `vercel.token`, `vercel.teamId` | Team members, roles, and pending email invitations |
| Asana | `asana.token`, `asana.workspaceGid` | Users visible in one workspace or organization |
| Canva | `canva.token` | SCIM-managed team users and lifecycle status |

Each supported collector has guided credential setup:

```sh
beacon secret set bamboohr
beacon secret set gcp
beacon secret set github
beacon secret set google
beacon secret set notion
beacon secret set slack
beacon secret set tailscale
beacon secret set twingate
beacon secret set zoom
# Also: anthropic, asana, canva, figma, linear, openai, and vercel
```

Beacon prompts for every required value, masks tokens and private keys, and
writes the complete integration profile to the encrypted vault in one update.
Running `beacon secret set` without an integration remains available for
generic single-secret entry.

`beacon run` reads the vault when the worker starts. If Beacon is already
running as a service, restart it after adding or changing credentials so the
control plane receives the new integration inventory before another review is
queued:

```sh
systemctl --user restart beacon.service
systemctl --user status beacon.service --no-pager
journalctl --user -u beacon.service -n 20 --no-pager
```

The startup log reports the number of integrations available. Confirm that
count and the integration status in iamly.io before starting a review. A review
keeps the application scope it had when queued; restarting Beacon cannot add a
new integration retroactively to an in-progress review.

## BambooHR collection

Create a dedicated read-only API key owned by a BambooHR user who can view the
complete employee roster and the work email, hire date, department, and job
title fields. Run `beacon secret set bamboohr` and follow the prompts for:

```text
bamboohr.companyDomain
bamboohr.apiKey
```

Credential names are case-sensitive; enter `companyDomain` and `apiKey`
exactly as shown.

For `https://acme.bamboohr.com`, the company domain is `acme`. Beacon calls only
the read-only employee roster endpoint. It intentionally does not use the
optional company directory because BambooHR excludes inactive and former
employees from that directory.

## Vault storage

Beacon encrypts every vault write locally with a fresh random data-encryption
key. Choose exactly one backend to protect that key:

```sh
beacon configure --local
beacon configure --google-kms
beacon configure --aws-kms
```

New vaults default to `--local` when no backend flag is supplied. Existing
vaults remember their provider, so `beacon status`, `beacon run`, and secret
commands do not need a backend flag. Running `configure` with a different
explicit backend decrypts the current vault and re-wraps it with the selected
provider after a successful self-test.

Local mode creates `local.key` beside `vault.bin`. Both remain on the Beacon
host in a `0700` directory with `0600` files. Back up both files together and
protect the backup: filesystem access to both is sufficient to decrypt the
vault. Local mode is convenient for development and single-host deployments;
cloud KMS gives stronger separation for production.

### Google Cloud KMS prerequisites

Create or select a symmetric `ENCRYPT_DECRYPT` CryptoKey, then grant Beacon's workload identity the narrow role below on that key:

```text
roles/cloudkms.cryptoKeyEncrypterDecrypter
```

Beacon accepts the full CryptoKey resource:

```text
projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY
```

Authentication uses Google Application Default Credentials. On GCP, prefer an attached service account through Workload Identity. For local development, use `gcloud auth application-default login`.

Start setup with `beacon configure --google-kms`. The key must be a full
CryptoKey resource such as
`projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY`.

### AWS KMS prerequisites

Use a symmetric `ENCRYPT_DECRYPT` AWS KMS key. Grant Beacon only `kms:Encrypt`
and `kms:Decrypt` on that key, then start setup with:

```sh
beacon configure --aws-kms
```

Beacon accepts a key ARN, key ID, alias ARN, or `alias/name`. A key ARN carries
its AWS Region with it; otherwise configure `AWS_REGION`. Authentication uses
the AWS SDK default credential chain, including environment, shared config,
ECS task roles, and EC2 instance roles. AWS KMS requests bind the key identifier
as encryption context.

## GitHub collection

Run `beacon secret set github` and follow the prompts, or use the bounded stdin
importer, for:

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

## Zoom collection

Create a Zoom Server-to-Server OAuth application, then run
`beacon secret set zoom` and follow the prompts (or use the bounded stdin
importer) for:

```text
zoom.accountId
zoom.clientId
zoom.clientSecret
```

Grant the granular read-only `user:read:list_users:admin` scope (or the classic
`user:read:admin` equivalent). Beacon exchanges the three local values for a
short-lived Zoom access token, inventories active, inactive, and pending users,
enriches role and last-login information, and sends only normalized account
observations to iamly.io.

## Develop

Requires Go 1.25.13 or newer so Beacon includes the current standard-library
TLS, URL, certificate, and HTTP security fixes.

```sh
git clone https://github.com/iamlyio/iamly-beacon.git
cd iamly-beacon
make check
make build
./beacon
```

Set `BEACON_HOME` to choose a local runtime directory. Otherwise Beacon uses the operating system's user configuration directory.

## Commands

```text
beacon                 Open the interactive terminal interface
beacon configure [--local | --google-kms | --aws-kms]
                       Configure interactively; new vaults default to local storage
beacon configure [STORAGE] --control-plane URL --name NAME [--kms-key KEY] --enrollment-token-stdin
                       Configure noninteractively; cloud providers require --kms-key
beacon secret set [integration]
                       Guided setup for any supported collector;
                       omit integration for generic single-secret entry
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

After any `beacon secret set ...` command, restart this service to reload the
vault and advertise the updated collector list.

See [the architecture](docs/ARCHITECTURE.md) for the SaaS/Beacon trust boundary.

## Project policy

- [Security policy and private vulnerability reporting](SECURITY.md)
- [Contributing guide](CONTRIBUTING.md)
- [Support guidance](SUPPORT.md)
- [Release process](docs/RELEASING.md)
- [Public release checklist](docs/PUBLIC_RELEASE_CHECKLIST.md)
- [Changelog](CHANGELOG.md)

iamly Beacon is available under the [Apache License 2.0](LICENSE).
