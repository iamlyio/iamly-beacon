# Beacon architecture

Beacon is IAMly's customer-hosted collection boundary.

```text
IAMly control plane                  Customer infrastructure
───────────                          ───────────────────────
Create review job  ◀── outbound ───  Beacon long-polls for work
Receive observations ◀─────────────  Vendor APIs + local enrichment
Freeze source snapshot               Integration credentials stay local
Normalize matrix
Apply policy and human decisions
Create findings and evidence
```

The control plane may only request fixed, versioned collection operations. It must never send shell commands, scripts, arbitrary URLs, or executable code. Beacon will contact only its configured IAMly control plane and compiled-in vendor API hosts.

## Provider-backed envelope encryption

Every vault write:

1. Generates a new random 256-bit data-encryption key (DEK) locally.
2. Encrypts and authenticates the vault locally using XChaCha20-Poly1305 and a fresh 24-byte nonce.
3. Wraps only the DEK with the configured local key, Google Cloud KMS key, or
   AWS KMS key.
4. Stores the ciphertext, wrapped DEK, nonce, provider, version, and non-secret
   key identifier together.
5. Erases plaintext key and vault byte slices after use on a best-effort basis.

The provider, key identifier, and format version are authenticated as associated
data. The vault is atomically replaced with `0600` permissions inside a `0700`
directory. Existing vault metadata selects the provider automatically; changing
providers requires an explicit `configure` backend flag and rewrites the vault
only after the new provider passes a wrap/unwrap self-test.

- **Local:** a random 256-bit wrapping key is stored as `local.key` beside the
  vault with `0600` permissions. This removes cloud availability dependencies,
  but possession of both files is sufficient to decrypt the vault.
- **Google Cloud KMS:** Beacon uses Application Default Credentials, including
  Workload Identity. Grant only `roles/cloudkms.cryptoKeyEncrypterDecrypter` on
  the selected CryptoKey. Requests and responses carry CRC32C integrity checks.
- **AWS KMS:** Beacon uses the AWS SDK default credential chain and requests only
  symmetric `Encrypt` and `Decrypt`. The selected key identifier is bound as KMS
  encryption context; key ARNs also provide their Region.

## Trust boundary

Beacon uploads the account data required for a review: vendor account identifiers, status, roles, memberships, last activity, and billing observations. Integration credentials never leave Beacon and must never appear in logs or status output.

### Canonical key metadata contract

The incompatible wire contract is protocol **2**, defined by
[`protocol/v2/manifest.json`](../protocol/v2/manifest.json) and
[`protocol/v2/schema.json`](../protocol/v2/schema.json). The API and app mirror
these files byte-for-byte. The HTTP paths remain `/api/v1/beacon/...`; the
unchanged `integration_test_v1` capability does not negotiate wire versions.
Protocol 1 payloads and the old `deployKeys` / `deployKeyCoverage` fields are
not accepted by a protocol 2 API.

Review results optionally carry `keys: KeyRecord[]` and
`keyCoverage: KeyCoverage[]`; omitted arrays mean no observations, never
authoritative empty inventory. Each record has exactly `id`, `kind`, `name`,
`resource`, `access`, `scopes`, `status`, `createdAt`, `lastUsedAt`, `expiresAt`,
`owner`, and `createdBy`. Kinds are `api_key`, `deploy_key`, and
`encryption_key`. Statuses are `active`, `disabled`, `revoked`, `expired`,
`pending_deletion`, and `unknown`. Dates, owner, and creator are nullable;
all other fields are required, and `scopes` is an array even when empty.

The identity is `(platform, kind, resource, id)`. A result is limited to
100,000 records and 32 MiB total encoded bytes. IDs and resources must contain
a non-whitespace character and are at most 1,000 characters; their exact text
is preserved, including surrounding whitespace. Names, access, owner, and
creator are at most 500 characters; empty names and access strings are valid.
Scopes contain at most 100 strings of at most 500 characters.
Unknown fields are rejected, including secret values, complete public or
private keys, hashes, and fingerprints.

Coverage has exactly `kind`, `status`, `resourcesScanned`, `resourcesTotal`,
and nullable `message` (at most 500 characters). At most one row per kind is
allowed. Status is `complete`, `partial`, or `unavailable`; counters are
nonnegative safe integers, scanned never exceeds total, and complete requires
equal counters. Each observed key needs matching non-unavailable coverage.
Duplicate identities, duplicate coverage kinds, invalid dates, and unknown
platforms are rejected. Missing or incomplete coverage must not imply
deletion or successful exhaustive collection.

All supplied metadata is validated even when a collection error is present.
A failed snapshot persists no key observations or authoritative coverage.
The API responds with HTTP 400 for `invalid_result`, `invalid_keys`,
`invalid_key`, and `invalid_key_coverage`; invalid payloads are not truncated
or silently accepted.

The `aws` platform is labeled **AWS** and collects KMS encryption-key metadata
only. It has no member directory and does not enumerate IAM access keys.
Historical raw deploy-key snapshots remain immutable evidence for migration
and read-only exports; they are not live wire aliases.

Beacon withholds whitespace-only key identities and oversized metadata before
upload, marking the affected key kind as partial rather than claiming complete
inventory. Nonblank identity text is preserved exactly. Coverage messages share
the wire contract's 500-character limit; oversized details are replaced with a
bounded, non-secret explanation.

## Worker ownership

The protocol client validates each review job's nonempty `pendingPlatforms`
as a subset of `platforms`. The worker collects only that pending subset, so a
resumed lease does not repeat already uploaded integrations. Each collector
owns its bounded context and normalized snapshot; uploads are independent,
while the worker owns lease heartbeats and waits for all collectors before
releasing the job context.

## Secret memory lifecycle

The encrypted vault decodes signing and integration secrets into owned mutable
byte buffers. Commands erase those buffers when the decrypted vault leaves
scope, including newly enrolled signing keys and partially decoded invalid
vault payloads. The long-running worker erases its decoded signing-key text immediately
after the protocol client copies the Ed25519 key and erases all remaining vault
buffers on shutdown. It creates integration credential strings only for the
duration of one review or connection-test job and drops their maps afterward.

Go strings are immutable. HTTP headers, URL form values, JSON libraries, and
vendor APIs can create temporary string copies whose exact memory lifetime is
controlled by the Go runtime. Beacon therefore does not claim complete process
memory erasure. The byte-owned vault model reduces the deterministic lifetime
of decrypted secrets; host isolation, least-privilege credentials, and process
restart remain required controls.
