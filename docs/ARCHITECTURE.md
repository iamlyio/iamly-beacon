# Beacon architecture

Beacon is iamly.io's customer-hosted collection boundary.

```text
iamly.io SaaS                         Customer infrastructure
───────────                          ───────────────────────
Create review job  ◀── outbound ───  Beacon long-polls for work
Receive observations ◀─────────────  Vendor APIs + local enrichment
Freeze source snapshot               Integration credentials stay local
Normalize matrix
Apply policy and human decisions
Create findings and evidence
```

The control plane may only request fixed, versioned collection operations. It must never send shell commands, scripts, arbitrary URLs, or executable code. Beacon will contact only its configured iamly.io control plane and compiled-in vendor API hosts.

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

Beacon may upload minimized source observations necessary for a review: vendor account identifiers, status, roles, memberships, last activity, and billing observations. Integration credentials never leave Beacon and must never appear in logs or status output.
