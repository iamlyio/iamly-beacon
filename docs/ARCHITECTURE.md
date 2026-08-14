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

## GCP KMS envelope encryption

Every vault write:

1. Generates a new random 256-bit data-encryption key (DEK) locally.
2. Encrypts and authenticates the vault locally using XChaCha20-Poly1305 and a fresh 24-byte nonce.
3. Sends only the DEK to the configured GCP Cloud KMS CryptoKey for wrapping.
4. Stores the ciphertext, wrapped DEK, nonce, provider, version, and non-secret KMS key resource together.
5. Erases plaintext key and vault byte slices after use on a best-effort basis.

The KMS key resource and format version are authenticated as associated data. KMS requests and responses carry CRC32C integrity checks. The vault is atomically replaced with `0600` permissions inside a `0700` directory.

Beacon uses Application Default Credentials, including Workload Identity on GCP. Operators should grant its workload principal `roles/cloudkms.cryptoKeyEncrypterDecrypter` on only the selected CryptoKey. No service-account JSON key is required or stored by Beacon.

## Trust boundary

Beacon may upload minimized source observations necessary for a review: vendor account identifiers, status, roles, memberships, last activity, and billing observations. Integration credentials never leave Beacon and must never appear in logs or status output.
