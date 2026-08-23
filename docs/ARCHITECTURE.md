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

## Secret memory lifecycle

The encrypted vault decodes signing and integration secrets into owned mutable
byte buffers. Commands erase those buffers when the decrypted vault leaves
scope. The long-running worker erases its decoded signing-key text immediately
after the protocol client copies the Ed25519 key and erases all remaining vault
buffers on shutdown. It creates integration credential strings only for the
duration of one review or connection-test job and drops their maps afterward.

Go strings are immutable. HTTP headers, URL form values, JSON libraries, and
vendor APIs can create temporary string copies whose exact memory lifetime is
controlled by the Go runtime. Beacon therefore does not claim complete process
memory erasure. The byte-owned vault model reduces the deterministic lifetime
of decrypted secrets; host isolation, least-privilege credentials, and process
restart remain required controls.
