# Security policy

iamly Beacon handles privileged integration credentials and should be treated
as security-sensitive infrastructure.

## Supported versions

Security fixes are provided for the latest published release. Operators should
upgrade promptly rather than relying on an older minor version.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the repository's
[private vulnerability reporting form](https://github.com/iamlyio/iamly-beacon/security/advisories/new)
and include:

- the affected version and platform;
- the impact and prerequisites;
- minimal reproduction steps or a proof of concept; and
- any suggested mitigation, if known.

Please avoid accessing data that is not yours, disrupting iamly.io services, or
publishing details before a fix and disclosure plan are agreed. The maintainers
will acknowledge a report through the private advisory and coordinate next
steps there.

## Security model

Beacon accepts only fixed, versioned collection operations from its configured
iamly.io control plane. It does not accept shell commands, scripts, arbitrary
URLs, or executable code. Integration credentials and Beacon's signing private
key remain in the customer environment. See
[the architecture](docs/ARCHITECTURE.md) for the trust boundary.
