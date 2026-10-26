# Security policy

## Reporting a vulnerability

Report privately. Do not open a public issue, pull request or discussion about it.

1. GitHub: open this repository's Security tab and choose "Report a vulnerability". This
   creates a private advisory that only the maintainers can see. If that option is not shown,
   private vulnerability reporting has not been enabled for this repository yet; use email.
2. Email: drake@aienos.com with the subject `[synapse] security report`.

Include the commit or release you tested, the component (path), steps to reproduce, and what an
attacker gains. If the report involves a secret, say where it was exposed and do not send the
secret itself. Encrypted mail is not required; do not post proof-of-concept payloads publicly.

## Response targets

This project has one maintainer; the targets below are best effort and stated honestly.

- Acknowledgement: within 3 working days.
- Triage and severity: within 7 days of acknowledgement.
- Fix or mitigation for confirmed issues: aim for 30 days for high and critical, 90 days
  otherwise, with a status update at least every 14 days until closed.
- Disclosure: coordinated. An advisory is published with credit (unless you ask otherwise)
  once the fix is on the default branch. Default embargo 90 days, negotiable.

## Scope

In scope:

- `synapse-auth`: Ed25519 `did:key` verification, capability grants, expiry, replay and quota
  guards, the hash-chained audit log.
- `synapse-radicle`: the `refs/rad/id` and `sigrefs` delegate threshold verifier and split-brain
  refusal.
- `synapse-store`: the append-only WAL (CRC32C and SHA-256 chain), blob store, recovery.
- `synapse-wire` frames, transport and shared-memory ring; `synapse-api` bounds and pagination.
- `synapse-git`: deterministic Git object writing and reading, ref namespace separation.
- `tests/gates/run.sh`, `.aien/`, `.github/workflows/aien-verification.yml`.

Out of scope: Git, Radicle and GitHub themselves; the Spark test judge `aien-test` (report to
aien-sovereign-core-mv); denial of service through the documented audit log backpressure, which is
by design (`docs/THREAT_MODEL.md`).

## Supported versions

Only the default branch `main`; there is no release (workspace version `0.1.0`). Fixes land on
the default branch only.

## Status

Research code with a written threat model in `docs/THREAT_MODEL.md`. There is no certification
and no bug bounty. See AUDIT_SCOPE.md for what to review and how to build and test it.
