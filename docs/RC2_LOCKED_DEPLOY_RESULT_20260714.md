# RC2 Locked Staging Deployment Result - 2026-07-14

RC2 was committed, tagged, and pushed across the five canonical repositories.
The API workflow run `29392689958` built a reproducible release, passed its
tests and scans, and then rejected the new coordinator during local startup.
The workflow restored the preceding locked staging release. No protocol or EVM
broadcast occurred and no write surface was enabled.

## Findings

1. The shared staging environment did not provide
   `SOLSLOT_TRUSTED_PROXY_CIDRS`. RC2 correctly failed its staging startup
   hardening check rather than serving with an undefined forwarding trust
   boundary.
2. The deployment's coordinator-seed assertion matched the public
   `generate_validator_seeds.py` operator tool by filename. No private
   validator seed was present in the release; the check was broader than the
   secret-material condition it was intended to enforce.
3. The shell verification function was called from a conditional context, so
   shell `errexit` did not stop at its first failed HTTP assertion. The final
   result still failed and rolled back, but the intervening diagnostics were
   noisy and could obscure the primary cause.

## RC3 Correction

RC3 keeps all RC2 protocol, EVM, customer-web, and admin-portal commits. Its
API-only correction:

- pins the complete reviewed Cloudflare IPv4 and IPv6 ranges in the staging
  unit;
- pins secure vault cookies and the exact staging CORS origin;
- rejects actual seed files and seed configuration without rejecting public
  seed-generation tooling;
- waits a bounded interval for startup and makes every verification assertion
  explicitly fail closed; and
- adds regression tests and deployment documentation for these conditions.

The published RC2 tags remain unchanged as evidence of the rejected candidate.
RC3 must pass the same full build, test, namespace, secret, reproducibility,
local health, public health, and release-identity gates before it becomes the
locked staging baseline.
