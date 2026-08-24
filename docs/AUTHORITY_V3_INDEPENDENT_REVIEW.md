# Authority V3 Independent Review Handoff

This procedure applies to the exact coordinated release. For the current
official Testnet11 candidate, every request and receipt must bind to
`solslot-v2-alpha-rc27.35-20260823` after all nine final commits are on
`main`, `release/testnet-alpha-rc27.35-20260823`, and the annotated release
tag. RC27.32 review notes remain historical evidence and cannot approve a
changed RC27.35 source scope.

## Purpose

Authority V3 cannot make the alpha ceremony ready by itself. A reviewer outside
the implementation team must examine four trust boundaries and return evidence
bound to the exact nine-source release and live Base Sepolia deployment.

The request packet is intentionally non-approving. It contains
`status: review-required`, leaves the EVM governance evidence hash empty, and
has no review outcome. The ceremony API rejects it as an approval receipt.

## Required Scopes

1. `chialisp-wrapper`
   - Verify owner slot 0 plus one coadministrator.
   - Verify recovery keys cannot perform protocol operations.
   - Verify replacements, vetoes, delays, cancellation, and exact completion.
2. `mips-composition`
   - Verify the pinned Chia wallet SDK source and Apache-2.0 license.
   - Verify singleton membership, restricted recovery, timelocks, and
     side-effect prevention compose as intended.
3. `safe-recovery-module`
   - Verify the two unaffected identity Safes approve lost-key recovery.
   - Verify the cross-chain replacement intent cannot be redirected or partly
     completed.
4. `safe-authority-guards`
   - Verify arbitrary Safe calls, owner swaps, module removal, and guard removal
     remain blocked, including while recovery is pending.

The packet lists the exact source paths, review objectives, and focused test
commands for each scope.

## Build The Request

Run this only after the coordinated release branch and tag are pushed to all
nine repositories, each release commit is on `main`, and all nine worktrees
are clean:

```bash
python scripts/build_authority_v3_review_packet.py \
  --protocol-repo ../solslot-protocol \
  --evm-repo ../solslot-evm \
  --omnichain-repo ../omnichain \
  --api-repo . \
  --legacy-backend-repo ../solslot-backend-rc22-reconcile \
  --key-of-solomon-repo ../key-of-solomon-rc22-reconcile \
  --samuel-repo ../samuel-rc22-reconcile \
  --customer-web-repo ../solslot \
  --admin-portal-repo ../solslot-portal \
  --source-manifest ../release-evidence/source-manifest.json \
  --puzzle-inventory ../solslot-protocol/release-manifests/rc27-puzzle-hashes.json \
  --output-dir /home/hiram/secure/solslot-v2/review-request
```

The builder verifies each canonical remote, clean release worktree, exact
remote `main`, release-branch, and tag ref, source-manifest hash, Authority V3
source commitment, current puzzle inventory and compiled inner-module hash,
all nine commits, and the pinned upstream dependency. Pull-request heads are
not release provenance: a normal merge changes the final commit, so the packet
binds only the final coordinated release refs and manifest.

Give the reviewer both generated files and retain their SHA-256.

If any source SHA changes after review, rebuild the request and repeat the
affected review. A receipt for the old request must remain invalid.

## Export The Deployment Roster

After all three administrators enroll with distinct daily wallets, complete
their separate recovery-kit drills, freeze the roster, and build the
deterministic Testnet11 plan, export the public Authority V3 deployment input:

```bash
python scripts/export_authority_v3_roster.py \
  --database /opt/solslot/api-staging/shared/state/genesis_ceremony_v2.db \
  --ceremony-id 0x... \
  --output /home/hiram/secure/solslot-v2/authority-v3-roster.json
```

The exporter opens the ceremony ledger read-only, refuses symlinks and
overwrites, and writes the result with mode `0600`. It verifies the frozen
roster hash; daily wallet/public-key bindings; three completed, separate
recovery drills; the source-manifest commitment; and all four deterministic
authority/identity launcher IDs. An unplanned or expired ceremony is rejected.

Do not use `export_safe_owner_roster.py` for Authority V3. That command emits
the legacy schema-v1 Safe roster and intentionally lacks the recovery and Chia
launcher bindings required by the current deployer. Supply the schema-v2 file
to the exact Omnichain release as `SOLSLOT_AUTHORITY_V3_ROSTER_PATH`. Exporting
the roster neither deploys contracts nor authorizes a chain transaction.

## Reviewer Evidence

The reviewer should produce one nonempty evidence file for each required scope.
Markdown, text, JSON, or PDF is acceptable. Each file should identify:

- reviewer and review date;
- exact request artifact hash and relevant commits;
- commands and fixtures run;
- assumptions and unresolved questions;
- findings and disposition;
- an explicit approval or rejection for that scope.

An unresolved high-severity finding is not an approval. Do not finalize a
receipt until the live Authority V3 EVM deployment evidence exists and passes
the API evidence loader.

## Finalize The Receipt

After the live Base Sepolia Authority V3 deployment exists, the independent
reviewer can run:

```bash
python scripts/finalize_authority_v3_review.py \
  --request review-request/authority-v3-review-request.json \
  --governance-evidence authority-v3-governance.json \
  --evidence-dir independent-evidence \
  --reviewer 'chialisp-wrapper=Reviewer Name' \
  --reviewer 'mips-composition=Reviewer Name' \
  --reviewer 'safe-recovery-module=Reviewer Name' \
  --reviewer 'safe-authority-guards=Reviewer Name' \
  --evidence 'chialisp-wrapper=chialisp-wrapper.md' \
  --evidence 'mips-composition=mips-composition.md' \
  --evidence 'safe-recovery-module=safe-recovery-module.md' \
  --evidence 'safe-authority-guards=safe-authority-guards.md' \
  --completed-at 'chialisp-wrapper=2026-07-29T19:00:00Z' \
  --completed-at 'mips-composition=2026-07-29T19:00:00Z' \
  --completed-at 'safe-recovery-module=2026-07-29T19:00:00Z' \
  --completed-at 'safe-authority-guards=2026-07-29T19:00:00Z' \
  --attestation \
    'I independently reviewed all listed Authority V3 trust boundaries' \
  --output authority-v3-independent-review.json
```

The command prints the receipt checksum. Configure the API with the receipt
path and that exact checksum. Keep the request, receipt, governance evidence,
and four evidence files together in the private release archive.

## Final Freeze Rule

The final ceremony source manifest requires every source commit to be the exact
commit on remote `main`, the coordinated release branch, and the release tag.
If any ref or manifest field changes, the independent reviewer must receive a
regenerated packet before the ceremony gate can become healthy. The tool never
converts a candidate review into approval automatically.
