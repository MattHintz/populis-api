# Authority V3 Independent Review Handoff

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

Run this only after the four Authority V3 branches are pushed and all nine
worktrees are clean:

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
  --protocol-pr https://github.com/MattHintz/solslot-protocol/pull/7 \
  --omnichain-pr https://github.com/solslot/omnichain/pull/4 \
  --api-pr https://github.com/MattHintz/solslot-api/pull/16 \
  --admin-portal-pr https://github.com/MattHintz/solslot-portal/pull/13 \
  --output-dir /home/hiram/secure/solslot-v2-rc23/review-request
```

The builder verifies the four remote PR heads, canonical remotes, clean
worktrees, the RC23 puzzle inventory, all nine commits, and the pinned upstream
dependency. Give the reviewer both generated files and retain their SHA-256.

If any source SHA changes after review, rebuild the request and repeat the
affected review. A receipt for the old request must remain invalid.

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

The independent reviewer can run:

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
commit on `origin/main` and the RC23 tag. If merging changes a commit, the
independent reviewer must receive a regenerated packet before the ceremony gate
can become healthy. The tool never converts a candidate review into approval
automatically.
