# Adversarial security review: OptimisticGovGuard

Review date basis: current contract revision. Every party that can call the
contract is assumed adversarial, including the proposer, the admin, the authors
of the fetched specification, and validators' inputs.

## 1. State machine

Proposal verdicts (`verdict` + `audited`):

| State | audited | Who may leave it | Method | Next state | Funds |
|-------|---------|------------------|--------|------------|-------|
| PENDING | False | anyone (permissionless) | audit_proposal | APPROVED / CONDITIONAL_REVIEW / VETOED | none |
| APPROVED | True | no one (terminal) | - | - | none |
| CONDITIONAL_REVIEW | True | no one (terminal) | - | - | none |
| VETOED | True | no one (terminal) | - | - | none |

Articles are admin-owned configuration, not fund states. `add_constitutional_article`
and `toggle_article` are admin-only.

Public write surface: add_constitutional_article, toggle_article, submit_proposal,
audit_proposal.

## 2. Liveness / stuck funds

The contract holds and transfers no native or ERC-20 value. A PENDING proposal is
inert metadata; any account may call `audit_proposal`, so there is no party that
must act to unstick a balance. There is no lock-up bug because there is no lock.
The external executor that reads the verdict owns any real timelock; that is a
documented trust boundary, not this primitive's responsibility.

## 3. Race conditions

- Double audit: `audit_proposal` checks `proposal.audited` BEFORE any
  non-deterministic work and sets it in the same transaction, so a second audit
  reverts ("already audited") and can never re-run web/LLM or overwrite a verdict.
  Proven by `test_audit_blocked_when_already_audited`.
- audit before submit: audit requires the proposal to exist, otherwise it reverts.
- Tier-1 selection is deterministic: active articles are walked in ascending id
  order (TreeMap.items is sorted) and the first breached ceiling wins, so two
  auditors of the same storage state always pick the same violated article.

## 4. Invariants (enforced in code and asserted in tests)

- I1: `audited == True` implies `verdict` is one of APPROVED, CONDITIONAL_REVIEW,
  VETOED, and the record is immutable thereafter.
- I2: `0 <= risk_score <= 100` always. `_coerce_risk` clamps and is applied on both
  the leader and the validator, and again before the storage write.
- I3: `violated_article_id != 0` only ever for a VETOED result that references a
  currently active article. `_parse_audit` zeroes it for non-VETOED, and the write
  path zeroes a VETOED id that is not in the active set. Proven by
  `test_audit_mocked_conditional_review` and `test_audit_vetoed_bogus_article_id_is_clamped`.
- I4: `next_article_id` / `next_proposal_id` are strictly greater than every stored
  id; ids are never reused.
- I5: summary counters (`approved + conditional + vetoed + pending == total`) are
  derived by a single scan of `proposals`, so they can never drift apart. Proven by
  `test_governance_summary_counts`.

## 5. Input validation (floor and ceiling on every window)

- Article: title 1..200 chars, mandate 1..2000 chars, `max_treasury_spend_bps`
  hard-bounded to 1..10000, active article count capped at 64 to bound prompt size.
- Proposal: title 1..200 chars, `spec_url` 1..2048 chars and must start with
  http:// or https:// (rejects file/ftp/javascript schemes), `requested_spend_bps`
  bounded 0..10000.
- Toggle and audit reject unknown ids; views reject unknown ids and return empty
  lists where a missing entity is benign.
- Rejection (not clamping) is used for every caller-supplied bound. The only
  clamping is on the untrusted LLM numeric output, and it is documented here.

## 6. Consensus safety

- The decision surface is a fixed label set (verdict) plus a bounded article id.
  The LLM `risk_score` is metadata only and never drives any transfer here, so no
  free-form number gates value.
- Tier-1 numeric breach is fully deterministic and injection-proof: it is decided
  from on-chain storage caps before any external fetch, so a malicious spec page
  cannot flip an over-cap proposal. Proven by
  `test_hardcap_veto_ignores_prompt_injection`.
- Tier-2 uses `gl.eq_principle.prompt_comparative`: every validator independently
  re-fetches the same `spec_url` and re-runs the audit, and the principle requires
  exact agreement on verdict and violated_article_id plus same-band agreement on
  risk. The free-text rationale is deliberately not compared.
- Fail-closed on bad evidence: an unreachable or empty spec raises a TRANSIENT
  error, so a leader failure versus a validator success is a disagreement that
  forces rotation instead of persisting a fabricated APPROVED.
- KNOWN LIMITATION (honest): Tier-2 semantic judgments are only as strong as
  validator re-audit. Fetched text is treated as untrusted but a sufficiently
  crafted injection could bias both leader and validator, since they run the same
  prompt. The deterministic hard cap bounds the blast radius of such a bias to
  semantic (non-numeric) mandates only. This was not proven injection-proof end to
  end; the numeric path was.
- Direct-mode tests exercise only the leader path. Validator agreement is covered
  by the live studionet integration run, not by direct mode.

## 7. Test coverage

Negative tests exist for: non-admin article add, non-admin toggle, unknown article
in toggle, empty/oversized bps, empty title, non-http url, over-cap spend, unknown
proposal audit, double audit, LLM-cited bogus article id, and injection against
the numeric cap. Scenario tests cover approval, conditional review, semantic veto,
deterministic veto, deactivated-cap passthrough, history, and summary counts.

## Findings

- FIXED: Hallucinated violated_article_id on a VETOED result is cleared to 0 at
  write time if it is not an active article (I3), with a dedicated test.
- FIXED: Double-audit / re-audit race closed by checking `audited` before the
  non-deterministic block, with a dedicated test.
- FIXED: Numeric hard cap is injection-independent (no fetch), with a dedicated
  test that poisons the spec page yet still yields VETOED.
- OPEN (by design, documented): Tier-2 semantic audit relies on validator re-audit
  and is not end-to-end proven injection-proof. Mitigated by the deterministic
  numeric tier and the comparative principle.
