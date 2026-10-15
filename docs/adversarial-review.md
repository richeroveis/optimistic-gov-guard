# Adversarial security review: OptimisticGovGuard

Review date basis: current contract revision (hardened). Every party that can
call the contract is assumed adversarial, including the proposer, the admin, the
authors of the fetched specification, and validators' inputs.

## 1. State machine

Proposal verdicts (`verdict` + `audited`):

| State | audited | Who may leave it | Method | Next state | Funds |
|-------|---------|------------------|--------|------------|-------|
| PENDING | False | anyone (permissionless) | audit_proposal | APPROVED / CONDITIONAL_REVIEW / VETOED | none |
| PENDING | False | proposer only | cancel_proposal | CANCELLED | none |
| APPROVED | True | no one (terminal) | - | - | none |
| CONDITIONAL_REVIEW | True | no one (terminal) | - | - | none |
| VETOED | True | no one (terminal) | - | - | none |
| CANCELLED | True | no one (terminal) | - | - | none |

Articles are admin-owned configuration, not fund states. `add_constitutional_article`
and `toggle_article` are admin-only.

Public write surface: add_constitutional_article, toggle_article, submit_proposal,
cancel_proposal, audit_proposal.

## 2. Liveness / stuck states

The contract holds and transfers no native or ERC-20 value. A PENDING proposal is
inert metadata; any account may call `audit_proposal`, so audits are never blocked
on a specific party. The proposer additionally has a dedicated exit:
`cancel_proposal` moves a PENDING, never-audited proposal to the terminal CANCELLED
state, so a proposer whose specification source becomes permanently unreachable is
never stuck with an unsettlable proposal. Proven by
`test_cancel_proposal_by_proposer_settles_cancelled` and
`test_spec_body_of_only_control_chars_fails_closed` (a fail-closed audit leaves the
proposal cancellable). The external executor that reads the verdict owns any real
timelock; that is a documented trust boundary, not this primitive's responsibility.

## 3. Race conditions

- Double audit: `audit_proposal` checks `proposal.audited` BEFORE any
  non-deterministic work and sets it in the same transaction, so a second audit
  reverts ("already audited") and can never re-run web/LLM or overwrite a verdict.
  Proven by `test_audit_blocked_when_already_audited`.
- Cancel versus audit: both transitions require the record to still be PENDING and
  un-audited inside the same deterministic state check, and each writes `audited =
  True` atomically. A cancelled proposal can never be audited
  (`test_cancelled_proposal_cannot_be_audited`), an audited proposal can never be
  cancelled (`test_cancel_after_audit_reverts`), and a second cancel reverts
  (`test_cancel_proposal_twice_reverts`).
- Cancel access control: only `proposal.proposer` may cancel; a third party reverts
  with no state change (`test_cancel_proposal_non_proposer_rejected`).
- audit before submit: audit requires the proposal to exist, otherwise it reverts;
  the same guard exists on cancel (`test_cancel_unknown_proposal_reverts`).
- Tier-1 selection is deterministic: active articles are walked in ascending id
  order (TreeMap.items is sorted) and the first breached ceiling wins, so two
  auditors of the same storage state always pick the same violated article.

## 4. Invariants (enforced in code and asserted in tests)

- I1: `audited == True` implies `verdict` is one of APPROVED, CONDITIONAL_REVIEW,
  VETOED or CANCELLED, and the record is immutable thereafter. Proven by
  `test_cancelled_proposal_cannot_be_audited` and `test_cancel_after_audit_reverts`.
- I2: `0 <= risk_score <= 100` always. `_coerce_risk` clamps and is applied on both
  the leader and the validator, and again before the storage write. Proven by
  `test_llm_oversized_risk_and_huge_rationale_are_clamped` and
  `test_llm_negative_risk_is_clamped_to_zero`.
- I3: `violated_article_id != 0` only ever for a VETOED result that references a
  currently active article. `_parse_audit` zeroes it for non-VETOED, and the write
  path zeroes a VETOED id that is not in the active set. Proven by
  `test_audit_mocked_conditional_review`,
  `test_audit_vetoed_bogus_article_id_is_clamped`,
  `test_llm_vetoed_with_inactive_article_id_is_clamped` and
  `test_llm_vetoed_with_active_article_id_is_kept`.
- I4: `next_article_id` / `next_proposal_id` are strictly greater than every stored
  id; ids are never reused.
- I5: summary counters (`approved + conditional + vetoed + cancelled + pending ==
  total`) are derived by a single scan of `proposals`, so they can never drift
  apart. Proven by `test_governance_summary_counts` and
  `test_summary_counts_cancelled_proposals`.
- I6: stored strings are length-bounded at write time: article title 1..100,
  mandate 1..1500, proposal title 1..120, spec_url 8..512 with no whitespace or
  control characters, rationale at most 400 characters (caller-set cancellation and
  Tier-1 rationales are fixed literals; LLM rationale is truncated). Proven by
  `test_add_article_string_length_overflow_rejected`,
  `test_submit_proposal_title_overflow_rejected`,
  `test_submit_proposal_url_length_bounds_rejected`,
  `test_submit_proposal_url_whitespace_and_control_chars_rejected` and
  `test_llm_oversized_risk_and_huge_rationale_are_clamped`.
- I7: the number of ACTIVE articles is capped at 25, so Tier-1 iteration cost and
  the Tier-2 prompt/context size are strictly bounded. Proven by
  `test_active_articles_cap_enforced`.

## 5. Input validation (floor and ceiling on every window)

- Article: title 1..100 chars, mandate 1..1500 chars, `max_treasury_spend_bps`
  hard-bounded to 1..10000, active article count capped at 25 to bound Tier-1
  iteration and prompt size.
- Proposal: title 1..120 chars, `spec_url` 8..512 chars, must start with http://
  or https:// (rejects file/ftp/javascript schemes), and must contain no
  whitespace, newline or control character (rejects token-splitting and
  prompt-shaping payloads in the fetch target), `requested_spend_bps` bounded
  0..10000.
- Toggle and audit reject unknown ids; cancel and audit reject settled records;
  views reject unknown ids and return empty lists where a missing entity is
  benign.
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
- Tier-2 prompt-injection hardening of the fetched specification: control
  characters are stripped, every embedded occurrence of the delimiter tags is
  defused so proposer text cannot close its own data frame, the sanitized body
  is truncated to 6000 characters, and both the proposal title and the
  specification text are wrapped in explicit
  `<untrusted_proposal_title>` / `<untrusted_proposal_specification>` delimiter
  tags with an instruction that tag content is data, never directives. A body
  that sanitizes to empty fails closed as a TRANSIENT error instead of auditing
  blank evidence. Proven by `test_prompt_wraps_untrusted_spec_in_delimiter_tags`,
  `test_spec_early_tag_close_attempt_is_defused` and
  `test_spec_body_of_only_control_chars_fails_closed`.
- Tier-2 output sanitization: verdict must map onto the canonical enum,
  `risk_score` is clamped to 0..100 (Infinity-style tokens and non-numeric
  values surface as tagged LLM errors that force rotation),
  `violated_article_id` is only kept for a VETOED answer that cites a verified
  active article (otherwise 0), and the rationale is truncated to 400 characters
  before the storage write. Proven by
  `test_llm_oversized_risk_and_huge_rationale_are_clamped`,
  `test_llm_negative_risk_is_clamped_to_zero`,
  `test_llm_infinity_risk_score_fails_closed`,
  `test_llm_vetoed_with_inactive_article_id_is_clamped` and
  `test_audit_vetoed_bogus_article_id_is_clamped`.
- Tier-2 uses `gl.eq_principle.prompt_comparative`: every validator independently
  re-fetches the same `spec_url` and re-runs the audit, and the principle requires
  exact agreement on verdict and violated_article_id plus same-band agreement on
  risk. The free-text rationale is deliberately not compared.
- Fail-closed on bad evidence: an unreachable or empty spec raises a TRANSIENT
  error, so a leader failure versus a validator success is a disagreement that
  forces rotation instead of persisting a fabricated APPROVED.
- Residual risk (honest): Tier-2 semantic judgments remain only as strong as
  validator re-audit; a sufficiently crafted natural-language injection could in
  principle bias both leader and validator because they run the same prompt. The
  sanitization layer above removes the byte-level and length-based attack
  surface, the delimiter framing marks proposer text as data, and the
  deterministic hard cap bounds the blast radius of any residual semantic bias to
  non-numeric mandates. End-to-end injection-proofness of natural-language
  semantics is not something a test can prove; it is mitigated, not eliminated.
- Direct-mode tests exercise only the leader path. Validator agreement is covered
  by the live studionet integration run, not by direct mode.

## 7. Test coverage

39 direct tests. Negative coverage: non-admin article add, non-admin toggle,
unknown article in toggle, empty/oversized bps, empty or oversized titles and
mandates, non-http url, url under the 8-char floor or over the 512-char ceiling,
url with embedded space/tab/NUL/newline, over-cap spend, 26th active article,
unknown proposal audit, unknown proposal cancel, double audit, double cancel,
non-proposer cancel, cancel after audit, audit after cancel, LLM-cited bogus or
deactivated article id, LLM risk score overflow, underflow and Infinity token,
LLM rationale overflow, control-character-only spec body, spec body attempting
an early delimiter-tag close. Scenario coverage: approval, conditional review,
semantic veto, deterministic veto, proposer cancellation, deactivated-cap
passthrough, delimiter-tagged prompt, history, and summary counts including the
cancelled bucket.

## Findings

- FIXED: Hallucinated violated_article_id on a VETOED result is cleared to 0 at
  write time if it is not an active article (I3). Tests:
  `test_audit_vetoed_bogus_article_id_is_clamped`,
  `test_llm_vetoed_with_inactive_article_id_is_clamped`.
- FIXED: Double-audit / re-audit race closed by checking `audited` before the
  non-deterministic block. Tests: `test_audit_blocked_when_already_audited`,
  `test_cancelled_proposal_cannot_be_audited`.
- FIXED: Numeric hard cap is injection-independent (no fetch). Test:
  `test_hardcap_veto_ignores_prompt_injection`.
- FIXED: Stuck PENDING proposal lifecycle gap closed by proposer-only
  `cancel_proposal` (PENDING to CANCELLED, terminal, pre-audit only). Tests:
  `test_cancel_proposal_by_proposer_settles_cancelled`,
  `test_cancel_proposal_twice_reverts`,
  `test_cancel_proposal_non_proposer_rejected`, `test_cancel_after_audit_reverts`,
  `test_cancel_unknown_proposal_reverts`, `test_summary_counts_cancelled_proposals`.
- FIXED: Unbounded caller strings inflated storage and the audit prompt. Now every
  string has a floor and ceiling (I6) and the active-article count is capped at 25
  (I7). Tests: `test_add_article_string_length_overflow_rejected`,
  `test_submit_proposal_title_overflow_rejected`,
  `test_submit_proposal_url_length_bounds_rejected`,
  `test_submit_proposal_url_whitespace_and_control_chars_rejected`,
  `test_active_articles_cap_enforced`.
- FIXED: Untrusted fetched specification and hostile LLM outputs shaped prompt
  bytes and storage writes without limits. Fetched text is now control-char
  stripped, defused of any embedded delimiter tags, truncated to 6000 chars,
  wrapped in untrusted-data delimiter tags, fail-closed when sanitization
  empties it, and every LLM decision field is clamped or truncated before the
  write (risk 0..100 with Infinity and non-numeric tokens surfacing as tagged
  LLM errors, rationale 400, article id active-set verified). Tests:
  `test_prompt_wraps_untrusted_spec_in_delimiter_tags`,
  `test_spec_early_tag_close_attempt_is_defused`,
  `test_spec_body_of_only_control_chars_fails_closed`,
  `test_llm_oversized_risk_and_huge_rationale_are_clamped`,
  `test_llm_negative_risk_is_clamped_to_zero`,
  `test_llm_infinity_risk_score_fails_closed`,
  `test_llm_vetoed_with_active_article_id_is_kept`.
- FIXED (mitigated, with residual risk documented above): the previously OPEN
  Tier-2 semantic injection finding. The byte-level injection surface is now
  sanitized and framed, and a crafted semantic bias cannot move any numeric
  decision because the hard cap is decided deterministically in Tier-1 before any
  fetch. No open findings remain.
