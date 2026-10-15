# OptimisticGovGuard

A production-grade, standalone GenLayer Intelligent Contract primitive that acts
as an automated Constitutional Guardrail for DAOs and on-chain governance
systems. Before a governance proposal can be executed, `OptimisticGovGuard`
fetches the live proposal specification, evaluates it against the DAO's on-chain
constitutional invariants, and produces a deterministic, validator-verified
compliance verdict that an external executor or timelock can gate on.

This repository contains the contract, a full test suite, a live studionet
deployment driver, collected on-chain evidence, and an adversarial security
review. It ships no frontend; it is a reusable building block.

- Network: GenLayer `studionet` (chain id 61999)
- Runner: `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`
- Deployed address: `0xEDB383B5539dcEbD9278C3227eCF1e8E6fcaF484`
- Explorer: https://explorer-studio.genlayer.com/address/0xEDB383B5539dcEbD9278C3227eCF1e8E6fcaF484

## The problem it solves

DAO governance frequently relies on a human committee or an off-chain script to
check whether a proposal respects the organization's constitution. That check is
slow, subjective, invisible, and easy to bypass. Numeric limits (for example "no
single proposal may spend more than 30% of the treasury") are often enforced only
after the fact, and qualitative mandates ("spending must serve the mission") are
never checked on chain at all.

`OptimisticGovGuard` moves that guardrail on chain and makes it independently
verifiable. A proposer submits a specification URL and a requested spend in basis
points. The contract then settles one of three verdicts through validator
consensus:

- `APPROVED`: respects every active cap and the fetched specification reads as compliant.
- `CONDITIONAL_REVIEW`: no hard breach, but the specification raises a non-fatal concern for a human committee.
- `VETOED`: violates a hard treasury cap or a semantic constitutional mandate.

A proposer that no longer wants a `PENDING` proposal, for example because its
specification source became permanently unreachable, can settle it terminally as
`CANCELLED` with the proposer-only `cancel_proposal` call. No proposal can ever
be stuck in `PENDING` against the will of its proposer.

A downstream executor or timelock reads the verdict through the view interface
and only executes approved proposals. The verdict itself is the settlement
product.

## Two-tier consensus design

The boundary of what needs GenLayer consensus is deliberately narrow: the
contract turns a subjective, externally-sourced judgment into a reproducible,
validator-verified decision, while keeping every cheap check deterministic.

### Tier 1, deterministic hard-cap pre-filter

On `audit_proposal`, the contract walks the active constitutional articles in
ascending id order (a `TreeMap` iterates sorted, so the traversal is deterministic)
and compares the proposal's `requested_spend_bps` against each article's
`max_treasury_spend_bps`. If any active cap is exceeded, the proposal is
immediately marked `VETOED` with `risk_score = 100`, the `violated_article_id` set
to the first breached article, and `audited = true`. No web fetch and no LLM call
happen, so:

- the decision is fully deterministic and identical on every validator,
- it cannot be influenced by anything the proposer writes in the specification
  document (this path never reads it),
- it costs nothing beyond a storage scan.

### Tier 2, comparative live specification audit

If every hard cap passes, the contract snapshots the proposal title, spec URL,
requested spend, and the active article list into plain Python values, then enters
a single non-deterministic block that:

1. fetches the specification with `gl.nondet.web.render(spec_url, mode="text")`,
2. runs `gl.nondet.exec_prompt(...)` asking the model to audit that text against
   the active mandates and return canonical JSON:
   `{"verdict": ..., "risk_score": 0..100, "violated_article_id": <int>, "rationale": "..."}`.

The block is settled with `gl.eq_principle.prompt_comparative`. Each validator
independently re-fetches the same URL and re-runs the same audit, and the leader is
accepted only when the decision fields agree. The comparative principle requires
exact agreement on `verdict` and `violated_article_id`, and same-band agreement on
`risk_score` (low 0..33, medium 34..66, high 67..100). The free-text `rationale`
is intentionally not compared.

Before the fetched page reaches the prompt it is sanitized: control characters are
stripped, every embedded occurrence of the delimiter tags is defused so proposer
text cannot close its own data frame, the result is truncated to 6000 characters,
and both the proposal title and the specification digest are wrapped in explicit
`<untrusted_proposal_title>` / `<untrusted_proposal_specification>` tags that the
auditor is instructed to treat as data, never as instructions. A body that
sanitizes to empty fails closed as a transient error instead of auditing blank
evidence.

After consensus, the result is re-validated deterministically and normalized
before it touches storage: `risk_score` is clamped to 0..100 (non-numeric or
Infinity-style tokens surface as tagged LLM errors that force validator
rotation), a non-`VETOED` result always clears `violated_article_id` to 0, a
`VETOED` id that is not a currently active article is also cleared to 0, and the
`rationale` is truncated to 400 characters.

The stored value model is governance metadata only. The contract never holds or
transfers funds, so it composes safely with any treasury or timelock layer.

## Storage schema

Two persistent records, both `@allow_storage @dataclass`.

### `ConstitutionalArticle`

| Field | Type | Meaning |
|-------|------|---------|
| `article_id` | `u256` | Monotonic id, starts at 1 |
| `title` | `str` | Short human label |
| `mandate_text` | `str` | The semantic mandate the LLM audits against |
| `max_treasury_spend_bps` | `u256` | Hard ceiling on a single proposal's spend, 1..10000 bps |
| `active` | `bool` | Inactive articles are ignored by both tiers |

### `ProposalAudit`

| Field | Type | Meaning |
|-------|------|---------|
| `proposal_id` | `u256` | Monotonic id, starts at 1 |
| `proposer` | `Address` | `gl.message.sender_address` at submission |
| `title` | `str` | Proposal title |
| `spec_url` | `str` | http(s) specification document to fetch and audit |
| `requested_spend_bps` | `u256` | Requested share of treasury, 0..10000 bps |
| `verdict` | `str` | `PENDING`, `APPROVED`, `CONDITIONAL_REVIEW`, `VETOED`, or `CANCELLED` |
| `risk_score` | `u256` | 0..100 |
| `violated_article_id` | `u256` | Breached article, or 0 when none |
| `rationale` | `str` | Concise explanation, at most 400 chars |
| `audited` | `bool` | False until settled; a settled record is immutable |

Contract state: `admin: Address`, `next_article_id: u256`,
`next_proposal_id: u256`, `articles: TreeMap[u256, ConstitutionalArticle]`,
`proposals: TreeMap[u256, ProposalAudit]`, and
`proposer_history: TreeMap[Address, DynArray[u256]]`.

## Public interface

### Write methods

| Method | Caller | Purpose | Reverts when |
|--------|--------|---------|--------------|
| `add_constitutional_article(title, mandate_text, max_treasury_spend_bps) -> u256` | admin | Register a new active article | Non-admin; title not in 1..100 chars; mandate not in 1..1500 chars; cap not in 1..10000; 25 active articles reached |
| `toggle_article(article_id, active) -> None` | admin | Activate or deactivate an article | Non-admin; unknown article |
| `submit_proposal(title, spec_url, requested_spend_bps) -> u256` | anyone | Record a PENDING proposal | Title not in 1..120 chars; url not in 8..512 chars, non-http(s), or containing whitespace/control chars; spend above 10000 |
| `cancel_proposal(proposal_id) -> None` | proposer | Settle an unaudited PENDING proposal as CANCELLED | Not the proposer; unknown proposal; already settled (audited or non-PENDING) |
| `audit_proposal(proposal_id) -> str` | anyone | Settle the verdict (Tier 1 then Tier 2) | Unknown proposal; already settled |

### View methods

| Method | Returns |
|--------|---------|
| `get_article(article_id) -> dict` | One article record |
| `get_proposal(proposal_id) -> dict` | One proposal record |
| `get_governance_summary() -> dict` | `total_articles`, `active_articles`, `total_proposals`, `approved_count`, `conditional_count`, `vetoed_count`, `cancelled_count`, `pending_count` |
| `get_proposer_proposals(proposer) -> list` | All proposals submitted by an address |

## Trust assumptions and limitations

- The `admin` is trusted to curate the constitution. It may add and toggle
  articles. It cannot forge a verdict, because verdicts come from validator
  consensus, not from the admin.
- Anyone may call `audit_proposal`; it is permissionless. A proposal can only be
  settled once, so the first audit on chain is the settlement. Before settlement
  the proposer alone may exit the lifecycle via `cancel_proposal`.
- The contract holds no value. It only stores metadata and a verdict. Any real
  treasury execution, timelock, and appeal window are the responsibility of a
  downstream executor, not this primitive.
- Tier 1 is injection-proof and fully deterministic. Tier 2 semantic judgment is
  as strong as the validators' independent re-audit of the fetched page. Fetched
  text is sanitized (control chars stripped, delimiter tags defused, truncated to
  6000 chars) and framed as untrusted data in the prompt, and the deterministic
  hard cap bounds the blast radius of any injection to non-numeric (semantic)
  mandates. Tier 2 has not been proven injection-proof end to end; see
  `docs/adversarial-review.md`.
- `max_treasury_spend_bps` is a per-proposal ceiling expressed in basis points of
  the treasury. It encodes the percentage limit only; the contract does not know
  the absolute treasury balance, by design, so it stays composable.
- At most 25 active articles are allowed so Tier-1 iteration and the Tier-2 audit
  prompt stay strictly bounded in gas and context size.

## On-chain deployment and integrity proof (studionet)

Deployed and driven live through `scripts/deploy_studionet.py`. The full machine-
readable proof, including every transaction hash and the sha256 comparison, is in
`evidence/studionet_deployment.json`.

- Contract address: `0xEDB383B5539dcEbD9278C3227eCF1e8E6fcaF484`
- Deployer account: `0x154a452b0755EE812014C1405B15D905BA06f9c7`
- Deploy transaction: `0xda010bc9d2cccbad75cc36a4d23044bed001bffc14838b0cb704f358b96dccf2`
- Local file sha256: `29c2a88a3f6be513097e1478f5347dacb947a31579f0cc029e456534b6cb133d`
- On-chain source sha256: `29c2a88a3f6be513097e1478f5347dacb947a31579f0cc029e456534b6cb133d`
- Byte-for-byte identical: `true` (31169 bytes each, read back via RPC `gen_getContractCode`)

Transactions executed on chain, each independently confirmed `FINALIZED` through
the explorer JSON API at `/api/address/0xEDB383B5539dcEbD9278C3227eCF1e8E6fcaF484`:

| Step | Transaction | Consensus | Execution |
|------|-------------|-----------|-----------|
| `add_constitutional_article` (3000 bps cap) | `0x4d084a3661d95e9631fea2f2dc7faa179f28979000a33fe69126c7f50ae49002` | MAJORITY_AGREE | return |
| `submit_proposal` (within cap, 2000 bps) | `0xd103fa5d78560b862809b537d7097545377fc66c4cfefa030a89160375df63dc` | MAJORITY_AGREE | return |
| `submit_proposal` (to be cancelled, 1000 bps) | `0xd62339419ebf03cd93fe0a4850e2134bbb567d1a4bf6db05da3989be650640e0` | MAJORITY_AGREE | return |
| `cancel_proposal(2)` (proposer-only lifecycle exit) | `0x181a88190b56a364eb0a897884826c7726cd894272123f8c9896c8c30a6a16f2` | MAJORITY_AGREE | return |
| `submit_proposal` (over cap, 5000 bps) | `0xba7d5264ef6d1e494ab4df35390a31fb3b93944893b6e9fac186da5e3fb49ea1` | MAJORITY_AGREE | return |
| `audit_proposal(3)` deterministic Tier-1 veto | `0x628702923891e757d73222bfe928fd5c51d63ce02cf6fd4d3372a1040cc31e4f` | MAJORITY_AGREE | return (`VETOED`) |
| `submit_proposal` with a non-http url (expected rollback) | `0x6658ea237c3f39dff1a572a3faf9fbbec08714a0199647861bb6e4524d2432c4` | MAJORITY_AGREE | rollback (`[EXPECTED] spec_url must be http(s)`) |

After the run, `get_governance_summary()` returned 1 active article, 3 total
proposals: 1 pending, 1 cancelled (rationale "Cancelled by proposer before
audit") and 1 vetoed. The rolled-back invalid submission created no proposal,
confirming the input guard and the no-state-change property of reverts on chain.

The live audit exercised on chain is the deterministic Tier-1 path (an over-cap
proposal), which needs no external fetch, so every validator derives the identical
`VETOED` result. The Tier-2 web-plus-LLM comparative path is covered by the
mocked direct tests; validator agreement on real fetches is the boundary that only
a fully live web audit would additionally prove.

## Repository layout

```
contracts/optimistic_gov_guard.py        the primitive
tests/conftest.py                        Windows stdin-injection compatibility shim for gltest direct mode
tests/test_gov_guard_direct.py           39 in-memory direct-mode tests
tests/test_gov_guard_integration.py      live studionet integration test (opt-in)
scripts/deploy_studionet.py              deploy + drive + sha256 verify + evidence
evidence/studionet_deployment.json       collected on-chain proof
docs/adversarial-review.md               adversarial security review notes
gltest.config.yaml / pytest.ini          test and network configuration
.env.example                             template; the real .env is git-ignored
```

## How to run

Reuse a Python environment that already has `genlayer-py`, `genlayer-test`, and
`genvm-linter` installed, then:

```bash
# 1. Static analysis (zero errors required)
genvm-lint check contracts/optimistic_gov_guard.py

# 2. Fast in-memory tests
pytest tests/test_gov_guard_direct.py -v

# 3. Live deployment, transaction drive, and sha256 proof on studionet.
#    Loads GENLAYER_PRIVATE_KEY from the git-ignored .env.
python scripts/deploy_studionet.py

# 4. Live integration test (same driver, asserted)
pytest -m integration tests/test_gov_guard_integration.py -v -s
```

`GENLAYER_PRIVATE_KEY` and `GITHUB_TOKEN` are read only from the local `.env`,
which is git-ignored. Copy `.env.example` to `.env` and fill in your own values.
The private key is never printed, logged, or committed.
