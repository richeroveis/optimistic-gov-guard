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
- Deployed address: `0xA84fe8580c27C97c51650977af4A28697e9708d8`
- Explorer: https://explorer-studio.genlayer.com/address/0xA84fe8580c27C97c51650977af4A28697e9708d8

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

After consensus, the result is re-validated deterministically and normalized
before it touches storage: `risk_score` is clamped to 0..100, a non-`VETOED`
result always clears `violated_article_id` to 0, and a `VETOED` id that is not a
currently active article is also cleared to 0.

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
| `verdict` | `str` | `PENDING`, `APPROVED`, `CONDITIONAL_REVIEW`, or `VETOED` |
| `risk_score` | `u256` | 0..100 |
| `violated_article_id` | `u256` | Breached article, or 0 when none |
| `rationale` | `str` | Concise explanation |
| `audited` | `bool` | False until settled; a settled record is immutable |

Contract state: `admin: Address`, `next_article_id: u256`,
`next_proposal_id: u256`, `articles: TreeMap[u256, ConstitutionalArticle]`,
`proposals: TreeMap[u256, ProposalAudit]`, and
`proposer_history: TreeMap[Address, DynArray[u256]]`.

## Public interface

### Write methods

| Method | Caller | Purpose | Reverts when |
|--------|--------|---------|--------------|
| `add_constitutional_article(title, mandate_text, max_treasury_spend_bps) -> u256` | admin | Register a new active article | Non-admin; empty title/mandate; cap not in 1..10000; 64 active articles reached |
| `toggle_article(article_id, active) -> None` | admin | Activate or deactivate an article | Non-admin; unknown article |
| `submit_proposal(title, spec_url, requested_spend_bps) -> u256` | anyone | Record a PENDING proposal | Empty title; non-http(s) or oversized url; spend above 10000 |
| `audit_proposal(proposal_id) -> str` | anyone | Settle the verdict (Tier 1 then Tier 2) | Unknown proposal; already audited |

### View methods

| Method | Returns |
|--------|---------|
| `get_article(article_id) -> dict` | One article record |
| `get_proposal(proposal_id) -> dict` | One proposal record |
| `get_governance_summary() -> dict` | `total_articles`, `active_articles`, `total_proposals`, `approved_count`, `conditional_count`, `vetoed_count`, `pending_count` |
| `get_proposer_proposals(proposer) -> list` | All proposals submitted by an address |

## Trust assumptions and limitations

- The `admin` is trusted to curate the constitution. It may add and toggle
  articles. It cannot forge a verdict, because verdicts come from validator
  consensus, not from the admin.
- Anyone may call `audit_proposal`; it is permissionless. A proposal can only be
  audited once, so the first audit on chain is the settlement.
- The contract holds no value. It only stores metadata and a verdict. Any real
  treasury execution, timelock, and appeal window are the responsibility of a
  downstream executor, not this primitive.
- Tier 1 is injection-proof and fully deterministic. Tier 2 semantic judgment is
  as strong as the validators' independent re-audit of the fetched page. Fetched
  text is treated as untrusted and the deterministic hard cap bounds the blast
  radius of any injection to non-numeric (semantic) mandates. Tier 2 has not been
  proven injection-proof end to end; see `docs/adversarial-review.md`.
- `max_treasury_spend_bps` is a per-proposal ceiling expressed in basis points of
  the treasury. It encodes the percentage limit only; the contract does not know
  the absolute treasury balance, by design, so it stays composable.
- At most 64 active articles are allowed so the audit prompt stays bounded.

## On-chain deployment and integrity proof (studionet)

Deployed and driven live through `scripts/deploy_studionet.py`. The full machine-
readable proof, including every transaction hash and the sha256 comparison, is in
`evidence/studionet_deployment.json`.

- Contract address: `0xA84fe8580c27C97c51650977af4A28697e9708d8`
- Deployer account: `0x154a452b0755EE812014C1405B15D905BA06f9c7`
- Deploy transaction: `0x9106d575ff7f12808c13dc95e2594e3e83426488642ebc4b8e4f91037ee03b20`
- Local file sha256: `4e6a441e59108cda0e5956154abfe44270d2c5b467629bf221e5c202bb1b4e9a`
- On-chain source sha256: `4e6a441e59108cda0e5956154abfe44270d2c5b467629bf221e5c202bb1b4e9a`
- Byte-for-byte identical: `true` (24706 bytes each, read back via RPC `gen_getContractCode`)

Transactions executed on chain, each independently confirmed `FINALIZED` through
the explorer JSON API at `/api/address/0xA84fe8580c27C97c51650977af4A28697e9708d8`:

| Step | Transaction | Consensus | Execution |
|------|-------------|-----------|-----------|
| `add_constitutional_article` (3000 bps cap) | `0x6d41cad0f7fef8982afa54e01885df8c16749a522039cbe898ccbd4a34cf5340` | MAJORITY_AGREE | return |
| `submit_proposal` (within cap, 2000 bps) | `0x50abca68cd67112c44fe8ccb1963cc574ef468956a74879e99afa8799c49dd53` | MAJORITY_AGREE | return |
| `submit_proposal` (over cap, 5000 bps) | `0xe281aeaf2cf752e552876fb29ea8b2de4c26232a41f633d6b0c444baa5d28cce` | MAJORITY_AGREE | return |
| `audit_proposal(2)` deterministic Tier-1 veto | `0xbc4f2ff9706e0b421b9225c0efad8e752a3429e134f620b00006aec4d5c5c213` | MAJORITY_AGREE | return (`VETOED`) |
| `submit_proposal` with a non-http url (expected rollback) | `0x493480a73ba73b8c1372f619692486fb0cd78fb1219d22f1606f9f37cf39bd19` | MAJORITY_AGREE | rollback (`[EXPECTED] spec_url must be http(s)`) |

After the run, `get_governance_summary()` returned 1 active article, 2 total
proposals, 1 vetoed and 1 pending. The rolled-back invalid submission created no
proposal, confirming the input guard and the no-state-change property of
reverts on chain.

The live audit exercised on chain is the deterministic Tier-1 path (an over-cap
proposal), which needs no external fetch, so every validator derives the identical
`VETOED` result. The Tier-2 web-plus-LLM comparative path is covered by the
mocked direct tests; validator agreement on real fetches is the boundary that only
a fully live web audit would additionally prove.

## Repository layout

```
contracts/optimistic_gov_guard.py        the primitive
tests/test_gov_guard_direct.py           19 in-memory direct-mode tests
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
