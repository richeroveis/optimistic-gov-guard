# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""OptimisticGovGuard: a standalone Constitutional Guardrail primitive for DAOs.

Before a governance proposal may be executed, this contract audits the live
proposal specification against the DAO's on-chain constitutional invariants and
settles a deterministic, validator-verified compliance verdict on chain:

    APPROVED            -> the proposal respects every active constitutional cap
                           and the fetched specification reads as compliant
    CONDITIONAL_REVIEW  -> no hard breach, but the specification raises a
                           non-fatal concern that a human committee must clear
    VETOED              -> the proposal violates a hard treasury cap or a
                           semantic constitutional mandate

Two-tier consensus design
-------------------------
Tier 1 (deterministic, in-storage pre-filter): every active article carries a
hard numeric ceiling `max_treasury_spend_bps`. If the requested spend exceeds
any active ceiling, the proposal is vetoed immediately with a full risk score.
No web or LLM call is made, so the decision is fully deterministic and cheap.

Tier 2 (non-deterministic, comparative consensus): otherwise the contract fetches
the proposal `spec_url` and asks an LLM to audit it against the active mandates.
The result is settled through `gl.eq_principle.prompt_comparative`, so every
validator independently re-fetches the same specification and re-runs the audit,
and the leader is only accepted when the decision fields agree.

Design boundary
---------------
- External source owns: the raw proposal specification. It is never trusted
  directly; validators re-fetch and re-audit it under the comparative principle.
- Nondeterministic block owns: the web render and the LLM audit, operating only
  on a plain-Python snapshot taken before the block. It never touches storage.
- Deterministic contract owns: every state transition (verdict write, risk
  clamp, violated-article selection, proposer history, summary counters).

The primitive holds no funds. It stores governance metadata and a verdict so it
composes safely with an external treasury or timelock executor that gates on the
verdict read back through the view interface.
"""

import json
import typing
from dataclasses import dataclass

from genlayer import *

# =============================================================================
# Error classification tags. Validators use these to decide whether a leader
# failure should force rotation (transient / LLM) or must match exactly.
# =============================================================================
ERROR_EXPECTED = "[EXPECTED]"  # deterministic business-logic rejection
ERROR_EXTERNAL = "[EXTERNAL]"  # deterministic 4xx from an external source
ERROR_TRANSIENT = "[TRANSIENT]"  # network / 5xx / empty body, agree if both transient
ERROR_LLM = "[LLM_ERROR]"  # LLM misbehavior, always disagree to force rotation

# =============================================================================
# Input bounds. Independent of any funds, these keep the state machine and the
# non-deterministic prompt bounded so no u256 product nears the ceiling and the
# prompt cannot be inflated by an adversarial proposer.
# =============================================================================
BASIS_POINTS_MAX = 10000  # a basis-point ceiling: 10000 == 100.00% of treasury
RISK_SCORE_MAX = 100  # risk is reported on a 0..100 scale
MAX_TITLE_LEN = 200
MAX_URL_LEN = 2048
MAX_MANDATE_LEN = 2000
MAX_RATIONALE_LEN = 600
MAX_ACTIVE_ARTICLES = 64  # bounds the snapshot size fed into the audit prompt

VERDICT_PENDING = "PENDING"
VERDICT_APPROVED = "APPROVED"
VERDICT_CONDITIONAL = "CONDITIONAL_REVIEW"
VERDICT_VETOED = "VETOED"
_VALID_VERDICTS = (VERDICT_APPROVED, VERDICT_CONDITIONAL, VERDICT_VETOED)


@allow_storage
@dataclass
class ConstitutionalArticle:
    article_id: u256
    title: str
    mandate_text: str
    max_treasury_spend_bps: u256  # hard ceiling on a single proposal's spend
    active: bool


@allow_storage
@dataclass
class ProposalAudit:
    proposal_id: u256
    proposer: Address
    title: str
    spec_url: str
    requested_spend_bps: u256
    verdict: str  # PENDING | APPROVED | CONDITIONAL_REVIEW | VETOED
    risk_score: u256  # 0..100
    violated_article_id: u256  # 0 when no article is violated
    rationale: str
    audited: bool


# =============================================================================
# Pure deterministic helpers. They run in both the leader and the validator, so
# they must never read contract storage and must be casing/format resilient.
# =============================================================================
def _normalize_verdict(raw) -> str:
    """Map an LLM verdict string onto the canonical enum, casing/spacing safe."""
    token = str(raw).strip().upper().replace(" ", "_").replace("-", "_")
    aliases = {
        "APPROVED": VERDICT_APPROVED,
        "APPROVE": VERDICT_APPROVED,
        "PASS": VERDICT_APPROVED,
        "COMPLIANT": VERDICT_APPROVED,
        "OK": VERDICT_APPROVED,
        "CONDITIONAL_REVIEW": VERDICT_CONDITIONAL,
        "CONDITIONAL": VERDICT_CONDITIONAL,
        "REVIEW": VERDICT_CONDITIONAL,
        "NEEDS_REVIEW": VERDICT_CONDITIONAL,
        "VETOED": VERDICT_VETOED,
        "VETO": VERDICT_VETOED,
        "REJECTED": VERDICT_VETOED,
        "REJECT": VERDICT_VETOED,
        "NON_COMPLIANT": VERDICT_VETOED,
    }
    if token not in aliases:
        raise gl.vm.UserError(f"{ERROR_LLM} Unrecognized verdict: {raw!r}")
    return aliases[token]


def _coerce_risk(raw) -> int:
    """Coerce an LLM risk score to a bounded integer in 0..100."""
    try:
        value = int(round(float(str(raw).strip())))
    except (ValueError, TypeError):
        raise gl.vm.UserError(f"{ERROR_LLM} Non-numeric risk_score: {raw!r}")
    if value < 0:
        value = 0
    if value > RISK_SCORE_MAX:
        value = RISK_SCORE_MAX
    return value


def _coerce_article_id(raw) -> int:
    """Coerce a violated article id to a non-negative integer (0 = none)."""
    if raw is None:
        return 0
    try:
        value = int(str(raw).strip())
    except (ValueError, TypeError):
        raise gl.vm.UserError(f"{ERROR_LLM} Non-integer violated_article_id: {raw!r}")
    if value < 0:
        return 0
    return value


def _parse_audit(raw) -> dict:
    """Validate the LLM audit into a strict canonical verdict record.

    Accepts an already-decoded dict or a raw JSON string. Never trusts the
    leader's shape: every decision field is normalized and bounded here so the
    deterministic state update that follows can only ever write legal values.
    """
    data = raw
    if isinstance(data, (str, bytes)):
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        first = text.find("{")
        last = text.rfind("}")
        if first == -1 or last == -1 or last <= first:
            raise gl.vm.UserError(f"{ERROR_LLM} No JSON object in LLM response")
        try:
            data = json.loads(text[first : last + 1])
        except json.JSONDecodeError as exc:
            raise gl.vm.UserError(f"{ERROR_LLM} Malformed JSON audit: {exc}")

    if not isinstance(data, dict):
        raise gl.vm.UserError(f"{ERROR_LLM} LLM audit is not an object: {type(data)}")

    verdict_val = data.get("verdict")
    if verdict_val is None:
        for alt in ("status", "decision", "outcome"):
            if alt in data:
                verdict_val = data[alt]
                break
    if verdict_val is None:
        raise gl.vm.UserError(f"{ERROR_LLM} Missing verdict. Keys: {list(data.keys())}")

    verdict = _normalize_verdict(verdict_val)

    risk_val = data.get("risk_score")
    if risk_val is None:
        risk_val = data.get("risk", data.get("score", 0))
    risk_score = _coerce_risk(risk_val)

    violated_article_id = _coerce_article_id(
        data.get("violated_article_id", data.get("violated_article", data.get("article_id")))
    )

    rationale_val = data.get("rationale")
    if rationale_val is None:
        rationale_val = data.get("reason", data.get("explanation", ""))
    rationale = str(rationale_val).strip()[:MAX_RATIONALE_LEN]

    # Deterministic normalization that helps leader and validator converge:
    # only a VETOED result may pin a violated article; everything else clears it.
    if verdict != VERDICT_VETOED:
        violated_article_id = 0

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "violated_article_id": violated_article_id,
        "rationale": rationale,
    }


class OptimisticGovGuard(gl.Contract):
    admin: Address
    next_article_id: u256
    next_proposal_id: u256
    articles: TreeMap[u256, ConstitutionalArticle]
    proposals: TreeMap[u256, ProposalAudit]
    proposer_history: TreeMap[Address, DynArray[u256]]

    def __init__(self):
        self.admin = gl.message.sender_address
        self.next_article_id = u256(1)
        self.next_proposal_id = u256(1)

    # -------------------------------------------------------------------------
    # Constitution administration (admin-only)
    # -------------------------------------------------------------------------
    @gl.public.write
    def add_constitutional_article(
        self, title: str, mandate_text: str, max_treasury_spend_bps: u256
    ) -> u256:
        sender = gl.message.sender_address
        if sender != self.admin:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} Only admin can add articles")

        clean_title = str(title).strip()
        if len(clean_title) == 0 or len(clean_title) > MAX_TITLE_LEN:
            raise gl.vm.UserError(
                f"{ERROR_EXPECTED} title must be 1..{MAX_TITLE_LEN} chars"
            )

        clean_mandate = str(mandate_text).strip()
        if len(clean_mandate) == 0 or len(clean_mandate) > MAX_MANDATE_LEN:
            raise gl.vm.UserError(
                f"{ERROR_EXPECTED} mandate_text must be 1..{MAX_MANDATE_LEN} chars"
            )

        # Floor and ceiling on the hard numeric cap so it is always a real limit.
        if max_treasury_spend_bps <= 0 or max_treasury_spend_bps > BASIS_POINTS_MAX:
            raise gl.vm.UserError(
                f"{ERROR_EXPECTED} max_treasury_spend_bps must be in 1..{BASIS_POINTS_MAX}"
            )

        active_count = 0
        for _, article in self.articles.items():
            if article.active:
                active_count += 1
        if active_count >= MAX_ACTIVE_ARTICLES:
            raise gl.vm.UserError(
                f"{ERROR_EXPECTED} At most {MAX_ACTIVE_ARTICLES} active articles allowed"
            )

        article_id = self.next_article_id
        self.articles[article_id] = ConstitutionalArticle(
            article_id=article_id,
            title=clean_title,
            mandate_text=clean_mandate,
            max_treasury_spend_bps=max_treasury_spend_bps,
            active=True,
        )
        self.next_article_id = article_id + 1
        return article_id

    @gl.public.write
    def toggle_article(self, article_id: u256, active: bool) -> None:
        sender = gl.message.sender_address
        if sender != self.admin:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} Only admin can toggle articles")

        if article_id not in self.articles:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} Unknown article {article_id}")

        article = self.articles[article_id]
        article.active = bool(active)
        self.articles[article_id] = article

    # -------------------------------------------------------------------------
    # Proposal lifecycle
    # -------------------------------------------------------------------------
    @gl.public.write
    def submit_proposal(
        self, title: str, spec_url: str, requested_spend_bps: u256
    ) -> u256:
        clean_title = str(title).strip()
        if len(clean_title) == 0 or len(clean_title) > MAX_TITLE_LEN:
            raise gl.vm.UserError(
                f"{ERROR_EXPECTED} title must be 1..{MAX_TITLE_LEN} chars"
            )

        url = str(spec_url).strip()
        if len(url) == 0 or len(url) > MAX_URL_LEN:
            raise gl.vm.UserError(
                f"{ERROR_EXPECTED} spec_url must be 1..{MAX_URL_LEN} chars"
            )
        # The audited evidence is fetched over http(s) only; reject anything else
        # so a proposer cannot smuggle a non-fetchable or file-style reference.
        if not (url.startswith("http://") or url.startswith("https://")):
            raise gl.vm.UserError(f"{ERROR_EXPECTED} spec_url must be http(s)")

        # Independent on-chain check: a spend above 100% of the treasury is never
        # legal, and the hard-cap pre-filter in audit_proposal compares against
        # per-article ceilings, so keep this value inside the basis-point domain.
        if requested_spend_bps > BASIS_POINTS_MAX:
            raise gl.vm.UserError(
                f"{ERROR_EXPECTED} requested_spend_bps must be in 0..{BASIS_POINTS_MAX}"
            )

        sender = gl.message.sender_address
        proposal_id = self.next_proposal_id
        self.proposals[proposal_id] = ProposalAudit(
            proposal_id=proposal_id,
            proposer=sender,
            title=clean_title,
            spec_url=url,
            requested_spend_bps=requested_spend_bps,
            verdict=VERDICT_PENDING,
            risk_score=u256(0),
            violated_article_id=u256(0),
            rationale="",
            audited=False,
        )

        # Record the proposal under its proposer for off-chain indexers and views.
        history = self.proposer_history.get_or_insert_default(sender)
        history.append(proposal_id)

        self.next_proposal_id = proposal_id + 1
        return proposal_id

    @gl.public.write
    def audit_proposal(self, proposal_id: u256) -> str:
        if proposal_id not in self.proposals:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} Unknown proposal {proposal_id}")

        proposal = self.proposals[proposal_id]

        # Race / double-audit guard: an already settled verdict is immutable. This
        # must run before any non-deterministic work so a re-audit never burns
        # web/LLM calls and never lets a second verdict overwrite the first.
        if proposal.audited:
            raise gl.vm.UserError(
                f"{ERROR_EXPECTED} Proposal {proposal_id} is already audited"
            )

        requested_spend_bps = proposal.requested_spend_bps

        # -------------------------------------------------------------------------
        # Tier 1: deterministic hard-cap pre-filter.
        # Walk the active articles in ascending id order (TreeMap.items is sorted)
        # and veto on the first breached ceiling. Fully deterministic, no external
        # calls, so validators reach the identical result without any re-fetch.
        # -------------------------------------------------------------------------
        breached_article_id = u256(0)
        breached_title = ""
        for _, article in self.articles.items():
            if not article.active:
                continue
            if requested_spend_bps > article.max_treasury_spend_bps:
                breached_article_id = article.article_id
                breached_title = article.title
                break

        if breached_article_id != 0:
            proposal.verdict = VERDICT_VETOED
            proposal.risk_score = u256(RISK_SCORE_MAX)
            proposal.violated_article_id = u256(int(breached_article_id))
            proposal.rationale = (
                f"Deterministic hard-cap veto: requested {int(requested_spend_bps)} bps "
                f"exceeds the ceiling of active article {int(breached_article_id)} "
                f"({breached_title}). No specification fetch required."
            )
            proposal.audited = True
            self.proposals[proposal_id] = proposal
            return VERDICT_VETOED

        # -------------------------------------------------------------------------
        # Tier 2: comparative web + LLM audit.
        # Snapshot EVERY value the non-deterministic block needs into plain Python
        # BEFORE entering it. The leader/validator functions never read storage.
        # -------------------------------------------------------------------------
        p_title = proposal.title
        p_spec_url = proposal.spec_url
        p_bps = int(requested_spend_bps)
        active_article_ids: typing.Set[int] = set()
        article_snapshot: typing.List[dict] = []
        for _, article in self.articles.items():
            if article.active:
                active_article_ids.add(int(article.article_id))
                article_snapshot.append(
                    {
                        "article_id": int(article.article_id),
                        "title": article.title,
                        "mandate_text": article.mandate_text,
                        "max_treasury_spend_bps": int(article.max_treasury_spend_bps),
                    }
                )

        def audit_with_spec():
            try:
                page = gl.nondet.web.render(p_spec_url, mode="text")
            except Exception as exc:
                raise gl.vm.UserError(f"{ERROR_TRANSIENT} spec fetch failed: {exc}")
            spec_text = "" if page is None else str(page)
            if len(spec_text.strip()) == 0:
                raise gl.vm.UserError(f"{ERROR_TRANSIENT} spec fetch returned empty body")

            spec_digest = spec_text[:6000]
            mandates = json.dumps(article_snapshot, sort_keys=True)

            prompt = (
                "You are an independent constitutional auditor for a DAO. Audit the "
                "governance proposal below strictly against the DAO's ACTIVE "
                "constitutional mandates. Use only the provided specification text; "
                "do not invent facts. The requested spend is expressed in basis "
                "points of the treasury (10000 = 100%).\n\n"
                f"PROPOSAL TITLE:\n{p_title}\n\n"
                f"REQUESTED SPEND (bps):\n{p_bps}\n\n"
                f"ACTIVE CONSTITUTIONAL ARTICLES (JSON):\n{mandates}\n\n"
                f"PROPOSAL SPECIFICATION TEXT (fetched from spec_url):\n{spec_digest}\n\n"
                "Decide a verdict: APPROVED (respects every mandate), "
                "CONDITIONAL_REVIEW (no hard breach but a non-fatal concern needs "
                "human committee review), or VETOED (violates a hard cap or a "
                "semantic mandate). If VETOED, set violated_article_id to the id of "
                "the article breached, otherwise 0. Give a concise rationale citing "
                "the specification evidence you saw.\n"
                "Return ONLY a JSON object with exactly these keys: "
                '{"verdict": "APPROVED" | "CONDITIONAL_REVIEW" | "VETOED", '
                '"risk_score": <integer 0..100>, '
                '"violated_article_id": <integer, 0 if none>, '
                '"rationale": "<concise explanation>"}'
            )
            raw = gl.nondet.exec_prompt(prompt, response_format="json")
            return _parse_audit(raw)

        # Comparative consensus: each validator independently re-fetches the SAME
        # specification and re-audits it. The leader is accepted only when the
        # decision fields agree. Rationale wording is intentionally not compared.
        verdict_record = gl.eq_principle.prompt_comparative(
            audit_with_spec,
            principle=(
                "Both answers audit the same proposal specification against the same "
                "active constitutional articles. They must agree exactly on `verdict` "
                "and on `violated_article_id` (a non-zero id must match, and a VETOED "
                "answer must not pair with a non-VETOED answer). The numeric "
                "`risk_score` must fall in the same band: low 0..33, medium 34..66, "
                "high 67..100. Ignore differences in `rationale` wording. If either "
                "answer is missing a decision field, uses a verdict outside APPROVED "
                "/ CONDITIONAL_REVIEW / VETOED, or reports a risk_score outside 0..100, "
                "the answers do NOT agree."
            ),
        )

        final_verdict = _parse_audit(verdict_record)

        # Defensive deterministic clamp: a VETOED answer may only pin a violated
        # article that is actually an active constitutional article. A hallucinated
        # (but leader/validator consistent) id is cleared to 0 rather than trusted.
        if (
            final_verdict["verdict"] == VERDICT_VETOED
            and final_verdict["violated_article_id"] not in active_article_ids
        ):
            final_verdict["violated_article_id"] = 0

        proposal.verdict = final_verdict["verdict"]
        proposal.risk_score = u256(final_verdict["risk_score"])
        proposal.violated_article_id = u256(final_verdict["violated_article_id"])
        proposal.rationale = final_verdict["rationale"]
        proposal.audited = True
        self.proposals[proposal_id] = proposal

        return proposal.verdict

    # -------------------------------------------------------------------------
    # Views
    # -------------------------------------------------------------------------
    @gl.public.view
    def get_article(self, article_id: u256) -> dict:
        if article_id not in self.articles:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} Unknown article {article_id}")
        a = self.articles[article_id]
        return {
            "article_id": int(a.article_id),
            "title": a.title,
            "mandate_text": a.mandate_text,
            "max_treasury_spend_bps": int(a.max_treasury_spend_bps),
            "active": a.active,
        }

    @gl.public.view
    def get_proposal(self, proposal_id: u256) -> dict:
        if proposal_id not in self.proposals:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} Unknown proposal {proposal_id}")
        p = self.proposals[proposal_id]
        return {
            "proposal_id": int(p.proposal_id),
            "proposer": str(p.proposer),
            "title": p.title,
            "spec_url": p.spec_url,
            "requested_spend_bps": int(p.requested_spend_bps),
            "verdict": p.verdict,
            "risk_score": int(p.risk_score),
            "violated_article_id": int(p.violated_article_id),
            "rationale": p.rationale,
            "audited": p.audited,
        }

    @gl.public.view
    def get_governance_summary(self) -> dict:
        total_articles = 0
        active_articles = 0
        for _, article in self.articles.items():
            total_articles += 1
            if article.active:
                active_articles += 1

        total_proposals = 0
        approved_count = 0
        conditional_count = 0
        vetoed_count = 0
        pending_count = 0
        for _, proposal in self.proposals.items():
            total_proposals += 1
            if proposal.verdict == VERDICT_APPROVED:
                approved_count += 1
            elif proposal.verdict == VERDICT_CONDITIONAL:
                conditional_count += 1
            elif proposal.verdict == VERDICT_VETOED:
                vetoed_count += 1
            else:
                pending_count += 1

        return {
            "total_articles": total_articles,
            "active_articles": active_articles,
            "total_proposals": total_proposals,
            "approved_count": approved_count,
            "conditional_count": conditional_count,
            "vetoed_count": vetoed_count,
            "pending_count": pending_count,
        }

    @gl.public.view
    def get_proposer_proposals(self, proposer: str) -> list:
        records: list = []
        history = self.proposer_history.get(Address(proposer))
        if history is None:
            return records
        for pid in history:
            if pid in self.proposals:
                p = self.proposals[pid]
                records.append(
                    {
                        "proposal_id": int(p.proposal_id),
                        "title": p.title,
                        "requested_spend_bps": int(p.requested_spend_bps),
                        "verdict": p.verdict,
                        "risk_score": int(p.risk_score),
                        "violated_article_id": int(p.violated_article_id),
                        "audited": p.audited,
                    }
                )
        return records
