"""Integration test: drive OptimisticGovGuard end-to-end on GenLayer studionet.

Excluded from the default run (see pytest.ini `-m "not integration"`) because it
talks to the live shared studionet endpoint. Run it explicitly with:

    pytest -m integration tests/test_gov_guard_integration.py -v -s

It reuses the same driver as `scripts/deploy_studionet.py`, so a green test run
and the collected on-chain evidence always come from identical code. Requires
GENLAYER_PRIVATE_KEY in the environment (loaded from .env). If the key is absent
the whole module skips so CI without secrets stays green.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "deploy_studionet.py"


def _load_driver():
    spec = importlib.util.spec_from_file_location("deploy_studionet", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["deploy_studionet"] = module
    spec.loader.exec_module(module)
    return module


# Load env + credentials before deciding to skip.
_driver = _load_driver()
_driver.load_dotenv()

pytestmark = pytest.mark.integration

skip_no_key = pytest.mark.skipif(
    not os.environ.get("GENLAYER_PRIVATE_KEY"),
    reason="GENLAYER_PRIVATE_KEY not set; integration test needs a studionet deployer",
)


@skip_no_key
def test_deploy_drive_and_verify_studionet():
    from genlayer_py import create_account, create_client, studionet

    account = create_account(os.environ["GENLAYER_PRIVATE_KEY"])
    client = create_client(studionet, account=account)

    address, deploy_tx = _driver.deploy_contract(client, account)

    # Deployment produced a real contract address and a real deploy transaction.
    assert address.startswith("0x")
    assert len(address) == 42
    assert deploy_tx.startswith("0x")

    # The deployed source is byte-for-byte identical to the local contract file.
    integrity = _driver.verify_sha256(address)
    assert integrity["byte_identical"] is True
    assert integrity["local_sha256"] == integrity["onchain_sha256"]

    evidence = _driver.drive(client, account, address)

    # The admin (deployer) stored the constitutional article and it reads back.
    article = evidence["article_after"]
    assert article["title"] == "Treasury Guardrail"
    assert article["max_treasury_spend_bps"] == 3000
    assert article["active"] is True

    # The within-cap proposal is stored PENDING and never audited in this run.
    pending = client.read_contract(address, "get_proposal", args=[int(evidence["pending_proposal_id"])])
    assert pending["verdict"] == "PENDING"
    assert pending["audited"] is False

    # The proposer-cancelled proposal is settled CANCELLED on chain, terminal
    # and immutable, with the exact proposer-cancellation rationale.
    cancelled = evidence["cancelled_proposal"]
    assert cancelled["verdict"] == "CANCELLED"
    assert cancelled["audited"] is True
    assert cancelled["rationale"] == "Cancelled by proposer before audit"

    # The over-cap proposal is deterministically vetoed on chain (Tier-1), which
    # is fully storage-derived, so leader and validators cannot diverge on it.
    assert str(evidence["audit_verdict"]) == "VETOED"
    audited = evidence["audited_proposal"]
    assert audited["verdict"] == "VETOED"
    assert audited["risk_score"] == 100
    assert audited["violated_article_id"] == 1
    assert audited["audited"] is True

    # Summary counts reflect exactly the three accepted proposals: one vetoed,
    # one cancelled, one pending, and no proposal was created by the invalid
    # (rolled back) submit.
    summary = evidence["summary_after_rollback"]
    assert summary["total_articles"] == 1
    assert summary["total_proposals"] == 3
    assert summary["vetoed_count"] == 1
    assert summary["cancelled_count"] == 1
    assert summary["pending_count"] == 1

    # Adversarial input must revert on chain, exactly as it does in direct mode.
    assert evidence["invalid_reverted"], "invalid submit_proposal should revert on studionet"

    # At least the article add, three submits, the cancel, the audit and the
    # invalid write ran.
    assert len(evidence["transactions"]) >= 7
