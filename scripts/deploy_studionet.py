"""Deploy OptimisticGovGuard to GenLayer studionet and drive real transactions.

The documented `genlayer` CLI deploy path (client.deploy_contract) is driven
through the same SDK primitive so it is fully scriptable from a headless session.
The private key is read from the git-ignored `.env` and is never printed, logged
or committed. studionet is gasless, so a 0 GEN deployer balance is expected.

Flow
----
1. submit the verbatim contract source as the deploy code and wait for FINALIZED;
2. resolve the created contract address from the deployment receipt;
3. confirm the public explorer indexes that address as a CONTRACT;
4. verify byte-for-byte sha256 identity between the local file and the deployed
   source read back through the chain RPC (gen_getContractCode);
5. drive the state-changing path with real transactions:
     add_constitutional_article -> submit_proposal (within cap) ->
     submit_proposal (over cap) -> audit_proposal (deterministic Tier-1 veto) ->
     get_proposer_proposals / get_governance_summary reads;
6. include one expected-rollback check (an invalid submit must revert on chain);
7. persist every transaction hash, the address and the sha256 proof to
   evidence/studionet_deployment.json.

Run:
    python scripts/deploy_studionet.py
Optionally reuse an existing address instead of redeploying:
    OPTIMISTIC_GOV_GUARD_ADDRESS=0x... python scripts/deploy_studionet.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from genlayer_py import create_account, create_client, studionet
from genlayer_py.types.transactions import TransactionStatus

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "contracts" / "optimistic_gov_guard.py"
EVIDENCE = ROOT / "evidence"

RPC_URL = os.environ.get("GENLAYER_RPC_URL", "https://studio.genlayer.com/api")
EXPLORER = "https://explorer-studio.genlayer.com"
RUNNER = "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6"

# A public, stable specification URL. The live audit exercised on chain is the
# deterministic Tier-1 hard-cap veto, so no validator ever fetches this URL; the
# value only has to satisfy the contract's http(s) input guard.
SPEC_URL = "https://www.githubstatus.com/"

DEFAULT_TIMEOUT = int(os.environ.get("GENLAYER_DEPLOY_TIMEOUT", "900"))


def load_dotenv() -> None:
    path = ROOT / ".env"
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def status_name(tx: dict) -> str:
    name = tx.get("status_name")
    if name:
        return str(name)
    by_number = {int(s.value): s.name for s in TransactionStatus if str(s.value).isdigit()}
    return by_number.get(tx.get("status"), str(tx.get("status")))


def result_name(tx: dict) -> str:
    return str(tx.get("result_name") or tx.get("result") or "").upper()


def _leader_result(receipt: dict) -> dict:
    cd = receipt.get("consensus_data") or {}
    lr = cd.get("leader_receipt") or []
    if lr and isinstance(lr[0], dict):
        return lr[0].get("result") or {}
    return {}


def exec_status(receipt: dict) -> str:
    # 'return' = applied; 'rollback'/'error' = reverted, no state change.
    return str(_leader_result(receipt).get("status", "")).lower()


def exec_payload(receipt: dict):
    p = _leader_result(receipt).get("payload")
    if isinstance(p, dict):
        return p.get("readable", p)
    return p


def _as_int(value) -> int:
    """Coerce a returned u256 readable payload to a Python int.

    The chain renders a u256 return as a numeric string. Chaining that value into
    the next call must send a real integer, otherwise the typed ABI delivers a str
    to a u256 parameter and the on-chain TreeMap lookup fails. Direct mode coerces
    silently, which is why this only surfaces on studionet.
    """
    if isinstance(value, dict):
        value = value.get("readable", value)
    return int(str(value).strip())


def _clean_str(value) -> str:
    """Unwrap a returned str payload that the chain renders as JSON-quoted text.

    A str return value arrives as `"VETOED"` (with literal quotes). Strip them so
    callers compare the bare enum value, mirroring how the view reads already
    return the plain string.
    """
    if isinstance(value, dict):
        value = value.get("readable", value)
    text = str(value).strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        try:
            return str(json.loads(text))
        except json.JSONDecodeError:
            return text.strip('"')
    return text


def wait_for_final(client, tx_hash: str, timeout: int, label: str) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            tx = client.get_transaction(tx_hash)
        except Exception as exc:  # not indexed yet
            print(f"  [wait] {label}: not readable yet ({type(exc).__name__})")
            time.sleep(4)
            continue
        name = status_name(tx)
        if name != last:
            print(f"  [wait] {label}: {name} (result={result_name(tx)})")
            last = name
        if name == "FINALIZED":
            return tx
        if name in {"CANCELED", "ERROR", "INVALID"}:
            raise SystemExit(f"{label} settled in terminal lifecycle state {name}: {tx}")
        time.sleep(4)
    raise SystemExit(f"{label} did not finalize within {timeout}s (last {last})")


def assert_execution_ok(receipt: dict, label: str) -> None:
    # FINALIZED + MAJORITY_AGREE are lifecycle/consensus states, NOT proof the
    # code applied. Gate every read on the leader execution status.
    st = exec_status(receipt)
    if st != "return":
        raise SystemExit(
            f"{label} finalized but leader execution status was {st!r}; "
            f"payload={exec_payload(receipt)!r}"
        )


def explorer_type(address: str) -> str:
    url = f"{EXPLORER}/api/address/{address}"
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "optimistic-gov-guard-deploy"},
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return (data.get("type") or "").upper()
    except urllib.error.HTTPError as exc:
        return f"http-{exc.code}"
    except Exception as exc:  # noqa: BLE001
        return f"error:{type(exc).__name__}"


def fetch_deployed_source(address: str) -> bytes:
    """Read the deployed contract source straight off the chain via RPC.

    studionet returns the verbatim Python source as a base64 blob through
    gen_getContractCode. Decoding it gives the exact bytes the network stored,
    which is what the sha256 integrity proof compares against.
    """
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "gen_getContractCode",
        "params": [address],
    }
    req = urllib.request.Request(
        RPC_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "optimistic-gov-guard-deploy"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=90) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    if "error" in body:
        raise SystemExit(f"gen_getContractCode failed: {body['error']}")
    result = body.get("result")
    if not isinstance(result, str) or not result:
        raise SystemExit(f"gen_getContractCode returned no source for {address}")
    return base64.b64decode(result)


def verify_sha256(address: str) -> dict:
    local_bytes = CONTRACT.read_bytes()
    local_sha = hashlib.sha256(local_bytes).hexdigest()
    deployed_bytes = fetch_deployed_source(address)
    deployed_sha = hashlib.sha256(deployed_bytes).hexdigest()
    match = local_bytes == deployed_bytes
    print(
        f"[integrity] local sha256={local_sha}\n"
        f"[integrity] onchain sha256={deployed_sha}\n"
        f"[integrity] byte-for-byte match={match}"
    )
    if not match:
        raise SystemExit("Deployed source does not match the local contract file byte for byte")
    return {
        "local_sha256": local_sha,
        "onchain_sha256": deployed_sha,
        "byte_identical": match,
        "local_size_bytes": len(local_bytes),
        "onchain_size_bytes": len(deployed_bytes),
        "rpc_method": "gen_getContractCode",
    }


def deploy_contract(client, account) -> tuple[str, str]:
    source = CONTRACT.read_text(encoding="utf-8")
    print(f"[deploy] submitting {CONTRACT.name} ({len(source)} chars) ...")
    tx_hash = str(client.deploy_contract(code=source, account=account))
    print(f"[deploy] tx={tx_hash}")
    receipt = wait_for_final(client, tx_hash, DEFAULT_TIMEOUT, "deploy OptimisticGovGuard")
    assert_execution_ok(receipt, "deploy")
    address = str(receipt.get("recipient") or receipt.get("to_address") or "")
    if not address:
        raise SystemExit(f"deploy finalized but no contract address on {tx_hash}")

    kind = ""
    for _ in range(12):
        kind = explorer_type(address)
        if kind == "CONTRACT":
            break
        time.sleep(5)
    print(f"[deploy] contract address = {address} (explorer type={kind!r})")
    print(f"[deploy] explorer: {EXPLORER}/address/{address}")
    if kind != "CONTRACT":
        print("[deploy] WARNING: explorer does not yet index this as a CONTRACT", file=sys.stderr)
    return address, tx_hash


def drive(client, account, address: str) -> dict:
    txs: list[dict] = []

    # --- write: add_constitutional_article (deployer is admin) ---
    print("\n[write] add_constitutional_article (30% treasury cap) ...")
    tx_art = str(
        client.write_contract(
            address,
            "add_constitutional_article",
            account=account,
            args=["Treasury Guardrail", "No single proposal may spend more than 30% of the treasury.", 3000],
        )
    )
    print(f"    tx={tx_art}")
    rc = wait_for_final(client, tx_art, DEFAULT_TIMEOUT, "add_constitutional_article")
    assert_execution_ok(rc, "add_constitutional_article")
    article_id = _as_int(exec_payload(rc))
    txs.append({"step": "add_constitutional_article", "tx": tx_art,
                "consensus": result_name(rc), "exec_status": exec_status(rc), "return_data": article_id})

    print("\n[read] get_article(1) ...")
    article = client.read_contract(address, "get_article", args=[1])
    print(f"    {json.dumps(article, default=str)}")

    # --- write: submit_proposal within cap (stays PENDING; not audited live) ---
    print("\n[write] submit_proposal (within cap, 2000 bps) ...")
    tx_ok = str(
        client.write_contract(
            address, "submit_proposal", account=account,
            args=["Marketing budget", SPEC_URL, 2000],
        )
    )
    print(f"    tx={tx_ok}")
    rc_ok = wait_for_final(client, tx_ok, DEFAULT_TIMEOUT, "submit_proposal_within_cap")
    assert_execution_ok(rc_ok, "submit_proposal_within_cap")
    pending_id = _as_int(exec_payload(rc_ok))
    txs.append({"step": "submit_proposal_within_cap", "tx": tx_ok,
                "consensus": result_name(rc_ok), "exec_status": exec_status(rc_ok), "return_data": pending_id})

    # --- write: submit_proposal over cap (candidate for the deterministic veto) ---
    print("\n[write] submit_proposal (over cap, 5000 bps) ...")
    tx_over = str(
        client.write_contract(
            address, "submit_proposal", account=account,
            args=["Overspend", SPEC_URL, 5000],
        )
    )
    print(f"    tx={tx_over}")
    rc_over = wait_for_final(client, tx_over, DEFAULT_TIMEOUT, "submit_proposal_over_cap")
    assert_execution_ok(rc_over, "submit_proposal_over_cap")
    over_id = _as_int(exec_payload(rc_over))
    txs.append({"step": "submit_proposal_over_cap", "tx": tx_over,
                "consensus": result_name(rc_over), "exec_status": exec_status(rc_over), "return_data": over_id})

    # --- write: audit_proposal over the over-cap id -> deterministic Tier-1 veto ---
    # Fully settled from on-chain storage, so it needs no live web or LLM fetch
    # and every validator derives the identical VETOED result.
    print(f"\n[write] audit_proposal({over_id}) expects deterministic VETOED ...")
    tx_audit = str(
        client.write_contract(address, "audit_proposal", account=account, args=[over_id])
    )
    print(f"    tx={tx_audit}")
    rc_audit = wait_for_final(client, tx_audit, DEFAULT_TIMEOUT, "audit_proposal")
    assert_execution_ok(rc_audit, "audit_proposal")
    verdict = _clean_str(exec_payload(rc_audit))
    txs.append({"step": "audit_proposal", "tx": tx_audit,
                "consensus": result_name(rc_audit), "exec_status": exec_status(rc_audit), "return_data": verdict})

    audited = client.read_contract(address, "get_proposal", args=[over_id])
    print(f"\n[read] get_proposal({over_id}) -> {json.dumps(audited, default=str)}")

    print("\n[read] get_governance_summary ...")
    summary = client.read_contract(address, "get_governance_summary")
    print(f"    {json.dumps(summary, default=str)}")

    print("\n[read] get_proposer_proposals(deployer) ...")
    history = client.read_contract(address, "get_proposer_proposals", args=[account.address])
    print(f"    {json.dumps(history, default=str)}")

    # --- expected rollback: an invalid submit must revert on chain ---
    print("\n[write] submit_proposal(non-http url) is expected to ROLLBACK ...")
    tx_bad = str(
        client.write_contract(
            address, "submit_proposal", account=account,
            args=["bad", "ftp://not-fetchable", 100],
        )
    )
    print(f"    tx={tx_bad}")
    rc_bad = wait_for_final(client, tx_bad, DEFAULT_TIMEOUT, "submit_proposal_invalid")
    bad_status = exec_status(rc_bad)
    bad_payload = exec_payload(rc_bad)
    txs.append({"step": "submit_proposal_invalid", "tx": tx_bad,
                "consensus": result_name(rc_bad), "exec_status": bad_status, "revert_reason": bad_payload})
    print(f"    exec_status={bad_status} reason={bad_payload!r}")

    # next id must be unchanged by the rollback (only 3 valid proposals exist)
    after_summary = client.read_contract(address, "get_governance_summary")
    print(f"\n[read] get_governance_summary after rollback -> {json.dumps(after_summary, default=str)}")

    return {
        "article_id_return": article_id,
        "article_after": article,
        "pending_proposal_id": pending_id,
        "over_cap_proposal_id": over_id,
        "audit_verdict": verdict,
        "audited_proposal": audited,
        "summary_after_audit": summary,
        "proposer_history": history,
        "transactions": txs,
        "invalid_reverted": bad_status != "return",
        "invalid_revert_reason": bad_payload,
        "summary_after_rollback": after_summary,
    }


def main() -> int:
    load_dotenv()
    private_key = os.environ.get("GENLAYER_PRIVATE_KEY")
    if not private_key:
        print("[deploy] GENLAYER_PRIVATE_KEY is not set", file=sys.stderr)
        return 2

    account = create_account(private_key)
    client = create_client(studionet, account=account)
    print(f"[deploy] chainId={studionet.id} deployer={account.address}")

    reused = os.environ.get("OPTIMISTIC_GOV_GUARD_ADDRESS")
    if reused:
        address = reused
        deploy_tx = "(reused)"
        print(f"[deploy] reusing existing contract {address}")
    else:
        address, deploy_tx = deploy_contract(client, account)

    integrity = verify_sha256(address)
    evidence = drive(client, account, address)

    record = {
        "network": {"name": "studionet", "chain_id": studionet.id, "rpc_urls": list(studionet.rpc_urls)},
        "rpc_url": RPC_URL,
        "deployer": account.address,
        "contract_address": address,
        "deploy_tx": deploy_tx,
        "explorer": f"{EXPLORER}/address/{address}",
        "runner": RUNNER,
        "integrity": integrity,
        "evidence": evidence,
        "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    out = EVIDENCE / "studionet_deployment.json"
    out.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    print(f"\n[deploy] wrote {out}")
    print(json.dumps({"contract_address": address,
                      "integrity": integrity,
                      "transactions": evidence["transactions"]}, indent=2, default=str))

    # Non-zero exit if the on-chain proof is incomplete.
    ok = True
    if str(evidence["audit_verdict"]) != "VETOED":
        print("[deploy] ERROR: deterministic audit did not return VETOED", file=sys.stderr)
        ok = False
    if not evidence["invalid_reverted"]:
        print("[deploy] WARNING: invalid submit_proposal did NOT revert", file=sys.stderr)
        ok = False
    if not integrity["byte_identical"]:
        print("[deploy] ERROR: sha256 integrity check failed", file=sys.stderr)
        ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
