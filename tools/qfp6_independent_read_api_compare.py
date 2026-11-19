#!/usr/bin/env python3
"""Compare QFP6 canonical read data from two remote operators.

This compares API data, not operator independence. It is GET-only, HTTPS-only
for remote endpoints, and never handles credentials or node private keys.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

HEX32 = re.compile(r"^[0-9a-fA-F]{64}$")
UINT = re.compile(r"^(0|[1-9][0-9]*)$")
MAX_BODY = 16 * 1024 * 1024
API_VERSION = 1

STATUS = ("api_version", "network_id", "profile_id", "height", "tip", "state_root",
          "consensus_fingerprint", "verification", "account_inclusion_proofs")
SUPPLY = ("api_version", "network_id", "profile_id", "native_asset_id",
          "ledger_total_atoms", "owner_genesis_atoms", "maximum_supply_atoms",
          "block_subsidy_atoms", "accounting_labels_total_atoms",
          "accounting_labels_are_minted", "issuance_policy", "policy_fingerprint",
          "height", "tip", "state_root", "proof_type", "verification")
ACCOUNT = ("api_version", "network_id", "profile_id", "native_asset_id", "account_id",
           "balance_atoms", "nonce", "height", "tip", "state_root", "proof_type",
           "account_inclusion_proof", "verification")
BLOCK = ("api_version", "network_id", "profile_id", "height", "timestamp",
         "parent_execution_hash", "execution_block_id", "consensus_tip", "producer",
         "state_root", "operation_count", "operations", "canonical",
         "canonical_height", "canonical_tip", "canonical_state_root", "proof_type",
         "verification")
TX = ("api_version", "transaction_id", "sender", "recipient", "nonce", "amount_atoms",
      "fee_atoms", "expires_at", "status", "lookup_scope", "mempool_checked",
      "block_height", "block_timestamp", "execution_block_id", "consensus_tip",
      "block_state_root", "producer", "confirmations", "finality",
      "canonical_height", "canonical_tip", "canonical_state_root")


class VerificationError(Exception):
    pass


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fail(message: str) -> None:
    raise VerificationError(message)


def dec(value: object, field: str) -> int:
    if not isinstance(value, str) or not UINT.fullmatch(value):
        fail(f"{field}: expected canonical unsigned decimal string")
    return int(value)


def h32(value: object, field: str) -> str:
    if not isinstance(value, str) or not HEX32.fullmatch(value):
        fail(f"{field}: expected 64 hexadecimal characters")
    return value.lower()


def require_obj(value: object, field: str) -> dict:
    if not isinstance(value, dict):
        fail(f"{field}: expected JSON object")
    return value


def require_fields(value: dict, fields: tuple[str, ...], field: str) -> None:
    missing = [item for item in fields if item not in value]
    if missing:
        fail(f"{field}: missing fields {', '.join(missing)}")


def parse_url(value: str, label: str) -> tuple[str, tuple[str, str, int]]:
    try:
        p = urlsplit(value)
        scheme = p.scheme.lower()
        host = (p.hostname or "").lower()
        port = p.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        fail(f"{label}: invalid URL: {exc}")
    if scheme not in ("https", "http") or not host:
        fail(f"{label}: URL must use HTTPS (HTTP only for loopback harnesses)")
    if p.username is not None or p.password is not None:
        fail(f"{label}: URL userinfo is forbidden")
    if p.path not in ("", "/") or p.query or p.fragment:
        fail(f"{label}: URL must be an origin without path/query/fragment")
    if scheme == "http":
        try:
            loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback:
            fail(f"{label}: non-loopback endpoint must use HTTPS")
    return value.rstrip("/"), (scheme, host, port)


def validate_distinct(a: tuple[str, str, int], b: tuple[str, str, int],
                      allow_loopback: bool = False) -> None:
    if a == b:
        fail("node-a and node-b must have different URL origins")
    if a[1] == b[1]:
        fail("node-a and node-b hostnames must differ; different ports on one host are not independent")
    if not allow_loopback:
        for label, item in (("node-a", a), ("node-b", b)):
            scheme, host, _ = item
            try:
                local = host == "localhost" or ipaddress.ip_address(host).is_loopback
            except ValueError:
                local = host == "localhost"
            if scheme != "https" or local:
                fail(f"{label}: use a remote HTTPS endpoint; loopback is harness-only")


def get_json(base: str, path: str, timeout: float) -> dict:
    req = Request(base + path, headers={"Accept": "application/json",
                                        "Cache-Control": "no-cache",
                                        "User-Agent": "QFP6-read-compare/1.0"},
                  method="GET")
    expected = urlsplit(base)
    try:
        opener = build_opener(NoRedirectHandler())
        with opener.open(req, timeout=timeout) as response:
            actual = urlsplit(response.geturl())
            if (actual.scheme, actual.hostname, actual.port) != (expected.scheme, expected.hostname, expected.port):
                fail("cross-origin HTTP redirect rejected")
            if response.status != 200:
                fail(f"GET {path}: HTTP {response.status}")
            body = response.read(MAX_BODY + 1)
    except HTTPError as exc:
        fail(f"GET {path}: HTTP {exc.code}")
    except URLError as exc:
        fail(f"GET {path}: transport error {exc.reason}")
    except TimeoutError:
        fail(f"GET {path}: timed out after {timeout:g}s")
    if len(body) > MAX_BODY:
        fail(f"GET {path}: response exceeds {MAX_BODY} bytes")
    try:
        return require_obj(json.loads(body.decode("utf-8")), path)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"GET {path}: invalid JSON: {exc}")


def validate_status(v: dict, label: str) -> None:
    require_fields(v, STATUS + ("manifest_generation",), label + " status")
    if v["api_version"] != API_VERSION:
        fail(f"{label}: unsupported status API version")
    for f in ("network_id", "profile_id", "tip", "state_root", "consensus_fingerprint"):
        h32(v[f], f"{label}.status.{f}")
    dec(v["height"], f"{label}.status.height")
    dec(v["manifest_generation"], f"{label}.status.manifest_generation")
    if v["verification"] != "canonical_full_node_replay_required" or v["account_inclusion_proofs"] is not False:
        fail(f"{label}: status proof/verification semantics changed")


def validate_supply(v: dict, status: dict, label: str) -> None:
    require_fields(v, SUPPLY, label + " supply")
    if v["api_version"] != API_VERSION:
        fail(f"{label}: unsupported supply API version")
    for f in ("network_id", "profile_id", "native_asset_id", "policy_fingerprint", "tip", "state_root"):
        h32(v[f], f"{label}.supply.{f}")
    for f in ("ledger_total_atoms", "owner_genesis_atoms", "maximum_supply_atoms",
              "block_subsidy_atoms", "accounting_labels_total_atoms", "height"):
        dec(v[f], f"{label}.supply.{f}")
    if v["accounting_labels_are_minted"] is not False or v["issuance_policy"] != "fee_only_no_subsidy":
        fail(f"{label}: CP-0651 issuance policy/labels mismatch")
    if v["proof_type"] != "global_state_root_only" or v["verification"] != "canonical_full_node_replay_required":
        fail(f"{label}: supply proof/verification semantics changed")
    if v["block_subsidy_atoms"] != "0":
        fail(f"{label}: block subsidy is not zero")
    if int(v["ledger_total_atoms"]) > int(v["maximum_supply_atoms"]):
        fail(f"{label}: ledger total exceeds maximum supply")
    if int(v["owner_genesis_atoms"]) + int(v["accounting_labels_total_atoms"]) != int(v["maximum_supply_atoms"]):
        fail(f"{label}: owner allocation plus non-minted labels differs from maximum supply")
    if v["network_id"].lower() != status["network_id"].lower() or v["profile_id"].lower() != status["profile_id"].lower():
        fail(f"{label}: supply network/profile differs from status")
    if (v["height"], v["tip"].lower(), v["state_root"].lower()) != (
        status["height"], status["tip"].lower(), status["state_root"].lower()
    ):
        fail(f"{label}: supply snapshot differs from status")


def validate_account(v: dict, status: dict, requested: str, label: str) -> None:
    require_fields(v, ACCOUNT, label + " account")
    if v["api_version"] != API_VERSION:
        fail(f"{label}: unsupported account API version")
    for f in ("network_id", "profile_id", "native_asset_id", "account_id", "tip", "state_root"):
        h32(v[f], f"{label}.account.{f}")
    if v["account_id"].lower() != requested.lower():
        fail(f"{label}: account ID differs from requested value")
    for f in ("balance_atoms", "nonce"):
        if v[f] is not None:
            dec(v[f], f"{label}.account.{f}")
    if v["proof_type"] != "global_state_root_only" or v["account_inclusion_proof"] is not None:
        fail(f"{label}: account response overstates proof type")
    if v["verification"] != "canonical_full_node_replay_required":
        fail(f"{label}: account verification semantics changed")
    if (v["height"], v["tip"].lower(), v["state_root"].lower()) != (
        status["height"], status["tip"].lower(), status["state_root"].lower()
    ):
        fail(f"{label}: account snapshot differs from status")
    if v["network_id"].lower() != status["network_id"].lower() or v["profile_id"].lower() != status["profile_id"].lower():
        fail(f"{label}: account network/profile differs from status")


def validate_block(v: dict, status: dict, height: int, label: str) -> None:
    require_fields(v, BLOCK, label + " block")
    if v["api_version"] != API_VERSION:
        fail(f"{label}: unsupported block API version")
    for f in ("network_id", "profile_id", "parent_execution_hash", "execution_block_id",
              "consensus_tip", "producer", "state_root", "canonical_tip", "canonical_state_root"):
        h32(v[f], f"{label}.block.{f}")
    if dec(v["height"], f"{label}.block.height") != height:
        fail(f"{label}: returned block height differs from requested height")
    dec(v["timestamp"], f"{label}.block.timestamp")
    n = dec(v["operation_count"], f"{label}.block.operation_count")
    if not isinstance(v["operations"], list) or n != len(v["operations"]):
        fail(f"{label}: operation_count does not match operations array")
    for i, op in enumerate(v["operations"]):
        if not isinstance(op, dict) or dec(op.get("index"), f"{label}.operation[{i}].index") != i:
            fail(f"{label}: operation indexes are not contiguous")
        if not isinstance(op.get("type"), str) or not op["type"]:
            fail(f"{label}: operation type missing")
        tx = op.get("transaction")
        if tx is not None:
            if not isinstance(tx, dict):
                fail(f"{label}: native transaction payload is not an object")
            for f in ("transaction_id", "sender", "recipient"):
                h32(tx.get(f), f"{label}.operation[{i}].{f}")
            for f in ("nonce", "amount_atoms", "fee_atoms", "expires_at"):
                dec(tx.get(f), f"{label}.operation[{i}].{f}")
    if v["canonical"] is not True:
        fail(f"{label}: requested block is not canonical")
    if v["proof_type"] != "global_state_root_only" or v["verification"] != "replay_and_recompute_with_trusted_genesis_or_checkpoint":
        fail(f"{label}: block proof/verification semantics changed")
    if (v["canonical_height"], v["canonical_tip"].lower(), v["canonical_state_root"].lower()) != (
        status["height"], status["tip"].lower(), status["state_root"].lower()
    ):
        fail(f"{label}: block canonical snapshot differs from status")
    if v["network_id"].lower() != status["network_id"].lower() or v["profile_id"].lower() != status["profile_id"].lower():
        fail(f"{label}: block network/profile differs from status")


def validate_tx(v: dict, status: dict, requested: str, label: str) -> None:
    require_fields(v, TX, label + " transaction")
    if v["api_version"] != API_VERSION:
        fail(f"{label}: unsupported transaction API version")
    for f in ("transaction_id", "sender", "recipient", "execution_block_id", "consensus_tip",
              "block_state_root", "producer", "canonical_tip", "canonical_state_root"):
        h32(v[f], f"{label}.transaction.{f}")
    if v["transaction_id"].lower() != requested.lower():
        fail(f"{label}: transaction ID differs from requested value")
    if v["status"] != "canonical":
        fail(f"{label}: transaction is not canonical")
    if v["lookup_scope"] != "retained_fork_archive" or v["mempool_checked"] is not False:
        fail(f"{label}: transaction lookup/mempool scope changed")
    if v["finality"] != "confirmation_depth_only":
        fail(f"{label}: finality semantics changed")
    for f in ("nonce", "amount_atoms", "fee_atoms", "expires_at", "block_height",
              "block_timestamp", "confirmations", "canonical_height"):
        dec(v[f], f"{label}.transaction.{f}")
    height, tip_height = int(v["block_height"]), int(v["canonical_height"])
    if height > tip_height or int(v["confirmations"]) != tip_height - height + 1:
        fail(f"{label}: confirmation depth is inconsistent")
    if (v["canonical_height"], v["canonical_tip"].lower(), v["canonical_state_root"].lower()) != (
        status["height"], status["tip"].lower(), status["state_root"].lower()
    ):
        fail(f"{label}: transaction canonical snapshot differs from status")


def same(a: dict, b: dict, fields: tuple[str, ...], context: str) -> None:
    diff = [f for f in fields if a.get(f) != b.get(f)]
    if diff:
        fail(f"{context} differs between endpoints: {', '.join(diff)}")


def compare(a: dict, b: dict, accounts: list[str], heights: list[int], txids: list[str]) -> dict:
    sa, sb = require_obj(a.get("status"), "node-a status"), require_obj(b.get("status"), "node-b status")
    validate_status(sa, "node-a")
    validate_status(sb, "node-b")
    same(sa, sb, STATUS, "canonical status")
    qa, qb = require_obj(a.get("supply"), "node-a supply"), require_obj(b.get("supply"), "node-b supply")
    validate_supply(qa, sa, "node-a")
    validate_supply(qb, sb, "node-b")
    same(qa, qb, SUPPLY, "canonical supply")
    result = {"status": "MATCH", "supply": "MATCH", "accounts": {}, "blocks": {}, "transactions": {}}
    for account in accounts:
        va, vb = require_obj(a["accounts"][account], "node-a account"), require_obj(b["accounts"][account], "node-b account")
        validate_account(va, sa, account, "node-a")
        validate_account(vb, sb, account, "node-b")
        same(va, vb, ACCOUNT, f"account {account}")
        result["accounts"][account.lower()] = "MATCH"
    for height in heights:
        va, vb = require_obj(a["blocks"][str(height)], "node-a block"), require_obj(b["blocks"][str(height)], "node-b block")
        validate_block(va, sa, height, "node-a")
        validate_block(vb, sb, height, "node-b")
        same(va, vb, BLOCK, f"block {height}")
        result["blocks"][str(height)] = "MATCH"
    for txid in txids:
        va, vb = require_obj(a["transactions"][txid], "node-a receipt"), require_obj(b["transactions"][txid], "node-b receipt")
        validate_tx(va, sa, txid, "node-a")
        validate_tx(vb, sb, txid, "node-b")
        same(va, vb, TX, f"transaction {txid}")
        result["transactions"][txid.lower()] = "MATCH"
    blocks = {str(h): a["blocks"][str(h)] for h in heights}
    for txid in txids:
        receipt = a["transactions"][txid]
        block = blocks.get(receipt["block_height"])
        if block is None:
            continue
        for rf, bf in (("execution_block_id","execution_block_id"),
                       ("consensus_tip","consensus_tip"),
                       ("block_state_root","state_root"), ("producer","producer")):
            if receipt[rf].lower() != block[bf].lower():
                fail(f"transaction {txid} receipt {rf} does not match selected block")
        matches = []
        for op in block["operations"]:
            payload = op.get("transaction") if isinstance(op, dict) else None
            if isinstance(payload, dict) and str(payload.get("transaction_id","")).lower() == txid.lower():
                matches.append((op,payload))
        if len(matches) != 1 or matches[0][0].get("type") != "native_transfer":
            fail(f"transaction {txid} must appear exactly once as a native_transfer in its selected block")
        payload = matches[0][1]
        for f in ("sender","recipient","nonce","amount_atoms","fee_atoms","expires_at"):
            if str(payload.get(f)) != str(receipt[f]):
                fail(f"transaction {txid} receipt {f} disagrees with selected block body")
    return {
        "schema": "qfp6-independent-read-api-comparison/v1",
        "data_match": True,
        "operator_independence": "NOT_VERIFIED_BY_API_COMPARISON",
        "independence_note": "Matching data does not prove distinct admins/providers/hosts/networks; existing out-of-band operator receipts are required.",
        "proof_limit": "global_state_root_only; no account inclusion proof",
        "finality_limit": "confirmation_depth_only; not irreversible finality",
        "mempool_checked": False,
        "compared": result,
        "canonical_snapshot": {"network_id":sa["network_id"].lower(), "profile_id":sa["profile_id"].lower(),
                               "height":sa["height"], "tip":sa["tip"].lower(), "state_root":sa["state_root"].lower()},
        "supply": {"ledger_total_atoms":qa["ledger_total_atoms"], "maximum_supply_atoms":qa["maximum_supply_atoms"],
                   "owner_genesis_atoms":qa["owner_genesis_atoms"], "accounting_labels_total_atoms":qa["accounting_labels_total_atoms"],
                   "block_subsidy_atoms":qa["block_subsidy_atoms"], "accounting_labels_are_minted":qa["accounting_labels_are_minted"],
                   "policy_fingerprint":qa["policy_fingerprint"].lower()},
    }


def observe(base: str, label: str, accounts: list[str], heights: list[int], txids: list[str], timeout: float) -> dict:
    status = get_json(base, "/v1/status", timeout)
    supply = get_json(base, "/v1/supply", timeout)
    validate_status(status, label)
    validate_supply(supply, status, label)
    return {
        "status": status, "supply": supply,
        "accounts": {x:get_json(base, f"/v1/account/{x}", timeout) for x in accounts},
        "blocks": {str(h):get_json(base, f"/v1/block/{h}", timeout) for h in heights},
        "transactions": {x:get_json(base, f"/v1/transaction/{x}", timeout) for x in txids},
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--node-a", required=True)
    p.add_argument("--node-b", required=True)
    p.add_argument("--account-id", action="append", default=[])
    p.add_argument("--block-height", action="append", default=[])
    p.add_argument("--txid", action="append", default=[])
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--allow-loopback-test", action="store_true")
    p.add_argument("--output", type=Path)
    args = p.parse_args(argv)
    try:
        if not 0.5 <= args.timeout <= 60:
            fail("--timeout must be between 0.5 and 60 seconds")
        ua, oa = parse_url(args.node_a, "node-a")
        ub, ob = parse_url(args.node_b, "node-b")
        validate_distinct(oa, ob, args.allow_loopback_test)
        accounts = [h32(x, "--account-id") for x in args.account_id]
        txids = [h32(x, "--txid") for x in args.txid]
        heights = [dec(x, "--block-height") for x in args.block_height]
        if any(h < 1 for h in heights):
            fail("--block-height must be >= 1")
        if any(len(set(x)) != len(x) for x in (accounts, heights, txids)):
            fail("duplicate query identifiers are not allowed")
        if max(len(accounts), len(heights), len(txids)) > 64:
            fail("each query list is capped at 64 items")
        result = compare(
            observe(ua, "node-a", accounts, heights, txids, args.timeout),
            observe(ub, "node-b", accounts, heights, txids, args.timeout),
            accounts, heights, txids,
        )
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        sys.stdout.write(rendered)
        print("READ_DATA_MATCH=PASS")
        print("OPERATOR_INDEPENDENCE=NOT_VERIFIED")
        return 0
    except (VerificationError, OSError) as exc:
        print(f"READ_DATA_MATCH=FAIL: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
