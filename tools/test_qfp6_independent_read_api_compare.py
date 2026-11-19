import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from tools.qfp6_independent_read_api_compare import (
    VerificationError, compare, get_json, parse_url, validate_distinct,
)

NET="11"*32
PROFILE="22"*32
TIP="33"*32
ROOT="44"*32
ASSET="55"*32
POLICY="66"*32
ACCOUNT="77"*32
TXID="88"*32
PRODUCER="99"*32
BLOCK="aa"*32
PARENT="bb"*32


def fixture():
    status={"api_version":1,"network_id":NET,"profile_id":PROFILE,"height":"12",
            "tip":TIP,"state_root":ROOT,"manifest_generation":"4",
            "consensus_fingerprint":"12"*32,
            "verification":"canonical_full_node_replay_required",
            "account_inclusion_proofs":False}
    supply={"api_version":1,"network_id":NET,"profile_id":PROFILE,"native_asset_id":ASSET,
            "ledger_total_atoms":"100000000000000000","owner_genesis_atoms":"100000000000000000",
            "maximum_supply_atoms":"700000000000000000","block_subsidy_atoms":"0",
            "accounting_labels_total_atoms":"600000000000000000","accounting_labels_are_minted":False,
            "issuance_policy":"fee_only_no_subsidy","policy_fingerprint":POLICY,
            "height":"12","tip":TIP,"state_root":ROOT,"proof_type":"global_state_root_only",
            "verification":"canonical_full_node_replay_required"}
    account={"api_version":1,"network_id":NET,"profile_id":PROFILE,"native_asset_id":ASSET,
             "account_id":ACCOUNT,"balance_atoms":"999","nonce":"3","height":"12","tip":TIP,
             "state_root":ROOT,"proof_type":"global_state_root_only","account_inclusion_proof":None,
             "verification":"canonical_full_node_replay_required"}
    native={"transaction_id":TXID,"sender":ACCOUNT,"recipient":"de"*32,
            "nonce":"3","amount_atoms":"100","fee_atoms":"1","expires_at":"1710000100"}
    block={"api_version":1,"network_id":NET,"profile_id":PROFILE,"height":"10",
           "timestamp":"1710000000","parent_execution_hash":PARENT,"execution_block_id":BLOCK,
           "consensus_tip":"ab"*32,"producer":PRODUCER,"state_root":"cd"*32,
           "operation_count":"1","operations":[{"index":"0","type":"native_transfer","transaction":native}],
           "canonical":True,"canonical_height":"12","canonical_tip":TIP,"canonical_state_root":ROOT,
           "proof_type":"global_state_root_only",
           "verification":"replay_and_recompute_with_trusted_genesis_or_checkpoint"}
    receipt={"api_version":1,"transaction_id":TXID,"sender":ACCOUNT,"recipient":"de"*32,
             "nonce":"3","amount_atoms":"100","fee_atoms":"1","expires_at":"1710000100",
             "status":"canonical","lookup_scope":"retained_fork_archive","mempool_checked":False,
             "block_height":"10","block_timestamp":"1710000000","execution_block_id":BLOCK,
             "consensus_tip":"ab"*32,"block_state_root":"cd"*32,"producer":PRODUCER,
             "confirmations":"3","finality":"confirmation_depth_only","canonical_height":"12",
             "canonical_tip":TIP,"canonical_state_root":ROOT}
    return {"status":status,"supply":supply,"accounts":{ACCOUNT:account},
            "blocks":{"10":block},"transactions":{TXID:receipt}}


class ComparatorTests(unittest.TestCase):
    def test_matching_status_supply_account_block_receipt(self):
        f=fixture()
        r=compare(f,f,[ACCOUNT],[10],[TXID])
        self.assertTrue(r["data_match"])
        self.assertEqual(r["operator_independence"],"NOT_VERIFIED_BY_API_COMPARISON")

    def test_receipt_block_body_cross_link_rejects_mismatch(self):
        a,b=fixture(),fixture()
        for n in (a,b):
            n["blocks"]["10"]["operations"][0]["transaction"]["amount_atoms"]="101"
        with self.assertRaisesRegex(VerificationError,"receipt amount_atoms disagrees"):
            compare(a,b,[],[10],[TXID])

    def test_rejects_status_root_divergence(self):
        a,b=fixture(),fixture()
        b["status"]["state_root"]="ef"*32
        with self.assertRaisesRegex(VerificationError,"canonical status differs"):
            compare(a,b,[],[],[])

    def test_rejects_account_proof_overclaim(self):
        a,b=fixture(),fixture()
        a["accounts"][ACCOUNT]["account_inclusion_proof"]={"made_up":True}
        with self.assertRaisesRegex(VerificationError,"overstates proof type"):
            compare(a,b,[ACCOUNT],[],[])

    def test_rejects_reorged_transaction(self):
        a,b=fixture(),fixture()
        b["transactions"][TXID]["status"]="reorged"
        b["transactions"][TXID]["confirmations"]="0"
        with self.assertRaisesRegex(VerificationError,"not canonical"):
            compare(a,b,[],[],[TXID])

    def test_rejects_bad_confirmation_depth(self):
        a,b=fixture(),fixture()
        a["transactions"][TXID]["confirmations"]="4"
        with self.assertRaisesRegex(VerificationError,"confirmation depth is inconsistent"):
            compare(a,b,[],[],[TXID])

    def test_rejects_nonzero_subsidy(self):
        a,b=fixture(),fixture()
        a["supply"]["block_subsidy_atoms"]="1"
        with self.assertRaisesRegex(VerificationError,"block subsidy is not zero"):
            compare(a,b,[],[],[])

    def test_rejects_noncanonical_block(self):
        a,b=fixture(),fixture()
        a["blocks"]["10"]["canonical"]=False
        with self.assertRaisesRegex(VerificationError,"not canonical"):
            compare(a,b,[],[10],[])

    def test_rejects_same_hostname_different_ports(self):
        _,a=parse_url("https://same.example:8443","a")
        _,b=parse_url("https://same.example:9443","b")
        with self.assertRaisesRegex(VerificationError,"hostnames must differ"):
            validate_distinct(a,b)

    def test_loopback_not_independence_evidence(self):
        _,a=parse_url("http://127.0.0.1:8443","a")
        _,b=parse_url("http://127.0.0.2:9443","b")
        with self.assertRaisesRegex(VerificationError,"loopback is harness-only"):
            validate_distinct(a,b)
        validate_distinct(a,b,allow_loopback=True)

    def test_remote_http_and_url_credentials_rejected(self):
        with self.assertRaisesRegex(VerificationError,"must use HTTPS"):
            parse_url("http://remote.example:8080","a")
        with self.assertRaisesRegex(VerificationError,"userinfo is forbidden"):
            parse_url("https://user:pass@remote.example","a")

    def test_http_get_transport_and_redirect_rejection(self):
        hits = []
        redirect_target_hits = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append((self.command, self.path))
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/target")
                    self.end_headers()
                    return
                if self.path == "/target":
                    redirect_target_hits.append(True)
                body = json.dumps({"ok": True}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *_args):
                return
        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            self.assertEqual(get_json(base, "/ok", 2), {"ok": True})
            with self.assertRaisesRegex(VerificationError, "HTTP 302"):
                get_json(base, "/redirect", 2)
            self.assertEqual(redirect_target_hits, [])
            self.assertTrue(all(method == "GET" for method, _path in hits))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_large_integer_must_be_decimal_string(self):
        a,b=fixture(),fixture()
        a["supply"]["ledger_total_atoms"]=1
        with self.assertRaisesRegex(VerificationError,"canonical unsigned decimal string"):
            compare(a,b,[],[],[])


if __name__ == "__main__":
    unittest.main()
