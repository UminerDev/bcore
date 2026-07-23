#!/usr/bin/env python3
# Copyright (c) 2026 TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise the REAL ValidationAPI amber follow-up flow over HTTP.

Reproduces the 2026-07-07 mainnet wedge: a validator that keeps answering
Full_Amber for a pending block that keeps being re-submitted. Asserts the two
fixes that unwedge it:

1. connman is wired into the validation API at startup (previously the hookup
   ran before g_ValidationApi existed and silently no-oped forever), so the
   amber follow-up dispatches getheaders to peers instead of logging
   "(connman unavailable)".
2. StartAmberFlow is idempotent: re-delivery of the validator's cached Amber
   while the block is re-submitted must not reset the no-peer fallback ladder,
   so the amber force-finalizes (~61s) instead of wedging the height for the
   validator's cache TTL.
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

AMBER_RESOLUTION_TIMEOUT = 150  # fallback ladder is 0/1/60/120s with force-finalize after the 4th attempt (~61s)

MINER = 0      # default mock backend; mines the candidate block
VALIDATED = 1  # real validation API pointed at the HTTP stub


class ValidatorStubHandler(BaseHTTPRequestHandler):
    """Minimal validator API: accepts submits, answers every status poll with
    the stub's configured verdict (mimicking the production status cache)."""

    def _send_json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _status_for(self, verification_type):
        vt = verification_type.replace("_", "-")
        if vt == "full":
            return self.server.full_status
        if vt in ("quick", "quick-smell"):
            return "Quick_OK_Smell_OK"
        if vt == "model":
            return "Model_OK"
        return "Challenge_OK"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        if "/v1/verify/status/batch" in self.path:
            req = json.loads(body.decode())
            completed = []
            for item in req.get("items", []):
                completed.append({
                    "hash_id": item["hash_id"],
                    "verification_type": item["verification_type"],
                    "status": self._status_for(item["verification_type"]),
                })
            self._send_json({"completed": completed, "still_pending": []})
            return
        if "/request/submit" in self.path:
            self._send_json({})
            return
        self._send_json({})

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/v1/public/status/"):
            vt = parse_qs(parsed.query).get("verification_type", ["full"])[0]
            self._send_json({"status": self._status_for(vt)})
            return
        self._send_json({})

    def log_message(self, fmt, *args):
        pass


class ValidationAmberHttpTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        # Clean chain: the cached-chain setup mines on node 0 and asserts every
        # node connects the block immediately, which a pending full validation
        # on the real-API node cannot satisfy.
        self.setup_clean_chain = True
        self.extra_args = [[], []]

    def setup_nodes(self):
        self.stub = ThreadingHTTPServer(("127.0.0.1", 0), ValidatorStubHandler)
        self.stub.full_status = "Full_Amber"
        self.stub_thread = threading.Thread(target=self.stub.serve_forever, daemon=True)
        self.stub_thread.start()
        self.extra_args[VALIDATED] = [
            "-validationapi=real",
            f"-validatorhttpurl=http://127.0.0.1:{self.stub.server_address[1]}",
            "-validatorapikey=test-key",
            "-validationapi-force-external=1",
            "-allowvalidationadjudication=1",
            # Require full validation for every block: the fresh clean-chain
            # node never counts as "live", and once the RED chainwork replay
            # zeroes the candidate it drops out of the tip window, which would
            # divert the post-resolution accept away from the RED path.
            "-fullvalidationtipwindow=0",
        ]
        super().setup_nodes()

    def read_log(self, node):
        with open(node.debug_log_path, "rb") as fh:
            return fh.read()

    def wait_for_log(self, node, needle, timeout):
        self.wait_until(lambda: needle.encode() in self.read_log(node), timeout=timeout)

    def run_test(self):
        miner = self.nodes[MINER]
        validated = self.nodes[VALIDATED]
        self.connect_nodes(MINER, VALIDATED)

        # Fix 1 (init ordering): the connman hookup must have happened at
        # startup. Pre-fix this log never appears because g_ValidationApi is
        # still null when the wiring code runs.
        self.wait_for_log(validated, "VALIDATOR: connman attached; amber peer corroboration enabled", timeout=10)

        parent_hash = validated.getbestblockhash()
        parent_work = int(validated.getblockheader(parent_hash)["chainwork"], 16)

        # The miner (mock backend) mines the candidate; deliver it to the
        # real-API node whose validator persistently answers Full_Amber.
        block_hash = self.generate(miner, 1, sync_fun=self.no_op)[0]
        block_hex = miner.getblock(block_hash, 0)
        assert_raises_rpc_error(
            -2,
            "Validation adjudication is disabled",
            miner.adjudicatefullgreen,
            block_hash,
            "ab" * 32,
        )
        validated.submitblock(block_hex)

        self.wait_for_log(validated, f"Full validation amber for {block_hash}", timeout=60)

        # Fix 1: the follow-up must actually poll peers for corroboration.
        # Pre-fix: "(connman unavailable)" and no dispatch, ever.
        self.wait_for_log(validated, f"Amber follow-up {block_hash} dispatched getheaders to", timeout=60)
        assert b"connman unavailable" not in self.read_log(validated)

        # Fix 2: keep re-submitting the pending block while the validator
        # keeps re-serving its cached Amber — the production wedge. Each
        # redelivery re-enters StartAmberFlow; pre-fix that reset the fallback
        # ladder every time and the amber never finalized. Post-fix the ladder
        # must force-finalize regardless. With no peer verdicts recorded the
        # resolution is Full_Red (status=9).
        resolution_needle = f"Amber resolution for {block_hash} final status=9".encode()
        deadline = time.time() + AMBER_RESOLUTION_TIMEOUT
        while resolution_needle not in self.read_log(validated):
            assert time.time() < deadline, "amber never finalized while block was being re-submitted (fallback ladder reset?)"
            validated.submitblock(block_hex)
            time.sleep(1)

        # RED terminal = zero-work accept: block stored, tip unchanged.
        self.wait_for_log(validated, f"Full {block_hash} is RED; accepting block data with zero local work contribution", timeout=30)
        self.wait_until(lambda: validated.getblockheader(block_hash) is not None, timeout=30)
        assert_equal(validated.getbestblockhash(), parent_hash)
        assert_equal(int(validated.getblockheader(block_hash)["chainwork"], 16), parent_work)
        assert_raises_rpc_error(
            -1,
            "Block must have a previous Full_Amber verdict",
            validated.adjudicatefullgreen,
            block_hash,
            "ab" * 32,
        )

        # Re-run the private validator after the no-peer fallback stored Red.
        # A fresh Amber remains non-terminal and is the only status eligible
        # for operator adjudication.
        amber_result = validated.revalidateblock(block_hash, 60000)
        assert_equal(amber_result["validation_status"], "full_amber")
        assert_equal(amber_result["chain_action"], "pending_amber")

        # Operator adjudication is the explicit recovery path when an
        # independent verifier has already returned Full_Green. It is gated by
        # a startup flag and records the digest of the persisted attestation.
        evidence_sha256 = "ab" * 32
        result = validated.adjudicatefullgreen(block_hash, evidence_sha256)
        assert_equal(result["previous_status"], "full_amber")
        assert_equal(result["chain_action"], "accepted")
        assert_equal(result["evidence_sha256"], evidence_sha256)
        assert_equal(validated.getbestblockhash(), block_hash)

        self.stub.shutdown()


if __name__ == '__main__':
    ValidationAmberHttpTest(__file__).main()
