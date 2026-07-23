#!/usr/bin/env python3
# Copyright (c) 2026-present The TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Build-ahead (speculative next-tip) mining — external_api happy path.

When we mine a block A that is quick-valid and smell-OK but still in async Full
validation, A has only a header index (AcceptBlockHeader ran, Full was kicked
off, the body is not connected yet — validation.cpp:9163) and is NOT the active
tip. `getmininginfo` advertises A as a `build_ahead_parent_hash`; the broker can
then mint a coinbase-only child of A (`create_mining_work_unit prev_block_hash`)
so the fleet mines A's child during the validation window instead of siblings of
the current tip.

This test forces the external-validation path on regtest with the mock
validation API (`-validationapi=mock -mockval-force-external`), submits one valid
solution that stays pending, and drives every eligibility gate off that single
pending block by toggling its mock smell/Full status:

  * advertised while own + pending + Quick_OK_Smell_OK + pprev==tip;
  * `create_mining_work_unit(prev_block_hash=A)` assembles A's child (height+1,
    tip_hash==A, header prevhash==A);
  * Quick_OK_Smell_Fail  -> not advertised, child mint fails closed;
  * own Full_Red         -> not advertised, child mint fails closed;
  * a bogus parent hash  -> child mint fails closed;
  * Full Amber and Full Red both fail closed.

Requires the same optional deps as feature_broker_mining_rpc.py (flatbuffers +
chiavdf) to build a real proof::MiningResponse that passes QuickVerify.
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.vdf_helper import HAS_CHIAVDF

try:
    import flatbuffers  # noqa: F401

    HAS_FLATBUFFERS = True
except ImportError:
    HAS_FLATBUFFERS = False

REGTEST_NETWORK = "regtest"
P2_OP_TRUE_HEX = "51"
# A syntactically valid but never-minted block hash: fail-closed target.
BOGUS_PARENT = "00" * 31 + "ff"


class BrokerMiningBuildAheadTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # submit_mining_response holds the RPC open ~45s polling for connect
        # while A stays pending; keep the client timeout comfortably above that.
        self.rpc_timeout = 120
        self.extra_args = [[
            "-validationapi=mock",
            "-mockval-force-external=1",
            "-mockval-default-quick=quick_ok_smell_ok",
            "-spv-asn-corroboration=0",
        ]]
        self.supports_cli = False

    def _advertised_parent(self, node):
        return node.getmininginfo().get("build_ahead_parent_hash")

    def run_test(self):
        if not (HAS_FLATBUFFERS and HAS_CHIAVDF):
            missing = [n for n, p in (("flatbuffers", HAS_FLATBUFFERS),
                                      ("chiavdf", HAS_CHIAVDF)) if not p]
            self.log.info("Skipping: missing optional deps: %s" % ", ".join(missing))
            return

        from test_framework.mining_response_builder import (
            build_mining_response,
            solve_work_unit,
        )

        node = self.nodes[0]

        # No eligible parent at genesis: the field must be absent.
        assert self._advertised_parent(node) is None, node.getmininginfo()

        registered = [m for m in node.getmodelslist()
                      if m["status"] == 2 and m["difficulty"] > 0]
        assert registered, "node has no registered model to mine against"
        model_id = "%s@%s" % (registered[0]["model_name"],
                              registered[0]["model_commit"])

        self.log.info("Mine block A on genesis and submit it (stays pending under mock Full)")
        genesis = node.getbestblockhash()
        unit_a = node.create_mining_work_unit(REGTEST_NETWORK, P2_OP_TRUE_HEX, "0a")
        assert_equal(unit_a["tip_hash"], genesis)
        sol_a = solve_work_unit(unit_a["header_prefix"], unit_a["target"])
        payload_a = build_mining_response(unit_a["req_id"], sol_a, model_identifier=model_id)
        # Full is left un-set in the mock, so submit polls then returns pending.
        res_a = node.submit_mining_response(unit_a["req_id"], payload_a)
        assert_equal(res_a["status"], "accepted_pending_connect")
        assert_equal(res_a["accepted"], False)
        a_hash = res_a["block_hash"]
        # A is pending, not the active tip: the tip is still genesis.
        assert_equal(node.getbestblockhash(), genesis)

        # Pin A's smell status explicitly so eligibility is deterministic
        # regardless of default-propagation timing.
        node.validationmockset(a_hash, "quick", "quick_ok_smell_ok")

        self.log.info("getmininginfo advertises A as the build-ahead parent")
        info = node.getmininginfo()
        assert_equal(info["build_ahead_parent_hash"], a_hash)
        assert_equal(info["build_ahead_parent_height"], 1)

        self.log.info("create_mining_work_unit(prev_block_hash=A) assembles A's child")
        child = node.create_mining_work_unit(REGTEST_NETWORK, P2_OP_TRUE_HEX, "", a_hash)
        assert_equal(child["tip_hash"], a_hash)          # builds on A, not genesis
        assert_equal(child["height"], 2)                 # A is height 1
        # Header prefix bytes 4..36 = prevhash (little-endian) = A.
        prefix = bytes.fromhex(child["header_prefix"])
        assert_equal(prefix[4:36], bytes.fromhex(a_hash)[::-1])

        self.log.info("Quick_OK_Smell_Fail excludes A (not advertised, child mint fails closed)")
        node.validationmockset(a_hash, "quick", "quick_ok_smell_fail")
        assert self._advertised_parent(node) is None, node.getmininginfo()
        assert_raises_rpc_error(
            -8, "not the current build-ahead target",
            node.create_mining_work_unit, REGTEST_NETWORK, P2_OP_TRUE_HEX, "", a_hash,
        )
        # Restore smell -> eligible again.
        node.validationmockset(a_hash, "quick", "quick_ok_smell_ok")
        assert_equal(self._advertised_parent(node), a_hash)

        self.log.info("own Full_Amber excludes A (borderline verdict: fleet reverts to confirmed tip)")
        node.validationmockset(a_hash, "full", "full_amber")
        assert self._advertised_parent(node) is None, node.getmininginfo()
        assert_raises_rpc_error(
            -8, "not the current build-ahead target",
            node.create_mining_work_unit, REGTEST_NETWORK, P2_OP_TRUE_HEX, "", a_hash,
        )

        self.log.info("own Full_Red excludes A (not advertised, child mint fails closed)")
        node.validationmockset(a_hash, "full", "full_red")
        assert self._advertised_parent(node) is None, node.getmininginfo()
        assert_raises_rpc_error(
            -8, "not the current build-ahead target",
            node.create_mining_work_unit, REGTEST_NETWORK, P2_OP_TRUE_HEX, "", a_hash,
        )

        self.log.info("A bogus / non-target parent fails closed")
        assert_raises_rpc_error(
            -8, "not the current build-ahead target",
            node.create_mining_work_unit, REGTEST_NETWORK, P2_OP_TRUE_HEX, "", BOGUS_PARENT,
        )

        # RPC server still alive.
        node.getmininginfo()


if __name__ == "__main__":
    BrokerMiningBuildAheadTest(__file__).main()
