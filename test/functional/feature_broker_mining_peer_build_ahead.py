#!/usr/bin/env python3
# Copyright (c) 2026-present The TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Peer-originated speculative build-ahead mining.

A source node accepts block A synchronously. Two isolated broker nodes then
receive A over P2P while their own Full verdict is pending:

  * the default node does not advertise A;
  * the opt-in node advertises A after local Quick/Smell approval and can mint
    a coinbase-only child;
  * local Full Amber/Red immediately removes A from eligibility;
  * once A becomes the active tip it is no longer a speculative parent.

The source and peers are deliberately disconnected. This keeps ownership
unambiguous and exercises the real ProcessNewBlock peer path.
"""

from test_framework.messages import CBlock, from_hex, msg_block
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.vdf_helper import HAS_CHIAVDF

try:
    import flatbuffers  # noqa: F401

    HAS_FLATBUFFERS = True
except ImportError:
    HAS_FLATBUFFERS = False


REGTEST_NETWORK = "regtest"
P2_OP_TRUE_HEX = "51"


class BrokerMiningPeerBuildAheadTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        common = [
            "-validationapi=mock",
            "-mockval-force-external=1",
            "-mockval-default-quick=quick_ok_smell_ok",
            "-spv-asn-corroboration=0",
        ]
        self.extra_args = [
            common + ["-mockval-default-full=full_green"],
            common + ["-miningbuildaheadpeers=0"],
            common + ["-miningbuildaheadpeers=1"],
        ]
        self.supports_cli = False

    def setup_network(self):
        # Do not connect the nodes. The block must enter nodes 1 and 2 only
        # through the explicit test peer so it remains peer-originated.
        self.setup_nodes()

    @staticmethod
    def _advertised_parent(node):
        return node.getmininginfo().get("build_ahead_parent_hash")

    def run_test(self):
        if not (HAS_FLATBUFFERS and HAS_CHIAVDF):
            missing = [
                name
                for name, present in (
                    ("flatbuffers", HAS_FLATBUFFERS),
                    ("chiavdf", HAS_CHIAVDF),
                )
                if not present
            ]
            self.log.info("Skipping: missing optional deps: %s" % ", ".join(missing))
            return

        from test_framework.mining_response_builder import (
            build_mining_response,
            solve_work_unit,
        )

        source, default_peer, enabled_peer = self.nodes
        genesis = source.getbestblockhash()
        assert_equal(default_peer.getbestblockhash(), genesis)
        assert_equal(enabled_peer.getbestblockhash(), genesis)

        registered = [
            model
            for model in source.getmodelslist()
            if model["status"] == 2 and model["difficulty"] > 0
        ]
        assert registered, "source node has no registered model"
        model_id = "%s@%s" % (
            registered[0]["model_name"],
            registered[0]["model_commit"],
        )

        self.log.info("Source node mines and synchronously accepts block A")
        unit = source.create_mining_work_unit(
            REGTEST_NETWORK, P2_OP_TRUE_HEX, "0a"
        )
        solution = solve_work_unit(unit["header_prefix"], unit["target"])
        payload = build_mining_response(
            unit["req_id"], solution, model_identifier=model_id
        )
        result = source.submit_mining_response(unit["req_id"], payload)
        assert_equal(result["accepted"], True)
        a_hash = result["block_hash"]
        assert_equal(source.getbestblockhash(), a_hash)
        block_a = from_hex(CBlock(), source.getblock(a_hash, 0))

        self.log.info("Deliver A as a peer block to both isolated broker nodes")
        default_link = default_peer.add_p2p_connection(P2PInterface())
        enabled_link = enabled_peer.add_p2p_connection(P2PInterface())
        default_link.send_and_ping(msg_block(block_a))
        enabled_link.send_and_ping(msg_block(block_a))

        assert_equal(default_peer.getbestblockhash(), genesis)
        assert_equal(enabled_peer.getbestblockhash(), genesis)
        assert self._advertised_parent(default_peer) is None
        assert_equal(self._advertised_parent(enabled_peer), a_hash)

        self.log.info("Opt-in node can mint a coinbase-only child of peer block A")
        child = enabled_peer.create_mining_work_unit(
            REGTEST_NETWORK, P2_OP_TRUE_HEX, "", a_hash
        )
        assert_equal(child["tip_hash"], a_hash)
        assert_equal(child["height"], 2)

        self.log.info("Full Amber and Red each fail closed")
        for full_status in ("full_amber", "full_red"):
            enabled_peer.validationmockset(a_hash, "full", full_status)
            assert self._advertised_parent(enabled_peer) is None
            assert_raises_rpc_error(
                -8,
                "not the current build-ahead target",
                enabled_peer.create_mining_work_unit,
                REGTEST_NETWORK,
                P2_OP_TRUE_HEX,
                "",
                a_hash,
            )

        self.log.info("After Full Green connects A, build-ahead is no longer advertised")
        enabled_peer.validationmockset(a_hash, "full", "full_green")
        enabled_link.send_and_ping(msg_block(block_a))
        self.wait_until(lambda: enabled_peer.getbestblockhash() == a_hash)
        assert self._advertised_parent(enabled_peer) is None


if __name__ == "__main__":
    BrokerMiningPeerBuildAheadTest(__file__).main()
