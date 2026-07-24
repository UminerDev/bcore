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

import os
import struct
from io import BytesIO
from pathlib import Path
from threading import Thread

from test_framework.messages import CBlock, CProofBlob, from_hex, msg_block
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, get_rpc_proxy
from test_framework.vdf_helper import HAS_CHIAVDF, compute_pow_commitment

try:
    import flatbuffers  # noqa: F401

    HAS_FLATBUFFERS = True
except ImportError:
    HAS_FLATBUFFERS = False


REGTEST_NETWORK = "regtest"
P2_OP_TRUE_HEX = "51"


class BrokerMiningPeerBuildAheadTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 5
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
            common + ["-miningbuildaheadpeers=1"],
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

    @staticmethod
    def _full_requests(node):
        return {
            request["id"]
            for request in node.validationmockrequests()
            if request["type"] == "Full"
        }

    @staticmethod
    def _journal_block(node, req_id):
        journal = (
            Path(node.datadir_path)
            / REGTEST_NETWORK
            / "broker-work-units"
            / ("%d.dat" % req_id)
        )
        raw = journal.read_bytes()
        version, stored_id = struct.unpack("<II", raw[:8])
        assert_equal(version, 1)
        assert_equal(stored_id, req_id)

        block = CBlock()
        block.deserialize(BytesIO(raw[8:-32]))
        return block

    @classmethod
    def _solved_block(
        cls,
        node,
        req_id,
        solution,
        model_id,
        parent_cumulative_tick,
    ):
        block = cls._journal_block(node, req_id)
        proof = CProofBlob()
        proof.version = 1
        proof.tick = solution["tick"]
        proof.timestamp = 1700000000
        proof.target = solution["target"]
        proof.vdf = solution["vdf"]
        proof.hash = solution["final_hash"]
        proof.block_hash = solution["header_prefix"][4:36]
        proof.header_prefix = solution["header_prefix"]
        proof.is_solution = True
        proof.model_identifier = model_id.encode()
        proof.compute_precision = b"fp16"
        proof.temperature = 1.0
        proof.top_p = 1.0
        proof.top_k = 8
        proof.repetition_penalty = 1.0
        proof.chosen_tokens = solution["chosen_tokens"]
        proof.sampling_u = solution["sampling_u"]
        fillers = [0x80000000 + index for index in range(7)]
        proof.topk_logits = [[50.0] + [0.0] * 7 for _ in proof.chosen_tokens]
        proof.topk_indices = [
            [token] + fillers for token in proof.chosen_tokens
        ]

        block.nNonce = solution["nonce"]
        block.nAdjBits = solution["adjusted_bits"]
        block.pow = proof
        block.cumulative_tick = parent_cumulative_tick + proof.tick
        block.hashPoW = int.from_bytes(
            compute_pow_commitment(proof, use_merkle=True),
            "little",
        )
        block.rehash()
        return block

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
        os.environ["TSC_VDF_TEST_HELPER"] = str(
            Path(self.config["environment"]["BUILDDIR"])
            / "bin"
            / "vdf_test_helper"
        )

        source, default_peer, enabled_peer, submit_peer, restart_peer = self.nodes
        genesis = source.getbestblockhash()
        assert_equal(default_peer.getbestblockhash(), genesis)
        assert_equal(enabled_peer.getbestblockhash(), genesis)
        assert_equal(submit_peer.getbestblockhash(), genesis)
        assert_equal(restart_peer.getbestblockhash(), genesis)

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
        submit_link = submit_peer.add_p2p_connection(P2PInterface())
        restart_link = restart_peer.add_p2p_connection(P2PInterface())
        default_link.send_and_ping(msg_block(block_a))
        enabled_link.send_and_ping(msg_block(block_a))
        submit_link.send_and_ping(msg_block(block_a))
        restart_link.send_and_ping(msg_block(block_a))

        assert_equal(default_peer.getbestblockhash(), genesis)
        assert_equal(enabled_peer.getbestblockhash(), genesis)
        assert_equal(submit_peer.getbestblockhash(), genesis)
        assert_equal(restart_peer.getbestblockhash(), genesis)
        assert self._advertised_parent(default_peer) is None
        assert_equal(self._advertised_parent(enabled_peer), a_hash)
        assert_equal(self._advertised_parent(submit_peer), a_hash)
        assert_equal(self._advertised_parent(restart_peer), a_hash)

        self.log.info("Opt-in node can mint a coinbase-only child of peer block A")
        child = enabled_peer.create_mining_work_unit(
            REGTEST_NETWORK, P2_OP_TRUE_HEX, "", a_hash
        )
        assert_equal(child["tip_hash"], a_hash)
        assert_equal(child["height"], 2)

        self.log.info("Restarted speculative child fails retriably when parent state is absent")
        restart_child = restart_peer.create_mining_work_unit(
            REGTEST_NETWORK, P2_OP_TRUE_HEX, "", a_hash
        )
        restart_solution = solve_work_unit(
            restart_child["header_prefix"], restart_child["target"]
        )
        restart_payload = build_mining_response(
            restart_child["req_id"],
            restart_solution,
            model_identifier=model_id,
        )
        self.restart_node(4)
        restart_peer = self.nodes[4]
        restart_result = restart_peer.submit_mining_response(
            restart_child["req_id"],
            restart_payload,
        )
        assert_equal(restart_result["accepted"], False)
        assert_equal(restart_result["status"], "parent_state_unavailable")

        self.log.info("A child submitted before peer parent Full completes is retained")
        submit_child = submit_peer.create_mining_work_unit(
            REGTEST_NETWORK, P2_OP_TRUE_HEX, "", a_hash
        )
        self.log.info(
            "Refresh-under-load keeps the oldest in-flight child addressable"
        )
        refreshed_ids = {submit_child["req_id"]}
        for refresh in range(1, 17):
            refreshed = submit_peer.create_mining_work_unit(
                REGTEST_NETWORK,
                P2_OP_TRUE_HEX,
                ("%02x" % refresh),
                a_hash,
            )
            assert_equal(refreshed["tip_hash"], a_hash)
            assert refreshed["req_id"] not in refreshed_ids
            refreshed_ids.add(refreshed["req_id"])
        assert_equal(len(refreshed_ids), 17)

        child_template = self._journal_block(
            submit_peer,
            submit_child["req_id"],
        )
        assert_equal(
            child_template.cumulative_tick,
            block_a.cumulative_tick + child_template.pow.tick,
        )
        solution = solve_work_unit(
            submit_child["header_prefix"], submit_child["target"]
        )
        payload = build_mining_response(
            submit_child["req_id"], solution, model_identifier=model_id
        )
        submit_rpc = get_rpc_proxy(
            submit_peer.url,
            100,
            timeout=120,
            coveragedir=submit_peer.coverage_dir,
        )
        child_result = {}
        child_error = []

        def submit_pending_child():
            try:
                child_result.update(
                    submit_rpc.submit_mining_response(
                        submit_child["req_id"], payload
                    )
                )
            except Exception as error:
                child_error.append(error)

        submit_thread = Thread(target=submit_pending_child)
        submit_thread.start()
        self.wait_until(
            lambda: len(self._full_requests(submit_peer) - {a_hash}) == 1,
            timeout=20,
        )
        child_hash = next(iter(self._full_requests(submit_peer) - {a_hash}))
        assert submit_thread.is_alive()
        assert_equal(submit_peer.getbestblockhash(), genesis)

        submit_peer.validationmockset(child_hash, "full", "full_green")
        solved_child = self._solved_block(
            submit_peer,
            submit_child["req_id"],
            solution,
            model_id,
            block_a.cumulative_tick,
        )
        assert_equal(solved_child.hash, child_hash)
        # validationmockset only records a verdict. Resend the exact solved
        # block to model the real verifier's ProcessNewBlock callback.
        submit_link.send_and_ping(msg_block(solved_child))
        assert_equal(submit_peer.getbestblockhash(), genesis)
        submit_peer.validationmockset(a_hash, "full", "full_green")
        submit_link.send_and_ping(msg_block(block_a))
        self.wait_until(
            lambda: submit_peer.getbestblockhash() == child_hash,
            timeout=30,
        )
        submit_thread.join(timeout=30)
        assert not submit_thread.is_alive()
        assert not child_error, child_error
        assert_equal(child_result["accepted"], True)
        assert_equal(child_result["status"], "accepted")
        assert_equal(submit_peer.getbestblockhash(), child_hash)

        self.log.info(
            "After soft rotation completes, fresh work immediately follows the new tip"
        )
        next_tip_work = submit_peer.create_mining_work_unit(
            REGTEST_NETWORK, P2_OP_TRUE_HEX, "ff"
        )
        assert_equal(next_tip_work["tip_hash"], child_hash)
        assert_equal(next_tip_work["height"], 3)

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
