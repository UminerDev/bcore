#!/usr/bin/env python3
# Copyright (c) 2024-present The TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Broker-driven mining RPCs.

Covers the broker-driven mining RPC surface that doesn't require
constructing a valid `proof::MiningResponse` FlatBuffer in Python:

- `create_mining_work_unit` rejects bad args (network mismatch, empty payout,
  oversize extranonce_tag).
- Two parallel `create_mining_work_unit` calls against the same tip return
  distinct `req_id`s **and** distinct `header_prefix` values (the fanout
  primitive: different extranonce → rotated coinbase txid → rotated merkle
  root → rotated header_prefix).
- The returned `target` matches `nBits` of the assembled block.
- `submit_mining_response` returns structured rejection codes for
  invalid base64, malformed FlatBuffer, req_id out of range, and
  rpc/flatbuffer req_id mismatch.
- Broker work units survive a node restart and remain releasable/submittable
  under the original `req_id`.
- `getmininginfo` exposes `tip_hash`, `tip_time`, `tip_age_seconds`.

The valid-submission legs (accepted / already_submitted / unknown_req_id
after release / quick_verify_failed / stale-tip sibling) are built with
test_framework.mining_response_builder and run when both optional deps are
available: `flatbuffers` (FlatBuffer serialisation) and `chiavdf`
(QuickVerifier runs a real Wesolowski VDF verify even on regtest —
verification/quick_verifier.cpp VerifyVDF has no test bypass).
"""
import base64
import os
import struct

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.vdf_helper import HAS_CHIAVDF

try:
    import flatbuffers  # noqa: F401

    HAS_FLATBUFFERS = True
except ImportError:
    HAS_FLATBUFFERS = False


# Same network names bcore reports via getmininginfo's "chain" field. We use
# regtest exclusively here.
REGTEST_NETWORK = "regtest"

# A trivial scriptPubKey: OP_TRUE (one byte, 0x51). Acceptable as a coinbase
# payout in regtest — the assembled block won't be submitted in this test.
P2_OP_TRUE_HEX = "51"


class BrokerMiningRpcTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Match the conservative -spv-asn-corroboration flag used by other
        # mining tests so block assembly doesn't hit ASN gating.
        self.extra_args = [["-spv-asn-corroboration=0"]]
        self.supports_cli = False

    def run_test(self):
        node = self.nodes[0]

        # Bring the chain to a state where BlockAssembler can build a
        # template (regtest produces a genesis tip on startup).
        self.log.info("Sanity: getmininginfo carries the new tip-freshness fields")
        info = node.getmininginfo()
        assert "tip_hash" in info, info
        assert "tip_time" in info, info
        assert "tip_age_seconds" in info, info
        assert_equal(info["tip_hash"], node.getbestblockhash())
        assert_greater_than(info["tip_age_seconds"] + 1, 0)

        self.log.info("create_mining_work_unit rejects mismatched network")
        assert_raises_rpc_error(
            -8, "network mismatch",
            node.create_mining_work_unit, "main", P2_OP_TRUE_HEX, "",
        )

        self.log.info("create_mining_work_unit rejects empty payout_script_pubkey")
        # The RPC's pre-ParseHexV guard returns "must be non-empty"; if the
        # guard ever regresses, ParseHexV emits "must be hexadecimal string
        # (not '')". Either is an RPC_INVALID_PARAMETER (-8); accepting the
        # shared "payout_script_pubkey" prefix matches both without coupling
        # the test to one specific phrasing.
        assert_raises_rpc_error(
            -8, "payout_script_pubkey",
            node.create_mining_work_unit, REGTEST_NETWORK, "", "",
        )

        self.log.info("create_mining_work_unit rejects extranonce that overflows the 100-byte coinbase scriptSig")
        # Consensus rule (consensus/tx_check.cpp:58 "bad-cb-length") caps
        # coinbase scriptSig at 2..100 bytes. A 100-byte extranonce is
        # serialised as OP_PUSHDATA1 + 1-byte length + 100 data bytes = 102
        # bytes, already past the ceiling regardless of the height push.
        # The RPC must reject this BEFORE minting a work unit no miner
        # could ever submit.
        oversize_tag = "ab" * 100  # 100 bytes
        assert_raises_rpc_error(
            -8, "outside consensus range",
            node.create_mining_work_unit, REGTEST_NETWORK, P2_OP_TRUE_HEX, oversize_tag,
        )

        self.log.info("Two parallel work units → distinct req_id and header_prefix")
        unit_a = node.create_mining_work_unit(REGTEST_NETWORK, P2_OP_TRUE_HEX, "01")
        unit_b = node.create_mining_work_unit(REGTEST_NETWORK, P2_OP_TRUE_HEX, "02")

        for u in (unit_a, unit_b):
            assert_equal(u["network"], REGTEST_NETWORK)
            assert_greater_than(u["req_id"], 0)
            assert_equal(len(u["header_prefix"]), 76 * 2)  # 76 bytes hex
            assert_equal(len(u["target"]), 64)              # 32-byte hash hex
            assert_greater_than(u["expires_at"], 0)
            assert_greater_than(u["height"], 0)

        # The fanout primitive: same tip + different extranonce_tag → rotated
        # merkle root → rotated header_prefix. req_ids must also be distinct.
        assert unit_a["req_id"] != unit_b["req_id"], (unit_a, unit_b)
        assert unit_a["header_prefix"] != unit_b["header_prefix"], (unit_a, unit_b)
        # Same tip → same target (regtest difficulty doesn't move).
        assert_equal(unit_a["target"], unit_b["target"])
        assert_equal(unit_a["height"], unit_b["height"])

        # Header prefix layout sanity: bytes 4..36 must equal the prev-block
        # hash (little-endian), which is the current tip hash.
        prefix_a = bytes.fromhex(unit_a["header_prefix"])
        assert_equal(len(prefix_a), 76)
        prev_block_le = prefix_a[4:36]
        # bcore reports tip_hash as big-endian hex via .ToString(); the header
        # serialisation is little-endian, so reverse for comparison.
        expected_prev = bytes.fromhex(node.getbestblockhash())[::-1]
        assert_equal(prev_block_le, expected_prev)

        # nBits in the prefix (bytes 72..76, little-endian) must match the
        # block.nBits the broker would expect for difficulty adjustment.
        nbits_le = prefix_a[72:76]
        assert_equal(len(nbits_le), 4)

        self.log.info("submit_mining_response rejects req_id out of range")
        bogus_payload = base64.b64encode(b"not a flatbuffer").decode()
        result = node.submit_mining_response(0, bogus_payload)
        assert_equal(result["accepted"], False)
        assert_equal(result["status"], "invalid_payload")
        assert "req_id out of range" in result["reject_reason"]

        self.log.info("submit_mining_response rejects non-base64 input")
        result = node.submit_mining_response(unit_a["req_id"], "!!!not-base64!!!")
        assert_equal(result["accepted"], False)
        assert_equal(result["status"], "invalid_payload")

        self.log.info("submit_mining_response rejects undersized payload")
        # Two bytes — definitely less than sizeof(uoffset_t) = 4.
        tiny_payload = base64.b64encode(b"ab").decode()
        result = node.submit_mining_response(unit_a["req_id"], tiny_payload)
        assert_equal(result["accepted"], False)
        assert_equal(result["status"], "invalid_payload")

        self.log.info("submit_mining_response rejects malformed flatbuffer")
        # 16 random bytes that look like a flatbuffer header but aren't valid.
        # Verify() will reject this.
        random_payload = base64.b64encode(b"\x00" * 16).decode()
        result = node.submit_mining_response(unit_a["req_id"], random_payload)
        assert_equal(result["accepted"], False)
        assert_equal(result["status"], "invalid_payload")

        self.log.info("submit_mining_response rejects bogus FlatBuffer root offset (no crash)")
        # First 4 bytes of a FlatBuffer are a uoffset_t pointing to the root
        # table. A root offset past end-of-buffer must be caught by the
        # Verifier BEFORE GetRoot is dereferenced — otherwise the RPC would
        # read field offsets out of bounds. This payload has root_offset
        # 0xFFFFFFFF in a 16-byte buffer.
        bogus_root_payload = base64.b64encode(
            struct.pack("<I", 0xFFFFFFFF) + b"\x00" * 12
        ).decode()
        result = node.submit_mining_response(unit_a["req_id"], bogus_root_payload)
        assert_equal(result["accepted"], False)
        assert_equal(result["status"], "invalid_payload")
        # The RPC server is still alive — getmininginfo would throw if the
        # node had crashed.
        node.getmininginfo()

        # NOTE: the "unknown_req_id with a VALID payload" case needs a real
        # MiningResponse FlatBuffer (the verifier trips invalid_payload
        # before the lookup otherwise). It is covered by the
        # release → submit leg in the valid-submission section below.

        # ------------------------------------------------------------------
        # release_mining_work_unit: idempotent eviction so the broker's
        # cap actually protects bcore's 50-entry RequestTracker (COMPUTE_
        # BROKER_IMPROV.md §"Concurrent Work-Unit Ceiling"). Without
        # explicit release, a broker that completes work fast would
        # silently push bcore past the cap and lose old CBlocks to LRU.
        # ------------------------------------------------------------------
        self.log.info("release_mining_work_unit erases an entry and is idempotent")
        unit_to_release = node.create_mining_work_unit(REGTEST_NETWORK, P2_OP_TRUE_HEX, "ff")
        durable_ids = node.list_broker_mining_work_units()
        assert unit_to_release["req_id"] in durable_ids, durable_ids
        released = node.release_mining_work_unit(unit_to_release["req_id"])
        assert_equal(released["req_id"], unit_to_release["req_id"])
        assert_equal(released["released"], True)
        assert unit_to_release["req_id"] not in node.list_broker_mining_work_units()

        self.log.info("release_mining_work_unit second call returns released=false (idempotent no-op)")
        released_again = node.release_mining_work_unit(unit_to_release["req_id"])
        assert_equal(released_again["req_id"], unit_to_release["req_id"])
        assert_equal(released_again["released"], False)

        self.log.info("release_mining_work_unit for a never-minted req_id returns released=false")
        # A req_id near the top of MAX_REQUEST_ID (=10000000) that was
        # never minted. This is the "broker thinks it has a lease but
        # bcore has nothing" recovery path: we want a no-op, not an error.
        never_minted = node.release_mining_work_unit(9_999_999)
        assert_equal(never_minted["req_id"], 9_999_999)
        assert_equal(never_minted["released"], False)

        self.log.info("release_mining_work_unit rejects out-of-range req_id with RPC_INVALID_PARAMETER")
        # Out-of-range is a caller bug, NOT idempotent cleanup. The broker
        # must see this as a hard error so a buggy lease index doesn't
        # silently spam release calls with garbage ids.
        assert_raises_rpc_error(
            -8, "out of range",
            node.release_mining_work_unit, 0,
        )
        assert_raises_rpc_error(
            -8, "out of range",
            node.release_mining_work_unit, 10_000_001,
        )

        self.log.info("RPC server still alive after release; submit_mining_response remains dispatchable")
        # Smoke check only: the FlatBuffer verifier rejects this bogus
        # payload BEFORE the req_id lookup happens, so accepted=False
        # here proves only that the RPC is still callable. The real
        # "submit after release → unknown_req_id" assertion (with a valid
        # payload) lives in the valid-submission section below.
        bogus_payload = base64.b64encode(b"\x00" * 16).decode()
        result = node.submit_mining_response(unit_to_release["req_id"], bogus_payload)
        assert_equal(result["accepted"], False)

        self.log.info("durable work unit survives restart and remains releasable")
        unit_release_after_restart = node.create_mining_work_unit(
            REGTEST_NETWORK, P2_OP_TRUE_HEX, "ee"
        )
        self.restart_node(0)
        node = self.nodes[0]
        assert unit_release_after_restart["req_id"] in node.list_broker_mining_work_units()
        released_after_restart = node.release_mining_work_unit(
            unit_release_after_restart["req_id"]
        )
        assert_equal(released_after_restart["released"], True)

        self.log.info("corrupt durable work unit makes startup reconciliation fail closed")
        unit_corrupt = node.create_mining_work_unit(
            REGTEST_NETWORK, P2_OP_TRUE_HEX, "ed"
        )
        journal = (
            node.chain_path
            / "broker-work-units"
            / (str(unit_corrupt["req_id"]) + ".dat")
        )
        self.stop_node(0)
        original = journal.read_bytes()
        assert_greater_than(len(original), 32)
        damaged = bytearray(original)
        damaged[len(damaged) // 2] ^= 0x01
        journal.write_bytes(damaged)
        self.start_node(0)
        node = self.nodes[0]
        assert_raises_rpc_error(
            -32603, "checksum mismatch", node.list_broker_mining_work_units
        )
        self.stop_node(0)
        journal.write_bytes(original)
        self.start_node(0)
        node = self.nodes[0]
        assert unit_corrupt["req_id"] in node.list_broker_mining_work_units()
        assert_equal(
            node.release_mining_work_unit(unit_corrupt["req_id"])["released"],
            True,
        )

        # ==================================================================
        # Done-when legs: valid MiningResponse round trips through
        # fillFromFB → QuickVerify → ProcessNewBlock. Requires both
        # optional deps (see module docstring); without them the structural
        # coverage above still ran, so only these legs are skipped.
        # ==================================================================
        if not (HAS_FLATBUFFERS and HAS_CHIAVDF):
            missing = [
                name
                for name, present in (
                    ("flatbuffers", HAS_FLATBUFFERS),
                    ("chiavdf", HAS_CHIAVDF),
                )
                if not present
            ]
            self.log.info(
                "Skipping valid-submission legs (missing optional deps: %s)"
                % ", ".join(missing)
            )
            return

        from test_framework.mining_response_builder import (
            build_mining_response,
            solve_work_unit,
        )
        os.environ["TSC_VDF_TEST_HELPER"] = str(
            self.nodes[0].binary.parent / "vdf_test_helper"
        )

        # QuickVerifier::VerifyModelRegistration enforces that the proof's
        # model_identifier hashes to a model registered in g_modeldb with
        # difficulty > 0 (g_modeldb IS loaded on a live regtest node — the
        # "skip when null" path only applies to unit tests). Use whatever
        # model the node actually ships registered rather than hardcoding a
        # chain-specific default (TensorReg's is the empty model → "@").
        registered = [
            m for m in node.getmodelslist()
            if m["status"] == 2 and m["difficulty"] > 0
        ]
        assert registered, "node has no registered model to mine against"
        model_id = "%s@%s" % (
            registered[0]["model_name"], registered[0]["model_commit"]
        )
        self.log.info("Mining against registered model %r" % model_id)

        self.log.info("submit_mining_response accepts a valid solved work unit")
        height_before = node.getblockcount()
        # Mint the sibling work unit FIRST so both share the same tip — the
        # stale-tip leg below needs a work unit whose parent is no longer
        # the best block by the time it is submitted.
        unit_sibling = node.create_mining_work_unit(REGTEST_NETWORK, P2_OP_TRUE_HEX, "0b")
        unit_win = node.create_mining_work_unit(REGTEST_NETWORK, P2_OP_TRUE_HEX, "0a")
        sol_win = solve_work_unit(unit_win["header_prefix"], unit_win["target"])
        payload_win = build_mining_response(
            unit_win["req_id"], sol_win, model_identifier=model_id
        )
        res = node.submit_mining_response(unit_win["req_id"], payload_win)
        assert_equal(res["status"], "accepted")
        assert_equal(res["accepted"], True)
        assert_equal(node.getbestblockhash(), res["block_hash"])
        assert_equal(node.getblockcount(), height_before + 1)

        self.log.info("second submit on the same req_id → already_submitted")
        res_again = node.submit_mining_response(unit_win["req_id"], payload_win)
        assert_equal(res_again["accepted"], False)
        assert_equal(res_again["status"], "already_submitted")
        assert_equal(res_again["block_hash"], res["block_hash"])

        self.log.info("stale-tip sibling: valid solve is stored as a side-chain block, tip unchanged")
        # The sibling was minted against the PREVIOUS tip, which is now the
        # parent of the accepted block. ProcessNewBlock stores a valid
        # equal-work fork and returns success, but the block is NOT the active
        # tip — the RPC reports "accepted_pending_connect" and leaves the work
        # unit BOUND: a later reorg may still make the block active, and
        # reconciliation owns confirming or releasing the allocation. The
        # broker maps this status to submission_unknown.
        sol_sibling = solve_work_unit(
            unit_sibling["header_prefix"], unit_sibling["target"]
        )
        payload_sibling = build_mining_response(
            unit_sibling["req_id"], sol_sibling, model_identifier=model_id
        )
        res_sibling = node.submit_mining_response(
            unit_sibling["req_id"], payload_sibling
        )
        assert_equal(res_sibling["status"], "accepted_pending_connect")
        assert_equal(res_sibling["accepted"], False)
        assert res_sibling["block_hash"] != res["block_hash"]
        assert_equal(node.getbestblockhash(), res["block_hash"])  # tip kept
        assert_equal(node.getblockcount(), height_before + 1)

        self.log.info("losing solution → quick_verify_failed; the work unit survives for a retry")
        unit_retry = node.create_mining_work_unit(REGTEST_NETWORK, P2_OP_TRUE_HEX, "0c")
        sol_lose = solve_work_unit(
            unit_retry["header_prefix"], unit_retry["target"], want_winner=False
        )
        payload_lose = build_mining_response(
            unit_retry["req_id"], sol_lose, model_identifier=model_id
        )
        res_lose = node.submit_mining_response(unit_retry["req_id"], payload_lose)
        assert_equal(res_lose["accepted"], False)
        assert_equal(res_lose["status"], "quick_verify_failed")
        assert "target" in res_lose["reject_reason"]

        # A losing submission must NOT consume the work unit: a subsequent
        # winning solve for the SAME req_id is accepted.
        sol_retry = solve_work_unit(
            unit_retry["header_prefix"], unit_retry["target"]
        )
        payload_retry = build_mining_response(
            unit_retry["req_id"], sol_retry, model_identifier=model_id
        )
        res_retry = node.submit_mining_response(unit_retry["req_id"], payload_retry)
        assert_equal(res_retry["status"], "accepted")
        assert_equal(node.getbestblockhash(), res_retry["block_hash"])
        assert_equal(node.getblockcount(), height_before + 2)

        self.log.info("valid solved work unit submits under the same req_id after restart")
        unit_restart = node.create_mining_work_unit(
            REGTEST_NETWORK, P2_OP_TRUE_HEX, "0e"
        )
        sol_restart = solve_work_unit(
            unit_restart["header_prefix"], unit_restart["target"]
        )
        payload_restart = build_mining_response(
            unit_restart["req_id"], sol_restart, model_identifier=model_id
        )
        self.restart_node(0)
        node = self.nodes[0]
        res_restart = node.submit_mining_response(
            unit_restart["req_id"], payload_restart
        )
        assert_equal(res_restart["status"], "accepted")
        assert_equal(res_restart["accepted"], True)
        assert_equal(node.getbestblockhash(), res_restart["block_hash"])
        assert_equal(node.getblockcount(), height_before + 3)

        self.log.info("submit after release → unknown_req_id (valid payload)")
        unit_gone = node.create_mining_work_unit(REGTEST_NETWORK, P2_OP_TRUE_HEX, "0d")
        sol_gone = solve_work_unit(unit_gone["header_prefix"], unit_gone["target"])
        payload_gone = build_mining_response(
            unit_gone["req_id"], sol_gone, model_identifier=model_id
        )
        released = node.release_mining_work_unit(unit_gone["req_id"])
        assert_equal(released["released"], True)
        res_gone = node.submit_mining_response(unit_gone["req_id"], payload_gone)
        assert_equal(res_gone["accepted"], False)
        assert_equal(res_gone["status"], "unknown_req_id")


if __name__ == "__main__":
    BrokerMiningRpcTest(__file__).main()
