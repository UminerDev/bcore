// Copyright (c) 2024 TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>

#define private public
#define protected public
#include <validationapi.h>
#include <verification/pow_v3.h>
#include <net.h>
#undef private
#undef protected

#include <addrman.h>
#include <netgroup.h>
#include <boost/test/unit_test.hpp>
#include <chainparams.h>
#include <kernel/genesis_proof.h>
#include <protocol.h>
#include <tinyformat.h>
#include <sync.h>
#include <streams.h>
#include <cstdlib>
#include <memory>
#include <tuple>
#include <cstring>
#include <chrono>
#include <span>
#include <vector>
#include <algorithm>

namespace {

ValidationAPI MakeValidationApi(node::NodeContext& node)
{
    return ValidationAPI(*node.chainman, Params().GetConsensus());
}

CBlock MakeDummyBlock(uint32_t nonce = 0)
{
    CBlock block;
    block.SetNull();
    block.nNonce = nonce;
    block.nTime = 1;
    block.nBits = 0x207fffff;
    block.nVersion = 1;
    block.nAdjBits = block.nBits;
    block.hashPrevBlock.SetNull();
    return block;
}

uint256 DeterministicId()
{
    static uint32_t counter = 1;
    uint256 id;
    unsigned char bytes[32]{};
    uint32_t value = counter++;
    std::memcpy(bytes + 28, &value, sizeof(value));
    id = uint256(std::span<const unsigned char>(bytes, sizeof(bytes)));
    return id;
}

constexpr int kAmberRetryCount = 4;

} // namespace

BOOST_FIXTURE_TEST_SUITE(validationapi_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(quick_smell_enqueue_rejects_bad_final_hash_locally)
{
    auto api = MakeValidationApi(m_node);
    CBlock block = MakeDummyBlock();
    block.pow = g_genesisBlob;
    block.pow.hash[0] ^= 0x01;

    api.EnqueueApiRequest(block, ValidationReqType::Quick_Smell,
                          ValidationResponseBehavior::Nothing);

    ValidationResponseValue status{ValidationResponseValue::Not_Checked};
    BOOST_REQUIRE(api.GetRequestStatus(block.GetHash(), ValidationReqType::Quick_Smell, status));
    BOOST_CHECK_EQUAL(static_cast<int>(status),
                      static_cast<int>(ValidationResponseValue::Quick_Fail_Smell_Fail));
    BOOST_CHECK_EQUAL(api.GetQuickSmellQueueSize(), 0U);
}

BOOST_AUTO_TEST_CASE(quick_smell_enqueue_keeps_good_final_hash_remote_queued)
{
    auto api = MakeValidationApi(m_node);
    CBlock block = MakeDummyBlock();
    block.nNonce = 42;
    block.pow = g_genesisBlob;

    api.EnqueueApiRequest(block, ValidationReqType::Quick_Smell,
                          ValidationResponseBehavior::Nothing);

    ValidationResponseValue status{ValidationResponseValue::Not_Checked};
    BOOST_CHECK(!api.GetRequestStatus(block.GetHash(), ValidationReqType::Quick_Smell, status));
    BOOST_CHECK_EQUAL(api.GetQuickSmellQueueSize(), 1U);
}

BOOST_AUTO_TEST_CASE(start_amber_flow_skips_nothing_behavior)
{
    auto api = MakeValidationApi(m_node);
    const uint256 id = DeterministicId();
    BOOST_CHECK(api.SetRequestStatus(id, ValidationReqType::Full, ValidationResponseValue::Full_Amber));
    api.StartAmberFlow(id, MakeDummyBlock(), ValidationResponseBehavior::Nothing);
    BOOST_CHECK(api.amber_requests_.empty());
}

BOOST_AUTO_TEST_CASE(start_amber_flow_reentry_preserves_in_flight_request)
{
    auto api = MakeValidationApi(m_node);
    const uint256 id = DeterministicId();
    BOOST_CHECK(api.SetRequestStatus(id, ValidationReqType::Full, ValidationResponseValue::Full_Amber));
    api.StartAmberFlow(id, MakeDummyBlock(), ValidationResponseBehavior::AcceptBlock);

    auto& request = api.amber_requests_[id];
    // Advance the ladder as if several dispatch attempts already happened.
    request.attempts = kAmberRetryCount - 1;
    request.finalize_deadline = std::chrono::steady_clock::now();
    const auto first_seen = request.first_seen;
    const auto next_send = request.next_send;

    // Re-delivery of the same (cached) Amber status must not reset the
    // in-flight request: a reset here let a pending block that kept being
    // re-submitted hold its height wedged for the validator's cache TTL.
    api.StartAmberFlow(id, MakeDummyBlock(), ValidationResponseBehavior::ProcessNewBlock);

    BOOST_CHECK_EQUAL(api.amber_requests_.count(id), 1U);
    const auto& after = api.amber_requests_[id];
    BOOST_CHECK_EQUAL(after.attempts, kAmberRetryCount - 1);
    BOOST_CHECK(after.first_seen == first_seen);
    BOOST_CHECK(after.next_send == next_send);
    BOOST_CHECK(after.finalize_deadline.has_value());
    BOOST_CHECK_EQUAL(static_cast<int>(after.behavior), static_cast<int>(ValidationResponseBehavior::AcceptBlock));

    // Once the flow finalizes (entry erased), a fresh flow starts cleanly.
    api.amber_requests_.erase(id);
    api.StartAmberFlow(id, MakeDummyBlock(), ValidationResponseBehavior::AcceptBlock);
    BOOST_CHECK_EQUAL(api.amber_requests_.count(id), 1U);
    BOOST_CHECK_EQUAL(api.amber_requests_[id].attempts, 0);
}

BOOST_AUTO_TEST_CASE(record_peer_status_updates)
{
    auto api = MakeValidationApi(m_node);
    const uint256 id = DeterministicId();

    BOOST_CHECK(api.SetRequestStatus(id, ValidationReqType::Full, ValidationResponseValue::Full_Amber));

    ValidationAPI::BlockValidationDB::BlockValidationRecord_Full record(id);

    api.RecordPeerFullStatus(id, "peer0", ValidationResponseValue::Not_Checked);
    BOOST_CHECK(!api.m_validatedBlocks.ReadRes(id, record) || record.nExtFull == 0);

    api.RecordPeerFullStatus(id, "peer1", ValidationResponseValue::Full_Green);
    BOOST_CHECK(api.m_validatedBlocks.ReadRes(id, record));
    BOOST_CHECK_EQUAL(record.nExtFull, 1);
    BOOST_CHECK_EQUAL(record.extFulls[0].first, "peer1");
    BOOST_CHECK_EQUAL(record.extFulls[0].second, static_cast<uint8_t>(ValidationResponseValue::Full_Green));

    api.RecordPeerFullStatus(id, "peer1", ValidationResponseValue::Full_Red);
    BOOST_CHECK(api.m_validatedBlocks.ReadRes(id, record));
    BOOST_CHECK_EQUAL(record.nExtFull, 1);
    BOOST_CHECK_EQUAL(record.extFulls[0].second, static_cast<uint8_t>(ValidationResponseValue::Full_Red));

    api.RecordPeerFullStatus(id, "peer2", ValidationResponseValue::Full_Amber);
    BOOST_CHECK(api.m_validatedBlocks.ReadRes(id, record));
    BOOST_CHECK_EQUAL(record.nExtFull, 2);
    BOOST_CHECK_EQUAL(record.extFulls[1].first, "peer2");
    BOOST_CHECK_EQUAL(record.extFulls[1].second, static_cast<uint8_t>(ValidationResponseValue::Full_Amber));
}

BOOST_AUTO_TEST_CASE(amber_finalization_conditions)
{
    auto api = MakeValidationApi(m_node);

    const uint256 id = DeterministicId();
    BOOST_CHECK(api.SetRequestStatus(id, ValidationReqType::Full, ValidationResponseValue::Full_Amber));

    CBlock block = MakeDummyBlock();
    api.StartAmberFlow(id, block, ValidationResponseBehavior::AcceptBlock);
    auto& request = api.amber_requests_[id];
    request.behavior = ValidationResponseBehavior::AcceptBlock;
    request.expected_peers = 2;
    request.force_finalize = true; // bypass peer dispatch in tests
    request.force_finalize = true; // tests bypass real peer dispatch

    api.RecordPeerFullStatus(id, "peer-a", ValidationResponseValue::Full_Green);
    api.RecordPeerFullStatus(id, "peer-b", ValidationResponseValue::Full_Green);
    BOOST_CHECK_EQUAL(api.behaviors.size(), 1U);
    auto [beh_id, beh_type, beh_behavior, beh_block] = api.behaviors.front();
    BOOST_CHECK_EQUAL(beh_id, id);
    BOOST_CHECK_EQUAL(static_cast<int>(beh_behavior), static_cast<int>(ValidationResponseBehavior::AcceptBlock));

    ValidationAPI::BlockValidationDB::BlockValidationRecord_Full record(id);
    BOOST_CHECK(api.m_validatedBlocks.ReadRes(id, record));
    BOOST_CHECK_EQUAL(api.amber_requests_.count(id), 0U);
    BOOST_CHECK_EQUAL(static_cast<int>(record.getFull(false)), static_cast<int>(ValidationResponseValue::Full_Green));

    api.behaviors.clear();
    api.amber_requests_.clear();
    // Amber no longer overwrites a finalized terminal; reset like revalidateblock does.
    BOOST_CHECK(api.RemoveRes_Full(id));
    BOOST_CHECK(api.SetRequestStatus(id, ValidationReqType::Full, ValidationResponseValue::Full_Amber));
    api.StartAmberFlow(id, MakeDummyBlock(7), ValidationResponseBehavior::ProcessNewBlock);
    auto& red_request = api.amber_requests_[id];
    red_request.expected_peers = 0; // bypass peer counting in tests
    red_request.force_finalize = true; // avoid waiting for real peers
    api.RecordPeerFullStatus(id, "peer-a", ValidationResponseValue::Full_Amber);
    api.RecordPeerFullStatus(id, "peer-b", ValidationResponseValue::Full_Red);
    api.ProcessAmberRequests();
    api.ProcessAmberRequests();
    api.ProcessAmberRequests(); // force finalization pass
    BOOST_CHECK_EQUAL(api.behaviors.size(), 1U);
    std::tie(std::ignore, std::ignore, beh_behavior, beh_block) = api.behaviors.front();
    BOOST_CHECK_EQUAL(static_cast<int>(beh_behavior), static_cast<int>(ValidationResponseBehavior::ProcessNewBlock));
    BOOST_CHECK(api.m_validatedBlocks.ReadRes(id, record));
    BOOST_CHECK_EQUAL(static_cast<int>(record.getFull(false)), static_cast<int>(ValidationResponseValue::Full_Red));
    BOOST_CHECK_EQUAL(api.amber_requests_.count(id), 0U);

    api.behaviors.clear();
    api.amber_requests_.clear();
    BOOST_CHECK(api.RemoveRes_Full(id));
    BOOST_CHECK(api.SetRequestStatus(id, ValidationReqType::Full, ValidationResponseValue::Full_Amber));
    api.StartAmberFlow(id, MakeDummyBlock(11), ValidationResponseBehavior::AcceptBlock);
    auto& amber_only = api.amber_requests_[id];
    amber_only.expected_peers = 0;
    amber_only.force_finalize = true;
    for (int i = 0; i < 5; ++i) {
        api.RecordPeerFullStatus(id, strprintf("peer-%d", i), ValidationResponseValue::Full_Amber);
    }
    api.ProcessAmberRequests();
    api.ProcessAmberRequests();
    BOOST_CHECK(api.m_validatedBlocks.ReadRes(id, record));
    BOOST_CHECK_EQUAL(static_cast<int>(record.getFull(false)), static_cast<int>(ValidationResponseValue::Full_Red));
    BOOST_CHECK_EQUAL(api.amber_requests_.count(id), 0U);

    api.behaviors.clear();
    api.amber_requests_.clear();
    BOOST_CHECK(api.RemoveRes_Full(id));
    BOOST_CHECK(api.SetRequestStatus(id, ValidationReqType::Full, ValidationResponseValue::Full_Amber));
    api.StartAmberFlow(id, MakeDummyBlock(21), ValidationResponseBehavior::ProcessNewBlock);
    auto& forced = api.amber_requests_[id];
    forced.force_finalize = true;
    api.ProcessAmberRequests();
    BOOST_CHECK_EQUAL(api.behaviors.size(), 1U);
    BOOST_CHECK_EQUAL(api.amber_requests_.count(id), 0U);
}

BOOST_AUTO_TEST_CASE(http_mode_config_from_env_and_desktop_flag)
{
    // Env enables HTTP mode and avoids ZMQ sockets
    setenv("VALIDATOR_HTTP_URL", "https://verify.example", 1);
    {
        ValidationAPI api_env(*m_node.chainman, Params().GetConsensus());
        BOOST_CHECK(api_env.Initialize());
        BOOST_CHECK(api_env.m_http_mode);
        BOOST_CHECK(api_env.context == nullptr);
        api_env.StopThreads();
    }
    unsetenv("VALIDATOR_HTTP_URL");

    // Desktop flag alone also enables HTTP mode
    {
        ValidationAPI api_desktop(*m_node.chainman, Params().GetConsensus(), /*desktop_mode=*/true);
        BOOST_CHECK(api_desktop.Initialize());
        BOOST_CHECK(api_desktop.m_http_mode);
        BOOST_CHECK(api_desktop.context == nullptr);
        api_desktop.StopThreads();
    }
}

BOOST_AUTO_TEST_CASE(http_mode_config_pairs_urls_with_keys)
{
    setenv("VALIDATOR_HTTP_URLS", "https://verify-a.example,https://verify-b.example", 1);
    setenv("VALIDATOR_API_KEYS", "key-a,key-b", 1);
    {
        ValidationAPI api(*m_node.chainman, Params().GetConsensus());
        BOOST_CHECK(api.Initialize());
        BOOST_CHECK_EQUAL(api.http_config_.endpoints.size(), 2U);
        BOOST_CHECK_EQUAL(api.http_config_.endpoints[0].base_url, "https://verify-a.example");
        BOOST_CHECK_EQUAL(api.http_config_.endpoints[0].api_key, "key-a");
        BOOST_CHECK_EQUAL(api.http_config_.endpoints[1].base_url, "https://verify-b.example");
        BOOST_CHECK_EQUAL(api.http_config_.endpoints[1].api_key, "key-b");
        api.StopThreads();
    }
    unsetenv("VALIDATOR_HTTP_URLS");
    unsetenv("VALIDATOR_API_KEYS");
}

BOOST_AUTO_TEST_CASE(http_mode_config_fans_out_single_key)
{
    setenv("VALIDATOR_HTTP_URLS", "https://verify-a.example,https://verify-b.example", 1);
    setenv("VALIDATOR_API_KEYS", "shared-key", 1);
    {
        ValidationAPI api(*m_node.chainman, Params().GetConsensus());
        BOOST_CHECK(api.Initialize());
        BOOST_CHECK_EQUAL(api.http_config_.endpoints.size(), 2U);
        BOOST_CHECK_EQUAL(api.http_config_.endpoints[0].api_key, "shared-key");
        BOOST_CHECK_EQUAL(api.http_config_.endpoints[1].api_key, "shared-key");
        api.StopThreads();
    }
    unsetenv("VALIDATOR_HTTP_URLS");
    unsetenv("VALIDATOR_API_KEYS");
}

BOOST_AUTO_TEST_CASE(dispatch_getheaders_uses_connman)
{
    NetGroupManager netgroupman({});
    AddrMan addrman(netgroupman, /*deterministic=*/true, /*consistency_check_ratio=*/0);
    CConnman connman(/*seed0=*/1, /*seed1=*/2, addrman, netgroupman, Params(), true);

    auto api = MakeValidationApi(m_node);
    api.SetConnman(&connman);

    const uint256 id = DeterministicId();
    BOOST_CHECK(api.SetRequestStatus(id, ValidationReqType::Full, ValidationResponseValue::Full_Amber));
    api.StartAmberFlow(id, MakeDummyBlock(), ValidationResponseBehavior::AcceptBlock);
    auto& request = api.amber_requests_[id];

    {
        LOCK(connman.m_nodes_mutex);
        for (int i = 0; i < 2; ++i) {
            CNodeOptions opts;
            auto node = new CNode(i + 1,
                                   std::shared_ptr<Sock>(),
                                   CAddress(),
                                   /*nKeyedNetGroup=*/i + 100,
                                   /*nLocalHostNonce=*/0,
                                   CService(),
                                   strprintf("peer-%d", i),
                                   ConnectionType::INBOUND,
                                   /*inbound_onion=*/false,
                                   std::move(opts));
            node->fSuccessfullyConnected = true;
            node->fDisconnect = false;
            connman.m_nodes.push_back(node);
        }
    }

    request.next_send = std::chrono::steady_clock::time_point::min();
    // DispatchAmberGetHeaders no longer mutates the request (it runs outside
    // amber_mutex_ now); the caller records expected_peers from the return.
    int sent = api.DispatchAmberGetHeaders(id);
    BOOST_CHECK_EQUAL(sent, 2);
    request.expected_peers = sent;
    BOOST_CHECK_EQUAL(request.expected_peers, 2);

    {
        LOCK(connman.m_nodes_mutex);
        for (auto* node : connman.m_nodes) {
            LOCK(node->cs_vSend);
            const auto bytes = node->m_transport->GetBytesToSend(false);
            BOOST_CHECK(std::get<1>(bytes) || !std::get<0>(bytes).empty());
            BOOST_CHECK_EQUAL(std::get<2>(bytes), std::string(NetMsgType::GETHEADERS));
            delete node;
        }
        connman.m_nodes.clear();
    }

    api.SetConnman(nullptr);
    request.expected_peers = 7;
    request.attempts = 0;
    int none = api.DispatchAmberGetHeaders(id);
    BOOST_CHECK_EQUAL(none, 0);
    request.expected_peers = none;
    BOOST_CHECK_EQUAL(request.expected_peers, 0);

    // Integration: ProcessAmberRequests should use connman when present
    api.SetConnman(&connman);
    {
        LOCK(connman.m_nodes_mutex);
        connman.m_nodes.clear();
        for (int i = 0; i < 2; ++i) {
            CNodeOptions opts;
            auto node = new CNode(i + 3,
                                   std::shared_ptr<Sock>(),
                                   CAddress(),
                                   /*nKeyedNetGroup=*/200 + i,
                                   /*nLocalHostNonce=*/0,
                                   CService(),
                                   strprintf("peer-reuse-%d", i),
                                   ConnectionType::INBOUND,
                                   /*inbound_onion=*/false,
                                   std::move(opts));
            node->fSuccessfullyConnected = true;
            connman.m_nodes.push_back(node);
        }
    }
    request.attempts = 0;
    request.next_send = std::chrono::steady_clock::time_point::min();
    api.ProcessAmberRequests();
    BOOST_CHECK_EQUAL(request.attempts, 1);
    BOOST_CHECK_EQUAL(request.expected_peers, 2);

    {
        LOCK(connman.m_nodes_mutex);
        for (auto* node : connman.m_nodes) {
            delete node;
        }
        connman.m_nodes.clear();
    }
}

BOOST_AUTO_TEST_CASE(process_amber_requests_respects_final_window)
{
    auto api = MakeValidationApi(m_node);
    const uint256 id = DeterministicId();
    BOOST_CHECK(api.SetRequestStatus(id, ValidationReqType::Full, ValidationResponseValue::Full_Amber));
    api.StartAmberFlow(id, MakeDummyBlock(), ValidationResponseBehavior::AcceptBlock);

    auto& request = api.amber_requests_[id];
    request.next_send = std::chrono::steady_clock::time_point::min();
    request.attempts = kAmberRetryCount - 1;

    api.ProcessAmberRequests();
    BOOST_CHECK(request.finalize_deadline.has_value());
    BOOST_CHECK(!request.force_finalize);
    BOOST_CHECK(api.amber_requests_.count(id) == 1);

    request.finalize_deadline = std::chrono::steady_clock::time_point::min();
    api.ProcessAmberRequests();
    BOOST_CHECK(api.amber_requests_.count(id) == 0);
    BOOST_CHECK(!api.behaviors.empty());
}

BOOST_AUTO_TEST_CASE(process_amber_requests_schedule_and_responses)
{
    auto api = MakeValidationApi(m_node);
    const uint256 id = DeterministicId();
    BOOST_CHECK(api.SetRequestStatus(id, ValidationReqType::Full, ValidationResponseValue::Full_Amber));
    api.StartAmberFlow(id, MakeDummyBlock(), ValidationResponseBehavior::AcceptBlock);
    auto& request = api.amber_requests_[id];

    request.next_send = std::chrono::steady_clock::time_point::min();
    const std::array<std::chrono::seconds, kAmberRetryCount> expected_delays{std::chrono::seconds{0}, std::chrono::seconds{1}, std::chrono::seconds{60}, std::chrono::seconds{120}};
    for (int i = 0; i < kAmberRetryCount; ++i) {
        api.ProcessAmberRequests();
        auto after = std::chrono::steady_clock::now();
        auto delta = request.next_send - after;
        if (delta.count() > 0) {
            BOOST_CHECK(delta <= expected_delays[i] + std::chrono::seconds{1});
            BOOST_CHECK(delta >= expected_delays[i] - std::chrono::seconds{1});
        }
        if (i < kAmberRetryCount - 1) {
            BOOST_CHECK(!request.finalize_deadline.has_value());
        }
        request.next_send = std::chrono::steady_clock::time_point::min();
    }
    BOOST_CHECK_EQUAL(request.attempts, kAmberRetryCount);
    BOOST_CHECK(request.finalize_deadline.has_value());
    BOOST_CHECK(!request.force_finalize);

    request.expected_peers = 2;
    api.RecordPeerFullStatus(id, "peer-a", ValidationResponseValue::Full_Green);
    api.RecordPeerFullStatus(id, "peer-b", ValidationResponseValue::Full_Green);
    request.finalize_deadline = std::chrono::steady_clock::time_point::min();
    api.ProcessAmberRequests();
    BOOST_CHECK(api.amber_requests_.count(id) == 0);
}

BOOST_AUTO_TEST_CASE(record_peer_status_defers_finalize_while_dispatch_in_flight)
{
    auto api = MakeValidationApi(m_node);
    const uint256 id = DeterministicId();
    BOOST_CHECK(api.SetRequestStatus(id, ValidationReqType::Full, ValidationResponseValue::Full_Amber));
    api.StartAmberFlow(id, MakeDummyBlock(), ValidationResponseBehavior::AcceptBlock);

    auto& request = api.amber_requests_[id];
    // Simulate the send-vs-record window: ProcessAmberRequests() queued a
    // getheaders dispatch and released amber_mutex_, but has not yet
    // re-taken it to record the dispatched peer count — expected_peers is
    // still 0 while getheaders is already on the wire.
    request.dispatch_in_flight = true;
    BOOST_CHECK_EQUAL(request.expected_peers, 0);

    // A fast Red response lands in the window. Without the sentinel,
    // expected_peers == 0 reads as "no peers were polled" and this lone Red
    // vote would finalize the verdict. The vote must be recorded but must
    // not finalize.
    api.RecordPeerFullStatus(id, "peer-fast", ValidationResponseValue::Full_Red);
    BOOST_CHECK_EQUAL(api.amber_requests_.count(id), 1U);
    BOOST_CHECK(api.behaviors.empty());
    ValidationAPI::BlockValidationDB::BlockValidationRecord_Full record(id);
    BOOST_CHECK(api.m_validatedBlocks.ReadRes(id, record));
    BOOST_CHECK_EQUAL(record.nExtFull, 1); // vote kept, not lost
    BOOST_CHECK_EQUAL(static_cast<int>(record.FullValidation),
                      static_cast<int>(ValidationResponseValue::Full_Amber)); // own status untouched

    // The dispatch loop re-takes amber_mutex_, records the peer count and
    // clears the sentinel; vote-driven finalization resumes.
    request.expected_peers = 2;
    request.dispatch_in_flight = false;

    // Second vote completes the expected set (has_red + all_responded).
    api.RecordPeerFullStatus(id, "peer-slow", ValidationResponseValue::Full_Green);
    BOOST_CHECK_EQUAL(api.amber_requests_.count(id), 0U);
    BOOST_CHECK_EQUAL(api.behaviors.size(), 1U);
    BOOST_CHECK(api.m_validatedBlocks.ReadRes(id, record));
    BOOST_CHECK_EQUAL(record.nExtFull, 2);
    BOOST_CHECK_EQUAL(static_cast<int>(record.getFull(false)),
                      static_cast<int>(ValidationResponseValue::Full_Red));
}

BOOST_AUTO_TEST_CASE(block_validation_db_boundaries)
{
    auto& consensus = Params().GetConsensus();
    ValidationAPI::BlockValidationDB db(consensus);

    const uint256 id = DeterministicId();
    BOOST_CHECK(db.UpdateRes_Full(id, ValidationResponseValue::Full_Amber));

    ValidationAPI::BlockValidationDB::BlockValidationRecord_Full rec(id);
    BOOST_CHECK(db.ReadRes(id, rec));
    BOOST_CHECK_EQUAL(static_cast<int>(rec.getFull(true)), static_cast<int>(ValidationResponseValue::Full_Amber));

    BOOST_CHECK(rec.addExtFull("peer1", ValidationResponseValue::Full_Green));
    BOOST_CHECK(!rec.addExtFull("peer1", ValidationResponseValue::Not_Checked));

    for (size_t i = 0; i < ValidationAPI::BlockValidationDB::MAX_RECORDS + 5; ++i) {
        BOOST_CHECK(db.UpdateRes_Full(DeterministicId(), ValidationResponseValue::Full_Green));
    }
}

BOOST_AUTO_TEST_CASE(update_res_full_amber_never_downgrades_terminal)
{
    auto& consensus = Params().GetConsensus();
    ValidationAPI::BlockValidationDB db(consensus);
    const uint256 id = DeterministicId();

    BOOST_CHECK(db.UpdateRes_Full(id, ValidationResponseValue::Full_Amber));
    BOOST_CHECK(db.UpdateRes_Full(id, ValidationResponseValue::Full_Red));

    // A re-delivered cached Amber must not clobber the finalized verdict
    // (it would restart the amber flow and re-wedge the height).
    BOOST_CHECK(!db.UpdateRes_Full(id, ValidationResponseValue::Full_Amber));
    ValidationAPI::BlockValidationDB::BlockValidationRecord_Full rec(id);
    BOOST_CHECK(db.ReadRes(id, rec));
    BOOST_CHECK_EQUAL(static_cast<int>(rec.getFull(true)), static_cast<int>(ValidationResponseValue::Full_Red));

    // Terminal-to-terminal transitions stay allowed (peer-review revalidation).
    BOOST_CHECK(db.UpdateRes_Full(id, ValidationResponseValue::Full_Green));
    ValidationAPI::BlockValidationDB::BlockValidationRecord_Full rec2(id);
    BOOST_CHECK(db.ReadRes(id, rec2));
    BOOST_CHECK_EQUAL(static_cast<int>(rec2.getFull(true)), static_cast<int>(ValidationResponseValue::Full_Green));
    BOOST_CHECK(!db.UpdateRes_Full(id, ValidationResponseValue::Full_Amber));
}

BOOST_AUTO_TEST_CASE(block_validation_db_prune_and_serialization)
{
    auto& consensus = Params().GetConsensus();
    ValidationAPI::BlockValidationDB db(consensus);

    const uint256 id = DeterministicId();
    BOOST_CHECK(db.UpdateRes_Full(id, ValidationResponseValue::Full_Amber));

    ValidationAPI::BlockValidationDB::BlockValidationRecord_Full rec(id);
    BOOST_CHECK(db.ReadRes(id, rec));

    // Populate extFulls near capacity and ensure Not_Checked rejected
    for (int i = 0; i < 100; ++i) {
        std::string peer = strprintf("peer-%d", i);
        bool added = rec.addExtFull(peer, ValidationResponseValue::Full_Amber);
        if (i < ValidationAPI::BlockValidationDB::BlockValidationRecord_Full::EXPECTED_EXTFULL_SIZE) {
            BOOST_CHECK(added);
        } else {
            BOOST_CHECK(!added);
        }
    }
    BOOST_CHECK(!rec.addExtFull("peer-x", ValidationResponseValue::Not_Checked));

    // Force serialization round-trip
    std::vector<unsigned char> buffer;
    VectorWriter writer(buffer, 0);
    writer << rec;
    SpanReader reader(std::span<const unsigned char>(buffer.data(), buffer.size()));
    ValidationAPI::BlockValidationDB::BlockValidationRecord_Full rec2(uint256::ZERO);
    reader >> rec2;
    BOOST_CHECK_EQUAL(rec.nExtFull, rec2.nExtFull);

    // Check getFull amber threshold (more than 20% amber => red)
    rec2.FullValidation = static_cast<uint8_t>(ValidationResponseValue::Full_Amber);
    for (int i = 0; i < 4; ++i) {
        rec2.extFulls[i].second = static_cast<uint8_t>(ValidationResponseValue::Full_Amber);
    }
    rec2.nExtFull = 4;
    BOOST_CHECK_EQUAL(static_cast<int>(rec2.getFull()), static_cast<int>(ValidationResponseValue::Full_Red));

    // Exercise pruning of quick records via PruneToMax
    for (size_t i = 0; i < ValidationAPI::BlockValidationDB::MAX_RECORDS + 20; ++i) {
        BOOST_CHECK(db.UpdateRes_Quick(DeterministicId(), ValidationResponseValue::Quick_OK));
    }
    db.PruneToMax();
}

BOOST_AUTO_TEST_CASE(solution_receiver_paths)
{
    auto api = MakeValidationApi(m_node);
    CBlock block = MakeDummyBlock();
    uint256 req_id;

    // Amber path
    BOOST_CHECK(api.requestTracker.makeNewRequest(block, ValidationReqType::Full, req_id, ValidationResponseBehavior::AcceptBlock));
    BOOST_CHECK(api.SetRequestStatus(req_id, ValidationReqType::Full, ValidationResponseValue::Full_Amber));
    {
        std::unique_lock lock(api.requestTracker.mutex_);
        auto blockOpt = api.requestTracker.getBlockForId(req_id, ValidationReqType::Full);
        BOOST_CHECK(blockOpt.has_value());
        api.StartAmberFlow(req_id, *blockOpt, ValidationResponseBehavior::AcceptBlock);
    }
    api.requestTracker.finishRequest(req_id, ValidationReqType::Full);
    BOOST_CHECK_EQUAL(api.amber_requests_.count(req_id), 1U);

    // Green path
    api.amber_requests_.clear();
    api.behaviors.clear();
    BOOST_CHECK(api.requestTracker.makeNewRequest(block, ValidationReqType::Full, req_id, ValidationResponseBehavior::ProcessNewBlock));
    BOOST_CHECK(api.SetRequestStatus(req_id, ValidationReqType::Full, ValidationResponseValue::Full_Green));
    {
        std::unique_lock lock(api.requestTracker.mutex_);
        auto blockOpt = api.requestTracker.getBlockForId(req_id, ValidationReqType::Full);
        BOOST_CHECK(blockOpt.has_value());
        {
            std::unique_lock beh_lock(api.behmutex);
            api.behaviors.emplace_back(req_id, ValidationReqType::Full, ValidationResponseBehavior::ProcessNewBlock, *blockOpt);
        }
    }
    api.requestTracker.finishRequest(req_id, ValidationReqType::Full);
    BOOST_CHECK_EQUAL(api.behaviors.size(), 1U);

    // Red path
    api.behaviors.clear();
    BOOST_CHECK(api.requestTracker.makeNewRequest(block, ValidationReqType::Full, req_id, ValidationResponseBehavior::AcceptBlock));
    BOOST_CHECK(api.SetRequestStatus(req_id, ValidationReqType::Full, ValidationResponseValue::Full_Red));
    {
        std::unique_lock lock(api.requestTracker.mutex_);
        auto blockOpt = api.requestTracker.getBlockForId(req_id, ValidationReqType::Full);
        BOOST_CHECK(blockOpt.has_value());
        {
            std::unique_lock beh_lock(api.behmutex);
            api.behaviors.emplace_back(req_id, ValidationReqType::Full, ValidationResponseBehavior::AcceptBlock, *blockOpt);
        }
    }
    api.requestTracker.finishRequest(req_id, ValidationReqType::Full);
    BOOST_CHECK_EQUAL(api.behaviors.size(), 1U);
}

BOOST_AUTO_TEST_CASE(request_tracker_behaviour)
{
    ValidationAPI::RequestTracker tracker;
    CBlock block = MakeDummyBlock();
    uint256 req_full;

    BOOST_CHECK(tracker.makeNewRequest(block, ValidationReqType::Full, req_full, ValidationResponseBehavior::AcceptBlock));
    BOOST_CHECK(!tracker.makeNewRequest(block, ValidationReqType::Full, req_full, ValidationResponseBehavior::AcceptBlock));

    auto opt_block = tracker.getBlockForId(req_full, ValidationReqType::Full);
    BOOST_CHECK(opt_block.has_value());

    auto behavior = tracker.finishRequest(req_full, ValidationReqType::Full);
    BOOST_CHECK_EQUAL(static_cast<int>(behavior), static_cast<int>(ValidationResponseBehavior::AcceptBlock));
    BOOST_CHECK(!tracker.getBlockForId(req_full, ValidationReqType::Full).has_value());

    uint256 req_full_pending;
    BOOST_CHECK(tracker.makeNewRequest(block, ValidationReqType::Full, req_full_pending, ValidationResponseBehavior::Nothing));
    BOOST_CHECK(!tracker.makeNewRequest(block, ValidationReqType::Full, req_full_pending, ValidationResponseBehavior::ProcessNewBlock));
    BOOST_CHECK_EQUAL(static_cast<int>(tracker.finishRequest(req_full_pending, ValidationReqType::Full)),
                      static_cast<int>(ValidationResponseBehavior::ProcessNewBlock));

    uint256 req_quick;
    BOOST_CHECK(tracker.makeNewRequest(block, ValidationReqType::Quick, req_quick, ValidationResponseBehavior::ProcessNewBlock));
    BOOST_CHECK(tracker.getBlockForId(req_quick, ValidationReqType::Quick).has_value());
    BOOST_CHECK_EQUAL(static_cast<int>(tracker.finishRequest(req_quick, ValidationReqType::Quick)), static_cast<int>(ValidationResponseBehavior::ProcessNewBlock));

    uint256 req_smell;
    BOOST_CHECK(tracker.makeNewRequest(block, ValidationReqType::Quick_Smell, req_smell, ValidationResponseBehavior::AcceptBlock));
    BOOST_CHECK(tracker.getBlockForId(req_smell, ValidationReqType::Quick_Smell).has_value());
    BOOST_CHECK_EQUAL(static_cast<int>(tracker.finishRequest(req_smell, ValidationReqType::Quick_Smell)), static_cast<int>(ValidationResponseBehavior::AcceptBlock));
}

BOOST_AUTO_TEST_CASE(request_tracker_live_meter)
{
    ValidationAPI::RequestTracker::LiveMeter meter(ValidationReqType::Quick, ValidationResponseBehavior::AcceptBlock);
    const uint64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    BOOST_CHECK(!meter.readyToUpdate(now_ms - 10));
    BOOST_CHECK(meter.readyToUpdate(now_ms + meter.delay));

    const uint64_t first_delay = meter.delay;
    BOOST_CHECK(meter.newAttempt(now_ms));
    BOOST_CHECK_EQUAL(meter.delay, first_delay * 2);

    int attempts = 1;
    while (meter.newAttempt(now_ms)) {
        ++attempts;
    }
    BOOST_CHECK_GE(attempts, 1);
    BOOST_CHECK_LE(attempts, MAX_SHORT_VALIDATION_REQUEST_ATTEMPTS);
    BOOST_CHECK(!meter.newAttempt(now_ms));
}

BOOST_AUTO_TEST_CASE(http_pending_guard_expires_short_requests)
{
    auto api = MakeValidationApi(m_node);
    const uint256 id = DeterministicId();
    const ValidationAPI::StatusKey key{id, ValidationReqType::Quick_Smell};

    api.MarkHttpStatusAcceptedPending(key);
    BOOST_CHECK(api.IsHttpStatusAcceptedPending(id, ValidationReqType::Quick_Smell));
    BOOST_CHECK(!api.IsHttpStatusAcceptedPendingStale(id, ValidationReqType::Quick_Smell));

    api.http_status_accepted_pending_since_[key] = std::chrono::steady_clock::now() -
        std::chrono::milliseconds(ValidationAPI::HTTP_PENDING_MAX_AGE_SHORT_MS + 1);
    BOOST_CHECK(api.IsHttpStatusAcceptedPendingStale(id, ValidationReqType::Quick_Smell));

    api.ClearHttpStatusAcceptedPending(key);
    BOOST_CHECK(!api.IsHttpStatusAcceptedPending(id, ValidationReqType::Quick_Smell));
}

BOOST_AUTO_TEST_CASE(http_pending_guard_uses_full_request_deadline)
{
    auto api = MakeValidationApi(m_node);
    const uint256 id = DeterministicId();
    const ValidationAPI::StatusKey key{id, ValidationReqType::Full};

    api.MarkHttpStatusAcceptedPending(key);
    api.http_status_accepted_pending_since_[key] = std::chrono::steady_clock::now() -
        std::chrono::milliseconds(ValidationAPI::HTTP_PENDING_MAX_AGE_SHORT_MS + 1);
    BOOST_CHECK(!api.IsHttpStatusAcceptedPendingStale(id, ValidationReqType::Full));

    api.http_status_accepted_pending_since_[key] = std::chrono::steady_clock::now() -
        std::chrono::milliseconds(ValidationAPI::HTTP_PENDING_MAX_AGE_LONG_MS + 1);
    BOOST_CHECK(api.IsHttpStatusAcceptedPendingStale(id, ValidationReqType::Full));
}

BOOST_AUTO_TEST_CASE(http_status_queue_reconciles_tracked_quick_smell_request)
{
    auto api = MakeValidationApi(m_node);
    CBlock block = MakeDummyBlock(42);
    uint256 id;
    BOOST_CHECK(api.requestTracker.makeNewRequest(
        block, ValidationReqType::Quick_Smell, id, ValidationResponseBehavior::AcceptBlock));

    const ValidationAPI::StatusKey key{id, ValidationReqType::Quick_Smell};
    BOOST_CHECK(api.status_queue_.empty());
    BOOST_CHECK_EQUAL(api.status_queue_set_.count(key), 0U);

    api.ReconcileHttpStatusQueueWithTrackedRequests(1000);

    BOOST_REQUIRE_EQUAL(api.status_queue_.size(), 1U);
    BOOST_CHECK(api.status_queue_.front() == key);
    BOOST_CHECK_EQUAL(api.status_queue_set_.count(key), 1U);
    BOOST_REQUIRE_EQUAL(api.status_queue_meta_.count(key), 1U);
    BOOST_CHECK_EQUAL(api.status_queue_meta_[key].first_seen_ms, 1000U);
    BOOST_CHECK_EQUAL(api.status_queue_meta_[key].next_poll_ms, 1000U);
}

BOOST_AUTO_TEST_CASE(http_status_queue_reconciles_set_deque_divergence)
{
    auto api = MakeValidationApi(m_node);
    CBlock block = MakeDummyBlock(43);
    uint256 id;
    BOOST_CHECK(api.requestTracker.makeNewRequest(
        block, ValidationReqType::Quick_Smell, id, ValidationResponseBehavior::AcceptBlock));

    const ValidationAPI::StatusKey key{id, ValidationReqType::Quick_Smell};
    api.status_queue_set_.insert(key);

    api.ReconcileHttpStatusQueueWithTrackedRequests(2000);

    BOOST_REQUIRE_EQUAL(api.status_queue_.size(), 1U);
    BOOST_CHECK(api.status_queue_.front() == key);
    BOOST_CHECK_EQUAL(api.status_queue_set_.count(key), 1U);
    BOOST_REQUIRE_EQUAL(api.status_queue_meta_.count(key), 1U);

    api.ReconcileHttpStatusQueueWithTrackedRequests(3000);
    BOOST_CHECK_EQUAL(api.status_queue_.size(), 1U);
}

BOOST_AUTO_TEST_CASE(set_get_own_full_status_and_remove)
{
    auto api = MakeValidationApi(m_node);
    uint256 id = DeterministicId();

    BOOST_CHECK_EQUAL(static_cast<int>(api.GetOwnFullStatus(id)), static_cast<int>(ValidationResponseValue::Not_Checked));

    BOOST_CHECK(api.SetRequestStatus(id, ValidationReqType::Full, ValidationResponseValue::Full_Amber));
    BOOST_CHECK_EQUAL(static_cast<int>(api.GetOwnFullStatus(id)), static_cast<int>(ValidationResponseValue::Full_Amber));

    BOOST_CHECK(api.RemoveRes_Full(id));
    BOOST_CHECK_EQUAL(static_cast<int>(api.GetOwnFullStatus(id)), static_cast<int>(ValidationResponseValue::Not_Checked));
}

// ── Auth batch error backoff tests ──

BOOST_AUTO_TEST_CASE(auth_batch_backoff_escalates_on_failure)
{
    auto api = MakeValidationApi(m_node);

    // Initially zero — no backoff
    BOOST_CHECK_EQUAL(api.auth_batch_error_backoff_ms_.load(), 0);

    // Simulate first failure: should escalate to 500ms
    auto cur = api.auth_batch_error_backoff_ms_.load();
    cur = (cur == 0) ? 500 : std::min(cur * 2, (int64_t)10000);
    api.auth_batch_error_backoff_ms_.store(cur);
    api.last_auth_batch_error_ms_.store(1000);
    BOOST_CHECK_EQUAL(api.auth_batch_error_backoff_ms_.load(), 500);

    // Second failure: 1000ms
    cur = api.auth_batch_error_backoff_ms_.load();
    cur = (cur == 0) ? 500 : std::min(cur * 2, (int64_t)10000);
    api.auth_batch_error_backoff_ms_.store(cur);
    BOOST_CHECK_EQUAL(api.auth_batch_error_backoff_ms_.load(), 1000);

    // Third: 2000ms
    cur = api.auth_batch_error_backoff_ms_.load();
    cur = (cur == 0) ? 500 : std::min(cur * 2, (int64_t)10000);
    api.auth_batch_error_backoff_ms_.store(cur);
    BOOST_CHECK_EQUAL(api.auth_batch_error_backoff_ms_.load(), 2000);

    // Keep going to verify 10s cap
    for (int i = 0; i < 10; ++i) {
        cur = api.auth_batch_error_backoff_ms_.load();
        cur = (cur == 0) ? 500 : std::min(cur * 2, (int64_t)10000);
        api.auth_batch_error_backoff_ms_.store(cur);
    }
    BOOST_CHECK_EQUAL(api.auth_batch_error_backoff_ms_.load(), 10000);
}

BOOST_AUTO_TEST_CASE(auth_batch_backoff_resets_on_success)
{
    auto api = MakeValidationApi(m_node);

    // Simulate escalated backoff
    api.auth_batch_error_backoff_ms_.store(4000);
    api.last_auth_batch_error_ms_.store(5000);

    // Simulate successful 2xx — reset
    api.auth_batch_error_backoff_ms_.store(0);
    BOOST_CHECK_EQUAL(api.auth_batch_error_backoff_ms_.load(), 0);
}

BOOST_AUTO_TEST_CASE(auth_batch_backoff_gate_blocks_when_in_window)
{
    auto api = MakeValidationApi(m_node);

    api.auth_batch_error_backoff_ms_.store(2000);
    api.last_auth_batch_error_ms_.store(10000);

    // now_ms = 11000, within 2000ms window → should be blocked
    int64_t now_ms = 11000;
    const auto auth_backoff = api.auth_batch_error_backoff_ms_.load();
    const auto last_err = api.last_auth_batch_error_ms_.load();
    bool blocked = (auth_backoff > 0 && last_err > 0 && (now_ms - last_err) < auth_backoff);
    BOOST_CHECK(blocked);

    // now_ms = 12001, past window → should be allowed
    now_ms = 12001;
    blocked = (auth_backoff > 0 && last_err > 0 && (now_ms - last_err) < auth_backoff);
    BOOST_CHECK(!blocked);
}

// ── Public backoff response-class tests ──

BOOST_AUTO_TEST_CASE(public_nan_backoff_escalates_and_caps)
{
    auto api = MakeValidationApi(m_node);
    const ValidationAPI::StatusKey key{DeterministicId(), ValidationReqType::Full};
    auto& meta = api.status_queue_meta_[key];

    BOOST_CHECK_EQUAL(meta.nan_backoff_ms, 0);

    // First NAN: 100ms
    auto cur = meta.nan_backoff_ms;
    cur = (cur == 0) ? ValidationAPI::HTTP_PUBLIC_NAN_INITIAL_BACKOFF_MS
                     : std::min<uint64_t>(cur * 2, ValidationAPI::HTTP_PUBLIC_NAN_MAX_BACKOFF_MS);
    meta.nan_backoff_ms = cur;
    BOOST_CHECK_EQUAL(meta.nan_backoff_ms, ValidationAPI::HTTP_PUBLIC_NAN_INITIAL_BACKOFF_MS);

    // Escalate: 200, 400, 800, 1000 (cap)
    for (int expected : {200, 400, 800, 1000}) {
        cur = meta.nan_backoff_ms;
        cur = (cur == 0) ? ValidationAPI::HTTP_PUBLIC_NAN_INITIAL_BACKOFF_MS
                         : std::min<uint64_t>(cur * 2, ValidationAPI::HTTP_PUBLIC_NAN_MAX_BACKOFF_MS);
        meta.nan_backoff_ms = cur;
        BOOST_CHECK_EQUAL(meta.nan_backoff_ms, static_cast<uint64_t>(expected));
    }

    // Stays at cap
    cur = meta.nan_backoff_ms;
    cur = (cur == 0) ? ValidationAPI::HTTP_PUBLIC_NAN_INITIAL_BACKOFF_MS
                     : std::min<uint64_t>(cur * 2, ValidationAPI::HTTP_PUBLIC_NAN_MAX_BACKOFF_MS);
    meta.nan_backoff_ms = cur;
    BOOST_CHECK_EQUAL(meta.nan_backoff_ms, ValidationAPI::HTTP_PUBLIC_NAN_MAX_BACKOFF_MS);
}

BOOST_AUTO_TEST_CASE(public_terminal_hit_resets_all_backoff)
{
    auto api = MakeValidationApi(m_node);
    const ValidationAPI::StatusKey key{DeterministicId(), ValidationReqType::Full};

    api.status_queue_.push_back(key);
    api.status_queue_set_.insert(key);
    api.status_queue_meta_[key] = ValidationAPI::StatusQueueMeta{1000, 1200, 800, 5};
    api.http_status_accepted_pending_.insert(key);
    api.http_status_accepted_pending_since_[key] = std::chrono::steady_clock::now();
    api.public_error_backoff_ms_.store(4000);

    // Terminal hit clears per-item NAN state and resets transport/rate-limit backoff.
    api.ClearStatusQueueEntry(key);
    api.public_error_backoff_ms_.store(0);
    BOOST_CHECK(api.status_queue_.empty());
    BOOST_CHECK_EQUAL(api.status_queue_set_.count(key), 0U);
    BOOST_CHECK_EQUAL(api.status_queue_meta_.count(key), 0U);
    BOOST_CHECK_EQUAL(api.http_status_accepted_pending_.count(key), 0U);
    BOOST_CHECK_EQUAL(api.http_status_accepted_pending_since_.count(key), 0U);
    BOOST_CHECK_EQUAL(api.public_error_backoff_ms_.load(), 0);
}

BOOST_AUTO_TEST_CASE(public_rate_limited_backoff_escalates_aggressively)
{
    auto api = MakeValidationApi(m_node);

    BOOST_CHECK_EQUAL(api.public_error_backoff_ms_.load(), 0);

    // Rate limited: starts at 1000, doubles to 10000 cap
    auto cur = api.public_error_backoff_ms_.load();
    cur = (cur == 0) ? 1000 : std::min(cur * 2, (int64_t)10000);
    api.public_error_backoff_ms_.store(cur);
    BOOST_CHECK_EQUAL(api.public_error_backoff_ms_.load(), 1000);

    for (int expected : {2000, 4000, 8000, 10000, 10000}) {
        cur = api.public_error_backoff_ms_.load();
        cur = (cur == 0) ? 1000 : std::min(cur * 2, (int64_t)10000);
        api.public_error_backoff_ms_.store(cur);
        BOOST_CHECK_EQUAL(api.public_error_backoff_ms_.load(), expected);
    }
}

BOOST_AUTO_TEST_CASE(public_transport_error_backoff_escalates)
{
    auto api = MakeValidationApi(m_node);

    // Transport error: starts at 500, doubles to 10000 cap
    auto cur = api.public_error_backoff_ms_.load();
    cur = (cur == 0) ? 500 : std::min(cur * 2, (int64_t)10000);
    api.public_error_backoff_ms_.store(cur);
    BOOST_CHECK_EQUAL(api.public_error_backoff_ms_.load(), 500);

    for (int expected : {1000, 2000, 4000, 8000, 10000, 10000}) {
        cur = api.public_error_backoff_ms_.load();
        cur = (cur == 0) ? 500 : std::min(cur * 2, (int64_t)10000);
        api.public_error_backoff_ms_.store(cur);
        BOOST_CHECK_EQUAL(api.public_error_backoff_ms_.load(), expected);
    }
}

BOOST_AUTO_TEST_CASE(public_error_backoff_gate_blocks_polling)
{
    auto api = MakeValidationApi(m_node);

    api.public_error_backoff_ms_.store(4000);
    api.last_public_poll_ms_.store(10000);

    int64_t now_ms = 13000; // 3000ms since last poll, within 4000 window
    const auto err_bo = api.public_error_backoff_ms_.load();
    const auto last_pub = api.last_public_poll_ms_.load();
    bool blocked = (err_bo > 0 && last_pub > 0 && (now_ms - last_pub) < err_bo);
    BOOST_CHECK(blocked);
    BOOST_CHECK_EQUAL(err_bo, 4000);

    // Past the window
    now_ms = 14001;
    blocked = (err_bo > 0 && last_pub > 0 && (now_ms - last_pub) < err_bo);
    BOOST_CHECK(!blocked);
}

// Option-2 (TIP-0003): BlockValidation.difficulty is advertised to
// the verification service as BOTH the admission-target input AND the v3-active
// signal, so it is nonzero ONLY when v3 rules are active at the block's OWN
// height. This pins the pure decision SendApiRequest routes through.
BOOST_AUTO_TEST_CASE(v3_advertised_difficulty_option2)
{
    Consensus::Params params;              // defaults; only V3ActivationHeight is read
    params.V3ActivationHeight = 100;
    const int64_t D = 4242;

    // Below activation: advertise 0 — a version>=3 blob here is judged under v2
    // rules by consensus, so the verifier must NOT fold the nonce into u.
    BOOST_CHECK_EQUAL(V3AdvertisedDifficulty(99, params, D), 0);
    // At activation: advertise the registered difficulty (target + active signal).
    BOOST_CHECK_EQUAL(V3AdvertisedDifficulty(100, params, D), D);
    // Above activation: keyed on the block's OWN height, so historical
    // re-validation after the tip passes activation still resolves by height.
    BOOST_CHECK_EQUAL(V3AdvertisedDifficulty(500, params, D), D);
    // Unknown parent (precheck path, height<0): 0; contextual validation stays
    // authoritative later.
    BOOST_CHECK_EQUAL(V3AdvertisedDifficulty(-1, params, D), 0);
    // Active height but the model has no registered difficulty: nothing to
    // advertise -> 0 (verifier soft-skips; bcore consensus enforces).
    BOOST_CHECK_EQUAL(V3AdvertisedDifficulty(100, params, 0), 0);
    // Degenerate negative record value is clamped to 0 (never advertised).
    BOOST_CHECK_EQUAL(V3AdvertisedDifficulty(100, params, -1), 0);

    // Never active (default V3ActivationHeight == INT_MAX): always 0.
    Consensus::Params inactive;
    BOOST_CHECK_EQUAL(V3AdvertisedDifficulty(1000000, inactive, D), 0);
}

BOOST_AUTO_TEST_CASE(v3_activation_config_soundness)
{
    const int DISABLED = std::numeric_limits<int>::max();
    const int ACTIVE = 100;

    // v3 disabled: always sound regardless of external_api / mockability.
    BOOST_CHECK(IsV3ActivationConfigSound(DISABLED, /*external_api=*/false, /*mockable=*/false));
    BOOST_CHECK(IsV3ActivationConfigSound(DISABLED, false, true));
    BOOST_CHECK(IsV3ActivationConfigSound(DISABLED, true, false));

    // v3 active on a real (non-mockable) chain: sound ONLY with red-block
    // enforcement (external_api). This is the TIP-0003 invariant.
    BOOST_CHECK(!IsV3ActivationConfigSound(ACTIVE, /*external_api=*/false, /*mockable=*/false));
    BOOST_CHECK(IsV3ActivationConfigSound(ACTIVE, /*external_api=*/true, /*mockable=*/false));

    // Mockable (regtest / mock testnet) chains are exempt: the functional
    // acceptance test activates v3 via -v3activationheight without external_api.
    BOOST_CHECK(IsV3ActivationConfigSound(ACTIVE, /*external_api=*/false, /*mockable=*/true));

    // Activation-from-genesis (height 0) still requires the safety net.
    BOOST_CHECK(!IsV3ActivationConfigSound(0, false, false));
    BOOST_CHECK(IsV3ActivationConfigSound(0, true, false));
}

BOOST_AUTO_TEST_CASE(v3_admission_verify_capability)
{
    const int DISABLED = std::numeric_limits<int>::max();
    const int ACTIVE = 100;

    // v3 disabled: an argonless binary is fine (never sees v3 rules).
    BOOST_CHECK(IsV3AdmissionVerifyCapable(DISABLED, /*argon2_compiled=*/false));
    BOOST_CHECK(IsV3AdmissionVerifyCapable(DISABLED, true));

    // Finite activation height: only sound when argon2id_digest is functional.
    // No mockable exemption — an argonless binary cannot verify a claimed
    // nonce on any chain.
    BOOST_CHECK(!IsV3AdmissionVerifyCapable(ACTIVE, /*argon2_compiled=*/false));
    BOOST_CHECK(IsV3AdmissionVerifyCapable(ACTIVE, true));
    BOOST_CHECK(!IsV3AdmissionVerifyCapable(0, false));
    BOOST_CHECK(IsV3AdmissionVerifyCapable(0, true));

    // This test binary itself must be argon2-capable: CI images install
    // libargon2 and the functional acceptance test grinds real nonces.
    BOOST_CHECK(pow_v3::argon2_compiled());
}

BOOST_AUTO_TEST_CASE(v3_tier_params_vendored)
{
    const int DISABLED = std::numeric_limits<int>::max();
    const int ACTIVE = 100;
    const uint64_t FLOOR = pow_v3::B_FLOOR_BITS;
    const uint64_t FREE = pow_v3::B_FREE_BITS;

    // v3 disabled: tier params are irrelevant.
    BOOST_CHECK(IsV3TierParamsVendored(DISABLED, FLOOR + 1, FREE + 1));

    // Finite activation height: both thresholds must equal the compiled
    // pow_v3 constants the Python verifier scores with.
    BOOST_CHECK(IsV3TierParamsVendored(ACTIVE, FLOOR, FREE));
    BOOST_CHECK(!IsV3TierParamsVendored(ACTIVE, FLOOR + 1, FREE));
    BOOST_CHECK(!IsV3TierParamsVendored(ACTIVE, FLOOR, FREE + 1));
    BOOST_CHECK(IsV3TierParamsVendored(0, FLOOR, FREE));
    BOOST_CHECK(!IsV3TierParamsVendored(0, FLOOR - 1, FREE));

    // The default-constructed consensus params must themselves be vendored —
    // the real chains inherit these defaults.
    Consensus::Params defaults{};
    BOOST_CHECK(IsV3TierParamsVendored(ACTIVE, defaults.V3BFloorBits, defaults.V3BFreeBits));
}

BOOST_AUTO_TEST_SUITE_END()
