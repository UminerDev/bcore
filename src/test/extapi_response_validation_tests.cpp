// Tests for ExtAPI::ValidateMiningResponse request lookup and block mutation.

#include <test/util/setup_common.h>

#define private public
#define protected public
#include <node/extapi.h>
#undef private
#undef protected

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <primitives/proofblob.h>
#include <rpc/blockheader_generated.h>
#include <script/script.h>
#include <test/util/mining.h>
#include <validation.h>

using node::ExtAPI;

namespace {

struct TensorRegExtApiSetup : public TestingSetup {
    TensorRegExtApiSetup() : TestingSetup{ChainType::TENSOR_REG} {}
};

const proof::MiningResponse* BuildMiningResponse(
    flatbuffers::FlatBufferBuilder& builder,
    uint32_t req_id,
    uint32_t nonce,
    uint32_t adjusted_bits,
    const std::vector<uint8_t>& pow_blob_hash,
    const CProofBlob* pow_blob,
    const char* completion_id = "test-completion")
{
    const auto hash_offset = builder.CreateVector(pow_blob_hash);
    const auto proof_offset = pow_blob ? pow_blob->ToFlatBuffer(builder) : 0;
    const auto resp_offset = proof::CreateMiningResponseDirect(
        builder,
        req_id,
        nonce,
        adjusted_bits,
        &pow_blob_hash,
        /*difficulty=*/0,
        proof_offset,
        completion_id);
    (void)hash_offset;
    builder.Finish(resp_offset);
    return flatbuffers::GetRoot<proof::MiningResponse>(builder.GetBufferPointer());
}

std::vector<uint8_t> HashBytes(const uint256& hash)
{
    return std::vector<uint8_t>(hash.begin(), hash.end());
}

template <typename T>
void CheckEqualVector(const std::vector<T>& lhs, const std::vector<T>& rhs)
{
    BOOST_REQUIRE_EQUAL(lhs.size(), rhs.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(lhs.begin(), lhs.end(), rhs.begin(), rhs.end());
}

std::vector<uint8_t> CommitmentBytesForProof(node::NodeContext& node, const uint256& prev_hash, const CProofBlob& pow)
{
    ChainstateManager& chainman = *Assert(node.chainman);
    const CBlockIndex* prev_index = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(prev_hash));
    const int height = prev_index ? prev_index->nHeight + 1 : 0;
    const bool use_merkle = chainman.GetConsensus().IsVdfSpvActive(height);
    return HashBytes(pow.GetCommitment(use_merkle));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(extapi_response_validation_tests, TensorRegExtApiSetup)

BOOST_AUTO_TEST_CASE(validate_mining_response_rejects_invalid_request_id)
{
    ExtAPI extapi(m_node);
    CBlock out;
    flatbuffers::FlatBufferBuilder builder;
    CBlock candidate = CreateTensorBlock(m_node);
    const auto resp = BuildMiningResponse(builder, /*req_id=*/0, 7, candidate.nAdjBits, HashBytes(candidate.hashPoW), &candidate.pow);

    BOOST_CHECK(extapi.ValidateMiningResponse(resp, out, nullptr) == ExtAPI::MiningResponseDisposition::Invalid);
}

BOOST_AUTO_TEST_CASE(validate_mining_response_rejects_invalid_pow_blob_hash_size)
{
    ExtAPI extapi(m_node);
    CBlock out;
    flatbuffers::FlatBufferBuilder builder;
    CBlock candidate = CreateTensorBlock(m_node);
    const uint32_t req_id = extapi.requestTracker.incrementAndStore(candidate);
    std::vector<uint8_t> short_hash(31, 0x42);
    const auto resp = BuildMiningResponse(builder, req_id, 7, candidate.nAdjBits, short_hash, &candidate.pow);

    BOOST_CHECK(extapi.ValidateMiningResponse(resp, out, nullptr) == ExtAPI::MiningResponseDisposition::Invalid);
}

BOOST_AUTO_TEST_CASE(validate_mining_response_rejects_unknown_request_id)
{
    ExtAPI extapi(m_node);
    CBlock out;
    flatbuffers::FlatBufferBuilder builder;
    CBlock candidate = CreateTensorBlock(m_node);
    const auto resp = BuildMiningResponse(builder, /*req_id=*/12345, 7, candidate.nAdjBits, HashBytes(candidate.hashPoW), &candidate.pow);

    BOOST_CHECK(extapi.ValidateMiningResponse(resp, out, nullptr) == ExtAPI::MiningResponseDisposition::Stale);
}

BOOST_AUTO_TEST_CASE(validate_mining_response_returns_stale_for_submitted_request)
{
    ExtAPI extapi(m_node);
    CBlock out;
    CBlock candidate = CreateTensorBlock(m_node);
    const uint32_t req_id = extapi.requestTracker.incrementAndStore(candidate);
    BOOST_REQUIRE(extapi.requestTracker.markSubmitted(req_id));

    flatbuffers::FlatBufferBuilder builder;
    const auto resp = BuildMiningResponse(builder, req_id, 7, candidate.nAdjBits, HashBytes(candidate.hashPoW), &candidate.pow);

    BOOST_CHECK(extapi.ValidateMiningResponse(resp, out, nullptr) == ExtAPI::MiningResponseDisposition::Stale);
}

BOOST_AUTO_TEST_CASE(validate_mining_response_rejects_empty_pow_blob)
{
    ExtAPI extapi(m_node);
    CBlock out;
    CBlock candidate = CreateTensorBlock(m_node);
    const uint32_t req_id = extapi.requestTracker.incrementAndStore(candidate);

    flatbuffers::FlatBufferBuilder builder;
    const auto resp = BuildMiningResponse(builder, req_id, 7, candidate.nAdjBits, HashBytes(candidate.hashPoW), /*pow_blob=*/nullptr);

    BOOST_CHECK(extapi.ValidateMiningResponse(resp, out, nullptr) == ExtAPI::MiningResponseDisposition::Invalid);
}

BOOST_AUTO_TEST_CASE(validate_mining_response_accepts_valid_response_and_updates_block)
{
    ExtAPI extapi(m_node);

    CBlock base = CreateTensorBlock(m_node);
    auto baseptr = std::make_shared<const CBlock>(base);
    bool base_new{false};
    BOOST_REQUIRE(Assert(m_node.chainman)->ProcessNewBlock(baseptr, /*force_processing=*/true, /*min_pow_checked=*/true, &base_new));
    BOOST_REQUIRE(base_new);

    CBlock candidate = CreateTensorBlock(m_node);
    const uint32_t req_id = extapi.requestTracker.incrementAndStore(candidate);

    CProofBlob solved_pow = candidate.pow;
    solved_pow.tick += 17;
    solved_pow.vdf = std::vector<uint8_t>{1, 2, 3, 4};
    solved_pow.model_identifier = "test-model@test-commit";

    flatbuffers::FlatBufferBuilder builder;
    const uint32_t response_nonce = 99;
    const uint32_t response_adjbits = candidate.nAdjBits + 1;
    const auto resp = BuildMiningResponse(
        builder,
        req_id,
        response_nonce,
        response_adjbits,
        CommitmentBytesForProof(m_node, candidate.hashPrevBlock, solved_pow),
        &solved_pow);

    CBlock out;
    uint32_t request_id_out{0};
    const auto disposition = extapi.ValidateMiningResponse(resp, out, &request_id_out);

    BOOST_CHECK(disposition == ExtAPI::MiningResponseDisposition::Valid);
    BOOST_CHECK_EQUAL(request_id_out, req_id);
    BOOST_CHECK_EQUAL(out.hashPrevBlock.ToString(), candidate.hashPrevBlock.ToString());
    BOOST_CHECK_EQUAL(out.hashMerkleRoot.ToString(), candidate.hashMerkleRoot.ToString());
    BOOST_CHECK_EQUAL(out.nTime, candidate.nTime);
    BOOST_CHECK_EQUAL(out.nBits, candidate.nBits);
    BOOST_CHECK_EQUAL(out.nNonce, response_nonce);
    BOOST_CHECK_EQUAL(out.nAdjBits, response_adjbits);
    BOOST_CHECK_EQUAL(out.pow.tick, solved_pow.tick);
    CheckEqualVector(out.pow.vdf, solved_pow.vdf);
    BOOST_CHECK_EQUAL(out.pow.model_identifier, solved_pow.model_identifier);
    BOOST_CHECK_EQUAL(out.hashPoW, out.pow.GetCommitment(/*use_merkle=*/true));

    const CBlockIndex* prev_index = WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveChain().Tip());
    BOOST_REQUIRE(prev_index);
    CBlock prev_block;
    BOOST_REQUIRE(Assert(m_node.chainman)->m_blockman.ReadBlock(prev_block, *prev_index));
    BOOST_CHECK_EQUAL(out.cumulative_tick, prev_block.cumulative_tick + solved_pow.tick);
}

BOOST_AUTO_TEST_CASE(validate_mining_response_updates_cumulative_tick_correctly)
{
    ExtAPI extapi(m_node);

    CBlock base = CreateTensorBlock(m_node);
    auto baseptr = std::make_shared<const CBlock>(base);
    bool base_new{false};
    BOOST_REQUIRE(Assert(m_node.chainman)->ProcessNewBlock(baseptr, /*force_processing=*/true, /*min_pow_checked=*/true, &base_new));
    BOOST_REQUIRE(base_new);

    const CBlockIndex* base_index = WITH_LOCK(::cs_main, return Assert(m_node.chainman)->ActiveChain().Tip());
    BOOST_REQUIRE(base_index != nullptr);
    CBlock accepted_base;
    BOOST_REQUIRE(Assert(m_node.chainman)->m_blockman.ReadBlock(accepted_base, *base_index));

    CBlock candidate = CreateTensorBlock(m_node);
    const uint32_t req_id = extapi.requestTracker.incrementAndStore(candidate);

    CProofBlob solved_pow = candidate.pow;
    solved_pow.tick = 123;
    solved_pow.vdf = std::vector<uint8_t>{8, 9, 10};

    flatbuffers::FlatBufferBuilder builder;
    const auto resp = BuildMiningResponse(
        builder,
        req_id,
        44,
        candidate.nAdjBits,
        CommitmentBytesForProof(m_node, candidate.hashPrevBlock, solved_pow),
        &solved_pow);

    CBlock out;
    BOOST_REQUIRE(extapi.ValidateMiningResponse(resp, out, nullptr) == ExtAPI::MiningResponseDisposition::Valid);
    BOOST_CHECK_EQUAL(out.cumulative_tick, accepted_base.cumulative_tick + solved_pow.tick);
}

BOOST_AUTO_TEST_CASE(validate_mining_response_without_prev_index_uses_tick_as_cumulative)
{
    ExtAPI extapi(m_node);
    CBlock candidate = CreateTensorBlock(m_node);
    uint256 missing_prev;
    missing_prev.begin()[0] = 1;
    candidate.hashPrevBlock = missing_prev;
    const uint32_t req_id = extapi.requestTracker.incrementAndStore(candidate);

    CProofBlob solved_pow = candidate.pow;
    solved_pow.tick += 11;
    solved_pow.vdf = std::vector<uint8_t>{4, 5, 6};

    flatbuffers::FlatBufferBuilder builder;
    const auto resp = BuildMiningResponse(
        builder,
        req_id,
        21,
        candidate.nAdjBits,
        CommitmentBytesForProof(m_node, candidate.hashPrevBlock, solved_pow),
        &solved_pow);

    CBlock out;
    BOOST_CHECK(extapi.ValidateMiningResponse(resp, out, nullptr) == ExtAPI::MiningResponseDisposition::Valid);
    BOOST_CHECK_EQUAL(out.cumulative_tick, solved_pow.tick);
}

BOOST_AUTO_TEST_CASE(validate_mining_response_with_header_only_prev_uses_tick_as_cumulative)
{
    ExtAPI extapi(m_node);

    CBlock prev_header_block = CreateTensorBlock(m_node);
    BlockValidationState state;
    std::array<CBlockHeader, 1> headers{prev_header_block};
    const CBlockIndex* prev_index{nullptr};
    BOOST_REQUIRE(Assert(m_node.chainman)->ProcessNewBlockHeaders(headers, /*min_pow_checked=*/true, state, &prev_index));
    BOOST_REQUIRE(prev_index != nullptr);

    CBlock candidate = CreateTensorBlock(m_node);
    candidate.hashPrevBlock = prev_header_block.GetHash();
    const uint32_t req_id = extapi.requestTracker.incrementAndStore(candidate);

    CProofBlob solved_pow = candidate.pow;
    solved_pow.tick += 29;
    solved_pow.vdf = std::vector<uint8_t>{7, 7, 7};

    flatbuffers::FlatBufferBuilder builder;
    const auto resp = BuildMiningResponse(
        builder,
        req_id,
        33,
        candidate.nAdjBits,
        CommitmentBytesForProof(m_node, candidate.hashPrevBlock, solved_pow),
        &solved_pow);

    CBlock out;
    BOOST_CHECK(extapi.ValidateMiningResponse(resp, out, nullptr) == ExtAPI::MiningResponseDisposition::Valid);
    BOOST_CHECK_EQUAL(out.cumulative_tick, solved_pow.tick);
}

BOOST_AUTO_TEST_CASE(validate_mining_response_valid_then_stale_after_mark_submitted)
{
    ExtAPI extapi(m_node);

    CBlock base = CreateTensorBlock(m_node);
    auto baseptr = std::make_shared<const CBlock>(base);
    bool base_new{false};
    BOOST_REQUIRE(Assert(m_node.chainman)->ProcessNewBlock(baseptr, /*force_processing=*/true, /*min_pow_checked=*/true, &base_new));
    BOOST_REQUIRE(base_new);

    CBlock candidate = CreateTensorBlock(m_node);
    const uint32_t req_id = extapi.requestTracker.incrementAndStore(candidate);

    CProofBlob solved_pow = candidate.pow;
    solved_pow.tick += 5;
    solved_pow.vdf = std::vector<uint8_t>{2, 2, 2};

    flatbuffers::FlatBufferBuilder builder;
    const auto resp = BuildMiningResponse(
        builder,
        req_id,
        12,
        candidate.nAdjBits,
        CommitmentBytesForProof(m_node, candidate.hashPrevBlock, solved_pow),
        &solved_pow);

    CBlock out;
    BOOST_CHECK(extapi.ValidateMiningResponse(resp, out, nullptr) == ExtAPI::MiningResponseDisposition::Valid);
    BOOST_REQUIRE(extapi.requestTracker.markSubmitted(req_id));

    CBlock duplicate_out;
    BOOST_CHECK(extapi.ValidateMiningResponse(resp, duplicate_out, nullptr) == ExtAPI::MiningResponseDisposition::Stale);
}

BOOST_AUTO_TEST_CASE(request_tracker_default_cap_retains_pool_scale_work_units)
{
    // Regression: the tracker used a hard cap of 50, so a pool minting one
    // work unit per connected miner per tip lost roughly half its solutions
    // past 50 miners (evicted ids come back as unknown_req_id).
    node::RequestTracker tracker;
    const CBlock block;
    std::vector<uint32_t> ids;
    for (int i = 0; i < 105; ++i) {
        ids.push_back(tracker.incrementAndStore(block));
    }
    for (const uint32_t id : ids) {
        BOOST_CHECK(tracker.getRequestForSolution(id).state == node::RequestTracker::LookupState::Available);
    }
}

BOOST_AUTO_TEST_CASE(request_tracker_restores_caller_owned_durable_id)
{
    node::RequestTracker tracker;
    CBlock block;
    block.nNonce = 77;
    tracker.storeWithId(9'999'999, block);
    const auto restored = tracker.getRequestForSolution(9'999'999);
    BOOST_REQUIRE(restored.state == node::RequestTracker::LookupState::Available);
    BOOST_REQUIRE(restored.block.has_value());
    BOOST_CHECK_EQUAL(restored.block->nNonce, 77U);
    BOOST_CHECK_THROW(tracker.storeWithId(0, block), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(request_tracker_retains_submitted_block_hash)
{
    node::RequestTracker tracker;
    CBlock block;
    const uint32_t id = tracker.incrementAndStore(block);
    const uint256 submitted_hash{uint256::ONE};
    BOOST_REQUIRE(tracker.markSubmitted(id, submitted_hash));

    const auto submitted = tracker.getRequestForSolution(id);
    BOOST_CHECK(submitted.state == node::RequestTracker::LookupState::Submitted);
    BOOST_REQUIRE(submitted.submitted_hash.has_value());
    BOOST_CHECK_EQUAL(submitted.submitted_hash->ToString(), submitted_hash.ToString());
}

BOOST_AUTO_TEST_CASE(request_tracker_evicts_oldest_beyond_cap)
{
    node::RequestTracker tracker;
    tracker.setMaxOpenRequests(3);
    const CBlock block;
    const uint32_t first = tracker.incrementAndStore(block);
    const uint32_t second = tracker.incrementAndStore(block);
    const uint32_t third = tracker.incrementAndStore(block);
    const uint32_t fourth = tracker.incrementAndStore(block);

    BOOST_CHECK(tracker.getRequestForSolution(first).state == node::RequestTracker::LookupState::Missing);
    BOOST_CHECK(tracker.getRequestForSolution(second).state == node::RequestTracker::LookupState::Available);
    BOOST_CHECK(tracker.getRequestForSolution(third).state == node::RequestTracker::LookupState::Available);
    BOOST_CHECK(tracker.getRequestForSolution(fourth).state == node::RequestTracker::LookupState::Available);
}

BOOST_AUTO_TEST_CASE(request_tracker_lowered_cap_drains_backlog_on_next_insert)
{
    node::RequestTracker tracker;
    const CBlock block;
    std::vector<uint32_t> ids;
    for (int i = 0; i < 5; ++i) {
        ids.push_back(tracker.incrementAndStore(block));
    }
    tracker.setMaxOpenRequests(2);
    const uint32_t last = tracker.incrementAndStore(block);

    for (size_t i = 0; i + 1 < ids.size(); ++i) {
        BOOST_CHECK(tracker.getRequestForSolution(ids[i]).state == node::RequestTracker::LookupState::Missing);
    }
    BOOST_CHECK(tracker.getRequestForSolution(ids.back()).state == node::RequestTracker::LookupState::Available);
    BOOST_CHECK(tracker.getRequestForSolution(last).state == node::RequestTracker::LookupState::Available);
}

BOOST_AUTO_TEST_CASE(request_tracker_cap_clamps_to_minimum_of_one)
{
    node::RequestTracker tracker;
    tracker.setMaxOpenRequests(0);
    const CBlock block;
    const uint32_t first = tracker.incrementAndStore(block);
    const uint32_t second = tracker.incrementAndStore(block);

    BOOST_CHECK(tracker.getRequestForSolution(first).state == node::RequestTracker::LookupState::Missing);
    BOOST_CHECK(tracker.getRequestForSolution(second).state == node::RequestTracker::LookupState::Available);
}

BOOST_AUTO_TEST_SUITE_END()
