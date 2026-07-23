// Tests for Quick_Smell vs Full gating and EarlyPropagation

#include <boost/test/unit_test.hpp>

#include <arith_uint256.h>
#include <chainparams.h>
#include <common/args.h>
#include <node/blockstorage.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>

#define private public
#include <validationapi.h>
#undef private

#include <test/util/mock_validation_api.h>
#include <test/util/validation.h>
#include <validationinterface.h>
#include <validation.h>

using node::BlockAssembler;

namespace {
struct PropagationCatcher : public CValidationInterface {
    int count{0};
    void NewPoWValidBlock(const CBlockIndex *, const std::shared_ptr<const CBlock>&) override { ++count; }
};
} // namespace

struct TensorMainSetup : public ChainTestingSetup {
    ScopedGenesisApproval genesis_ok;
    TensorMainSetup()
        : ChainTestingSetup{ChainType::TENSOR_MAIN, {/*extra_args*/{}, /*coins_db_in_memory=*/true, /*block_tree_db_in_memory=*/true, /*setup_net=*/false, /*setup_validation_interface=*/true, /*min_validation_cache=*/false}}
        , genesis_ok{Params()}
    {
        genesis_ok->SetDefaultResponse(ValidationReqType::Quick_Smell, ValidationResponseValue::Quick_OK_Smell_OK);
        LoadVerifyActivateChainstate();
        // Ensure EarlyPropagation conditions: not in IBD.
        auto& tcm = static_cast<TestChainstateManager&>(*m_node.chainman);
        tcm.JumpOutOfIbd();
    }
};

BOOST_FIXTURE_TEST_SUITE(validation_quick_full_tests, TensorMainSetup)

BOOST_AUTO_TEST_CASE(quick_ok_smell_ok_triggers_early_propagation)
{
    // Default Quick_Smell already set in fixture; no Full status preset

    PropagationCatcher catcher;
    m_node.validation_signals->RegisterValidationInterface(&catcher);

    CBlock block = CreateTensorBlock(m_node);
    auto blockptr = std::make_shared<const CBlock>(block);
    bool new_block{false};

    // No Full status preset: should enqueue Full, not accept, but early propagate
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK_EQUAL(catcher.count, 1);

    m_node.validation_signals->UnregisterValidationInterface(&catcher);
}

BOOST_AUTO_TEST_CASE(delayed_quick_ok_smell_ok_triggers_early_propagation)
{
    PropagationCatcher catcher;
    m_node.validation_signals->RegisterValidationInterface(&catcher);

    CBlock block = CreateTensorBlock(m_node);
    ValidationAPI api{*Assert(m_node.chainman), Params().GetConsensus()};
    uint256 request_id;
    BOOST_REQUIRE(api.requestTracker.makeNewRequest(
        block,
        ValidationReqType::Quick_Smell,
        request_id,
        ValidationResponseBehavior::Nothing));

    BOOST_CHECK(api.HandleQuickSmellResult(
        request_id, ValidationResponseValue::Quick_OK_Smell_OK));
    BOOST_CHECK_EQUAL(catcher.count, 1);
    BOOST_CHECK(!api.requestTracker
                     .getBlockForId(request_id, ValidationReqType::Quick_Smell)
                     .has_value());

    m_node.validation_signals->UnregisterValidationInterface(&catcher);
}

BOOST_AUTO_TEST_CASE(peer_pending_build_ahead_requires_explicit_opt_in)
{
    CBlock block = CreateTensorBlock(m_node);
    auto blockptr = std::make_shared<const CBlock>(block);
    bool new_block{false};

    gArgs.ForceSetArg("-miningbuildaheadpeers", "0");
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(
        blockptr,
        /*force_processing=*/true,
        /*min_pow_checked=*/true,
        &new_block));
    {
        LOCK(cs_main);
        BOOST_CHECK(node::SelectBuildAheadParent(*Assert(m_node.chainman)) == nullptr);
    }

    gArgs.ForceSetArg("-miningbuildaheadpeers", "1");
    {
        LOCK(cs_main);
        const CBlockIndex* selected{
            node::SelectBuildAheadParent(*Assert(m_node.chainman))};
        BOOST_REQUIRE(selected != nullptr);
        BOOST_CHECK_EQUAL(selected->GetBlockHash(), block.GetHash());
        BOOST_CHECK_EQUAL(selected->pprev, Assert(m_node.chainman)->ActiveTip());
    }

    BOOST_REQUIRE(g_ValidationApi->SetRequestStatus(
        block.GetHash(),
        ValidationReqType::Full,
        ValidationResponseValue::Full_Amber));
    {
        LOCK(cs_main);
        BOOST_CHECK(node::SelectBuildAheadParent(*Assert(m_node.chainman)) == nullptr);
    }
    BOOST_REQUIRE(g_ValidationApi->RemoveRes_Full(block.GetHash()));

    // Tests share the global ArgsManager; restore the production-safe default.
    gArgs.ForceSetArg("-miningbuildaheadpeers", "0");
}

BOOST_AUTO_TEST_CASE(delayed_quick_smell_failure_does_not_propagate)
{
    PropagationCatcher catcher;
    m_node.validation_signals->RegisterValidationInterface(&catcher);

    CBlock block = CreateTensorBlock(m_node);
    ValidationAPI api{*Assert(m_node.chainman), Params().GetConsensus()};
    uint256 request_id;
    BOOST_REQUIRE(api.requestTracker.makeNewRequest(
        block,
        ValidationReqType::Quick_Smell,
        request_id,
        ValidationResponseBehavior::Nothing));

    BOOST_CHECK(!api.HandleQuickSmellResult(
        request_id, ValidationResponseValue::Quick_OK_Smell_Fail));
    BOOST_CHECK_EQUAL(catcher.count, 0);
    BOOST_CHECK(!api.requestTracker
                     .getBlockForId(request_id, ValidationReqType::Quick_Smell)
                     .has_value());

    m_node.validation_signals->UnregisterValidationInterface(&catcher);
}

BOOST_AUTO_TEST_CASE(quick_ok_smell_fail_no_propagation)
{
    // Override Quick_Smell default for this test
    genesis_ok->SetDefaultResponse(ValidationReqType::Quick_Smell, ValidationResponseValue::Quick_OK_Smell_Fail);

    PropagationCatcher catcher;
    m_node.validation_signals->RegisterValidationInterface(&catcher);

    CBlock block = CreateTensorBlock(m_node);
    auto blockptr = std::make_shared<const CBlock>(block);
    bool new_block{false};

    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK_EQUAL(catcher.count, 0);

    m_node.validation_signals->UnregisterValidationInterface(&catcher);
}

BOOST_AUTO_TEST_CASE(missing_remote_quick_smell_uses_local_quick_to_reject)
{
    CBlock block = CreateTensorBlock(m_node);
    const uint256 block_hash{block.GetHash()};

    genesis_ok->ClearAll();
    genesis_ok->SetLocalQuickResponse(ValidationResponseValue::Quick_Fail_Smell_Fail);
    genesis_ok->ClearCapturedRequests();

    auto blockptr = std::make_shared<const CBlock>(block);
    bool new_block{false};
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(!new_block);

    bool saw_quick_smell_request{false};
    bool saw_full_request{false};
    for (const auto& request : genesis_ok->GetCapturedRequests()) {
        if (request.hash == block_hash && request.type == ValidationReqType::Quick_Smell) {
            saw_quick_smell_request = true;
        }
        if (request.hash == block_hash && request.type == ValidationReqType::Full) {
            saw_full_request = true;
        }
    }
    BOOST_CHECK(saw_quick_smell_request);
    BOOST_CHECK(!saw_full_request);

    {
        LOCK(cs_main);
        BOOST_CHECK(Assert(m_node.chainman)->m_blockman.LookupBlockIndex(block_hash) == nullptr);
    }
}

BOOST_AUTO_TEST_CASE(full_green_accepts_without_request)
{
    // Quick_Smell is OK via fixture default

    CBlock block = CreateTensorBlock(m_node);
    const uint256 h = block.GetHash();
    // Pre-set Full_Green so no Full request is sent
    genesis_ok->SetRequestStatus(h, ValidationReqType::Full, ValidationResponseValue::Full_Green);

    auto blockptr = std::make_shared<const CBlock>(block);
    bool new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);
}

BOOST_AUTO_TEST_CASE(full_red_flip_active_tip_reorgs_to_parent)
{
    CBlock block = CreateTensorBlock(m_node);
    const uint256 block_hash{block.GetHash()};
    genesis_ok->SetRequestStatus(block_hash, ValidationReqType::Full, ValidationResponseValue::Full_Green);

    uint256 parent_hash;
    arith_uint256 parent_work;
    {
        LOCK(cs_main);
        CBlockIndex* parent_index{Assert(m_node.chainman)->ActiveChain().Tip()};
        parent_hash = parent_index->GetBlockHash();
        parent_work = parent_index->nChainWork;
    }

    bool new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(std::make_shared<const CBlock>(block),
                                                         /*force_processing=*/true,
                                                         /*min_pow_checked=*/true,
                                                         &new_block));
    BOOST_CHECK(new_block);

    {
        LOCK(cs_main);
        CBlockIndex* block_index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(block_hash)};
        BOOST_REQUIRE(block_index);
        BOOST_CHECK_EQUAL(Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockHash().ToString(), block_hash.ToString());
        BOOST_CHECK(Assert(m_node.chainman)->SetBlockFullValidationRedStatus(block_index, true));
        Assert(m_node.chainman)->RecalculateBlockIndexWorkForFullValidation(block_index);
        BOOST_CHECK((block_index->nStatus & BLOCK_FULL_RED_LOCAL) != 0);
        BOOST_CHECK_EQUAL(block_index->nChainWork.ToString(), parent_work.ToString());
    }

    BlockValidationState state;
    BOOST_CHECK(Assert(m_node.chainman)->ActiveChainstate().ActivateBestChain(state));

    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockHash().ToString(), parent_hash.ToString());
    }
}

BOOST_AUTO_TEST_CASE(full_red_penalty_requires_good_descendants_to_recover)
{
    const auto blocks = CreateBlockChain(3, Params());
    const auto& red_block = blocks.at(0);
    const auto& first_child_block = blocks.at(1);
    const auto& second_child_block = blocks.at(2);
    const uint256 red_hash{red_block->GetHash()};
    const uint256 first_child_hash{first_child_block->GetHash()};
    const uint256 second_child_hash{second_child_block->GetHash()};

    genesis_ok->SetRequestStatus(red_hash, ValidationReqType::Full, ValidationResponseValue::Full_Red);
    genesis_ok->SetRequestStatus(first_child_hash, ValidationReqType::Full, ValidationResponseValue::Full_Green);
    genesis_ok->SetRequestStatus(second_child_hash, ValidationReqType::Full, ValidationResponseValue::Full_Green);

    uint256 parent_hash;
    arith_uint256 parent_work;
    arith_uint256 parent_penalty;
    arith_uint256 red_block_penalty;
    {
        LOCK(cs_main);
        CBlockIndex* parent_index{Assert(m_node.chainman)->ActiveChain().Tip()};
        parent_hash = parent_index->GetBlockHash();
        parent_work = parent_index->nChainWork;
        parent_penalty = parent_index->nChainPenalty;
        red_block_penalty = GetBlockProof(*parent_index);
    }

    bool new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(red_block, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);

    {
        LOCK(cs_main);
        CBlockIndex* parent_index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(parent_hash)};
        CBlockIndex* red_index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(red_hash)};
        BOOST_REQUIRE(parent_index);
        BOOST_REQUIRE(red_index);
        BOOST_CHECK(red_index->IsValid(BLOCK_VALID_TRANSACTIONS));
        BOOST_CHECK((red_index->nStatus & BLOCK_FAILED_MASK) == 0);
        BOOST_CHECK((red_index->nStatus & BLOCK_FULL_RED_LOCAL) != 0);
        BOOST_CHECK_EQUAL(red_index->nChainWork.ToString(), parent_work.ToString());
        BOOST_CHECK_EQUAL(red_index->nChainPenalty.ToString(), (parent_penalty + red_block_penalty).ToString());
        node::CBlockIndexPolicyComparator policy_comparator;
        BOOST_CHECK(policy_comparator(red_index, parent_index));
        BOOST_CHECK(!policy_comparator(parent_index, red_index));
        BOOST_CHECK_EQUAL(Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockHash().ToString(), parent_hash.ToString());
    }

    new_block = false;
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(first_child_block, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);

    arith_uint256 first_child_zero_red_work;
    {
        LOCK(cs_main);
        CBlockIndex* parent_index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(parent_hash)};
        CBlockIndex* red_index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(red_hash)};
        CBlockIndex* child_index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(first_child_hash)};
        BOOST_REQUIRE(parent_index);
        BOOST_REQUIRE(red_index);
        BOOST_REQUIRE(child_index);
        first_child_zero_red_work = parent_work + GetBlockProof(*child_index);
        BOOST_CHECK_EQUAL(child_index->nChainWork.ToString(), first_child_zero_red_work.ToString());
        BOOST_CHECK_EQUAL(child_index->nChainPenalty.ToString(), (parent_penalty + red_block_penalty).ToString());
        node::CBlockIndexPolicyComparator policy_comparator;
        BOOST_CHECK(policy_comparator(child_index, parent_index));
        BOOST_CHECK(!policy_comparator(parent_index, child_index));
        BOOST_CHECK_EQUAL(Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockHash().ToString(), parent_hash.ToString());
    }

    BlockAssembler::Options options;
    auto block_template = BlockAssembler{Assert(m_node.chainman)->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock();
    BOOST_REQUIRE(block_template);
    BOOST_CHECK_EQUAL(block_template->block.hashPrevBlock.ToString(), parent_hash.ToString());

    new_block = false;
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(second_child_block, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);

    {
        LOCK(cs_main);
        CBlockIndex* parent_index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(parent_hash)};
        CBlockIndex* red_index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(red_hash)};
        CBlockIndex* first_child_index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(first_child_hash)};
        CBlockIndex* second_child_index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(second_child_hash)};
        BOOST_REQUIRE(parent_index);
        BOOST_REQUIRE(red_index);
        BOOST_REQUIRE(first_child_index);
        BOOST_REQUIRE(second_child_index);
        const arith_uint256 recovered_work{first_child_zero_red_work + GetBlockProof(*second_child_index)};
        BOOST_CHECK_EQUAL(second_child_index->nChainWork.ToString(), recovered_work.ToString());
        BOOST_CHECK_EQUAL(second_child_index->nChainPenalty.ToString(), (parent_penalty + red_block_penalty).ToString());
        node::CBlockIndexPolicyComparator policy_comparator;
        BOOST_CHECK(policy_comparator(parent_index, second_child_index));
        BOOST_CHECK(!policy_comparator(second_child_index, parent_index));
        BOOST_CHECK_EQUAL(Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockHash().ToString(), second_child_hash.ToString());
        BOOST_CHECK_EQUAL(Assert(m_node.chainman)->ActiveChain()[red_index->nHeight]->GetBlockHash().ToString(), red_hash.ToString());
    }

    block_template = BlockAssembler{Assert(m_node.chainman)->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock();
    BOOST_REQUIRE(block_template);
    BOOST_CHECK_EQUAL(block_template->block.hashPrevBlock.ToString(), second_child_hash.ToString());

    genesis_ok->SetRequestStatus(red_hash, ValidationReqType::Full, ValidationResponseValue::Full_Green);
    {
        LOCK(cs_main);
        CBlockIndex* red_index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(red_hash)};
        CBlockIndex* first_child_index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(first_child_hash)};
        CBlockIndex* second_child_index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(second_child_hash)};
        BOOST_REQUIRE(red_index);
        BOOST_REQUIRE(first_child_index);
        BOOST_REQUIRE(second_child_index);
        BOOST_CHECK(Assert(m_node.chainman)->SetBlockFullValidationRedStatus(red_index, false));
        Assert(m_node.chainman)->RecalculateBlockIndexWorkForFullValidation(red_index);
        const arith_uint256 red_green_work{parent_work + GetBlockProof(*red_index)};
        const arith_uint256 second_child_green_work{red_green_work + GetBlockProof(*first_child_index) + GetBlockProof(*second_child_index)};
        BOOST_CHECK_EQUAL(red_index->nChainWork.ToString(), red_green_work.ToString());
        BOOST_CHECK_EQUAL(red_index->nChainPenalty.ToString(), parent_penalty.ToString());
        BOOST_CHECK_EQUAL(second_child_index->nChainPenalty.ToString(), parent_penalty.ToString());
        BOOST_CHECK_EQUAL(second_child_index->nChainWork.ToString(), second_child_green_work.ToString());
    }
}

BOOST_AUTO_TEST_CASE(full_red_run_with_three_good_descendants_does_not_beat_parent)
{
    constexpr size_t red_blocks{5};
    constexpr size_t good_blocks{3};
    const auto blocks = CreateBlockChain(red_blocks + good_blocks, Params());

    for (size_t i{0}; i < blocks.size(); ++i) {
        const ValidationResponseValue status{i < red_blocks
            ? ValidationResponseValue::Full_Red
            : ValidationResponseValue::Full_Green};
        genesis_ok->SetRequestStatus(blocks.at(i)->GetHash(), ValidationReqType::Full, status);
    }

    uint256 parent_hash;
    {
        LOCK(cs_main);
        parent_hash = Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockHash();
    }

    for (const auto& block : blocks) {
        bool new_block{false};
        BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
        BOOST_CHECK(new_block);
    }

    {
        LOCK(cs_main);
        CBlockIndex* parent_index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(parent_hash)};
        CBlockIndex* tip_index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(blocks.back()->GetHash())};
        BOOST_REQUIRE(parent_index);
        BOOST_REQUIRE(tip_index);
        node::CBlockIndexPolicyComparator policy_comparator;
        BOOST_CHECK(policy_comparator(tip_index, parent_index));
        BOOST_CHECK(!policy_comparator(parent_index, tip_index));
        BOOST_CHECK(tip_index->nChainPenalty > parent_index->nChainPenalty);
        BOOST_CHECK_EQUAL(Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockHash().ToString(), parent_hash.ToString());
    }
}

BOOST_AUTO_TEST_CASE(model_challenge_zero_work_does_not_add_full_red_penalty)
{
    CBlock block = CreateTensorBlock(m_node);
    const uint256 block_hash{block.GetHash()};
    genesis_ok->SetRequestStatus(block_hash, ValidationReqType::Full, ValidationResponseValue::Full_Green);

    arith_uint256 parent_work;
    arith_uint256 parent_penalty;
    uint256 parent_hash;
    {
        LOCK(cs_main);
        CBlockIndex* parent_index{Assert(m_node.chainman)->ActiveChain().Tip()};
        parent_hash = parent_index->GetBlockHash();
        parent_work = parent_index->nChainWork;
        parent_penalty = parent_index->nChainPenalty;
    }

    bool new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(std::make_shared<const CBlock>(block),
                                                         /*force_processing=*/true,
                                                         /*min_pow_checked=*/true,
                                                         &new_block));
    BOOST_CHECK(new_block);

    {
        LOCK(cs_main);
        CBlockIndex* block_index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(block_hash)};
        BOOST_REQUIRE(block_index);
        BOOST_CHECK(Assert(m_node.chainman)->SetBlockModelChallengeZeroWorkStatus(block_index, true));
        Assert(m_node.chainman)->RecalculateBlockIndexWorkForFullValidation(block_index);
        BOOST_CHECK((block_index->nStatus & BLOCK_MODEL_CHALLENGE_ZERO_WORK) != 0);
        BOOST_CHECK_EQUAL(block_index->nChainWork.ToString(), parent_work.ToString());
        BOOST_CHECK_EQUAL(block_index->nChainPenalty.ToString(), parent_penalty.ToString());
    }

    BlockValidationState state;
    BOOST_CHECK(Assert(m_node.chainman)->ActiveChainstate().ActivateBestChain(state));

    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockHash().ToString(), parent_hash.ToString());
    }
}

BOOST_AUTO_TEST_CASE(full_red_loses_to_green_sibling_at_same_height)
{
    CBlock red_block = CreateTensorBlock(m_node);
    const uint256 red_hash{red_block.GetHash()};
    genesis_ok->SetRequestStatus(red_hash, ValidationReqType::Full, ValidationResponseValue::Full_Red);

    uint256 parent_hash;
    {
        LOCK(cs_main);
        parent_hash = Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockHash();
    }

    bool new_block{false};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(std::make_shared<const CBlock>(red_block),
                                                         /*force_processing=*/true,
                                                         /*min_pow_checked=*/true,
                                                         &new_block));
    BOOST_CHECK(new_block);

    CBlock green_block = CreateTensorBlock(m_node);
    while (green_block.GetHash() == red_hash ||
           !CheckProofOfWork(green_block.GetShortHash(), green_block.nAdjBits ? green_block.nAdjBits : green_block.nBits, Params().GetConsensus())) {
        ++green_block.nNonce;
    }
    const uint256 green_hash{green_block.GetHash()};
    genesis_ok->SetRequestStatus(green_hash, ValidationReqType::Full, ValidationResponseValue::Full_Green);

    new_block = false;
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(std::make_shared<const CBlock>(green_block),
                                                         /*force_processing=*/true,
                                                         /*min_pow_checked=*/true,
                                                         &new_block));
    BOOST_CHECK(new_block);

    {
        LOCK(cs_main);
        CBlockIndex* red_index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(red_hash)};
        CBlockIndex* green_index{Assert(m_node.chainman)->m_blockman.LookupBlockIndex(green_hash)};
        BOOST_REQUIRE(red_index);
        BOOST_REQUIRE(green_index);
        BOOST_CHECK_EQUAL(red_index->pprev->GetBlockHash().ToString(), parent_hash.ToString());
        BOOST_CHECK_EQUAL(green_index->pprev->GetBlockHash().ToString(), parent_hash.ToString());
        BOOST_CHECK(green_index->nChainWork > red_index->nChainWork);
        BOOST_CHECK_EQUAL(Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockHash().ToString(), green_hash.ToString());
    }
}

BOOST_AUTO_TEST_SUITE_END()
