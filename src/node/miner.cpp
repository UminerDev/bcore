// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/miner.h>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <deploymentstatus.h>
#include <logging.h>
#include <node/context.h>
#include <node/kernel_notifications.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <pow.h>
#include <modeldb.h>
#include <validationapi.h>
#include <wallet/rpc/api_model_registration.h>
#include <primitives/transaction.h>
#include <vdf/VdfGenerate.h>
#include <util/moneystr.h>
#include <util/signalinterrupt.h>
#include <util/time.h>
#include <validation.h>
#include <txmempool.h>

#include <algorithm>
#include <limits>
#include <map>
#include <mutex>
#include <unordered_set>
#include <utility>

namespace node {

namespace {
std::mutex g_model_override_mutex;
std::optional<std::string> g_model_override;

struct PendingBuildAheadBlock {
    int height{0};
    uint256 prev_hash;
    uint64_t cumulative_tick{0};
    bool owned{false};
};

Mutex g_pending_build_ahead_mutex;
std::map<uint256, PendingBuildAheadBlock> g_pending_build_ahead
    GUARDED_BY(g_pending_build_ahead_mutex);
} // namespace

std::optional<uint64_t> GetBuildAheadParentCumulativeTick(
    ChainstateManager& chainman,
    const uint256& prev_hash)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    const CBlockIndex* pprev = chainman.m_blockman.LookupBlockIndex(prev_hash);
    if (pprev != nullptr && (pprev->nStatus & BLOCK_HAVE_DATA)) {
        CBlock previous;
        if (chainman.m_blockman.ReadBlock(previous, *pprev)) {
            return previous.cumulative_tick;
        }
    }
    LOCK(g_pending_build_ahead_mutex);
    const auto it = g_pending_build_ahead.find(prev_hash);
    if (it != g_pending_build_ahead.end()) {
        return it->second.cumulative_tick;
    }
    return std::nullopt;
}

bool RecordPendingBuildAheadBlock(
    ChainstateManager& chainman,
    const CBlock& block,
    bool owned)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    AssertLockHeld(::cs_main);
    const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(block.GetHash());
    const CBlockIndex* pprev = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
    if (pindex == nullptr || pprev == nullptr || pindex->pprev != pprev) {
        return false;
    }
    const std::optional<uint64_t> parent_tick{
        GetBuildAheadParentCumulativeTick(chainman, block.hashPrevBlock)};
    if (!parent_tick ||
        block.pow.tick > std::numeric_limits<uint64_t>::max() - *parent_tick) {
        return false;
    }
    const uint64_t cumulative_tick{*parent_tick + block.pow.tick};
    if (block.cumulative_tick != cumulative_tick) {
        LogPrintLevel(
            BCLog::VALIDATION,
            BCLog::Level::Warning,
            "Ignoring build-ahead candidate %s with inconsistent cumulative_tick "
            "(body=%llu, derived=%llu)\n",
            block.GetHash().ToString(),
            static_cast<unsigned long long>(block.cumulative_tick),
            static_cast<unsigned long long>(cumulative_tick));
        return false;
    }

    LOCK(g_pending_build_ahead_mutex);
    auto [it, inserted] = g_pending_build_ahead.try_emplace(
        block.GetHash(),
        PendingBuildAheadBlock{
            pindex->nHeight,
            block.hashPrevBlock,
            cumulative_tick,
            owned});
    if (!inserted) {
        it->second.owned = it->second.owned || owned;
        it->second.height = pindex->nHeight;
        it->second.prev_hash = block.hashPrevBlock;
        it->second.cumulative_tick = cumulative_tick;
    }

    // Eligibility is always rechecked against the live active tip. Pruning is
    // only a memory bound for stale side branches and does not decide validity.
    if (g_pending_build_ahead.size() > 64) {
        int highest{0};
        for (const auto& entry : g_pending_build_ahead) {
            highest = std::max(highest, entry.second.height);
        }
        for (auto candidate = g_pending_build_ahead.begin();
             candidate != g_pending_build_ahead.end();) {
            if (candidate->second.height + 8 < highest) {
                candidate = g_pending_build_ahead.erase(candidate);
            } else {
                ++candidate;
            }
        }
    }
    return true;
}

bool IsOwnedPendingBuildAheadInFlight(
    ChainstateManager& chainman,
    const uint256& hash)
{
    {
        LOCK(g_pending_build_ahead_mutex);
        const auto it = g_pending_build_ahead.find(hash);
        if (it == g_pending_build_ahead.end() || !it->second.owned) {
            return false;
        }
    }
    if (g_ValidationApi != nullptr) {
        const uint8_t own_full = g_ValidationApi->GetOwnFullStatus(hash);
        if (own_full == static_cast<uint8_t>(ValidationResponseValue::Full_Red) ||
            own_full == static_cast<uint8_t>(ValidationResponseValue::Full_Amber)) {
            return false;
        }
    }
    LOCK(::cs_main);
    const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
    if (pindex == nullptr) {
        return true;
    }
    return !(pindex->nStatus & BLOCK_FAILED_MASK) &&
           !chainman.ActiveChain().Contains(pindex);
}

namespace {
bool IsBuildAheadEligible(ChainstateManager& chainman, const uint256& hash)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    bool owned{false};
    {
        LOCK(g_pending_build_ahead_mutex);
        const auto it = g_pending_build_ahead.find(hash);
        if (it == g_pending_build_ahead.end()) {
            return false;
        }
        owned = it->second.owned;
    }
    if (!owned && !gArgs.GetBoolArg("-miningbuildaheadpeers", false)) {
        return false;
    }

    const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
    if (pindex == nullptr || pindex->pprev == nullptr ||
        pindex->pprev != chainman.ActiveChain().Tip() ||
        (pindex->nStatus & BLOCK_FAILED_MASK) || g_ValidationApi == nullptr) {
        return false;
    }

    const uint8_t own_full = g_ValidationApi->GetOwnFullStatus(hash);
    if (own_full == static_cast<uint8_t>(ValidationResponseValue::Full_Red) ||
        own_full == static_cast<uint8_t>(ValidationResponseValue::Full_Amber)) {
        return false;
    }
    ValidationResponseValue quick_status;
    return g_ValidationApi->GetRequestStatus(
               hash,
               ValidationReqType::Quick_Smell,
               quick_status) &&
           quick_status == ValidationResponseValue::Quick_OK_Smell_OK;
}
} // namespace

const CBlockIndex* SelectBuildAheadParent(ChainstateManager& chainman)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    std::vector<uint256> candidates;
    {
        LOCK(g_pending_build_ahead_mutex);
        candidates.reserve(g_pending_build_ahead.size());
        for (const auto& entry : g_pending_build_ahead) {
            candidates.push_back(entry.first);
        }
    }

    const CBlockIndex* best{nullptr};
    uint64_t best_tick{0};
    for (const uint256& hash : candidates) {
        if (!IsBuildAheadEligible(chainman, hash)) {
            continue;
        }
        uint64_t candidate_tick{0};
        {
            LOCK(g_pending_build_ahead_mutex);
            const auto it = g_pending_build_ahead.find(hash);
            if (it != g_pending_build_ahead.end()) {
                candidate_tick = it->second.cumulative_tick;
            }
        }
        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (best == nullptr || candidate_tick > best_tick ||
            (candidate_tick == best_tick && hash < best->GetBlockHash())) {
            best = pindex;
            best_tick = candidate_tick;
        }
    }
    return best;
}

std::optional<std::string> GetMiningModelOverride()
{
    std::lock_guard<std::mutex> l(g_model_override_mutex);
    return g_model_override;
}

void SetMiningModelOverride(const std::string& identifier)
{
    std::lock_guard<std::mutex> l(g_model_override_mutex);
    g_model_override = identifier;
}

void ClearMiningModelOverride()
{
    std::lock_guard<std::mutex> l(g_model_override_mutex);
    g_model_override.reset();
}

int64_t GetMinimumTime(const CBlockIndex* pindexPrev, const int64_t difficulty_adjustment_interval)
{
    int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
    // Height of block to be mined.
    const int height{pindexPrev->nHeight + 1};
    // Account for BIP94 timewarp rule on all networks. This makes future
    // activation safer.
    if (height % difficulty_adjustment_interval == 0) {
        min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    return min_time;
}

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime{std::max<int64_t>(GetMinimumTime(pindexPrev, consensusParams.DifficultyAdjustmentInterval()),
                                       TicksSinceEpoch<std::chrono::seconds>(NodeClock::now()))};

    if (nOldTime < nNewTime) {
        pblock->nTime = nNewTime;
    }

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks) {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
    }

    return nNewTime - nOldTime;
}

void RegenerateCommitments(CBlock& block, ChainstateManager& chainman)
{
    CMutableTransaction tx{*block.vtx.at(0)};
    tx.vout.erase(tx.vout.begin() + GetWitnessCommitmentIndex(block));
    block.vtx.at(0) = MakeTransactionRef(tx);

    const CBlockIndex* prev_block = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock));
    chainman.GenerateCoinbaseCommitment(block, prev_block);

    block.hashMerkleRoot = BlockMerkleRoot(block);
}

static BlockAssembler::Options ClampOptions(BlockAssembler::Options options)
{
    Assert(options.block_reserved_weight <= MAX_BLOCK_WEIGHT);
    Assert(options.block_reserved_weight >= MINIMUM_BLOCK_RESERVED_WEIGHT);
    Assert(options.coinbase_output_max_additional_sigops <= MAX_BLOCK_SIGOPS_COST);
    // Limit weight to between block_reserved_weight and MAX_BLOCK_WEIGHT for sanity:
    // block_reserved_weight can safely exceed -blockmaxweight, but the rest of the block template will be empty.
    options.nBlockMaxWeight = std::clamp<size_t>(options.nBlockMaxWeight, options.block_reserved_weight, MAX_BLOCK_WEIGHT);
    return options;
}

BlockAssembler::BlockAssembler(Chainstate& chainstate, const CTxMemPool* mempool, const Options& options)
    : chainparams{chainstate.m_chainman.GetParams()},
      m_mempool{options.use_mempool ? mempool : nullptr},
      m_chainstate{chainstate},
      m_options{ClampOptions(options)}
{
}

void ApplyArgsManOptions(const ArgsManager& args, BlockAssembler::Options& options)
{
    // Block resource limits
    options.nBlockMaxWeight = args.GetIntArg("-blockmaxweight", options.nBlockMaxWeight);
    if (const auto blockmintxfee{args.GetArg("-blockmintxfee")}) {
        if (const auto parsed{ParseMoney(*blockmintxfee)}) options.blockMinFeeRate = CFeeRate{*parsed};
    }
    options.print_modified_fee = args.GetBoolArg("-printpriority", options.print_modified_fee);
    options.block_reserved_weight = args.GetIntArg("-blockreservedweight", options.block_reserved_weight);
}

void BlockAssembler::resetBlock()
{
    inBlock.clear();
    m_commit_models_in_block.clear();
    m_challenge_models_in_block.clear();

    // Reserve space for fixed-size block header, txs count, and coinbase tx.
    nBlockWeight = m_options.block_reserved_weight;
    nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock()
{
    const auto time_start{SteadyClock::now()};

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());
    CBlock* const pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction. It is skipped by the
    // getblocktemplate RPC and mining interface consumers must not use it.
    pblock->vtx.emplace_back();

    LOCK(::cs_main);
    CBlockIndex* pindexPrev = nullptr;
    if (m_options.prev_block_hash) {
        // Build-ahead: assemble on a specific pending parent one level above the
        // active tip, instead of the tip itself. Enforce the invariant HERE,
        // atomically under cs_main, rather than trusting the caller/selector:
        // the target can go stale between getmininginfo and this call.
        //
        // Enforce the assembler mode in code, not just by caller convention: the
        // parent's UTXO set is NOT the active coins view, so mempool selection
        // and TestBlockValidity (both run against the active chainstate) would be
        // wrong. Build-ahead templates are coinbase-only.
        if (m_mempool != nullptr) {
            throw std::runtime_error(strprintf(
                "%s: build-ahead requires use_mempool=false (parent coins view is not the active one)",
                __func__));
        }
        if (m_options.test_block_validity) {
            throw std::runtime_error(strprintf(
                "%s: build-ahead requires test_block_validity=false (would validate against the active tip)",
                __func__));
        }
        pindexPrev = m_chainstate.m_chainman.m_blockman.LookupBlockIndex(*m_options.prev_block_hash);
        if (pindexPrev == nullptr) {
            throw std::runtime_error(strprintf("%s: build-ahead prev_block_hash %s not found",
                                               __func__, m_options.prev_block_hash->ToString()));
        }
        if (pindexPrev->pprev != m_chainstate.m_chain.Tip()) {
            throw std::runtime_error(strprintf(
                "%s: build-ahead parent %s is not one level above the active tip",
                __func__, m_options.prev_block_hash->ToString()));
        }
        if (pindexPrev->nStatus & BLOCK_FAILED_MASK) {
            throw std::runtime_error(strprintf("%s: build-ahead parent %s is failed",
                                               __func__, m_options.prev_block_hash->ToString()));
        }
        // Recheck the local Full verdict under the same cs_main critical section
        // as template assembly. The selector excludes Red and Amber, but the
        // verdict can change between getmininginfo and this call.
        if (g_ValidationApi != nullptr) {
            const uint8_t own_full{
                g_ValidationApi->GetOwnFullStatus(*m_options.prev_block_hash)};
            if (own_full == static_cast<uint8_t>(ValidationResponseValue::Full_Red) ||
                own_full == static_cast<uint8_t>(ValidationResponseValue::Full_Amber)) {
                throw std::runtime_error(strprintf(
                    "%s: build-ahead parent %s has non-eligible Full status %u",
                    __func__,
                    m_options.prev_block_hash->ToString(),
                    own_full));
            }
        }
    } else {
        pindexPrev = m_chainstate.m_chain.Tip();
    }
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    pblock->nVersion = m_chainstate.m_chainman.m_versionbitscache.ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand()) {
        pblock->nVersion = gArgs.GetIntArg("-blockversion", pblock->nVersion);
    }

    pblock->nTime = TicksSinceEpoch<std::chrono::seconds>(NodeClock::now());
    m_lock_time_cutoff = pindexPrev->GetMedianTimePast();

    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    if (m_mempool) {
        addPackageTxs(nPackagesSelected, nDescendantsUpdated);
    }

    const auto time_1{SteadyClock::now()};

    m_last_block_num_txs = nBlockTx;
    m_last_block_weight = nBlockWeight;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL; // Make sure timelock is enforced.
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = m_options.coinbase_output_script;
    coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
    Assert(nHeight > 0);
    coinbaseTx.nLockTime = static_cast<uint32_t>(nHeight - 1);
    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    pblocktemplate->vchCoinbaseCommitment = m_chainstate.m_chainman.GenerateCoinbaseCommitment(*pblock, pindexPrev);

    LogPrintf("CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d\n", GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
    pblock->nAdjBits       = pblock->nBits;
    pblock->nNonce         = 0;
    pblock->flags          = 0;
    // Ensure model identifier is populated for consensus model validation.
    // Prefer runtime override, then CLI override, then consensus defaults.
    if (pblock->pow.model_identifier.empty()) {
        if (const auto runtime_model = GetMiningModelOverride()) {
            if (!runtime_model->empty()) pblock->pow.model_identifier = *runtime_model;
        }
        if (pblock->pow.model_identifier.empty()) {
            const std::string override_model = gArgs.GetArg("-minermodel", "");
            if (!override_model.empty()) {
                pblock->pow.model_identifier = override_model;
            } else {
                const auto& cons = chainparams.GetConsensus();
                if (!cons.DefaultModelName.empty() && !cons.DefaultModelCommit.empty()) {
                    pblock->pow.model_identifier = cons.DefaultModelName + "@" + cons.DefaultModelCommit;
                }
            }
        }
    }
    // Adjust nAdjBits according to model difficulty if available
    if (g_modeldb && !pblock->pow.model_identifier.empty()) {
        ModelRecord rec;
        const uint256 mid = pblock->pow.GetModelHash();
        if (g_modeldb->ReadModel(mid, rec) && rec.metadata.difficulty > 0) {
            const auto& cons = chainparams.GetConsensus();
            if (auto base_target = DeriveTarget(pblock->nBits, cons.powLimit)) {
                const uint64_t diff = static_cast<uint64_t>(rec.metadata.difficulty);
                const uint64_t norm = cons.ModelDifficultyNormalizer == 0 ? 1 : cons.ModelDifficultyNormalizer;
                arith_uint256 powlim = UintToArith256(cons.powLimit);

                // q = floor(base / diff)
                arith_uint256 q = *base_target;
                arith_uint256 diff_b = arith_uint256(diff);
                q /= diff_b;
                // adj = q * norm (saturate)
                arith_uint256 adj = q;
                if (norm != 0 && adj > (powlim / norm)) {
                    adj = powlim;
                } else {
                    adj *= norm;
                }
                // remainder to improve precision
                arith_uint256 prod = q * diff_b;
                arith_uint256 rem = *base_target;
                rem -= prod;
                uint64_t r64 = rem.GetLow64();
                unsigned __int128 extra = 0;
                if (diff != 0) extra = (static_cast<unsigned __int128>(r64) * norm) / diff;
                if (extra > 0) {
                    if (adj > powlim - (uint64_t)extra) adj = powlim; else adj += (uint64_t)extra;
                }
                pblock->nAdjBits = adj.GetCompact();
            }
        }
    }
    // Populate PoW VDF fields if consensus requires it or test generation is enabled
    {
        const int next_height = pindexPrev->nHeight + 1;
        const bool gen_test_vdf = gArgs.GetBoolArg("-vdfspvgen", false);
        if (chainparams.GetConsensus().IsVdfVdfVerifyActive(next_height) || gen_test_vdf) {
            if (pblock->pow.tick == 0) {
                // Use a minimal test-friendly default tick when not provided.
                pblock->pow.tick = 10;
            }
            if (pblock->pow.vdf.empty()) {
                // Generate a valid Wesolowski proof for the previous block hash.
                // Discriminant size matches verifier default (1024).
                pblock->pow.vdf = vdf::GenerateProofForTesting(pblock->hashPrevBlock, pblock->pow.tick, 1024);
            }
        } else {
            // If VDF is not active, ensure fields don't carry stale values.
            pblock->pow.tick = 0;
            pblock->pow.vdf.clear();
        }
    }

    // Set cumulative tick from previous block plus this block's tick
    {
        const CBlockIndex* prev_index = pindexPrev;
        if (prev_index != nullptr) {
            uint64_t prev_cum{0};
            if (m_options.prev_block_hash) {
                const auto pending_cum{
                    GetBuildAheadParentCumulativeTick(
                        m_chainstate.m_chainman,
                        *m_options.prev_block_hash)};
                if (!pending_cum) {
                    throw std::runtime_error(strprintf(
                        "%s: build-ahead parent %s has no cumulative tick",
                        __func__,
                        m_options.prev_block_hash->ToString()));
                }
                prev_cum = *pending_cum;
            } else {
                CBlock prev_block;
                if (!m_chainstate.m_chainman.m_blockman.ReadBlock(
                        prev_block,
                        *prev_index)) {
                    return nullptr;
                }
                prev_cum = prev_block.cumulative_tick;
            }
            const uint64_t tick{pblock->pow.tick}; // default may be 0
            if (tick > std::numeric_limits<uint64_t>::max() - prev_cum) {
                throw std::runtime_error(strprintf(
                    "%s: cumulative tick overflow for parent %s",
                    __func__,
                    prev_index->GetBlockHash().ToString()));
            }
            pblock->cumulative_tick = prev_cum + tick;
        }
    }

    // Set hashPoW to the appropriate commitment (Merkle root if VDF SPV is active)
    {
        const int nHeight = pindexPrev->nHeight + 1;
        const bool use_merkle = chainparams.GetConsensus().IsVdfSpvActive(nHeight);
        pblock->hashPoW = pblock->pow.GetCommitment(use_merkle);
    }

    BlockValidationState state;
    if (m_options.test_block_validity &&
        !TestBlockValidity(state, chainparams, m_chainstate, *pblock, pindexPrev,
                           /*fCheckApi=*/false, /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false)) {
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, state.ToString()));
    }
    const auto time_2{SteadyClock::now()};

    LogDebug(BCLog::BENCH, "CreateNewBlock() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n",
             Ticks<MillisecondsDouble>(time_1 - time_start), nPackagesSelected, nDescendantsUpdated,
             Ticks<MillisecondsDouble>(time_2 - time_1),
             Ticks<MillisecondsDouble>(time_2 - time_start));

    return std::move(pblocktemplate);
}

void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the block
        if (inBlock.count((*iit)->GetSharedTx()->GetHash())) {
            testSet.erase(iit++);
        } else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost) const
{
    // TODO: switch to weight-based accounting for packages instead of vsize-based accounting.
    if (nBlockWeight + WITNESS_SCALE_FACTOR * packageSize >= m_options.nBlockMaxWeight) {
        return false;
    }
    if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST) {
        return false;
    }
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
bool BlockAssembler::TestPackageTransactions(const CTxMemPool::setEntries& package) const
{
    for (CTxMemPool::txiter it : package) {
        // Absolute locktime (nLockTime) check
        if (!IsFinalTx(it->GetTx(), nHeight, m_lock_time_cutoff)) {
            return false;
        }
        // Relative locktime (BIP68) check when CSV is active: use cached LockPoints
        // from the mempool entry and ensure they are valid at the current tip.
        const int next_height = m_chainstate.m_chain.Height() + 1;
        if (next_height >= m_chainstate.m_chainman.GetConsensus().CSVHeight) {
            LOCK(cs_main);
            const LockPoints& lp = it->GetLockPoints();
            bool ok_seq = false;
            if (TestLockPointValidity(m_chainstate.m_chain, lp)) {
                ok_seq = CheckSequenceLocksAtTip(m_chainstate.m_chain.Tip(), lp);
            }
            if (!ok_seq) {
                // Compute fresh lockpoints against a coins view that includes mempool
                if (m_mempool) {
                    LOCK(m_mempool->cs);
                    CCoinsViewMemPool view{&m_chainstate.CoinsTip(), *m_mempool};
                    auto fresh_lp = CalculateLockPointsAtTip(m_chainstate.m_chain.Tip(), view, it->GetTx());
                    if (!fresh_lp.has_value()) return false;
                    if (!CheckSequenceLocksAtTip(m_chainstate.m_chain.Tip(), *fresh_lp)) return false;
                } else {
                    return false;
                }
            }
        }
    }
    return true;
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
{
    pblocktemplate->block.vtx.emplace_back(iter->GetSharedTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());
    nBlockWeight += iter->GetTxWeight();
    ++nBlockTx;
    nBlockSigOpsCost += iter->GetSigOpCost();
    nFees += iter->GetFee();
    inBlock.insert(iter->GetSharedTx()->GetHash());

    const CTransaction& tx = iter->GetTx();
    if (tx.version == static_cast<int32_t>(Consensus::MODEL_REGISTER_COMMIT_TX_VERSION)) {
        ModelCommitPayload commit_payload;
        if (ParseModelCommitTx(tx, commit_payload) && !commit_payload.model_hash.IsNull()) {
            m_commit_models_in_block.insert(commit_payload.model_hash);
        }
    }

    if (tx.version == static_cast<int32_t>(Consensus::MODEL_CHALLENGE_COMMIT_TX_VERSION)) {
        ModelChallengeCommitPayload commit_payload;
        if (ParseModelChallengeCommitTx(tx, commit_payload) && !commit_payload.model_hash.IsNull()) {
            m_challenge_models_in_block.insert(commit_payload.model_hash);
        }
    }

    if (m_options.print_modified_fee) {
        LogPrintf("fee rate %s txid %s\n",
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

/** Add descendants of given transactions to mapModifiedTx with ancestor
 * state updated assuming given transactions are inBlock. Returns number
 * of updated descendants. */
static int UpdatePackagesForAdded(const CTxMemPool& mempool,
                                  const CTxMemPool::setEntries& alreadyAdded,
                                  indexed_modified_transaction_set& mapModifiedTx) EXCLUSIVE_LOCKS_REQUIRED(mempool.cs)
{
    AssertLockHeld(mempool.cs);

    int nDescendantsUpdated = 0;
    for (CTxMemPool::txiter it : alreadyAdded) {
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in block) into the modified set
        for (CTxMemPool::txiter desc : descendants) {
            if (alreadyAdded.count(desc)) {
                continue;
            }
            ++nDescendantsUpdated;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                mit = mapModifiedTx.insert(modEntry).first;
            }
            mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
        }
    }
    return nDescendantsUpdated;
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries& package, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

bool BlockAssembler::PackageHasApiValidatedCommits(const CTxMemPool::setEntries& package) const
{
    std::unordered_set<uint256, SaltedTxidHasher> package_commit_hashes;
    std::unordered_set<uint256, SaltedTxidHasher> package_challenge_commit_hashes;
    const auto& consensus = chainparams.GetConsensus();

    for (const auto& txit : package) {
        const CTransaction& tx = txit->GetTx();
        if (tx.version == static_cast<int32_t>(Consensus::MODEL_REGISTER_COMMIT_TX_VERSION)) {
            ModelCommitPayload commit_payload;
            if (!ParseModelCommitTx(tx, commit_payload)) {
                return false;
            }

            if (commit_payload.model_hash.IsNull()) {
                return false;
            }

            if (!package_commit_hashes.emplace(commit_payload.model_hash).second) {
                return false;
            }

            if (m_commit_models_in_block.count(commit_payload.model_hash) != 0) {
                return false;
            }

            if (!commit_payload.success) {
                continue;
            }

            if (!g_modeldb || !g_ValidationApi) {
                return false;
            }

            ModelRecord record;
            if (!g_modeldb->ReadModel(commit_payload.model_hash, record)) {
                return false;
            }
            if (record.status == ModelRegistrationStatus::Locked || record.status == ModelRegistrationStatus::Registered || record.status == ModelRegistrationStatus::Banned) {
                return false;
            }

            if (record.deposit_block_height > 0) {
                const uint32_t deadline = static_cast<uint32_t>(record.deposit_block_height) + consensus.ModelVerificationBlockCount;
                if (static_cast<uint32_t>(nHeight) > deadline) {
                    return false;
                }
            }

            ValidationResponseValue status;
            if (!g_ValidationApi->GetRequestStatus(commit_payload.model_hash, ValidationReqType::Model, status)) {
                g_ValidationApi->EnqueueApiRequest(commit_payload.model_hash, record, ValidationReqType::Model);
                return false;
            }

            switch (status) {
            case ValidationResponseValue::Model_OK:
                break;
            default:
                return false;
            }
        } else if (tx.version == static_cast<int32_t>(Consensus::MODEL_CHALLENGE_COMMIT_TX_VERSION)) {
            if (!g_modeldb || !g_ValidationApi) {
                return false;
            }
            ModelChallengeCommitPayload payload;
            if (!ParseModelChallengeCommitTx(tx, payload)) {
                return false;
            }
            if (!package_challenge_commit_hashes.emplace(payload.model_hash).second) {
                return false;
            }
            if (m_challenge_models_in_block.count(payload.model_hash) != 0) {
                return false;
            }
            ModelRecord record;
            if (!g_modeldb->ReadModel(payload.model_hash, record) || record.status != ModelRegistrationStatus::Registered) {
                return false;
            }

            if (record.challenge_deposit_height > 0) {
                const uint32_t deadline = static_cast<uint32_t>(record.challenge_deposit_height) + consensus.ModelChallengeVerdictBlockCount;
                if (static_cast<uint32_t>(nHeight) > deadline) {
                    return false;
                }
            }

            ValidationResponseValue status;
            if (!g_ValidationApi->GetRequestStatus(record.challenge_block_hash, ValidationReqType::Challenge, status)) {
                LOCK(cs_main);
                const CBlockIndex* challenged_index = m_chainstate.m_chainman.m_blockman.LookupBlockIndex(record.challenge_block_hash);
                if (!challenged_index) {
                    return false;
                }

                CBlock challenged_block;
                if (!m_chainstate.m_chainman.m_blockman.ReadBlock(challenged_block, *challenged_index)) {
                    return false;
                }

                g_ValidationApi->EnqueueApiRequest(challenged_block, ValidationReqType::Challenge, ValidationResponseBehavior::Nothing);
                return false;
            }

            switch (status) {
            case ValidationResponseValue::Challenge_OK:
                break;
            default:
                return false;
            }
        } else if (tx.version == static_cast<int32_t>(Consensus::MODEL_ACCUSATION_TX_VERSION)) {
            ModelChallengePayload challenge_payload;
            if (!ParseModelChallengeTx(tx, challenge_payload, consensus)) {
                return false;
            }
        }
    }

    return true;
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BlockAssembler::addPackageTxs(int& nPackagesSelected, int& nDescendantsUpdated)
{
    const auto& mempool{*Assert(m_mempool)};
    LOCK(mempool.cs);

    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    indexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    std::set<Txid> failedTx;

    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;

    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    constexpr int32_t BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000;
    int64_t nConsecutiveFailed = 0;

    while (mi != mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty()) {
        // First try to find a new transaction in mapTx to evaluate.
        //
        // Skip entries in mapTx that are already in a block or are present
        // in mapModifiedTx (which implies that the mapTx ancestor state is
        // stale due to ancestor inclusion in the block)
        // Also skip transactions that we've already failed to add. This can happen if
        // we consider a transaction in mapModifiedTx and it fails: we can then
        // potentially consider it again while walking mapTx.  It's currently
        // guaranteed to fail again, but as a belt-and-suspenders check we put it in
        // failedTx and avoid re-evaluation, since the re-evaluation would be using
        // cached size/sigops/fee values that are not actually correct.
        /** Return true if given transaction from mapTx has already been evaluated,
         * or if the transaction's cached data in mapTx is incorrect. */
        if (mi != mempool.mapTx.get<ancestor_score>().end()) {
            auto it = mempool.mapTx.project<0>(mi);
            assert(it != mempool.mapTx.end());
            if (mapModifiedTx.count(it) || inBlock.count(it->GetSharedTx()->GetHash()) || failedTx.count(it->GetSharedTx()->GetHash())) {
                ++mi;
                continue;
            }
        }

        // Now that mi is not stale, determine which transaction to evaluate:
        // the next entry from mapTx, or the best from mapModifiedTx?
        bool fUsingModified = false;

        modtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();
        if (mi == mempool.mapTx.get<ancestor_score>().end()) {
            // We're out of entries in mapTx; use the entry from mapModifiedTx
            iter = modit->iter;
            fUsingModified = true;
        } else {
            // Try to compare the mapTx entry to the mapModifiedTx entry
            iter = mempool.mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<ancestor_score>().end() &&
                    CompareTxMemPoolEntryByAncestorFee()(*modit, CTxMemPoolModifiedEntry(iter))) {
                // The best entry in mapModifiedTx has higher score
                // than the one from mapTx.
                // Switch which transaction (package) to consider
                iter = modit->iter;
                fUsingModified = true;
            } else {
                // Either no entry in mapModifiedTx, or it's worse than mapTx.
                // Increment mi for the next loop iteration.
                ++mi;
            }
        }

        // We skip mapTx entries that are inBlock, and mapModifiedTx shouldn't
        // contain anything that is inBlock.
        assert(!inBlock.count(iter->GetSharedTx()->GetHash()));

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        int64_t packageSigOpsCost = iter->GetSigOpCostWithAncestors();
        if (fUsingModified) {
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
            packageSigOpsCost = modit->nSigOpCostWithAncestors;
        }

        if (packageFees < m_options.blockMinFeeRate.GetFee(packageSize)) {
            // Everything else we might consider has a lower fee rate
            return;
        }

        if (!TestPackage(packageSize, packageSigOpsCost)) {
            if (fUsingModified) {
                // Since we always look at the best entry in mapModifiedTx,
                // we must erase failed entries so that we can consider the
                // next best entry on the next loop iteration
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter->GetSharedTx()->GetHash());
            }

            ++nConsecutiveFailed;

            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight >
                    m_options.nBlockMaxWeight - BLOCK_FULL_ENOUGH_WEIGHT_DELTA) {
                // Give up if we're close to full and haven't succeeded in a while
                break;
            }
            continue;
        }

        auto ancestors{mempool.AssumeCalculateMemPoolAncestors(__func__, *iter, CTxMemPool::Limits::NoLimits(), /*fSearchForParents=*/false)};

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        if (!PackageHasApiValidatedCommits(ancestors)) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
            }
            failedTx.insert(iter->GetSharedTx()->GetHash());
            continue;
        }

        // Test if all tx's are Final
        if (!TestPackageTransactions(ancestors)) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter->GetSharedTx()->GetHash());
            }
            continue;
        }

        // This transaction will make it in; reset the failed counter.
        nConsecutiveFailed = 0;

        // Package can be added. Sort the entries in a valid order.
        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(ancestors, sortedEntries);

        for (size_t i = 0; i < sortedEntries.size(); ++i) {
            AddToBlock(sortedEntries[i]);
            // Erase from the modified set, if present
            mapModifiedTx.erase(sortedEntries[i]);
        }

        ++nPackagesSelected;
        pblocktemplate->m_package_feerates.emplace_back(packageFees, static_cast<int32_t>(packageSize));

        // Update transactions that depend on each of these
        nDescendantsUpdated += UpdatePackagesForAdded(mempool, ancestors, mapModifiedTx);
    }
}

void AddMerkleRootAndCoinbase(CBlock& block, CTransactionRef coinbase, uint32_t version, uint32_t timestamp, uint32_t nonce)
{
    if (block.vtx.size() == 0) {
        block.vtx.emplace_back(coinbase);
    } else {
        block.vtx[0] = coinbase;
    }
    block.nVersion = version;
    block.nTime = timestamp;
    block.nNonce = nonce;
    block.hashMerkleRoot = BlockMerkleRoot(block);
}

std::unique_ptr<CBlockTemplate> WaitAndCreateNewBlock(ChainstateManager& chainman,
                                                      KernelNotifications& kernel_notifications,
                                                      CTxMemPool* mempool,
                                                      const std::unique_ptr<CBlockTemplate>& block_template,
                                                      const BlockWaitOptions& options,
                                                      const BlockAssembler::Options& assemble_options)
{
    // Delay calculating the current template fees, just in case a new block
    // comes in before the next tick.
    CAmount current_fees = -1;

    // Alternate waiting for a new tip and checking if fees have risen.
    // The latter check is expensive so we only run it once per second.
    auto now{NodeClock::now()};
    const auto deadline = now + options.timeout;
    const MillisecondsDouble tick{1000};
    const bool allow_min_difficulty{chainman.GetParams().GetConsensus().fPowAllowMinDifficultyBlocks};

    do {
        bool tip_changed{false};
        {
            WAIT_LOCK(kernel_notifications.m_tip_block_mutex, lock);
            // Note that wait_until() checks the predicate before waiting
            kernel_notifications.m_tip_block_cv.wait_until(lock, std::min(now + tick, deadline), [&]() EXCLUSIVE_LOCKS_REQUIRED(kernel_notifications.m_tip_block_mutex) {
                AssertLockHeld(kernel_notifications.m_tip_block_mutex);
                const auto tip_block{kernel_notifications.TipBlock()};
                // We assume tip_block is set, because this is an instance
                // method on BlockTemplate and no template could have been
                // generated before a tip exists.
                tip_changed = Assume(tip_block) && tip_block != block_template->block.hashPrevBlock;
                return tip_changed || chainman.m_interrupt;
            });
        }

        if (chainman.m_interrupt) return nullptr;
        // At this point the tip changed, a full tick went by or we reached
        // the deadline.

        // Must release m_tip_block_mutex before locking cs_main, to avoid deadlocks.
        LOCK(::cs_main);

        // On test networks return a minimum difficulty block after 20 minutes
        if (!tip_changed && allow_min_difficulty) {
            const NodeClock::time_point tip_time{std::chrono::seconds{chainman.ActiveChain().Tip()->GetBlockTime()}};
            if (now > tip_time + 20min) {
                tip_changed = true;
            }
        }

        /**
         * We determine if fees increased compared to the previous template by generating
         * a fresh template. There may be more efficient ways to determine how much
         * (approximate) fees for the next block increased, perhaps more so after
         * Cluster Mempool.
         *
         * We'll also create a new template if the tip changed during this iteration.
         */
        if (options.fee_threshold < MAX_MONEY || tip_changed) {
            auto new_tmpl{BlockAssembler{
                chainman.ActiveChainstate(),
                mempool,
                assemble_options}
                              .CreateNewBlock()};

            // If the tip changed, return the new template regardless of its fees.
            if (tip_changed) return new_tmpl;

            // Calculate the original template total fees if we haven't already
            if (current_fees == -1) {
                current_fees = 0;
                for (CAmount fee : block_template->vTxFees) {
                    current_fees += fee;
                }
            }

            CAmount new_fees = 0;
            for (CAmount fee : new_tmpl->vTxFees) {
                new_fees += fee;
                Assume(options.fee_threshold != MAX_MONEY);
                if (new_fees >= current_fees + options.fee_threshold) return new_tmpl;
            }
        }

        now = NodeClock::now();
    } while (now < deadline);

    return nullptr;
}

std::optional<BlockRef> GetTip(ChainstateManager& chainman)
{
    LOCK(::cs_main);
    CBlockIndex* tip{chainman.ActiveChain().Tip()};
    if (!tip) return {};
    return BlockRef{tip->GetBlockHash(), tip->nHeight};
}

std::optional<BlockRef> WaitTipChanged(ChainstateManager& chainman, KernelNotifications& kernel_notifications, const uint256& current_tip, MillisecondsDouble& timeout)
{
    Assume(timeout >= 0ms); // No internal callers should use a negative timeout
    if (timeout < 0ms) timeout = 0ms;
    if (timeout > std::chrono::years{100}) timeout = std::chrono::years{100}; // Upper bound to avoid UB in std::chrono
    auto deadline{std::chrono::steady_clock::now() + timeout};
    {
        WAIT_LOCK(kernel_notifications.m_tip_block_mutex, lock);
        // For callers convenience, wait longer than the provided timeout
        // during startup for the tip to be non-null. That way this function
        // always returns valid tip information when possible and only
        // returns null when shutting down, not when timing out.
        kernel_notifications.m_tip_block_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(kernel_notifications.m_tip_block_mutex) {
            return kernel_notifications.TipBlock() || chainman.m_interrupt;
        });
        if (chainman.m_interrupt) return {};
        // At this point TipBlock is set, so continue to wait until it is
        // different then `current_tip` provided by caller.
        kernel_notifications.m_tip_block_cv.wait_until(lock, deadline, [&]() EXCLUSIVE_LOCKS_REQUIRED(kernel_notifications.m_tip_block_mutex) {
            return Assume(kernel_notifications.TipBlock()) != current_tip || chainman.m_interrupt;
        });
    }
    if (chainman.m_interrupt) return {};

    // Must release m_tip_block_mutex before getTip() locks cs_main, to
    // avoid deadlocks.
    return GetTip(chainman);
}
} // namespace node
