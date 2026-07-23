// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <init.h>

#include <kernel/checks.h>

#include <addrman.h>
#include <banman.h>
#include <blockfilter.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/system.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <deploymentstatus.h>
#include <hash.h>
#include <httprpc.h>
#include <httpserver.h>
#include <index/blockfilterindex.h>
#include <index/coinstatsindex.h>
#include <index/icu_acceptance_index.h>
#include <index/txindex.h>
#include <init/common.h>
#include <interfaces/chain.h>
#include <interfaces/init.h>
#include <interfaces/ipc.h>
#include <interfaces/mining.h>
#include <interfaces/node.h>
#include <net_processing.h>
#include <kernel/caches.h>
#include <kernel/context.h>
#include <key.h>
#include <logging.h>
#include <mapport.h>
#include <modeldb.h>
#include <net.h>
#include <net_permissions.h>
#include <net_processing.h>
#include <netbase.h>
#include <netgroup.h>
#include <node/blockmanager_args.h>
#include <node/blockstorage.h>
#include <node/caches.h>
#include <node/chainstate.h>
#include <node/chainstatemanager_args.h>
#include <node/context.h>
#include <node/extapi.h>
#include <node/interface_ui.h>
#include <node/kernel_notifications.h>
#include <node/mempool_args.h>
#include <node/mempool_persist.h>
#include <node/mempool_persist_args.h>
#include <node/miner.h>
#include <node/peerman_args.h>
#include <policy/feerate.h>
#include <policy/fees.h>
#include <policy/fees_args.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <protocol.h>
#include <rpc/blockchain.h>
#include <rpc/register.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <scheduler.h>
#include <script/sigcache.h>
#include <sync.h>
#include <torcontrol.h>
#include <txdb.h>
#include <txmempool.h>
#include <util/asmap.h>
#include <util/batchpriority.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/moneystr.h>
#include <util/result.h>
#include <util/signalinterrupt.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/syserror.h>
#include <util/thread.h>
#include <util/threadnames.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <validationadvisory.h>
#include <validationapi.h>
#include <validationapi_mock.h>
#include <validationinterface.h>
#include <verification/pow_v3.h>
#include <wallet/rpc/api_model_registration.h>
#include <walletinitinterface.h>

#include <algorithm>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <functional>
#include <limits>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifndef WIN32
#include <cerrno>
#include <signal.h>
#include <sys/stat.h>
#endif

#include <boost/signals2/signal.hpp>

#ifdef ENABLE_ZMQ
#include <zmq/zmqabstractnotifier.h>
#include <zmq/zmqnotificationinterface.h>
#include <zmq/zmqrpc.h>
#endif

using common::AmountErrMsg;
using common::InvalidPortErrMsg;
using common::ResolveErrMsg;

using node::ApplyArgsManOptions;
using node::BlockManager;
using node::CalculateCacheSizes;
using node::ChainstateLoadResult;
using node::ChainstateLoadStatus;
using node::DEFAULT_PERSIST_MEMPOOL;
using node::DEFAULT_PRINT_MODIFIED_FEE;
using node::DEFAULT_STOPATHEIGHT;
using node::DumpMempool;
using node::ImportBlocks;
using node::KernelNotifications;
using node::LoadChainstate;
using node::LoadMempool;
using node::MempoolPath;
using node::NodeContext;
using node::ShouldPersistMempool;
using node::VerifyLoadedChainstate;
using util::Join;
using util::ReplaceAll;
using util::ToString;

static const uint256 MODELDB_CHALLENGE_BURN_SENTINEL{"00004348414c4c454e47455f4255524e53454e54494e454c0000000000000000"};

static constexpr bool DEFAULT_PROXYRANDOMIZE{true};
static constexpr bool DEFAULT_REST_ENABLE{false};
static constexpr bool DEFAULT_I2P_ACCEPT_INCOMING{true};
static constexpr bool DEFAULT_STOPAFTERBLOCKIMPORT{false};

#ifdef WIN32
// Win32 LevelDB doesn't use filedescriptors, and the ones used for
// accessing block files don't count towards the fd_set size limit
// anyway.
#define MIN_LEVELDB_FDS 0
#else
#define MIN_LEVELDB_FDS 150
#endif

static constexpr int MIN_CORE_FDS = MIN_LEVELDB_FDS + NUM_FDS_MESSAGE_CAPTURE;
static const char* DEFAULT_ASMAP_FILENAME="ip_asn.map";

/**
 * The PID file facilities.
 */
static const char* BITCOIN_PID_FILENAME = "bitcoind.pid";
/**
 * True if this process has created a PID file.
 * Used to determine whether we should remove the PID file on shutdown.
 */
static bool g_generated_pid{false};

static fs::path GetPidFile(const ArgsManager& args)
{
    return AbsPathForConfigVal(args, args.GetPathArg("-pid", BITCOIN_PID_FILENAME));
}

[[nodiscard]] static bool CreatePidFile(const ArgsManager& args)
{
    if (args.IsArgNegated("-pid")) return true;

    std::ofstream file{GetPidFile(args)};
    if (file) {
#ifdef WIN32
        tfm::format(file, "%d\n", GetCurrentProcessId());
#else
        tfm::format(file, "%d\n", getpid());
#endif
        g_generated_pid = true;
        return true;
    } else {
        return InitError(strprintf(_("Unable to create the PID file '%s': %s"), fs::PathToString(GetPidFile(args)), SysErrorString(errno)));
    }
}

static void RemovePidFile(const ArgsManager& args)
{
    if (!g_generated_pid) return;
    const auto pid_path{GetPidFile(args)};
    if (std::error_code error; !fs::remove(pid_path, error)) {
        std::string msg{error ? error.message() : "File does not exist"};
        LogPrintf("Unable to remove PID file (%s): %s\n", fs::PathToString(pid_path), msg);
    }
}

static std::optional<util::SignalInterrupt> g_shutdown;

void InitContext(NodeContext& node)
{
    assert(!g_shutdown);
    g_shutdown.emplace();

    node.args = &gArgs;
    node.shutdown_signal = &*g_shutdown;
    node.shutdown_request = [&node] {
        assert(node.shutdown_signal);
        if (!(*node.shutdown_signal)()) return false;
        // Wake any threads that may be waiting for the tip to change.
        if (node.notifications) WITH_LOCK(node.notifications->m_tip_block_mutex, node.notifications->m_tip_block_cv.notify_all());
        return true;
    };
}

//////////////////////////////////////////////////////////////////////////////
//
// Shutdown
//

//
// Thread management and startup/shutdown:
//
// The network-processing threads are all part of a thread group
// created by AppInit() or the Qt main() function.
//
// A clean exit happens when the SignalInterrupt object is triggered, which
// makes the main thread's SignalInterrupt::wait() call return, and join all
// other ongoing threads in the thread group to the main thread.
// Shutdown() is then called to clean up database connections, and stop other
// threads that should only be stopped after the main network-processing
// threads have exited.
//
// Shutdown for Qt is very similar, only it uses a QTimer to detect
// ShutdownRequested() getting set, and then does the normal Qt
// shutdown thing.
//

bool ShutdownRequested(node::NodeContext& node)
{
    return bool{*Assert(node.shutdown_signal)};
}

#if HAVE_SYSTEM
static void ShutdownNotify(const ArgsManager& args)
{
    std::vector<std::thread> threads;
    for (const auto& cmd : args.GetArgs("-shutdownnotify")) {
        threads.emplace_back(runCommand, cmd);
    }
    for (auto& t : threads) {
        t.join();
    }
}
#endif

void Interrupt(NodeContext& node)
{
#if HAVE_SYSTEM
    ShutdownNotify(*node.args);
#endif
    InterruptHTTPServer();
    InterruptHTTPRPC();
    InterruptRPC();
    InterruptREST();
    InterruptTorControl();
    InterruptMapPort();
    if (node.connman)
        node.connman->Interrupt();
    for (auto* index : node.indexes) {
        index->Interrupt();
    }
}

void Shutdown(NodeContext& node)
{
    static Mutex g_shutdown_mutex;
    TRY_LOCK(g_shutdown_mutex, lock_shutdown);
    if (!lock_shutdown) return;
    LogPrintf("%s: In progress...\n", __func__);
    Assert(node.args);

    /// Note: Shutdown() must be able to handle cases in which initialization failed part of the way,
    /// for example if the data directory was found to be locked.
    /// Be sure that anything that writes files or flushes caches only does this if the respective
    /// module was initialized.
    util::ThreadRename("shutoff");
    if (node.mempool) node.mempool->AddTransactionsUpdated(1);

    StopHTTPRPC();
    StopREST();
    StopRPC();
    StopHTTPServer();
    StopMapPort();

    // Because these depend on each-other, we make sure that neither can be
    // using the other before destroying them.
    if (node.peerman && node.validation_signals) node.validation_signals->UnregisterValidationInterface(node.peerman.get());
    if (node.connman) node.connman->Stop();

    StopTorControl();

    if (node.background_init_thread.joinable()) node.background_init_thread.join();
    // ValidationAPI owns worker threads and keeps references to chainman and
    // connman. Destroy it after network/background processing has stopped,
    // but before either referenced object is released. Leaving this to static
    // destruction can hang process exit on an in-flight HTTP status request
    // and risks accessing an already-destroyed chainman.
    g_ValidationApi.reset();
    // The reorg-gate hooks reference the scheduler and chainman; drop them
    // before either is torn down. Pending gates/vetoes are in-memory only and
    // die with the process (a restart may re-prompt but never auto-accepts).
    GetReorgGatingManager().ResetAsyncHooks();
    // After everything has been shut down, but before things get flushed, stop the
    // the scheduler. After this point, SyncWithValidationInterfaceQueue() should not be called anymore
    // as this would prevent the shutdown from completing.
    if (node.scheduler) node.scheduler->stop();

    // Stop the advisory worker pool to ensure clean shutdown of background threads.
    StopAdvisoryWorkerPool();

    // After the threads that potentially access these pointers have been stopped,
    // destruct and reset all to nullptr.
    // connman must be destroyed before peerman: ~CConnman() calls Stop() which
    // invokes m_msgproc->FinalizeNode() — m_msgproc points to peerman.
    node.connman.reset();
    node.peerman.reset();
    node.banman.reset();
    node.addrman.reset();
    node.netgroupman.reset();

    if (node.mempool && node.mempool->GetLoadTried() && ShouldPersistMempool(*node.args)) {
        DumpMempool(*node.mempool, MempoolPath(*node.args));
    }

    // Drop transactions we were still watching, record fee estimations and unregister
    // fee estimator from validation interface.
    if (node.fee_estimator) {
        node.fee_estimator->Flush();
        if (node.validation_signals) {
            node.validation_signals->UnregisterValidationInterface(node.fee_estimator.get());
        }
    }

    // FlushStateToDisk generates a ChainStateFlushed callback, which we should avoid missing
    if (node.chainman) {
        LOCK(cs_main);
        for (Chainstate* chainstate : node.chainman->GetAll()) {
            if (chainstate->CanFlushToDisk()) {
                chainstate->ForceFlushStateToDisk();
            }
        }
    }

    // After there are no more peers/RPC left to give us new data which may generate
    // CValidationInterface callbacks, flush them...
    if (node.validation_signals) node.validation_signals->FlushBackgroundCallbacks();

    // Stop and delete all indexes only after flushing background callbacks.
    for (auto* index : node.indexes) index->Stop();
    if (g_txindex) g_txindex.reset();
    if (g_icu_acceptance_index) g_icu_acceptance_index.reset();
    if (g_coin_stats_index) g_coin_stats_index.reset();
    DestroyAllBlockFilterIndexes();
    node.indexes.clear(); // all instances are nullptr now

    // Any future callbacks will be dropped. This should absolutely be safe - if
    // missing a callback results in an unrecoverable situation, unclean shutdown
    // would too. The only reason to do the above flushes is to let the wallet catch
    // up with our current chain to avoid any strange pruning edge cases and make
    // next startup faster by avoiding rescan.

    if (node.chainman) {
        LOCK(cs_main);
        for (Chainstate* chainstate : node.chainman->GetAll()) {
            if (chainstate->CanFlushToDisk()) {
                chainstate->ForceFlushStateToDisk();
                chainstate->ResetCoinsViews();
            }
        }
    }
    for (const auto& client : node.chain_clients) {
        client->stop();
    }

#ifdef ENABLE_ZMQ
    if (g_zmq_notification_interface) {
        if (node.validation_signals) node.validation_signals->UnregisterValidationInterface(g_zmq_notification_interface.get());
        g_zmq_notification_interface.reset();
    }
#endif

    node.chain_clients.clear();
    if (node.validation_signals) {
        node.validation_signals->UnregisterAllValidationInterfaces();
    }
    node.mempool.reset();
    node.fee_estimator.reset();
    node.chainman.reset();
    node.validation_signals.reset();
    node.scheduler.reset();
    node.ecc_context.reset();
    node.kernel.reset();

    RemovePidFile(*node.args);

    LogPrintf("%s: done\n", __func__);
}

/**
 * Signal handlers are very limited in what they are allowed to do.
 * The execution context the handler is invoked in is not guaranteed,
 * so we restrict handler operations to just touching variables:
 */
#ifndef WIN32
static void HandleSIGTERM(int)
{
    // Return value is intentionally ignored because there is not a better way
    // of handling this failure in a signal handler.
    (void)(*Assert(g_shutdown))();
}

static void HandleSIGHUP(int)
{
    LogInstance().m_reopen_file = true;
}
#else
static BOOL WINAPI consoleCtrlHandler(DWORD dwCtrlType)
{
    if (!(*Assert(g_shutdown))()) {
        LogError("Failed to send shutdown signal on Ctrl-C\n");
        return false;
    }
    Sleep(INFINITE);
    return true;
}
#endif

#ifndef WIN32
static void registerSignalHandler(int signal, void(*handler)(int))
{
    struct sigaction sa;
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(signal, &sa, nullptr);
}
#endif

void SetupServerArgs(ArgsManager& argsman, bool can_listen_ipc)
{
    SetupHelpOptions(argsman);
    argsman.AddArg("-help-debug", "Print help message with debugging options and exit", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST); // server-only for now

    init::AddLoggingArgs(argsman);

    const auto defaultBaseParams = CreateBaseChainParams(ChainType::MAIN);
    const auto testnetBaseParams = CreateBaseChainParams(ChainType::TESTNET);
    const auto testnet4BaseParams = CreateBaseChainParams(ChainType::TESTNET4);
    const auto signetBaseParams = CreateBaseChainParams(ChainType::SIGNET);
    const auto regtestBaseParams = CreateBaseChainParams(ChainType::REGTEST);
    const auto tensorMainBaseParams = CreateBaseChainParams(ChainType::TENSOR_MAIN);
    const auto tensorTestBaseParams = CreateBaseChainParams(ChainType::TENSOR_TEST);
    const auto tensorRegBaseParams = CreateBaseChainParams(ChainType::TENSOR_REG);
    const auto defaultChainParams = CreateChainParams(argsman, ChainType::MAIN);
    const auto testnetChainParams = CreateChainParams(argsman, ChainType::TESTNET);
    const auto testnet4ChainParams = CreateChainParams(argsman, ChainType::TESTNET4);
    const auto signetChainParams = CreateChainParams(argsman, ChainType::SIGNET);
    const auto regtestChainParams = CreateChainParams(argsman, ChainType::REGTEST);
    const auto tensorMainChainParams = CreateChainParams(argsman, ChainType::TENSOR_MAIN);
    const auto tensorTestChainParams = CreateChainParams(argsman, ChainType::TENSOR_TEST);
    const auto tensorRegChainParams = CreateChainParams(argsman, ChainType::TENSOR_REG);

    // Hidden Options
    std::vector<std::string> hidden_args = {
        "-dbcrashratio", "-forcecompactdb",
        // GUI args. These will be overwritten by SetupUIArgs for the GUI
        "-choosedatadir", "-lang=<lang>", "-min", "-resetguisettings", "-splash", "-uiplatform"};

    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
#if HAVE_SYSTEM
    argsman.AddArg("-alertnotify=<cmd>", "Execute command when an alert is raised (%s in cmd is replaced by message)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
#endif
    argsman.AddArg("-assumevalid=<hex>", strprintf("If this block is in the chain assume that it and its ancestors are valid and potentially skip their script verification (0 to verify all, default: %s, testnet3: %s, testnet4: %s, signet: %s)", defaultChainParams->GetConsensus().defaultAssumeValid.GetHex(), testnetChainParams->GetConsensus().defaultAssumeValid.GetHex(), testnet4ChainParams->GetConsensus().defaultAssumeValid.GetHex(), signetChainParams->GetConsensus().defaultAssumeValid.GetHex()), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-blocksdir=<dir>", "Specify directory to hold blocks subdirectory for *.dat files (default: <datadir>)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-blocksxor",
                   strprintf("Whether an XOR-key applies to blocksdir *.dat files. "
                             "The created XOR-key will be zeros for an existing blocksdir or when `-blocksxor=0` is "
                             "set, and random for a freshly initialized blocksdir. "
                             "(default: %u)",
                             kernel::DEFAULT_XOR_BLOCKSDIR),
                   ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-fastprune", "Use smaller block files and lower minimum prune height for testing purposes", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
#if HAVE_SYSTEM
    argsman.AddArg("-blocknotify=<cmd>", "Execute command when the best block changes (%s in cmd is replaced by block hash)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reorgadvisorynotify=<cmd>", "Execute command when a deep reorg advisory is triggered (%d=depth, %h=lca_height, %f=fork_depth, %o=overlap_pct)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
#endif
    argsman.AddArg("-blockreconstructionextratxn=<n>", strprintf("Extra transactions to keep in memory for compact block reconstructions (default: %u)", DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-blocksonly", strprintf("Whether to reject transactions from network peers. Disables automatic broadcast and rebroadcast of transactions, unless the source peer has the 'forcerelay' permission. RPC transactions are not affected. (default: %u)", DEFAULT_BLOCKSONLY), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-peermanmaxheadersresult=<n>", strprintf("Maximum number of headers processed per getheaders response (test-only, default: %u)", MAX_HEADERS_RESULTS), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-coinstatsindex", strprintf("Maintain coinstats index used by the gettxoutsetinfo RPC (default: %u)", DEFAULT_COINSTATSINDEX), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-conf=<file>", strprintf("Specify path to read-only configuration file. Relative paths will be prefixed by datadir location (only useable from command line, not configuration file) (default: %s)", BITCOIN_CONF_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-datadir=<dir>", "Specify data directory", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::OPTIONS);
    argsman.AddArg("-dbbatchsize", strprintf("Maximum database write batch size in bytes (default: %u)", nDefaultDbBatchSize), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::OPTIONS);
    argsman.AddArg("-dbcache=<n>", strprintf("Maximum database cache size <n> MiB (minimum %d, default: %d). Make sure you have enough RAM. In addition, unused memory allocated to the mempool is shared with this cache (see -maxmempool).", MIN_DB_CACHE >> 20, DEFAULT_DB_CACHE >> 20), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-includeconf=<file>", "Specify additional configuration file, relative to the -datadir path (only useable from configuration file, not command line)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-allowignoredconf", strprintf("For backwards compatibility, treat an unused %s file in the datadir as a warning, not an error.", BITCOIN_CONF_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-loadblock=<file>", "Imports blocks from external file on startup", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-maxmempool=<n>", strprintf("Keep the transaction memory pool below <n> megabytes (default: %u)", DEFAULT_MAX_MEMPOOL_SIZE_MB), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-maxorphantx=<n>", strprintf("Keep at most <n> unconnectable transactions in memory (default: %u)", DEFAULT_MAX_ORPHAN_TRANSACTIONS), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-mempoolexpiry=<n>", strprintf("Do not keep transactions in the mempool longer than <n> hours (default: %u)", DEFAULT_MEMPOOL_EXPIRY_HOURS), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-minimumchainwork=<hex>", strprintf("Minimum work assumed to exist on a valid chain in hex (default: %s, testnet3: %s, testnet4: %s, signet: %s)", defaultChainParams->GetConsensus().nMinimumChainWork.GetHex(), testnetChainParams->GetConsensus().nMinimumChainWork.GetHex(), testnet4ChainParams->GetConsensus().nMinimumChainWork.GetHex(), signetChainParams->GetConsensus().nMinimumChainWork.GetHex()), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::OPTIONS);
    argsman.AddArg("-par=<n>", strprintf("Set the number of script verification threads (0 = auto, up to %d, <0 = leave that many cores free, default: %d)",
        MAX_SCRIPTCHECK_THREADS, DEFAULT_SCRIPTCHECK_THREADS), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-persistmempool", strprintf("Whether to save the mempool on shutdown and load on restart (default: %u)", DEFAULT_PERSIST_MEMPOOL), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-persistmempoolv1",
                   strprintf("Whether a mempool.dat file created by -persistmempool or the savemempool RPC will be written in the legacy format "
                             "(version 1) or the current format (version 2). This temporary option will be removed in the future. (default: %u)",
                             DEFAULT_PERSIST_V1_DAT),
                   ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-pid=<file>", strprintf("Specify pid file. Relative paths will be prefixed by a net-specific datadir location. (default: %s)", BITCOIN_PID_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-prune=<n>", strprintf("Reduce storage requirements by enabling pruning (deleting) of old blocks. This allows the pruneblockchain RPC to be called to delete specific blocks and enables automatic pruning of old blocks if a target size in MiB is provided. This mode is incompatible with -txindex. "
            "Warning: Reverting this setting requires re-downloading the entire blockchain. "
            "(default: 0 = disable pruning blocks, 1 = allow manual pruning via RPC, >=%u = automatically prune block files to stay under the specified target size in MiB)", MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reindex", "If enabled, wipe chain state and block index, and rebuild them from blk*.dat files on disk. Also wipe and rebuild other optional indexes that are active. If an assumeutxo snapshot was loaded, its chainstate will be wiped as well. The snapshot can then be reloaded via RPC.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reindex-chainstate", "If enabled, wipe chain state, and rebuild it from blk*.dat files on disk. If an assumeutxo snapshot was loaded, its chainstate will be wiped as well. The snapshot can then be reloaded via RPC.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-settings=<file>", strprintf("Specify path to dynamic settings data file. Can be disabled with -nosettings. File is written at runtime and not meant to be edited by users (use %s instead for custom settings). Relative paths will be prefixed by datadir location. (default: %s)", BITCOIN_CONF_FILENAME, BITCOIN_SETTINGS_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
#if HAVE_SYSTEM
    argsman.AddArg("-startupnotify=<cmd>", "Execute command on startup.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-shutdownnotify=<cmd>", "Execute command immediately before beginning shutdown. The need for shutdown may be urgent, so be careful not to delay it long (if the command doesn't require interaction with the server, consider having it fork into the background).", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
#endif
    argsman.AddArg("-txindex", strprintf("Maintain a full transaction index, used by the getrawtransaction rpc call (default: %u)", DEFAULT_TXINDEX), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-icuacceptanceindex", strprintf("Maintain an index of on-chain ICU acceptance (0x40) records by asset_id, so icu.acceptance.record.list avoids a full block scan (default: %u)", DEFAULT_ICU_ACCEPTANCE_INDEX), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-blockfilterindex=<type>",
                 strprintf("Maintain an index of compact filters by block (default: %s, values: %s).", DEFAULT_BLOCKFILTERINDEX, ListBlockFilterTypes()) +
                 " If <type> is not supplied or if <type> = 1, indexes for all known types are enabled.",
                 ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    argsman.AddArg("-addnode=<ip>", strprintf("Add a node to connect to and attempt to keep the connection open (see the addnode RPC help for more info). This option can be specified multiple times to add multiple nodes; connections are limited to %u at a time and are counted separately from the -maxconnections limit.", MAX_ADDNODE_CONNECTIONS), ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::CONNECTION);
    argsman.AddArg("-asmap=<file>", strprintf("Specify asn mapping used for bucketing of the peers (default: %s). Relative paths will be prefixed by the net-specific datadir location.", DEFAULT_ASMAP_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-bantime=<n>", strprintf("Default duration (in seconds) of manually configured bans (default: %u)", DEFAULT_MISBEHAVING_BANTIME), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-bind=<addr>[:<port>][=onion]", strprintf("Bind to given address and always listen on it (default: 0.0.0.0). Use [host]:port notation for IPv6. Append =onion to tag any incoming connections to that address and port as incoming Tor connections (default: 127.0.0.1:%u=onion, testnet3: 127.0.0.1:%u=onion, testnet4: 127.0.0.1:%u=onion, signet: 127.0.0.1:%u=onion, regtest: 127.0.0.1:%u=onion)", defaultChainParams->GetDefaultPort() + 1, testnetChainParams->GetDefaultPort() + 1, testnet4ChainParams->GetDefaultPort() + 1, signetChainParams->GetDefaultPort() + 1, regtestChainParams->GetDefaultPort() + 1), ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::CONNECTION);
    argsman.AddArg("-cjdnsreachable", "If set, then this host is configured for CJDNS (connecting to fc00::/8 addresses would lead us to the CJDNS network, see doc/cjdns.md) (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-connect=<ip>", "Connect only to the specified node; -noconnect disables automatic connections (the rules for this peer are the same as for -addnode). This option can be specified multiple times to connect to multiple nodes.", ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::CONNECTION);
    argsman.AddArg("-discover", "Discover own IP addresses (default: 1 when listening and no -externalip or -proxy)", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-dns", strprintf("Allow DNS lookups for -addnode, -seednode and -connect (default: %u)", DEFAULT_NAME_LOOKUP), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-dnsseed", strprintf("Query for peer addresses via DNS lookup, if low on addresses (default: %u unless -connect used or -maxconnections=0)", DEFAULT_DNSSEED), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-externalip=<ip>", "Specify your own public address", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-fixedseeds", strprintf("Allow fixed seeds if DNS seeds don't provide peers (default: %u)", DEFAULT_FIXEDSEEDS), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-forcednsseed", strprintf("Always query for peer addresses via DNS lookup (default: %u)", DEFAULT_FORCEDNSSEED), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-listen", strprintf("Accept connections from outside (default: %u if no -proxy, -connect or -maxconnections=0)", DEFAULT_LISTEN), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-listenonion", strprintf("Automatically create Tor onion service (default: %d)", DEFAULT_LISTEN_ONION), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-maxconnections=<n>", strprintf("Maintain at most <n> automatic connections to peers (default: %u). This limit does not apply to connections manually added via -addnode or the addnode RPC, which have a separate limit of %u.", DEFAULT_MAX_PEER_CONNECTIONS, MAX_ADDNODE_CONNECTIONS), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-maxreceivebuffer=<n>", strprintf("Maximum per-connection receive buffer, <n>*1000 bytes (default: %u)", DEFAULT_MAXRECEIVEBUFFER), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-maxsendbuffer=<n>", strprintf("Maximum per-connection memory usage for the send buffer, <n>*1000 bytes (default: %u)", DEFAULT_MAXSENDBUFFER), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-maxuploadtarget=<n>", strprintf("Tries to keep outbound traffic under the given target per 24h. Limit does not apply to peers with 'download' permission or blocks created within past week. 0 = no limit (default: %s). Optional suffix units [k|K|m|M|g|G|t|T] (default: M). Lowercase is 1000 base while uppercase is 1024 base", DEFAULT_MAX_UPLOAD_TARGET), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
#ifdef HAVE_SOCKADDR_UN
    argsman.AddArg("-onion=<ip:port|path>", "Use separate SOCKS5 proxy to reach peers via Tor onion services, set -noonion to disable (default: -proxy). May be a local file path prefixed with 'unix:'.", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
#else
    argsman.AddArg("-onion=<ip:port>", "Use separate SOCKS5 proxy to reach peers via Tor onion services, set -noonion to disable (default: -proxy)", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
#endif
    argsman.AddArg("-i2psam=<ip:port>", "I2P SAM proxy to reach I2P peers and accept I2P connections (default: none)", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-i2pacceptincoming", strprintf("Whether to accept inbound I2P connections (default: %i). Ignored if -i2psam is not set. Listening for inbound I2P connections is done through the SAM proxy, not by binding to a local address and port.", DEFAULT_I2P_ACCEPT_INCOMING), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-onlynet=<net>", "Make automatic outbound connections only to network <net> (" + Join(GetNetworkNames(), ", ") + "). Inbound and manual connections are not affected by this option. It can be specified multiple times to allow multiple networks.", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-v2transport", strprintf("Support v2 transport (default: %u)", DEFAULT_V2_TRANSPORT), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-peerbloomfilters", strprintf("Support filtering of blocks and transaction with bloom filters (default: %u)", DEFAULT_PEERBLOOMFILTERS), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-peerblockfilters", strprintf("Serve compact block filters to peers per BIP 157 (default: %u)", DEFAULT_PEERBLOCKFILTERS), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-txreconciliation", strprintf("Enable transaction reconciliations per BIP 330 (default: %d)", DEFAULT_TXRECONCILIATION_ENABLE), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CONNECTION);
    argsman.AddArg("-port=<port>", strprintf("Listen for connections on <port> (default: %u, testnet3: %u, testnet4: %u, signet: %u, regtest: %u). Not relevant for I2P (see doc/i2p.md). If set to a value x, the default onion listening port will be set to x+1.", defaultChainParams->GetDefaultPort(), testnetChainParams->GetDefaultPort(), testnet4ChainParams->GetDefaultPort(), signetChainParams->GetDefaultPort(), regtestChainParams->GetDefaultPort()), ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::CONNECTION);
#ifdef HAVE_SOCKADDR_UN
    argsman.AddArg("-proxy=<ip:port|path>", "Connect through SOCKS5 proxy, set -noproxy to disable (default: disabled). May be a local file path prefixed with 'unix:' if the proxy supports it.", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_ELISION, OptionsCategory::CONNECTION);
#else
    argsman.AddArg("-proxy=<ip:port>", "Connect through SOCKS5 proxy, set -noproxy to disable (default: disabled)", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_ELISION, OptionsCategory::CONNECTION);
#endif
    argsman.AddArg("-proxyrandomize", strprintf("Randomize credentials for every proxy connection. This enables Tor stream isolation (default: %u)", DEFAULT_PROXYRANDOMIZE), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-seednode=<ip>", "Connect to a node to retrieve peer addresses, and disconnect. This option can be specified multiple times to connect to multiple nodes. During startup, seednodes will be tried before dnsseeds.", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-networkactive", "Enable all P2P network activity (default: 1). Can be changed by the setnetworkactive RPC command", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-timeout=<n>", strprintf("Specify socket connection timeout in milliseconds. If an initial attempt to connect is unsuccessful after this amount of time, drop it (minimum: 1, default: %d)", DEFAULT_CONNECT_TIMEOUT), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-peertimeout=<n>", strprintf("Specify a p2p connection timeout delay in seconds. After connecting to a peer, wait this amount of time before considering disconnection based on inactivity (minimum: 1, default: %d)", DEFAULT_PEER_CONNECT_TIMEOUT), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CONNECTION);
    argsman.AddArg("-torcontrol=<ip>:<port>", strprintf("Tor control host and port to use if onion listening enabled (default: %s). If no port is specified, the default port of %i will be used.", DEFAULT_TOR_CONTROL, DEFAULT_TOR_CONTROL_PORT), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-torpassword=<pass>", "Tor control port password (default: empty)", ArgsManager::ALLOW_ANY | ArgsManager::SENSITIVE, OptionsCategory::CONNECTION);
    argsman.AddArg("-natpmp", strprintf("Use PCP or NAT-PMP to map the listening port (default: %u)", DEFAULT_NATPMP), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    argsman.AddArg("-whitebind=<[permissions@]addr>", "Bind to the given address and add permission flags to the peers connecting to it. "
        "Use [host]:port notation for IPv6. Allowed permissions: " + Join(NET_PERMISSIONS_DOC, ", ") + ". "
        "Specify multiple permissions separated by commas (default: download,noban,mempool,relay). Can be specified multiple times.", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);

    argsman.AddArg("-whitelist=<[permissions@]IP address or network>", "Add permission flags to the peers using the given IP address (e.g. 1.2.3.4) or "
        "CIDR-notated network (e.g. 1.2.3.0/24). Uses the same permissions as "
        "-whitebind. "
        "Additional flags \"in\" and \"out\" control whether permissions apply to incoming connections and/or manual (default: incoming only). "
        "Can be specified multiple times.", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);

    g_wallet_init_interface.AddWalletOptions(argsman);

#ifdef ENABLE_ZMQ
    argsman.AddArg("-zmqpubhashblock=<address>", "Enable publish hash block in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubhashtx=<address>", "Enable publish hash transaction in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawblock=<address>", "Enable publish raw block in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawtx=<address>", "Enable publish raw transaction in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubsequence=<address>", "Enable publish hash block and tx sequence in <address>", ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubhashblockhwm=<n>", strprintf("Set publish hash block outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubhashtxhwm=<n>", strprintf("Set publish hash transaction outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawblockhwm=<n>", strprintf("Set publish raw block outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubrawtxhwm=<n>", strprintf("Set publish raw transaction outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
    argsman.AddArg("-zmqpubsequencehwm=<n>", strprintf("Set publish hash sequence message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), ArgsManager::ALLOW_ANY, OptionsCategory::ZMQ);
#else
    hidden_args.emplace_back("-zmqpubhashblock=<address>");
    hidden_args.emplace_back("-zmqpubhashtx=<address>");
    hidden_args.emplace_back("-zmqpubrawblock=<address>");
    hidden_args.emplace_back("-zmqpubrawtx=<address>");
    hidden_args.emplace_back("-zmqpubsequence=<n>");
    hidden_args.emplace_back("-zmqpubhashblockhwm=<n>");
    hidden_args.emplace_back("-zmqpubhashtxhwm=<n>");
    hidden_args.emplace_back("-zmqpubrawblockhwm=<n>");
    hidden_args.emplace_back("-zmqpubrawtxhwm=<n>");
    hidden_args.emplace_back("-zmqpubsequencehwm=<n>");
#endif

    argsman.AddArg("-checkblocks=<n>", strprintf("How many blocks to check at startup (default: %u, 0 = all)", DEFAULT_CHECKBLOCKS), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-checklevel=<n>", strprintf("How thorough the block verification of -checkblocks is: %s (0-4, default: %u)", Join(CHECKLEVEL_DOC, ", "), DEFAULT_CHECKLEVEL), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-checkblockindex", strprintf("Do a consistency check for the block tree, chainstate, and other validation data structures every <n> operations. Use 0 to disable. (default: %u, regtest: %u)", defaultChainParams->DefaultConsistencyChecks(), regtestChainParams->DefaultConsistencyChecks()), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-checkaddrman=<n>", strprintf("Run addrman consistency checks every <n> operations. Use 0 to disable. (default: %u)", DEFAULT_ADDRMAN_CONSISTENCY_CHECKS), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);

    // Reorg advisory options
    argsman.AddArg("-reorgadvisory", "Enable reorg advisory logging for deep chain reorganizations (default: 1)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reorgadvisorydepth=<n>", "Minimum reorg depth to trigger advisory logging (default: 3)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reorgadvisoryoffline=<n>", "Skip advisory if last block was seen more than <n> seconds ago (default: 21600 = 6 hours)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reorgadvisorytxidblocks=<n>", "Maximum blocks to read for transaction overlap analysis during reorg advisory (default: 100, max: 10000, 0=unlimited)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-fullvalidationtipwindow=<n>", strprintf("For non-live nodes, require external Full validation only for blocks within <n> blocks of a best tip (default: %d, 0 = verify every block)", DEFAULT_FULL_VALIDATION_TIP_WINDOW), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    // Reorg gating options (operator decision required before chain switch)
    argsman.AddArg("-reorgadvisorygating", "Enable operator gating for deep reorgs - node will pause and await 'submitreorgdecision' RPC before switching chains (default: 1)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reorgadvisorygatingdepth=<n>", "Minimum reorg depth to trigger gating when enabled (default: 3)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reorgadvisoryautofollow", "Auto-follow otherwise-gated reorgs that look like sane partition recovery (default: 1)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reorgadvisoryautofollowminforkhashrate=<n>", "Minimum candidate fork hashrate as percentage of advisory baseline for sane-partition auto-follow (default: 25)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reorgadvisoryautofollowmaxforkhashrate=<n>", "Maximum candidate fork hashrate as percentage of advisory baseline for sane-partition auto-follow (default: 400)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reorgadvisoryautofollowminratio=<n>", "Minimum candidate fork hashrate as percentage of current branch hashrate for sane-partition auto-follow (default: 125)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reorgadvisoryautofollowmindelay=<n>", "Minimum seconds before first competing block was seen for sane-partition auto-follow (default: 1200)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reorgadvisorytimeout=<n>", "Timeout in seconds for operator decision before default action (default: 1800 = 30 minutes, min: 60, max: 86400)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reorgadvisorytimeoutaccept", "Default action on timeout: 1=accept fork, 0=reject and stay on current chain (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reorgadvisoryapprovalttl=<n>", "How long in seconds an accepted reorg decision keeps covering later segments of the same reorg without re-prompting (default: 3600, min: 60, max: 86400)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reorgadvisorygatingmode=<mode>", "How an armed reorg gate constrains the node: 'mask' (default) keeps validation, P2P and RPC fully live and only excludes the gated branch from fork choice until a decision; 'block' restores the legacy behavior of parking chain activation until a decision (with a shutdown-interruptible wait). Escape hatch for one release; unknown values fall back to 'mask'", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reorgadvisoryvetottl=<n>", "How long in seconds a rejected reorg stays vetoed before the branch may prompt again (mask mode; default: 3600, min: 60, max: 86400). A veto also expires early if the branch extends by -reorgadvisoryvetogrowth blocks or its raw-work margin over the local tip grows", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reorgadvisoryvetogrowth=<n>", "Number of blocks a vetoed branch must extend beyond its length at veto time to escape the veto early and re-prompt once (default: 6, min: 1)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-checkmempool=<n>", strprintf("Run mempool consistency checks every <n> transactions. Use 0 to disable. (default: %u, regtest: %u)", defaultChainParams->DefaultConsistencyChecks(), regtestChainParams->DefaultConsistencyChecks()), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    // Checkpoints were removed. We keep `-checkpoints` as a hidden arg to display a more user friendly error when set.
    argsman.AddArg("-checkpoints", "", ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN);
    argsman.AddArg("-deprecatedrpc=<method>", "Allows deprecated RPC method(s) to be used", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    // Asset policy knobs
    static bool s_asset_policy_args_added = false;
    if (!s_asset_policy_args_added) {
        argsman.AddArg("-policymaxassetspertx=<n>", "Maximum number of AssetTag outputs per transaction (default: 64)", ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
        argsman.AddArg("-policymaxassetoutsize=<n>", "Maximum size in bytes for per-output vExt (default: 160)", ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
        argsman.AddArg("-assetminmultitouchfee=<sats>", "Minimum base fee per touched asset for transactions that touch >= 2 assets (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
        argsman.AddArg("-assetmindustbtc=<sats>", "Minimum BTC value in satoshis for AssetTag outputs (default: 0, uses family-aware dust threshold)", ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
        argsman.AddArg("-permitassetanyonecanpay", "Permit asset/ICU inputs to use ANYONECANPAY (SIGHASH policies) (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
        s_asset_policy_args_added = true;
    }
    // Asset-specific params
    static bool s_asset_args_added = false;
    if (!s_asset_args_added) {
        argsman.AddArg("-assetsheight=<n>", "Regtest only: block height at/after which per-output asset TLVs and rules activate (default: 0). Ignored on main/test chains, where activation is hardwired consensus.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
        argsman.AddArg("-assetsdelegationheight=<n>", "Regtest only: activation height for delegated/reusable KYC (IssuerReg v2 delegate pointers) (default: 0). Ignored on main/test chains.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
        argsman.AddArg("-scalarcfdheight=<n>", "Regtest only: block height at/after which scalar-CFD ISSUER_SCALAR publication carriers (0x11) activate (default: 0). Ignored on main/test chains, where activation is hardwired consensus.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
        argsman.AddArg("-reuseentropyheight=<n>", "Regtest only: block height at/after which the quick verifier reuse entropy score activates (default: disabled). Ignored on main/test chains.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
        argsman.AddArg("-v3activationheight=<n>", "Regtest only: block height at/after which the v3 prompt-binding proof rules (admission nonce, B_cred tiering, fixed sampler profile) activate (default: disabled). Ignored on main/test chains, where activation is hardwired consensus.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
        // -assetminicubond removed: the minimum initial ICU bond is consensus-critical
        // (enforced in ConnectBlock) and now lives in Consensus::Params::AssetMinIcuBond.
        s_asset_args_added = true;
    }
    argsman.AddArg("-stopafterblockimport", strprintf("Stop running after importing blocks from disk (default: %u)", DEFAULT_STOPAFTERBLOCKIMPORT), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-stopatheight", strprintf("Stop running after reaching the given height in the main chain (default: %u)", DEFAULT_STOPATHEIGHT), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-limitancestorcount=<n>", strprintf("Do not accept transactions if number of in-mempool ancestors is <n> or more (default: %u)", DEFAULT_ANCESTOR_LIMIT), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-limitancestorsize=<n>", strprintf("Do not accept transactions whose size with all in-mempool ancestors exceeds <n> kilobytes (default: %u)", DEFAULT_ANCESTOR_SIZE_LIMIT_KVB), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-limitdescendantcount=<n>", strprintf("Do not accept transactions if any ancestor would have <n> or more in-mempool descendants (default: %u)", DEFAULT_DESCENDANT_LIMIT), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-limitdescendantsize=<n>", strprintf("Do not accept transactions if any ancestor would have more than <n> kilobytes of in-mempool descendants (default: %u).", DEFAULT_DESCENDANT_SIZE_LIMIT_KVB), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-test=<option>", "Pass a test-only option. Options include : " + Join(TEST_OPTIONS_DOC, ", ") + ".", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-capturemessages", "Capture all P2P messages to disk", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-mocktime=<n>", "Replace actual time with " + UNIX_EPOCH_TIME + " (default: 0)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-maxsigcachesize=<n>", strprintf("Limit sum of signature cache and script execution cache sizes to <n> MiB (default: %u)", DEFAULT_VALIDATION_CACHE_BYTES >> 20), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-maxtipage=<n>",
                   strprintf("Maximum tip age in seconds to consider node in initial block download (default: %u)",
                             Ticks<std::chrono::seconds>(DEFAULT_MAX_TIP_AGE)),
                   ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-printpriority", strprintf("Log transaction fee rate in %s/kvB when mining blocks (default: %u)", CURRENCY_UNIT, DEFAULT_PRINT_MODIFIED_FEE), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-uacomment=<cmt>", "Append comment to the user agent string", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);

    SetupChainParamsBaseOptions(argsman);

    argsman.AddArg("-acceptnonstdtxn", strprintf("Relay and mine \"non-standard\" transactions (test networks only; default: %u)", DEFAULT_ACCEPT_NON_STD_TXN), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-incrementalrelayfee=<amt>", strprintf("Fee rate (in %s/kvB) used to define cost of relay, used for mempool limiting and replacement policy. (default: %s)", CURRENCY_UNIT, FormatMoney(DEFAULT_INCREMENTAL_RELAY_FEE)), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-dustrelayfee=<amt>", strprintf("Fee rate (in %s/kvB) used to define dust, the value of an output such that it will cost more than its value in fees at this fee rate to spend it. (default: %s)", CURRENCY_UNIT, FormatMoney(DUST_RELAY_TX_FEE)), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-acceptstalefeeestimates", strprintf("Read fee estimates even if they are stale (%sdefault: %u) fee estimates are considered stale if they are %s hours old", "regtest only; ", DEFAULT_ACCEPT_STALE_FEE_ESTIMATES, Ticks<std::chrono::hours>(MAX_FILE_AGE)), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-bytespersigop", strprintf("Equivalent bytes per sigop in transactions for relay and mining (default: %u)", DEFAULT_BYTES_PER_SIGOP), ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-datacarrier", strprintf("Relay and mine data carrier transactions (default: %u)", DEFAULT_ACCEPT_DATACARRIER), ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-datacarriersize",
                   strprintf("Relay and mine transactions whose data-carrying raw scriptPubKey "
                             "is of this size or less (default: %u)",
                             MAX_OP_RETURN_RELAY),
                   ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-permitbaremultisig", strprintf("Relay transactions creating non-P2SH multisig outputs (default: %u)", DEFAULT_PERMIT_BAREMULTISIG), ArgsManager::ALLOW_ANY,
                   OptionsCategory::NODE_RELAY);
    argsman.AddArg("-minrelaytxfee=<amt>", strprintf("Fees (in %s/kvB) smaller than this are considered zero fee for relaying, mining and transaction creation (default: %s)",
        CURRENCY_UNIT, FormatMoney(DEFAULT_MIN_RELAY_TX_FEE)), ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-whitelistforcerelay", strprintf("Add 'forcerelay' permission to whitelisted peers with default permissions. This will relay transactions even if the transactions were already in the mempool. (default: %d)", DEFAULT_WHITELISTFORCERELAY), ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-whitelistrelay", strprintf("Add 'relay' permission to whitelisted peers with default permissions. This will accept relayed transactions even when not relaying transactions (default: %d)", DEFAULT_WHITELISTRELAY), ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);


    argsman.AddArg("-blockmaxweight=<n>", strprintf("Set maximum BIP141 block weight (default: %d)", DEFAULT_BLOCK_MAX_WEIGHT), ArgsManager::ALLOW_ANY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-blockreservedweight=<n>", strprintf("Reserve space for the fixed-size block header plus the largest coinbase transaction the mining software may add to the block. (default: %d).", DEFAULT_BLOCK_RESERVED_WEIGHT), ArgsManager::ALLOW_ANY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-blockmintxfee=<amt>", strprintf("Set lowest fee rate (in %s/kvB) for transactions to be included in block creation. (default: %s)", CURRENCY_UNIT, FormatMoney(DEFAULT_BLOCK_MIN_TX_FEE)), ArgsManager::ALLOW_ANY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-blockversion=<n>", "Override block version to test forking scenarios", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::BLOCK_CREATION);

    argsman.AddArg("-rest", strprintf("Accept public REST requests (default: %u)", DEFAULT_REST_ENABLE), ArgsManager::ALLOW_ANY, OptionsCategory::RPC);
    argsman.AddArg("-rpcallowip=<ip>", "Allow JSON-RPC connections from specified source. Valid values for <ip> are a single IP (e.g. 1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0), a network/CIDR (e.g. 1.2.3.4/24), all ipv4 (0.0.0.0/0), or all ipv6 (::/0). This option can be specified multiple times", ArgsManager::ALLOW_ANY, OptionsCategory::RPC);
    argsman.AddArg("-rpcauth=<userpw>", "Username and HMAC-SHA-256 hashed password for JSON-RPC connections. The field <userpw> comes in the format: <USERNAME>:<SALT>$<HASH>. A canonical python script is included in share/rpcauth. The client then connects normally using the rpcuser=<USERNAME>/rpcpassword=<PASSWORD> pair of arguments. This option can be specified multiple times", ArgsManager::ALLOW_ANY | ArgsManager::SENSITIVE, OptionsCategory::RPC);
    argsman.AddArg("-rpcbind=<addr>[:port]", "Bind to given address to listen for JSON-RPC connections. Do not expose the RPC server to untrusted networks such as the public internet! This option is ignored unless -rpcallowip is also passed. Port is optional and overrides -rpcport. Use [host]:port notation for IPv6. This option can be specified multiple times (default: 127.0.0.1 and ::1 i.e., localhost)", ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::RPC);
    argsman.AddArg("-rpcdoccheck", strprintf("Throw a non-fatal error at runtime if the documentation for an RPC is incorrect (default: %u)", DEFAULT_RPC_DOC_CHECK), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::RPC);
    argsman.AddArg("-rpccookiefile=<loc>", "Location of the auth cookie. Relative paths will be prefixed by a net-specific datadir location. (default: data dir)", ArgsManager::ALLOW_ANY, OptionsCategory::RPC);
    argsman.AddArg("-rpccookieperms=<readable-by>", strprintf("Set permissions on the RPC auth cookie file so that it is readable by [owner|group|all] (default: owner [via umask 0077])"), ArgsManager::ALLOW_ANY, OptionsCategory::RPC);
    argsman.AddArg("-rpcpassword=<pw>", "Password for JSON-RPC connections", ArgsManager::ALLOW_ANY | ArgsManager::SENSITIVE, OptionsCategory::RPC);
    argsman.AddArg("-rpcport=<port>", strprintf("Listen for JSON-RPC connections on <port> (default: %u, testnet3: %u, testnet4: %u, signet: %u, regtest: %u)", defaultBaseParams->RPCPort(), testnetBaseParams->RPCPort(), testnet4BaseParams->RPCPort(), signetBaseParams->RPCPort(), regtestBaseParams->RPCPort()), ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::RPC);
    argsman.AddArg("-rpcservertimeout=<n>", strprintf("Timeout during HTTP requests (default: %d)", DEFAULT_HTTP_SERVER_TIMEOUT), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::RPC);
    argsman.AddArg("-rpcthreads=<n>", strprintf("Set the number of threads to service RPC calls (default: %d)", DEFAULT_HTTP_THREADS), ArgsManager::ALLOW_ANY, OptionsCategory::RPC);
    argsman.AddArg("-rpcuser=<user>", "Username for JSON-RPC connections", ArgsManager::ALLOW_ANY | ArgsManager::SENSITIVE, OptionsCategory::RPC);
    argsman.AddArg("-rpcwhitelist=<whitelist>", "Set a whitelist to filter incoming RPC calls for a specific user. The field <whitelist> comes in the format: <USERNAME>:<rpc 1>,<rpc 2>,...,<rpc n>. If multiple whitelists are set for a given user, they are set-intersected. See -rpcwhitelistdefault documentation for information on default whitelist behavior.", ArgsManager::ALLOW_ANY, OptionsCategory::RPC);
    argsman.AddArg("-rpcwhitelistdefault", "Sets default behavior for rpc whitelisting. Unless rpcwhitelistdefault is set to 0, if any -rpcwhitelist is set, the rpc server acts as if all rpc users are subject to empty-unless-otherwise-specified whitelists. If rpcwhitelistdefault is set to 1 and no -rpcwhitelist is set, rpc server acts as if all rpc users are subject to empty whitelists.", ArgsManager::ALLOW_ANY, OptionsCategory::RPC);
    argsman.AddArg("-rpcworkqueue=<n>", strprintf("Set the maximum depth of the work queue to service RPC calls (default: %d)", DEFAULT_HTTP_WORKQUEUE), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::RPC);
    argsman.AddArg("-cosignbridge=<path>", "Path to cosign bridge binary for Fair-Sign ceremony coordination (Phase 4)", ArgsManager::ALLOW_ANY, OptionsCategory::RPC);
    argsman.AddArg("-server", "Accept command line and JSON-RPC commands", ArgsManager::ALLOW_ANY, OptionsCategory::RPC);
    if (can_listen_ipc) {
        argsman.AddArg("-ipcbind=<address>", "Bind to Unix socket address and listen for incoming connections. Valid address values are \"unix\" to listen on the default path, <datadir>/node.sock, or \"unix:/custom/path\" to specify a custom path. Can be specified multiple times to listen on multiple paths. Default behavior is not to listen on any path. If relative paths are specified, they are interpreted relative to the network data directory. If paths include any parent directory components and the parent directories do not exist, they will be created.", ArgsManager::ALLOW_ANY, OptionsCategory::IPC);
    }

#if HAVE_DECL_FORK
    argsman.AddArg("-daemon", strprintf("Run in the background as a daemon and accept commands (default: %d)", DEFAULT_DAEMON), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-daemonwait", strprintf("Wait for initialization to be finished before exiting. This implies -daemon (default: %d)", DEFAULT_DAEMONWAIT), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
#else
    hidden_args.emplace_back("-daemon");
    hidden_args.emplace_back("-daemonwait");
#endif

    // Validation API selection and mock controls (primarily for tests/functional)
    argsman.AddArg("-validationapi=<real|mock|desktop>", "Select external validation backend (real uses ZMQ, mock is in-process and deterministic, desktop uses local quick + HTTPS full/model). Default: real", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-mockval-default-quick=<VALUE>", "Default Quick/Smell mock response (Quick_OK_Smell_OK | Quick_OK_Smell_Fail | Quick_Fail_Smell_OK | Quick_Fail_Smell_Fail)", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-mockval-default-full=<VALUE>", "Default Full mock response (Full_Green | Full_Amber | Full_Red)", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-mockval-default-model=<VALUE>", "Default Model mock response (Model_OK | Model_Fail)", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-mockval-force-external", "Treat mock validation backend as requiring external flow (for functional tests)", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-validationapi-force-external", "Force the external full-validation flow with the real validation backend on chains that do not enable it by consensus (for functional tests)", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-mockval-preapprove-genesis", "If set, pre-approve genesis Quick/Smell in mock backend", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-minermodel=<name@commit>", "Override model identifier used by the miner when building blocks (default: consensus defaults)", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-validatorhttpurl=<url>", "Gateway verification service base URL for desktop/HTTP mode (e.g., https://verify.tensorcash.org, no trailing slash)", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-validatorapikey=<key>", "API key for gateway verification service (desktop/HTTP mode)", ArgsManager::ALLOW_ANY | ArgsManager::SENSITIVE, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-validatorapikeys=<k1,k2,...>", "Comma-separated API keys for gateway verification service endpoints in desktop/HTTP mode. Either provide one shared key or one key per configured base URL.", ArgsManager::ALLOW_ANY | ArgsManager::SENSITIVE, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-allowvalidationadjudication", "Allow the local operator RPC to promote a Full_Amber block after independently verified Full_Green evidence (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    // External miner API toggle (useful for tests)
    argsman.AddArg("-useextapi", "Enable external miner API (default: 1)", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    // Selects the mining-orchestration mode. There are two first-class
    // options and they are mutually exclusive:
    //   * default (-miningbrokermode=0): sovereign / self-hosted mining.
    //     The operator drives mining locally via startmining /
    //     startminingwithrotation, with the in-process JobSchedulerLoop and
    //     SolutionReceiverLoop using the MINER PUSH/PULL transport.
    //   * -miningbrokermode=1: compute-broker driven mining. The broker
    //     drives mining via the create_mining_work_unit and
    //     submit_mining_response RPCs. The sovereign-mode entry points are
    //     refused and the MINER PUSH/PULL transport is not bound, so a
    //     solution can never reach bcore outside the broker's lease index.
    argsman.AddArg("-miningbrokermode", "Run mining in compute-broker mode (default: 0). Mutually exclusive with sovereign startmining/startminingwithrotation; when set, broker drives mining via create_mining_work_unit / submit_mining_response and the MINER PUSH/PULL transport is not bound.", ArgsManager::ALLOW_ANY, OptionsCategory::EXTERNAL_API);
    argsman.AddArg("-maxminingworkunits=<n>", strprintf("Maximum outstanding mining work units tracked at once (default: %u, minimum: 1). Past the cap the oldest work unit is evicted and any solution submitted for it is rejected as unknown_req_id, so pools minting one work unit per connected miner per tip must keep this above their peak work units per 10-minute expiry window. Each tracked unit holds a full candidate block in memory.", DEFAULT_MAX_MINING_WORK_UNITS), ArgsManager::ALLOW_ANY, OptionsCategory::EXTERNAL_API);

    // SPV presync selection and sampling knobs
    argsman.AddArg("-spv-asn-corroboration", "Require distinct ASNs to corroborate candidate tips before fetching (default: 1). Negate to disable.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-spv-asn-min=<n>", "Minimum number of distinct ASNs required to corroborate a candidate tip (default: 2)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-spv-asn-min-reorg-depth=<n>", "Reorg depth above which ASN corroboration is required (default: 3). Raise on low-diversity (e.g. Tor-heavy) nodes to avoid wedging behind the anti-eclipse gate during a hashrate spike.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-spv-hysteresis-alpha-bps=<n>", "EMA alpha in basis points for expected ticks per block (default: 200 = 2%)", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-spv-hysteresis-base-bps=<n>", "Base hysteresis fraction of E in basis points (default: 5000 = 50%)", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-spv-hysteresis-default-tick=<n>", "Fallback expected tick per block before EMA observations (default: 1000000)", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-spv-min-cumulative-tick-per-block=<n>", strprintf("Minimum verified cumulative VDF tick per block for header-only candidate fetch (default: %llu, 0 = disabled)", static_cast<unsigned long long>(DEFAULT_SPV_MIN_CUMULATIVE_TICK_PER_BLOCK)), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-spv-min-cumulative-tick-slack-days=<n>", strprintf("Slack in days, converted to blocks at 9 minutes per block, before enforcing the minimum cumulative VDF tick floor (default: %u)", DEFAULT_SPV_MIN_CUMULATIVE_TICK_SLACK_DAYS), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-spv-reorg-sampling-threshold=<n>", "Reorg depth D threshold above which M-of-N body sampling is required (default: 6)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-spv-sampling-max-n=<n>", "Maximum number of sample blocks N for deep reorg sampling (default: 12)", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-spv-onion-prefix=<s>", "Vanity .onion prefix for diversity credit (default: derived from chain — tensorc on tensor, ten on tensor-test/tensor-reg)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-spv-onion-tag-len=<n>", "Freshness tag length after vanity prefix (default: 3)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-spv-onion-freshness-window=<n>", "Block window for valid freshness tags (default: 1400)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    // Add the hidden options
    argsman.AddHiddenArgs(hidden_args);
}

#if HAVE_SYSTEM
static void StartupNotify(const ArgsManager& args)
{
    std::string cmd = args.GetArg("-startupnotify", "");
    if (!cmd.empty()) {
        std::thread t(runCommand, cmd);
        t.detach(); // thread runs free
    }
}
#endif

static bool AppInitServers(NodeContext& node)
{
    const ArgsManager& args = *Assert(node.args);
    if (!InitHTTPServer(*Assert(node.shutdown_signal))) {
        return false;
    }
    StartRPC();
    node.rpc_interruption_point = RpcInterruptionPoint;
    if (!StartHTTPRPC(&node))
        return false;
    if (args.GetBoolArg("-rest", DEFAULT_REST_ENABLE)) StartREST(&node);
    StartHTTPServer();
    return true;
}

// Parameter interaction based on rules
void InitParameterInteraction(ArgsManager& args)
{
    // when specifying an explicit binding address, you want to listen on it
    // even when -connect or -proxy is specified
    if (!args.GetArgs("-bind").empty()) {
        if (args.SoftSetBoolArg("-listen", true))
            LogInfo("parameter interaction: -bind set -> setting -listen=1\n");
    }
    if (!args.GetArgs("-whitebind").empty()) {
        if (args.SoftSetBoolArg("-listen", true))
            LogInfo("parameter interaction: -whitebind set -> setting -listen=1\n");
    }

    if (!args.GetArgs("-connect").empty() || args.IsArgNegated("-connect") || args.GetIntArg("-maxconnections", DEFAULT_MAX_PEER_CONNECTIONS) <= 0) {
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default
        // do the same when connections are disabled
        if (args.SoftSetBoolArg("-dnsseed", false))
            LogInfo("parameter interaction: -connect or -maxconnections=0 set -> setting -dnsseed=0\n");
        if (args.SoftSetBoolArg("-listen", false))
            LogInfo("parameter interaction: -connect or -maxconnections=0 set -> setting -listen=0\n");
    }

    std::string proxy_arg = args.GetArg("-proxy", "");
    if (proxy_arg != "" && proxy_arg != "0") {
        // to protect privacy, do not listen by default if a default proxy server is specified
        if (args.SoftSetBoolArg("-listen", false))
            LogInfo("parameter interaction: -proxy set -> setting -listen=0\n");
        // to protect privacy, do not map ports when a proxy is set. The user may still specify -listen=1
        // to listen locally, so don't rely on this happening through -listen below.
        if (args.SoftSetBoolArg("-natpmp", false)) {
            LogInfo("parameter interaction: -proxy set -> setting -natpmp=0\n");
        }
        // to protect privacy, do not discover addresses by default
        if (args.SoftSetBoolArg("-discover", false))
            LogInfo("parameter interaction: -proxy set -> setting -discover=0\n");
    }

    if (!args.GetBoolArg("-listen", DEFAULT_LISTEN)) {
        // do not map ports or try to retrieve public IP when not listening (pointless)
        if (args.SoftSetBoolArg("-natpmp", false)) {
            LogInfo("parameter interaction: -listen=0 -> setting -natpmp=0\n");
        }
        if (args.SoftSetBoolArg("-discover", false))
            LogInfo("parameter interaction: -listen=0 -> setting -discover=0\n");
        if (args.SoftSetBoolArg("-listenonion", false))
            LogInfo("parameter interaction: -listen=0 -> setting -listenonion=0\n");
        if (args.SoftSetBoolArg("-i2pacceptincoming", false)) {
            LogInfo("parameter interaction: -listen=0 -> setting -i2pacceptincoming=0\n");
        }
    }

    if (!args.GetArgs("-externalip").empty()) {
        // if an explicit public IP is specified, do not try to find others
        if (args.SoftSetBoolArg("-discover", false))
            LogInfo("parameter interaction: -externalip set -> setting -discover=0\n");
    }

    if (args.GetBoolArg("-blocksonly", DEFAULT_BLOCKSONLY)) {
        // disable whitelistrelay in blocksonly mode
        if (args.SoftSetBoolArg("-whitelistrelay", false))
            LogInfo("parameter interaction: -blocksonly=1 -> setting -whitelistrelay=0\n");
        // Reduce default mempool size in blocksonly mode to avoid unexpected resource usage
        if (args.SoftSetArg("-maxmempool", ToString(DEFAULT_BLOCKSONLY_MAX_MEMPOOL_SIZE_MB)))
            LogInfo("parameter interaction: -blocksonly=1 -> setting -maxmempool=%d\n", DEFAULT_BLOCKSONLY_MAX_MEMPOOL_SIZE_MB);
    }

    // Forcing relay from whitelisted hosts implies we will accept relays from them in the first place.
    if (args.GetBoolArg("-whitelistforcerelay", DEFAULT_WHITELISTFORCERELAY)) {
        if (args.SoftSetBoolArg("-whitelistrelay", true))
            LogInfo("parameter interaction: -whitelistforcerelay=1 -> setting -whitelistrelay=1\n");
    }
    const auto onlynets = args.GetArgs("-onlynet");
    if (!onlynets.empty()) {
        bool clearnet_reachable = std::any_of(onlynets.begin(), onlynets.end(), [](const auto& net) {
            const auto n = ParseNetwork(net);
            return n == NET_IPV4 || n == NET_IPV6;
        });
        if (!clearnet_reachable && args.SoftSetBoolArg("-dnsseed", false)) {
            LogInfo("parameter interaction: -onlynet excludes IPv4 and IPv6 -> setting -dnsseed=0\n");
        }
    }
}

/**
 * Initialize global loggers.
 *
 * Note that this is called very early in the process lifetime, so you should be
 * careful about what global state you rely on here.
 */
void InitLogging(const ArgsManager& args)
{
    init::SetLoggingOptions(args);
    init::LogPackageVersion();
}

namespace { // Variables internal to initialization process only

int nMaxConnections;
int available_fds;
ServiceFlags g_local_services = ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS);
int64_t peer_connect_timeout;
std::set<BlockFilterType> g_enabled_filter_types;

} // namespace

[[noreturn]] static void new_handler_terminate()
{
    // Rather than throwing std::bad-alloc if allocation fails, terminate
    // immediately to (try to) avoid chain corruption.
    // Since logging may itself allocate memory, set the handler directly
    // to terminate first.
    std::set_new_handler(std::terminate);
    LogError("Out of memory. Terminating.\n");

    // The log was successful, terminate now.
    std::terminate();
};

bool AppInitBasicSetup(const ArgsManager& args, std::atomic<int>& exit_status)
{
    // ********************************************************* Step 1: setup
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, 0));
    // Disable confusing "helpful" text message on abort, Ctrl-C
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifdef WIN32
    // Enable heap terminate-on-corruption
    HeapSetInformation(nullptr, HeapEnableTerminationOnCorruption, nullptr, 0);
#endif
    if (!SetupNetworking()) {
        return InitError(Untranslated("Initializing networking failed."));
    }

#ifndef WIN32
    // Clean shutdown on SIGTERM
    registerSignalHandler(SIGTERM, HandleSIGTERM);
    registerSignalHandler(SIGINT, HandleSIGTERM);

    // Reopen debug.log on SIGHUP
    registerSignalHandler(SIGHUP, HandleSIGHUP);

    // Ignore SIGPIPE, otherwise it will bring the daemon down if the client closes unexpectedly
    signal(SIGPIPE, SIG_IGN);
#else
    SetConsoleCtrlHandler(consoleCtrlHandler, true);
#endif

    std::set_new_handler(new_handler_terminate);

    return true;
}

bool AppInitParameterInteraction(const ArgsManager& args)
{
    const CChainParams& chainparams = Params();
    // ********************************************************* Step 2: parameter interactions

    // also see: InitParameterInteraction()

    // We removed checkpoints but keep the option to warn users who still have it in their config.
    if (args.IsArgSet("-checkpoints")) {
        InitWarning(_("Option '-checkpoints' is set but checkpoints were removed. This option has no effect."));
    }

    // Error if network-specific options (-addnode, -connect, etc) are
    // specified in default section of config file, but not overridden
    // on the command line or in this chain's section of the config file.
    ChainType chain = args.GetChainType();
    if (chain == ChainType::SIGNET) {
        LogPrintf("Signet derived magic (message start): %s\n", HexStr(chainparams.MessageStart()));
    }
    bilingual_str errors;
    for (const auto& arg : args.GetUnsuitableSectionOnlyArgs()) {
        errors += strprintf(_("Config setting for %s only applied on %s network when in [%s] section."), arg, ChainTypeToString(chain), ChainTypeToString(chain)) + Untranslated("\n");
    }

    if (!errors.empty()) {
        return InitError(errors);
    }

    // TIP-0003: refuse to run a chain that activates v3 without
    // red-block enforcement (external_api full replay). v3's fast-path B_cred
    // free tier is only sound when forged high-entropy evidence is caught by
    // full validation; without it the free tier is exploitable. Mockable
    // (regtest) chains are exempt — they test the fast path in isolation.
    if (!IsV3ActivationConfigSound(chainparams.GetConsensus().V3ActivationHeight,
                                   chainparams.GetConsensus().external_api,
                                   chainparams.IsMockableChain())) {
        return InitError(Untranslated(
            "V3ActivationHeight is set on this chain but red-block enforcement "
            "(external_api full validation) is disabled; the v3 free-tier "
            "B_cred is unsound without it (TIP-0003). Enable "
            "external_api or unset the activation height."));
    }

    // A finite V3ActivationHeight also requires Argon2 admission verification
    // in THIS binary: pow_v3::argon2id_digest() throws in an argonless build
    // and the throw maps to proof-invalid, so such a node would reject every
    // consensus-valid admission-band block after activation and fork off.
    if (!IsV3AdmissionVerifyCapable(chainparams.GetConsensus().V3ActivationHeight,
                                    pow_v3::argon2_compiled())) {
        return InitError(Untranslated(
            "V3ActivationHeight is set on this chain but this binary was built "
            "without libargon2 (POW_V3_HAVE_ARGON2), so it cannot verify v3 "
            "admission nonces and would reject valid admission-band blocks "
            "after activation. Rebuild with libargon2 (libargon2-dev / "
            "brew install argon2) or unset the activation height."));
    }

    // The tier thresholds must match the compiled pow_v3 constants (which the
    // external Python verifier also scores with): a params-only recalibration
    // would silently split this node from the verification fleet. Ship
    // recalibrations as a coordinated constants change in both languages.
    if (!IsV3TierParamsVendored(chainparams.GetConsensus().V3ActivationHeight,
                                chainparams.GetConsensus().V3BFloorBits,
                                chainparams.GetConsensus().V3BFreeBits)) {
        return InitError(Untranslated(
            "V3ActivationHeight is set but this chain's V3BFloorBits/"
            "V3BFreeBits differ from the compiled pow_v3 tier constants; "
            "recalibration must ship as a coordinated constants change "
            "(pow_v3 + verifier), not a chain-params edit."));
    }

    // Testnet3 deprecation warning
    if (chain == ChainType::TESTNET) {
        LogInfo("Warning: Support for testnet3 is deprecated and will be removed in an upcoming release. Consider switching to testnet4.\n");
    }

    // Warn if unrecognized section name are present in the config file.
    bilingual_str warnings;
    for (const auto& section : args.GetUnrecognizedSections()) {
        warnings += Untranslated(strprintf("%s:%i ", section.m_file, section.m_line)) + strprintf(_("Section [%s] is not recognized."), section.m_name) + Untranslated("\n");
    }

    if (!warnings.empty()) {
        InitWarning(warnings);
    }

    if (!fs::is_directory(args.GetBlocksDirPath())) {
        return InitError(strprintf(_("Specified blocks directory \"%s\" does not exist."), args.GetArg("-blocksdir", "")));
    }

    // parse and validate enabled filter types
    std::string blockfilterindex_value = args.GetArg("-blockfilterindex", DEFAULT_BLOCKFILTERINDEX);
    if (blockfilterindex_value == "" || blockfilterindex_value == "1") {
        g_enabled_filter_types = AllBlockFilterTypes();
    } else if (blockfilterindex_value != "0") {
        const std::vector<std::string> names = args.GetArgs("-blockfilterindex");
        for (const auto& name : names) {
            BlockFilterType filter_type;
            if (!BlockFilterTypeByName(name, filter_type)) {
                return InitError(strprintf(_("Unknown -blockfilterindex value %s."), name));
            }
            g_enabled_filter_types.insert(filter_type);
        }
    }

    // Signal NODE_P2P_V2 if BIP324 v2 transport is enabled.
    if (args.GetBoolArg("-v2transport", DEFAULT_V2_TRANSPORT)) {
        g_local_services = ServiceFlags(g_local_services | NODE_P2P_V2);
    }

    // Always advertise VDF SPV sidecar support in this fork (optional presync feature).
    g_local_services = ServiceFlags(g_local_services | NODE_VDFSPV);

    // Signal NODE_COMPACT_FILTERS if peerblockfilters and basic filters index are both enabled.
    if (args.GetBoolArg("-peerblockfilters", DEFAULT_PEERBLOCKFILTERS)) {
        if (g_enabled_filter_types.count(BlockFilterType::BASIC) != 1) {
            return InitError(_("Cannot set -peerblockfilters without -blockfilterindex."));
        }

        g_local_services = ServiceFlags(g_local_services | NODE_COMPACT_FILTERS);
    }

    if (args.GetIntArg("-prune", 0)) {
        if (args.GetBoolArg("-txindex", DEFAULT_TXINDEX))
            return InitError(_("Prune mode is incompatible with -txindex."));
        if (args.GetBoolArg("-reindex-chainstate", false)) {
            return InitError(_("Prune mode is incompatible with -reindex-chainstate. Use full -reindex instead."));
        }
    }

    // If -forcednsseed is set to true, ensure -dnsseed has not been set to false
    if (args.GetBoolArg("-forcednsseed", DEFAULT_FORCEDNSSEED) && !args.GetBoolArg("-dnsseed", DEFAULT_DNSSEED)){
        return InitError(_("Cannot set -forcednsseed to true when setting -dnsseed to false."));
    }

    // -bind and -whitebind can't be set when not listening
    size_t nUserBind = args.GetArgs("-bind").size() + args.GetArgs("-whitebind").size();
    if (nUserBind != 0 && !args.GetBoolArg("-listen", DEFAULT_LISTEN)) {
        return InitError(Untranslated("Cannot set -bind or -whitebind together with -listen=0"));
    }

    // if listen=0, then disallow listenonion=1
    if (!args.GetBoolArg("-listen", DEFAULT_LISTEN) && args.GetBoolArg("-listenonion", DEFAULT_LISTEN_ONION)) {
        return InitError(Untranslated("Cannot set -listen=0 together with -listenonion=1"));
    }

    // Make sure enough file descriptors are available. We need to reserve enough FDs to account for the bare minimum,
    // plus all manual connections and all bound interfaces. Any remainder will be available for connection sockets

    // Number of bound interfaces (we have at least one)
    int nBind = std::max(nUserBind, size_t(1));
    // Maximum number of connections with other nodes, this accounts for all types of outbounds and inbounds except for manual
    int user_max_connection = args.GetIntArg("-maxconnections", DEFAULT_MAX_PEER_CONNECTIONS);
    if (user_max_connection < 0) {
        return InitError(Untranslated("-maxconnections must be greater or equal than zero"));
    }
    // Reserve enough FDs to account for the bare minimum, plus any manual connections, plus the bound interfaces
    int min_required_fds = MIN_CORE_FDS + MAX_ADDNODE_CONNECTIONS + nBind;

    // Try raising the FD limit to what we need (available_fds may be smaller than the requested amount if this fails)
    available_fds = RaiseFileDescriptorLimit(user_max_connection + min_required_fds);
    // If we are using select instead of poll, our actual limit may be even smaller
#ifndef USE_POLL
    available_fds = std::min(FD_SETSIZE, available_fds);
#endif
    if (available_fds < min_required_fds)
        return InitError(strprintf(_("Not enough file descriptors available. %d available, %d required."), available_fds, min_required_fds));

    // Trim requested connection counts, to fit into system limitations
    nMaxConnections = std::min(available_fds - min_required_fds, user_max_connection);

    if (nMaxConnections < user_max_connection)
        InitWarning(strprintf(_("Reducing -maxconnections from %d to %d, because of system limitations."), user_max_connection, nMaxConnections));

    // ********************************************************* Step 3: parameter-to-internal-flags
    if (auto result{init::SetLoggingCategories(args)}; !result) return InitError(util::ErrorString(result));
    if (auto result{init::SetLoggingLevel(args)}; !result) return InitError(util::ErrorString(result));

    nConnectTimeout = args.GetIntArg("-timeout", DEFAULT_CONNECT_TIMEOUT);
    if (nConnectTimeout <= 0) {
        nConnectTimeout = DEFAULT_CONNECT_TIMEOUT;
    }

    peer_connect_timeout = args.GetIntArg("-peertimeout", DEFAULT_PEER_CONNECT_TIMEOUT);
    if (peer_connect_timeout <= 0) {
        return InitError(Untranslated("peertimeout must be a positive integer."));
    }

    if (const auto arg{args.GetArg("-blockmintxfee")}) {
        if (!ParseMoney(*arg)) {
            return InitError(AmountErrMsg("blockmintxfee", *arg));
        }
    }

    {
        const auto max_block_weight = args.GetIntArg("-blockmaxweight", DEFAULT_BLOCK_MAX_WEIGHT);
        if (max_block_weight > MAX_BLOCK_WEIGHT) {
            return InitError(strprintf(_("Specified -blockmaxweight (%d) exceeds consensus maximum block weight (%d)"), max_block_weight, MAX_BLOCK_WEIGHT));
        }
    }

    {
        const auto block_reserved_weight = args.GetIntArg("-blockreservedweight", DEFAULT_BLOCK_RESERVED_WEIGHT);
        if (block_reserved_weight > MAX_BLOCK_WEIGHT) {
            return InitError(strprintf(_("Specified -blockreservedweight (%d) exceeds consensus maximum block weight (%d)"), block_reserved_weight, MAX_BLOCK_WEIGHT));
        }
        if (block_reserved_weight < MINIMUM_BLOCK_RESERVED_WEIGHT) {
            return InitError(strprintf(_("Specified -blockreservedweight (%d) is lower than minimum safety value of (%d)"), block_reserved_weight, MINIMUM_BLOCK_RESERVED_WEIGHT));
        }
    }

    nBytesPerSigOp = args.GetIntArg("-bytespersigop", nBytesPerSigOp);

    if (!g_wallet_init_interface.ParameterInteraction()) return false;

    // Option to startup with mocktime set (used for regression testing):
    SetMockTime(args.GetIntArg("-mocktime", 0)); // SetMockTime(0) is a no-op

    if (args.GetBoolArg("-peerbloomfilters", DEFAULT_PEERBLOOMFILTERS))
        g_local_services = ServiceFlags(g_local_services | NODE_BLOOM);

    const std::vector<std::string> test_options = args.GetArgs("-test");
    if (!test_options.empty()) {
        if (chainparams.GetChainType() != ChainType::REGTEST) {
            return InitError(Untranslated("-test=<option> can only be used with regtest"));
        }
        for (const std::string& option : test_options) {
            auto it = std::find_if(TEST_OPTIONS_DOC.begin(), TEST_OPTIONS_DOC.end(), [&option](const std::string& doc_option) {
                size_t pos = doc_option.find(" (");
                return (pos != std::string::npos) && (doc_option.substr(0, pos) == option);
            });
            if (it == TEST_OPTIONS_DOC.end()) {
                InitWarning(strprintf(_("Unrecognised option \"%s\" provided in -test=<option>."), option));
            }
        }
    }

    // Also report errors from parsing before daemonization
    {
        kernel::Notifications notifications{};
        ChainstateManager::Options chainman_opts_dummy{
            .chainparams = chainparams,
            .datadir = args.GetDataDirNet(),
            .notifications = notifications,
        };
        auto chainman_result{ApplyArgsManOptions(args, chainman_opts_dummy)};
        if (!chainman_result) {
            return InitError(util::ErrorString(chainman_result));
        }
        BlockManager::Options blockman_opts_dummy{
            .chainparams = chainman_opts_dummy.chainparams,
            .blocks_dir = args.GetBlocksDirPath(),
            .notifications = chainman_opts_dummy.notifications,
            .block_tree_db_params = DBParams{
                .path = args.GetDataDirNet() / "blocks" / "index",
                .cache_bytes = 0,
            },
        };
        auto blockman_result{ApplyArgsManOptions(args, blockman_opts_dummy)};
        if (!blockman_result) {
            return InitError(util::ErrorString(blockman_result));
        }
        CTxMemPool::Options mempool_opts{};
        auto mempool_result{ApplyArgsManOptions(args, chainparams, mempool_opts)};
        if (!mempool_result) {
            return InitError(util::ErrorString(mempool_result));
        }
    }

    return true;
}

static bool LockDirectory(const fs::path& dir, bool probeOnly)
{
    // Make sure only a single process is using the directory.
    switch (util::LockDirectory(dir, ".lock", probeOnly)) {
    case util::LockResult::ErrorWrite:
        return InitError(strprintf(_("Cannot write to directory '%s'; check permissions."), fs::PathToString(dir)));
    case util::LockResult::ErrorLock:
        return InitError(strprintf(_("Cannot obtain a lock on directory %s. %s is probably already running."), fs::PathToString(dir), CLIENT_NAME));
    case util::LockResult::Success: return true;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}
static bool LockDirectories(bool probeOnly)
{
    return LockDirectory(gArgs.GetDataDirNet(), probeOnly) && \
           LockDirectory(gArgs.GetBlocksDirPath(), probeOnly);
}

bool AppInitSanityChecks(const kernel::Context& kernel)
{
    // ********************************************************* Step 4: sanity checks
    auto result{kernel::SanityChecks(kernel)};
    if (!result) {
        InitError(util::ErrorString(result));
        return InitError(strprintf(_("Initialization sanity check failed. %s is shutting down."), CLIENT_NAME));
    }

    if (!ECC_InitSanityCheck()) {
        return InitError(strprintf(_("Elliptic curve cryptography sanity check failure. %s is shutting down."), CLIENT_NAME));
    }

    // Probe the directory locks to give an early error message, if possible
    // We cannot hold the directory locks here, as the forking for daemon() hasn't yet happened,
    // and a fork will cause weird behavior to them.
    return LockDirectories(true);
}

bool AppInitLockDirectories()
{
    // After daemonization get the directory locks again and hold on to them until exit
    // This creates a slight window for a race condition to happen, however this condition is harmless: it
    // will at most make us exit without printing a message to console.
    if (!LockDirectories(false)) {
        // Detailed error printed inside LockDirectory
        return false;
    }
    return true;
}

bool AppInitInterfaces(NodeContext& node)
{
    node.chain = node.init->makeChain();
    node.mining = node.init->makeMining();
    return true;
}

bool CheckHostPortOptions(const ArgsManager& args) {
    for (const std::string port_option : {
        "-port",
        "-rpcport",
    }) {
        if (const auto port{args.GetArg(port_option)}) {
            uint16_t n;
            if (!ParseUInt16(*port, &n) || n == 0) {
                return InitError(InvalidPortErrMsg(port_option, *port));
            }
        }
    }

    for ([[maybe_unused]] const auto& [arg, unix] : std::vector<std::pair<std::string, bool>>{
        // arg name            UNIX socket support
        {"-i2psam",                 false},
        {"-onion",                  true},
        {"-proxy",                  true},
        {"-rpcbind",                false},
        {"-torcontrol",             false},
        {"-whitebind",              false},
        {"-zmqpubhashblock",        true},
        {"-zmqpubhashtx",           true},
        {"-zmqpubrawblock",         true},
        {"-zmqpubrawtx",            true},
        {"-zmqpubsequence",         true},
    }) {
        for (const std::string& socket_addr : args.GetArgs(arg)) {
            std::string host_out;
            uint16_t port_out{0};
            if (!SplitHostPort(socket_addr, port_out, host_out)) {
#ifdef HAVE_SOCKADDR_UN
                // Allow unix domain sockets for some options e.g. unix:/some/file/path
                if (!unix || !socket_addr.starts_with(ADDR_PREFIX_UNIX)) {
                    return InitError(InvalidPortErrMsg(arg, socket_addr));
                }
#else
                return InitError(InvalidPortErrMsg(arg, socket_addr));
#endif
            }
        }
    }

    return true;
}

// A GUI user may opt to retry once with do_reindex set if there is a failure during chainstate initialization.
// The function therefore has to support re-entry.
static ChainstateLoadResult InitAndLoadChainstate(
    NodeContext& node,
    bool do_reindex,
    const bool do_reindex_chainstate,
    const kernel::CacheSizes& cache_sizes,
    const ArgsManager& args)
{
    const CChainParams& chainparams = Params();
    CTxMemPool::Options mempool_opts{
        .check_ratio = chainparams.DefaultConsistencyChecks() ? 1 : 0,
        .signals = node.validation_signals.get(),
    };
    Assert(ApplyArgsManOptions(args, chainparams, mempool_opts)); // no error can happen, already checked in AppInitParameterInteraction
    bilingual_str mempool_error;
    node.mempool = std::make_unique<CTxMemPool>(mempool_opts, mempool_error);
    if (!mempool_error.empty()) {
        return {ChainstateLoadStatus::FAILURE_FATAL, mempool_error};
    }
    LogPrintf("* Using %.1f MiB for in-memory UTXO set (plus up to %.1f MiB of unused mempool space)\n", cache_sizes.coins * (1.0 / 1024 / 1024), mempool_opts.max_size_bytes * (1.0 / 1024 / 1024));
    ChainstateManager::Options chainman_opts{
        .chainparams = chainparams,
        .datadir = args.GetDataDirNet(),
        .notifications = *node.notifications,
        .signals = node.validation_signals.get(),
    };
    Assert(ApplyArgsManOptions(args, chainman_opts)); // no error can happen, already checked in AppInitParameterInteraction

    BlockManager::Options blockman_opts{
        .chainparams = chainman_opts.chainparams,
        .blocks_dir = args.GetBlocksDirPath(),
        .notifications = chainman_opts.notifications,
        .block_tree_db_params = DBParams{
            .path = args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = cache_sizes.block_tree_db,
            .wipe_data = do_reindex,
        },
    };
    Assert(ApplyArgsManOptions(args, blockman_opts)); // no error can happen, already checked in AppInitParameterInteraction

    // Creating the chainstate manager internally creates a BlockManager, opens
    // the blocks tree db, and wipes existing block files in case of a reindex.
    // The coinsdb is opened at a later point on LoadChainstate.
    try {
        node.chainman = std::make_unique<ChainstateManager>(*Assert(node.shutdown_signal), chainman_opts, blockman_opts);
    } catch (dbwrapper_error& e) {
        LogError("%s", e.what());
        return {ChainstateLoadStatus::FAILURE, _("Error opening block database")};
    } catch (std::exception& e) {
        return {ChainstateLoadStatus::FAILURE_FATAL, Untranslated(strprintf("Failed to initialize ChainstateManager: %s", e.what()))};
    }
    ChainstateManager& chainman = *node.chainman;
    if (chainman.m_interrupt) return {ChainstateLoadStatus::INTERRUPTED, {}};

    // This is defined and set here instead of inline in validation.h to avoid a hard
    // dependency between validation and index/base, since the latter is not in
    // libbitcoinkernel.
    chainman.snapshot_download_completed = [&node]() {
        if (!node.chainman->m_blockman.IsPruneMode()) {
            LogPrintf("[snapshot] re-enabling NODE_NETWORK services\n");
            node.connman->AddLocalServices(NODE_NETWORK);
        }
        LogPrintf("[snapshot] restarting indexes\n");
        // Drain the validation interface queue to ensure that the old indexes
        // don't have any pending work.
        Assert(node.validation_signals)->SyncWithValidationInterfaceQueue();
        for (auto* index : node.indexes) {
            index->Interrupt();
            index->Stop();
            if (!(index->Init() && index->StartBackgroundSync())) {
                LogPrintf("[snapshot] WARNING failed to restart index %s on snapshot chain\n", index->GetName());
            }
        }
    };
    node::ChainstateLoadOptions options;
    options.mempool = Assert(node.mempool.get());
    options.wipe_chainstate_db = do_reindex || do_reindex_chainstate;
    options.prune = chainman.m_blockman.IsPruneMode();
    options.check_blocks = args.GetIntArg("-checkblocks", DEFAULT_CHECKBLOCKS);
    options.check_level = args.GetIntArg("-checklevel", DEFAULT_CHECKLEVEL);
    options.require_full_verification = args.IsArgSet("-checkblocks") || args.IsArgSet("-checklevel");
    options.coins_error_cb = [] {
        uiInterface.ThreadSafeMessageBox(
            _("Error reading from database, shutting down."),
            "", CClientUIInterface::MSG_ERROR);
    };
    uiInterface.InitMessage(_("Loading block index…"));
    auto catch_exceptions = [](auto&& f) -> ChainstateLoadResult {
        try {
            return f();
        } catch (const std::exception& e) {
            LogError("%s\n", e.what());
            return std::make_tuple(node::ChainstateLoadStatus::FAILURE, _("Error loading databases"));
        }
    };

    // Helper to parse enum values from strings (case-insensitive)
    auto to_lower = [](std::string s){ std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){return std::tolower(c);}); return s; };
    auto parse_quick = [&](const std::string& s) -> std::optional<ValidationResponseValue> {
        const std::string v = to_lower(s);
        if (v == "quick_ok_smell_ok" || v == "ok" || v == "ok_ok") return ValidationResponseValue::Quick_OK_Smell_OK;
        if (v == "quick_ok_smell_fail" || v == "ok_fail") return ValidationResponseValue::Quick_OK_Smell_Fail;
        if (v == "quick_fail_smell_ok" || v == "fail_ok") return ValidationResponseValue::Quick_Fail_Smell_OK;
        if (v == "quick_fail_smell_fail" || v == "fail") return ValidationResponseValue::Quick_Fail_Smell_Fail;
        return std::nullopt;
    };
    auto parse_full = [&](const std::string& s) -> std::optional<ValidationResponseValue> {
        const std::string v = to_lower(s);
        if (v == "full_green" || v == "green") return ValidationResponseValue::Full_Green;
        if (v == "full_amber" || v == "amber") return ValidationResponseValue::Full_Amber;
        if (v == "full_red" || v == "red") return ValidationResponseValue::Full_Red;
        return std::nullopt;
    };
    auto parse_model = [&](const std::string& s) -> std::optional<ValidationResponseValue> {
        const std::string v = to_lower(s);
        if (v == "model_ok" || v == "ok") return ValidationResponseValue::Model_OK;
        if (v == "model_fail" || v == "fail") return ValidationResponseValue::Model_Fail;
        return std::nullopt;
    };

    const std::string api_mode = to_lower(args.GetArg("-validationapi", "real"));
    // On mockable/testing chains, default to mock unless explicitly overridden
    const bool is_mockable_chain = chainparams.IsMockableChain();
    if (api_mode == "mock" || (is_mockable_chain && !args.IsArgSet("-validationapi"))) {
        auto mock = std::make_unique<ValidationAPIMock>();
        // Apply defaults if provided
        if (args.IsArgSet("-mockval-default-quick")) {
            if (auto q = parse_quick(args.GetArg("-mockval-default-quick", "")); q) mock->SetDefaultResponse(ValidationReqType::Quick_Smell, *q);
        }
        if (args.IsArgSet("-mockval-default-full")) {
            if (auto f = parse_full(args.GetArg("-mockval-default-full", "")); f) mock->SetDefaultResponse(ValidationReqType::Full, *f);
        }
        if (args.IsArgSet("-mockval-default-model")) {
            if (auto m = parse_model(args.GetArg("-mockval-default-model", "")); m) mock->SetDefaultResponse(ValidationReqType::Model, *m);
        }
        g_ValidationApi = std::move(mock);
        g_ValidationApi->Initialize();
        if (args.GetBoolArg("-mockval-preapprove-genesis", false)) {
            const uint256& gh = chainparams.GenesisBlock().GetHash();
            g_ValidationApi->SetRequestStatus(gh, ValidationReqType::Quick_Smell, ValidationResponseValue::Quick_OK_Smell_OK);
        }
        LogPrintf("ValidationAPI: using mock backend\n");
    } else if (api_mode == "desktop") {
        g_ValidationApi = std::make_unique<ValidationAPI>(chainman, chainparams.GetConsensus(), /*desktop_mode=*/true);
        g_ValidationApi->Initialize();
        LogPrintf("ValidationAPI: using desktop HTTP backend\n");
    } else {
        g_ValidationApi = std::make_unique<ValidationAPI>(chainman, chainparams.GetConsensus());
        g_ValidationApi->Initialize();
    }

    auto [status, error] = catch_exceptions([&] { return LoadChainstate(chainman, cache_sizes, options); });
    if (status == node::ChainstateLoadStatus::SUCCESS) {
        uiInterface.InitMessage(_("Verifying blocks…"));
        if (chainman.m_blockman.m_have_pruned && options.check_blocks > MIN_BLOCKS_TO_KEEP) {
            LogWarning("pruned datadir may not have more than %d blocks; only checking available blocks\n",
                       MIN_BLOCKS_TO_KEEP);
        }
        std::tie(status, error) = catch_exceptions([&] { return VerifyLoadedChainstate(chainman, options); });
        if (status == node::ChainstateLoadStatus::SUCCESS) {
            LogInfo("Block index and chainstate loaded");
        }
    }
    return {status, error};
};

static bool RebuildModelDbFromActiveChain(ChainstateManager& chainman, const Consensus::Params& consensus, bilingual_str& error)
{
    // Default failure reason; specific paths below refine it. The caller surfaces
    // this via InitError().
    error = Untranslated("ModelDB recovery failed while rebuilding from active chain");
    if (!g_modeldb) return false;

    std::vector<const CBlockIndex*> active_chain;
    bool has_synced_tip{false};
    int synced_height{0};
    uint256 synced_hash{uint256::ZERO};
    bool full_rebuild{true};
    int start_height{1};

    has_synced_tip = g_modeldb->ReadSyncedTip(synced_height, synced_hash);

    {
        LOCK(cs_main);
        const CChain& chain = chainman.ActiveChain();
        active_chain.reserve(std::max(0, chain.Height()) + 1);
        for (int h = 0; h <= chain.Height(); ++h) active_chain.push_back(chain[h]);
    }

    const int active_tip_height = static_cast<int>(active_chain.size()) - 1;
    const auto block_on_active_chain = [&](int height, const uint256& hash) -> bool {
        return height >= 0 && height <= active_tip_height &&
               active_chain[height] && active_chain[height]->GetBlockHash() == hash;
    };

    // Crash-consistent recovery via the per-block undo journal. The on-disk ModelDB
    // advances one block at a time; each commit atomically bundles that block's
    // writes, an undo record, and the applied-tip marker (CModelDB::CommitBlock).
    // After an unclean shutdown the applied tip can be AHEAD of the reloaded
    // (last-flushed) chain tip or sit on an orphaned branch. Rewind it block-by-block
    // using the undo journal — which needs no historical block bodies, so it is safe
    // even on a pruned datadir — until it lands on a block that is on the active
    // chain (or genesis). Then replay forward only the shallow remainder. This
    // replaces the old "tip off active chain -> full rebuild from block 1" path that
    // turned every unclean restart on a pruned node into a fatal error.
    if (has_synced_tip) {
        full_rebuild = false;
        while (synced_height > 0 && !block_on_active_chain(synced_height, synced_hash)) {
            CModelBlockUndo undo;
            // Require an undo record whose own (height,hash) matches the marker we are
            // about to rewind — never apply a stale/corrupt same-height record to the
            // wrong block. A miss here means a pre-undo-journal ModelDB, divergence
            // older than the retention window, or corruption: fall back to a full
            // rebuild, which the guard below refuses (fatal) on a pruned datadir.
            if (!g_modeldb->ReadBlockUndo(synced_height, undo) ||
                undo.height != synced_height || undo.hash != synced_hash) {
                LogPrintf("[ModelDB] Applied tip %s@%d is off the active chain and has no matching "
                          "undo record; falling back to full rebuild\n", synced_hash.ToString(), synced_height);
                full_rebuild = true;
                break;
            }
            LogPrintf("[ModelDB] Rewinding applied tip %s@%d (off active chain) via undo journal\n",
                      synced_hash.ToString(), synced_height);
            if (!g_modeldb->ApplyUndoAndRewindTip(undo)) {
                error = Untranslated(strprintf(
                    "ModelDB recovery failed while rewinding block %d via undo journal.", synced_height));
                return false;
            }
            synced_height = undo.parent_height;
            synced_hash = undo.parent_hash;
        }
        if (!full_rebuild) {
            start_height = synced_height + 1;
            LogPrintf("[ModelDB] Incremental sync from height=%d to tip=%d\n", synced_height, active_tip_height);
        }
    } else {
        LogPrintf("[ModelDB] No synced tip marker found; switching to full rebuild\n");
        full_rebuild = true;
    }

    if (full_rebuild) {
        // A full rebuild WIPES modeldb and replays every block from height 1. If
        // this node has actually PRUNED block bodies (m_have_pruned), the
        // pre-pruneheight blocks — and any model registrations they carried — are
        // gone for good, so the replay would silently skip them and then stamp
        // synced_tip=tip: the "genesis-only, synced-to-tip" corruption seen on
        // core-node-0/4. Refuse before wiping (existing registry left intact).
        //
        // Gate on m_have_pruned AND not-in-an-assumeutxo-snapshot, NOT merely on
        // a missing BLOCK_HAVE_DATA bit: during IBD (m_have_pruned is false) or an
        // assumeutxo background sync (IsSnapshotActive — blocks below the snapshot
        // base are not-yet-downloaded, not pruned), the missing bodies get
        // re-validated normally, so they must NOT abort the rebuild (regression
        // caught by feature_assumeutxo / p2p_ibd_stalling). The incremental path
        // likewise skips-and-continues.
        if (chainman.m_blockman.m_have_pruned && !chainman.IsSnapshotActive()) {
            int pruned_height = -1;
            {
                LOCK(cs_main);
                for (size_t h = 1; h < active_chain.size(); ++h) {
                    if (!active_chain[h] || !(active_chain[h]->nStatus & BLOCK_HAVE_DATA)) {
                        pruned_height = static_cast<int>(h);
                        break;
                    }
                }
            }
            if (pruned_height >= 0) {
                LogPrintf("[ModelDB] FATAL: full rebuild required on a pruned datadir; block %d is "
                          "gone, so model registrations below the prune height cannot be "
                          "reconstructed here.\n", pruned_height);
                error = Untranslated(strprintf(
                    "ModelDB cannot be rebuilt from a pruned datadir: a full rebuild needs block %d, "
                    "which has been pruned. Remediate with one of: a full -reindex (re-downloads all "
                    "blocks), wipe the datadir and resync, or restore a ModelDB snapshot.",
                    pruned_height));
                return false; // existing ModelDB left intact (not wiped)
            }
        }
        LogPrintf("[ModelDB] Full rebuild from active chain, tip=%d\n", static_cast<int>(active_chain.size()) - 1);
        g_modeldb.reset();
        try {
            g_modeldb = std::make_unique<CModelDB>(Params().GetConsensus(), 1 << 20, /*fMemory=*/false, /*fWipe=*/true);
        } catch (const dbwrapper_error& e) {
            LogPrintf("[ModelDB] Rebuild failed to reopen DB: %s\n", e.what());
            return false;
        } catch (const std::exception& e) {
            LogPrintf("[ModelDB] Rebuild failed to reopen DB: %s\n", e.what());
            return false;
        }
        start_height = 1;
    }

    std::unordered_map<int, std::vector<uint256>> verification_schedule;
    std::unordered_map<int, std::vector<uint256>> challenge_schedule;

    auto apply_model_challenge_zero_work = [&](const uint256& model_hash, const uint256& challenged_block_hash) {
        if (model_hash.IsNull() || challenged_block_hash.IsNull()) {
            return;
        }
        LOCK(cs_main);
        CBlockIndex* challenged_index = chainman.m_blockman.LookupBlockIndex(challenged_block_hash);
        if (!challenged_index) {
            return;
        }
        chainman.ApplyModelChallengeZeroWork(model_hash, challenged_index->nHeight);
    };

    if (!full_rebuild) {
        g_modeldb->ForEachModel([&](const uint256& model_hash, const ModelRecord& record) {
            if (record.verification_event_height > 0) {
                verification_schedule[record.verification_event_height].push_back(model_hash);
            }
            if (record.challenge_verdict_height > 0) {
                challenge_schedule[record.challenge_verdict_height].push_back(model_hash);
            }
        });
    }

    for (int h = start_height; h < static_cast<int>(active_chain.size()); ++h) {
        const CBlockIndex* pindex = active_chain[h];
        if (!pindex) {
            LogPrintf("[ModelDB] Sync failed: active chain index missing at height %d\n", h);
            return false;
        }

        CBlock block;
        if (!chainman.m_blockman.ReadBlock(block, *pindex)) {
            // Missing block body. A cleared BLOCK_HAVE_DATA bit means the data is
            // absent — either pruned, or not-yet-downloaded during IBD / an
            // assumeutxo background sync. Skip it and let normal validation
            // (re)register its models when/if the block is processed; aborting
            // here would break legitimate IBD/snapshot startup. The genuinely
            // unrecoverable case (a full rebuild that wiped modeldb on a *pruned*
            // datadir) is already refused above, before the wipe. A read failure
            // on a block we DO have is real corruption/IO error -> fatal.
            if (!(pindex->nStatus & BLOCK_HAVE_DATA)) {
                LogPrintf("[ModelDB] Skipping block at height %d (%s): data not on disk\n",
                          pindex->nHeight, pindex->GetBlockHash().ToString());
                continue;
            }
            LogPrintf("[ModelDB] Sync failed: unable to read block at height %d (%s) — "
                      "data present but unreadable (corruption / IO error).\n",
                      pindex->nHeight, pindex->GetBlockHash().ToString());
            error = Untranslated(strprintf(
                "ModelDB rebuild failed: could not read block at height %d (corruption / IO error).",
                pindex->nHeight));
            return false;
        }
        g_modeldb->WriteBlockModelIndex(pindex->GetBlockHash(), static_cast<uint32_t>(pindex->nHeight), block.pow.GetModelHash());

        // Replay this block's ModelDB mutations through the journaled batch so the
        // undo journal + applied-tip advance atomically per block, exactly as live
        // block connection does — making a subsequent unclean restart recoverable too.
        g_modeldb->BeginBlock(pindex->nHeight, pindex->GetBlockHash(),
                              pindex->nHeight - 1,
                              pindex->pprev ? pindex->pprev->GetBlockHash() : uint256::ZERO);

        for (const auto& tx_ref : block.vtx) {
            const CTransaction& tx = *tx_ref;

            ModelDepositPayload deposit_payload;
            if (ParseModelDepositTx(tx, deposit_payload, consensus)) {
                ModelRecord record;
                record.metadata = deposit_payload.metadata;
                record.status = ModelRegistrationStatus::PendingDeposit;
                record.deposit_txid = tx.GetHash().ToUint256();
                record.deposit_vout = deposit_payload.deposit_vout;
                record.deposit_amount = deposit_payload.deposit_amount;
                record.owner_key_hash = deposit_payload.owner_key_hash;
                record.deposit_block_hash = pindex->GetBlockHash();
                record.deposit_block_height = pindex->nHeight;
                record.commit_txid.SetNull();
                record.commit_block_hash.SetNull();
                record.commit_block_height = 0;
                record.burn_txid.SetNull();
                record.burn_vout = 0;
                record.burn_block_height = 0;
                record.verification_code = 0;
                record.verification_details.clear();
                record.successful_commit_count = 0;
                record.verification_event_height = consensus.ModelVerificationBlockCount == 0
                    ? 0
                    : pindex->nHeight + static_cast<int>(consensus.ModelVerificationBlockCount);
                record.challenge_block_hash.SetNull();
                record.challenge_deposit_txid.SetNull();
                record.challenge_deposit_vout = 0;
                record.challenge_deposit_height = 0;
                record.challenge_commit_count = 0;
                record.challenge_verdict_height = 0;

                g_modeldb->WriteModel(deposit_payload.model_hash, record, /*overwrite=*/true);
                g_modeldb->WriteDepositIndex(COutPoint(tx.GetHash(), deposit_payload.deposit_vout), deposit_payload.model_hash);
                if (record.verification_event_height > pindex->nHeight) {
                    verification_schedule[record.verification_event_height].push_back(deposit_payload.model_hash);
                }
                continue;
            }

            ModelCommitPayload commit_payload;
            if (ParseModelCommitTx(tx, commit_payload)) {
                ModelRecord record;
                if (!g_modeldb->ReadModel(commit_payload.model_hash, record)) continue;

                record.commit_txid = tx.GetHash().ToUint256();
                record.commit_block_hash = pindex->GetBlockHash();
                record.commit_block_height = pindex->nHeight;
                record.burn_block_height = 0;

                if (commit_payload.success) {
                    record.status = ModelRegistrationStatus::PendingVerification;
                    record.verification_code = 0;
                    record.verification_details.clear();
                    if (record.successful_commit_count < std::numeric_limits<uint32_t>::max()) {
                        record.successful_commit_count += 1;
                    }
                } else {
                    record.status = ModelRegistrationStatus::Locked;
                    record.verification_code = commit_payload.failure_reason;
                    record.verification_details = "commit_failed";
                    record.burn_txid = record.deposit_txid;
                    record.burn_vout = record.deposit_vout;
                    const COutPoint deposit_out(Txid::FromUint256(record.deposit_txid), record.deposit_vout);
                    g_modeldb->EraseDepositIndex(deposit_out);
                    g_modeldb->WriteBurnIndex(deposit_out, commit_payload.model_hash);
                }
                g_modeldb->WriteModel(commit_payload.model_hash, record, /*overwrite=*/true);
                continue;
            }

            ModelChallengePayload challenge_payload;
            if (ParseModelChallengeTx(tx, challenge_payload, consensus)) {
                CBlockIndex* challenged_index = chainman.m_blockman.LookupBlockIndex(challenge_payload.block_hash);
                if (!challenged_index) continue;

                CBlock challenged_block;
                if (!chainman.m_blockman.ReadBlock(challenged_block, *challenged_index)) continue;
                const uint256 model_hash = challenged_block.pow.GetModelHash();

                ModelRecord record;
                if (!g_modeldb->ReadModel(model_hash, record)) continue;

                record.challenge_block_hash = challenge_payload.block_hash;
                record.challenge_deposit_txid = tx.GetHash().ToUint256();
                record.challenge_deposit_vout = challenge_payload.deposit_vout;
                record.challenge_deposit_height = pindex->nHeight;
                record.challenge_commit_count = 0;
                record.challenge_verdict_height = pindex->nHeight + static_cast<int>(consensus.ModelChallengeVerdictBlockCount);
                g_modeldb->WriteModel(model_hash, record, /*overwrite=*/true);
                g_modeldb->WriteChallengeDepositIndex(COutPoint(tx.GetHash(), challenge_payload.deposit_vout), model_hash);
                if (record.challenge_verdict_height > pindex->nHeight) {
                    challenge_schedule[record.challenge_verdict_height].push_back(model_hash);
                }
                continue;
            }

            ModelChallengeCommitPayload challenge_commit_payload;
            if (ParseModelChallengeCommitTx(tx, challenge_commit_payload)) {
                ModelRecord record;
                if (!g_modeldb->ReadModel(challenge_commit_payload.model_hash, record)) continue;
                if (record.challenge_verdict_height <= 0 || pindex->nHeight > record.challenge_verdict_height) continue;
                if (record.challenge_commit_count < std::numeric_limits<uint32_t>::max()) {
                    record.challenge_commit_count += 1;
                }
                if (record.challenge_commit_count >= CHALLENGE_COMMIT_THRESHOLD &&
                    record.status != ModelRegistrationStatus::Banned) {
                    record.status = ModelRegistrationStatus::Banned;
                    record.commit_block_height = pindex->nHeight;
                    record.commit_block_hash = pindex->GetBlockHash();
                    record.burn_txid = record.deposit_txid;
                    record.burn_vout = record.deposit_vout;
                    const COutPoint deposit_out(Txid::FromUint256(record.deposit_txid), record.deposit_vout);
                    g_modeldb->EraseDepositIndex(deposit_out);
                    g_modeldb->WriteBurnIndex(deposit_out, challenge_commit_payload.model_hash);
                    apply_model_challenge_zero_work(challenge_commit_payload.model_hash, record.challenge_block_hash);
                }
                g_modeldb->WriteModel(challenge_commit_payload.model_hash, record, /*overwrite=*/true);
                continue;
            }

            if (tx.version == static_cast<int32_t>(Consensus::MODEL_REGISTER_BURN_TX_VERSION) && tx.vin.size() == 1) {
                const COutPoint& burn_prevout = tx.vin[0].prevout;
                auto model_hash_opt = g_modeldb->LookupModelByBurn(burn_prevout);
                if (!model_hash_opt) continue;

                ModelRecord record;
                if (!g_modeldb->ReadModel(*model_hash_opt, record)) continue;
                record.burn_block_height = pindex->nHeight;
                g_modeldb->WriteModel(*model_hash_opt, record, /*overwrite=*/true);
                g_modeldb->EraseBurnIndex(burn_prevout);
            }
        }

        auto ver_it = verification_schedule.find(pindex->nHeight);
        if (ver_it != verification_schedule.end()) {
            for (const uint256& model_hash : ver_it->second) {
                ModelRecord record;
                if (!g_modeldb->ReadModel(model_hash, record)) continue;
                if (record.verification_event_height != pindex->nHeight) continue;

                if (record.successful_commit_count >= consensus.ModelSuccessfulCommitsThreshold) {
                    record.status = ModelRegistrationStatus::Registered;
                } else {
                    record.status = ModelRegistrationStatus::Locked;
                    record.commit_block_height = pindex->nHeight;
                    record.commit_block_hash = pindex->GetBlockHash();
                    record.commit_txid.SetNull();
                    record.burn_txid = record.deposit_txid;
                    record.burn_vout = record.deposit_vout;
                    record.burn_block_height = 0;
                    const COutPoint deposit_out(Txid::FromUint256(record.deposit_txid), record.deposit_vout);
                    g_modeldb->EraseDepositIndex(deposit_out);
                    g_modeldb->WriteBurnIndex(deposit_out, model_hash);
                }
                record.verification_event_height = 0;
                g_modeldb->WriteModel(model_hash, record, /*overwrite=*/true);
            }
            verification_schedule.erase(ver_it);
        }

        auto ch_it = challenge_schedule.find(pindex->nHeight);
        if (ch_it != challenge_schedule.end()) {
            for (const uint256& model_hash : ch_it->second) {
                ModelRecord record;
                if (!g_modeldb->ReadModel(model_hash, record)) continue;
                if (record.challenge_verdict_height != pindex->nHeight) continue;

                const COutPoint challenge_out(Txid::FromUint256(record.challenge_deposit_txid), record.challenge_deposit_vout);
                if (record.challenge_commit_count >= CHALLENGE_COMMIT_THRESHOLD) {
                    if (record.status != ModelRegistrationStatus::Banned) {
                        record.status = ModelRegistrationStatus::Banned;
                        record.commit_block_height = pindex->nHeight;
                        record.commit_block_hash = pindex->GetBlockHash();
                        record.burn_txid = record.deposit_txid;
                        record.burn_vout = record.deposit_vout;
                        const COutPoint deposit_out(Txid::FromUint256(record.deposit_txid), record.deposit_vout);
                        g_modeldb->EraseDepositIndex(deposit_out);
                        g_modeldb->WriteBurnIndex(deposit_out, model_hash);
                    }
                    apply_model_challenge_zero_work(model_hash, record.challenge_block_hash);
                } else {
                    g_modeldb->WriteBurnIndex(challenge_out, MODELDB_CHALLENGE_BURN_SENTINEL);
                }

                record.challenge_block_hash.SetNull();
                record.challenge_deposit_txid.SetNull();
                record.challenge_deposit_vout = 0;
                record.challenge_deposit_height = 0;
                record.challenge_commit_count = 0;
                record.challenge_verdict_height = 0;
                g_modeldb->EraseChallengeDepositIndex(challenge_out);
                g_modeldb->WriteModel(model_hash, record, /*overwrite=*/true);
            }
            challenge_schedule.erase(ch_it);
        }

        if (!g_modeldb->CommitBlock()) {
            error = Untranslated(strprintf(
                "ModelDB recovery failed to commit replayed block at height %d.", pindex->nHeight));
            return false;
        }
    }

    // If node restarts after a model verification event height has already passed,
    // finalize those overdue records now to prevent indefinite pending states.
    // Also repair legacy/corrupted pending records where verification_event_height
    // is missing by reconstructing it from deposit_block_height.
    if (!active_chain.empty() && active_chain.back()) {
        const int tip_height = active_chain.back()->nHeight;
        std::vector<uint256> candidate_models;
        g_modeldb->ForEachModel([&](const uint256& model_hash, const ModelRecord& record) {
            if (record.status != ModelRegistrationStatus::PendingDeposit &&
                record.status != ModelRegistrationStatus::PendingVerification) {
                return;
            }
            candidate_models.push_back(model_hash);
        });

        // Journal the finalization writes below into the tip block's undo record so
        // they are reversible on a later reorg/restart (candidates were gathered above
        // against committed state, before opening the block).
        const CBlockIndex* tip_index = active_chain.back();
        const CBlockIndex* tip_parent =
            (tip_index->nHeight >= 1 && tip_index->nHeight - 1 < static_cast<int>(active_chain.size()))
                ? active_chain[tip_index->nHeight - 1]
                : nullptr;
        // Journal the repair writes into the tip block's undo record IF that block has
        // one (always true for blocks this binary connected/replayed). On an upgraded
        // node whose tip predates the journal, ResumeBlock returns false and we DEFER the
        // repair entirely (skip the mutations, only advance the marker) — the next
        // journaled block re-applies any overdue finalization. See the commit branch below.
        const bool repair_journaled = g_modeldb->ResumeBlock(
            tip_index->nHeight, tip_index->GetBlockHash(),
            tip_index->nHeight - 1,
            tip_parent ? tip_parent->GetBlockHash() : uint256::ZERO);

        if (repair_journaled) {
            // The repair mutations are staged into the tip block's undo record (via
            // ResumeBlock), so they are reversible on a later reorg/rewind.
            for (const uint256& model_hash : candidate_models) {
                ModelRecord record;
                if (!g_modeldb->ReadModel(model_hash, record)) continue;
                if (record.status != ModelRegistrationStatus::PendingDeposit &&
                    record.status != ModelRegistrationStatus::PendingVerification) {
                    continue;
                }

                // Repair missing event height for pending records.
                if (record.verification_event_height <= 0 && record.deposit_block_height > 0 &&
                    consensus.ModelVerificationBlockCount > 0) {
                    record.verification_event_height =
                        record.deposit_block_height + static_cast<int>(consensus.ModelVerificationBlockCount);
                    g_modeldb->WriteModel(model_hash, record, /*overwrite=*/true);
                    if (record.verification_event_height > tip_height) {
                        CModelDB::VerificationValue sched;
                        g_modeldb->WriteVerificationSchedule(
                            static_cast<uint32_t>(record.verification_event_height), model_hash, sched);
                    }
                    LogPrintf("[ModelDB] Repaired missing verification_event_height for %s: event_height=%d (tip=%d)\n",
                              model_hash.ToString(), record.verification_event_height, tip_height);
                }

                if (record.verification_event_height <= 0 || record.verification_event_height > tip_height) continue;

                const int event_height = record.verification_event_height;
                const bool meets_threshold = record.successful_commit_count >= consensus.ModelSuccessfulCommitsThreshold;
                if (meets_threshold) {
                    record.status = ModelRegistrationStatus::Registered;
                } else {
                    record.status = ModelRegistrationStatus::Locked;
                    record.commit_txid.SetNull();
                    record.commit_block_height = event_height;
                    if (event_height >= 0 && event_height < static_cast<int>(active_chain.size()) && active_chain[event_height]) {
                        record.commit_block_hash = active_chain[event_height]->GetBlockHash();
                    } else {
                        record.commit_block_hash.SetNull();
                    }
                    record.burn_txid = record.deposit_txid;
                    record.burn_vout = record.deposit_vout;
                    record.burn_block_height = 0;
                    const COutPoint deposit_out(Txid::FromUint256(record.deposit_txid), record.deposit_vout);
                    g_modeldb->EraseDepositIndex(deposit_out);
                    g_modeldb->WriteBurnIndex(deposit_out, model_hash);
                }

                record.verification_event_height = 0;
                g_modeldb->WriteModel(model_hash, record, /*overwrite=*/true);
                g_modeldb->EraseVerificationSchedule(static_cast<uint32_t>(event_height), model_hash);
                LogPrintf("[ModelDB] Finalized overdue model verification for %s at event_height=%d (tip=%d), new_status=%u\n",
                          model_hash.ToString(), event_height, tip_height, static_cast<unsigned>(record.status));
            }

            // Atomically commit the repair writes + advance the applied-tip marker
            // (merged into the tip block's undo record).
            if (!g_modeldb->CommitBlock()) {
                error = Untranslated("ModelDB recovery failed to commit post-replay repair writes.");
                return false;
            }
        } else {
            // Pre-journal tip (no undo record for the tip). Performing the overdue
            // finalization writes here would be UN-journaled and NOT reversible by
            // body-based DisconnectBlock — they are catch-up effects, not effects of the
            // tip block's body — which is a soundness hole on a later reorg/rewind. So
            // skip them entirely: the next connected block's runtime catch-up (in
            // ConnectTip) re-applies any overdue finalization, journaled under that
            // block. Only advance the marker here.
            if (!candidate_models.empty()) {
                LogPrintf("[ModelDB] Pre-journal tip at height=%d with %d pending model(s); deferring "
                          "finalization to the next connected block's journaled catch-up\n",
                          tip_height, static_cast<int>(candidate_models.size()));
            }
            if (!g_modeldb->WriteSyncedTip(tip_index->nHeight, tip_index->GetBlockHash())) {
                error = Untranslated("ModelDB recovery failed to persist the synced tip on the pre-journal fallback path.");
                return false;
            }
        }
    }

    LogPrintf("[ModelDB] Sync complete.\n");
    return true;
}

bool AppInitMain(NodeContext& node, interfaces::BlockAndHeaderTipInfo* tip_info)
{
    const ArgsManager& args = *Assert(node.args);
    const CChainParams& chainparams = Params();

    auto opt_max_upload = ParseByteUnits(args.GetArg("-maxuploadtarget", DEFAULT_MAX_UPLOAD_TARGET), ByteUnit::M);
    if (!opt_max_upload) {
        return InitError(strprintf(_("Unable to parse -maxuploadtarget: '%s'"), args.GetArg("-maxuploadtarget", "")));
    }

    // ********************************************************* Step 4a: application initialization
    if (!CreatePidFile(args)) {
        // Detailed error printed inside CreatePidFile().
        return false;
    }
    if (!init::StartLogging(args)) {
        // Detailed error printed inside StartLogging().
        return false;
    }

    LogPrintf("Using at most %i automatic connections (%i file descriptors available)\n", nMaxConnections, available_fds);

    // Warn about relative -datadir path.
    if (args.IsArgSet("-datadir") && !args.GetPathArg("-datadir").is_absolute()) {
        LogPrintf("Warning: relative datadir option '%s' specified, which will be interpreted relative to the "
                  "current working directory '%s'. This is fragile, because if bitcoin is started in the future "
                  "from a different location, it will be unable to locate the current data files. There could "
                  "also be data loss if bitcoin is started while in a temporary directory.\n",
                  args.GetArg("-datadir", ""), fs::PathToString(fs::current_path()));
    }

    assert(!node.scheduler);
    node.scheduler = std::make_unique<CScheduler>();
    auto& scheduler = *node.scheduler;

    // Start the lightweight task scheduler thread
    scheduler.m_service_thread = std::thread(util::TraceThread, "scheduler", [&] { scheduler.serviceQueue(); });

    // Gather some entropy once per minute.
    scheduler.scheduleEvery([]{
        RandAddPeriodic();
    }, std::chrono::minutes{1});

    // Check disk space every 5 minutes to avoid db corruption.
    scheduler.scheduleEvery([&args, &node]{
        constexpr uint64_t min_disk_space = 50 << 20; // 50 MB
        if (!CheckDiskSpace(args.GetBlocksDirPath(), min_disk_space)) {
            LogError("Shutting down due to lack of disk space!\n");
            if (!(Assert(node.shutdown_request))()) {
                LogError("Failed to send shutdown signal after disk space check\n");
            }
        }
    }, std::chrono::minutes{5});

    assert(!node.validation_signals);
    node.validation_signals = std::make_unique<ValidationSignals>(std::make_unique<SerialTaskRunner>(scheduler));
    auto& validation_signals = *node.validation_signals;

    g_modeldb = std::make_unique<CModelDB>(chainparams.GetConsensus());
    // Create client interfaces for wallets that are supposed to be loaded
    // according to -wallet and -disablewallet options. This only constructs
    // the interfaces, it doesn't load wallet data. Wallets actually get loaded
    // when load() and start() interface methods are called below.
    g_wallet_init_interface.Construct(node);
    uiInterface.InitWallet();

    if (interfaces::Ipc* ipc = node.init->ipc()) {
        for (std::string address : gArgs.GetArgs("-ipcbind")) {
            try {
                ipc->listenAddress(address);
            } catch (const std::exception& e) {
                return InitError(Untranslated(strprintf("Unable to bind to IPC address '%s'. %s", address, e.what())));
            }
            LogPrintf("Listening for IPC requests on address %s\n", address);
        }
    }

    /* Register RPC commands regardless of -server setting so they will be
     * available in the GUI RPC console even if external calls are disabled.
     */
    RegisterAllCoreRPCCommands(tableRPC);
    for (const auto& client : node.chain_clients) {
        client->registerRpcs();
    }
#ifdef ENABLE_ZMQ
    RegisterZMQRPCCommands(tableRPC);
#endif

    // Check port numbers
    if (!CheckHostPortOptions(args)) return false;

    /* Start the RPC server already.  It will be started in "warmup" mode
     * and not really process calls already (but it will signify connections
     * that the server is there and will be ready later).  Warmup mode will
     * be disabled when initialisation is finished.
     */
    if (args.GetBoolArg("-server", false)) {
        uiInterface.InitMessage_connect(SetRPCWarmupStatus);
        if (!AppInitServers(node))
            return InitError(_("Unable to start HTTP server. See debug log for details."));
    }

    // ********************************************************* Step 5: verify wallet database integrity
    for (const auto& client : node.chain_clients) {
        if (!client->verify()) {
            return false;
        }
    }

    // ********************************************************* Step 6: network initialization
    // Note that we absolutely cannot open any actual connections
    // until the very end ("start node") as the UTXO/block state
    // is not yet setup and may end up being set up twice if we
    // need to reindex later.

    fListen = args.GetBoolArg("-listen", DEFAULT_LISTEN);
    fDiscover = args.GetBoolArg("-discover", true);

    PeerManager::Options peerman_opts{};
    ApplyArgsManOptions(args, peerman_opts);

    {

        // Read asmap: an explicit -asmap file, else the compiled-in default map,
        // unless disabled with -noasmap. ASN-based bucketing is thus ON BY DEFAULT.
        std::vector<bool> asmap;
        std::string asmap_source{"none"}; // provenance surfaced via getnetworkinfo.asmap
        if (args.IsArgNegated("-asmap")) {
            LogPrintf("asmap disabled (-noasmap). Using /16 prefix for IP bucketing\n");
        } else if (args.IsArgSet("-asmap")) {
            fs::path asmap_path = args.GetPathArg("-asmap", DEFAULT_ASMAP_FILENAME);
            if (!asmap_path.is_absolute()) {
                asmap_path = args.GetDataDirNet() / asmap_path;
            }
            if (!fs::exists(asmap_path)) {
                InitError(strprintf(_("Could not find asmap file %s"), fs::quoted(fs::PathToString(asmap_path))));
                return false;
            }
            asmap = DecodeAsmap(asmap_path);
            if (asmap.size() == 0) {
                InitError(strprintf(_("Could not parse asmap file %s"), fs::quoted(fs::PathToString(asmap_path))));
                return false;
            }
            const uint256 asmap_version = (HashWriter{} << asmap).GetHash();
            LogPrintf("Using asmap version %s for IP bucketing\n", asmap_version.ToString());
            asmap_source = "file";
        } else {
            // No -asmap argument: prefer a datadir ip_asn.map if an operator dropped one in
            // (override without recompiling), otherwise use the compiled-in default map.
            fs::path default_path = args.GetDataDirNet() / DEFAULT_ASMAP_FILENAME;
            if (fs::exists(default_path)) {
                asmap = DecodeAsmap(default_path);
                if (asmap.size() == 0) {
                    InitError(strprintf(_("Could not parse asmap file %s"), fs::quoted(fs::PathToString(default_path))));
                    return false;
                }
                const uint256 asmap_version = (HashWriter{} << asmap).GetHash();
                LogPrintf("Using asmap version %s (datadir default file) for IP bucketing\n", asmap_version.ToString());
                asmap_source = "datadir";
            } else {
                asmap = DecodeAsmap(GetEmbeddedAsmapBytes(), "embedded default");
                if (asmap.size() == 0) {
                    // Should never happen: the embedded map is validated at build/commit time.
                    // An empty result here means a corrupt/broken build artifact, which would
                    // silently degrade every node to /16. Make it impossible to miss (and note
                    // -noasmap is the intentional disable). Not fatal so a bad map can't brick startup.
                    InitWarning(_("Embedded default asmap failed to decode (corrupt build artifact?). "
                                  "Falling back to /16 prefix bucketing, which weakens Sybil resistance. "
                                  "Use -noasmap to silence this if the fallback is intended."));
                    LogPrintf("ERROR: embedded default asmap failed sanity check; using /16 prefix for IP bucketing\n");
                } else {
                    const uint256 asmap_version = (HashWriter{} << asmap).GetHash();
                    LogPrintf("Using embedded default asmap version %s for IP bucketing\n", asmap_version.ToString());
                    asmap_source = "embedded";
                }
            }
        }

        // Initialize netgroup manager
        assert(!node.netgroupman);
        node.netgroupman = std::make_unique<NetGroupManager>(std::move(asmap), asmap_source);

        // Initialize addrman
        assert(!node.addrman);
        uiInterface.InitMessage(_("Loading P2P addresses…"));
        auto addrman{LoadAddrman(*node.netgroupman, args)};
        if (!addrman) return InitError(util::ErrorString(addrman));
        node.addrman = std::move(*addrman);
    }

    FastRandomContext rng;
    assert(!node.banman);
    node.banman = std::make_unique<BanMan>(args.GetDataDirNet() / "banlist", &uiInterface, args.GetIntArg("-bantime", DEFAULT_MISBEHAVING_BANTIME));
    assert(!node.connman);
    node.connman = std::make_unique<CConnman>(rng.rand64(),
                                              rng.rand64(),
                                              *node.addrman, *node.netgroupman, chainparams, args.GetBoolArg("-networkactive", true));

    assert(!node.fee_estimator);
    // Don't initialize fee estimation with old data if we don't relay transactions,
    // as they would never get updated.
    if (!peerman_opts.ignore_incoming_txs) {
        bool read_stale_estimates = args.GetBoolArg("-acceptstalefeeestimates", DEFAULT_ACCEPT_STALE_FEE_ESTIMATES);
        if (read_stale_estimates && (chainparams.GetChainType() != ChainType::REGTEST)) {
            return InitError(strprintf(_("acceptstalefeeestimates is not supported on %s chain."), chainparams.GetChainTypeString()));
        }
        node.fee_estimator = std::make_unique<CBlockPolicyEstimator>(FeeestPath(args), read_stale_estimates);

        // Flush estimates to disk periodically
        CBlockPolicyEstimator* fee_estimator = node.fee_estimator.get();
        scheduler.scheduleEvery([fee_estimator] { fee_estimator->FlushFeeEstimates(); }, FEE_FLUSH_INTERVAL);
        validation_signals.RegisterValidationInterface(fee_estimator);
    }

    for (const std::string& socket_addr : args.GetArgs("-bind")) {
        std::string host_out;
        uint16_t port_out{0};
        std::string bind_socket_addr = socket_addr.substr(0, socket_addr.rfind('='));
        if (!SplitHostPort(bind_socket_addr, port_out, host_out)) {
            return InitError(InvalidPortErrMsg("-bind", socket_addr));
        }
    }

    // sanitize comments per BIP-0014, format user agent and check total size
    std::vector<std::string> uacomments;
    for (const std::string& cmt : args.GetArgs("-uacomment")) {
        if (cmt != SanitizeString(cmt, SAFE_CHARS_UA_COMMENT))
            return InitError(strprintf(_("User Agent comment (%s) contains unsafe characters."), cmt));
        uacomments.push_back(cmt);
    }
    strSubVersion = FormatSubVersion(UA_NAME, CLIENT_VERSION, uacomments);
    if (strSubVersion.size() > MAX_SUBVERSION_LENGTH) {
        return InitError(strprintf(_("Total length of network version string (%i) exceeds maximum length (%i). Reduce the number or size of uacomments."),
            strSubVersion.size(), MAX_SUBVERSION_LENGTH));
    }

    const auto onlynets = args.GetArgs("-onlynet");
    if (!onlynets.empty()) {
        g_reachable_nets.RemoveAll();
        for (const std::string& snet : onlynets) {
            enum Network net = ParseNetwork(snet);
            if (net == NET_UNROUTABLE)
                return InitError(strprintf(_("Unknown network specified in -onlynet: '%s'"), snet));
            g_reachable_nets.Add(net);
        }
    }

    if (!args.IsArgSet("-cjdnsreachable")) {
        if (!onlynets.empty() && g_reachable_nets.Contains(NET_CJDNS)) {
            return InitError(
                _("Outbound connections restricted to CJDNS (-onlynet=cjdns) but "
                  "-cjdnsreachable is not provided"));
        }
        g_reachable_nets.Remove(NET_CJDNS);
    }
    // Now g_reachable_nets.Contains(NET_CJDNS) is true if:
    // 1. -cjdnsreachable is given and
    // 2.1. -onlynet is not given or
    // 2.2. -onlynet=cjdns is given

    // Requesting DNS seeds entails connecting to IPv4/IPv6, which -onlynet options may prohibit:
    // If -dnsseed=1 is explicitly specified, abort. If it's left unspecified by the user, we skip
    // the DNS seeds by adjusting -dnsseed in InitParameterInteraction.
    if (args.GetBoolArg("-dnsseed") == true && !g_reachable_nets.Contains(NET_IPV4) && !g_reachable_nets.Contains(NET_IPV6)) {
        return InitError(strprintf(_("Incompatible options: -dnsseed=1 was explicitly specified, but -onlynet forbids connections to IPv4/IPv6")));
    };

    // Check for host lookup allowed before parsing any network related parameters
    fNameLookup = args.GetBoolArg("-dns", DEFAULT_NAME_LOOKUP);

    Proxy onion_proxy;

    bool proxyRandomize = args.GetBoolArg("-proxyrandomize", DEFAULT_PROXYRANDOMIZE);
    // -proxy sets a proxy for all outgoing network traffic
    // -noproxy (or -proxy=0) as well as the empty string can be used to not set a proxy, this is the default
    std::string proxyArg = args.GetArg("-proxy", "");
    if (proxyArg != "" && proxyArg != "0") {
        Proxy addrProxy;
        if (IsUnixSocketPath(proxyArg)) {
            addrProxy = Proxy(proxyArg, /*tor_stream_isolation=*/proxyRandomize);
        } else {
            const std::optional<CService> proxyAddr{Lookup(proxyArg, 9050, fNameLookup)};
            if (!proxyAddr.has_value()) {
                return InitError(strprintf(_("Invalid -proxy address or hostname: '%s'"), proxyArg));
            }

            addrProxy = Proxy(proxyAddr.value(), /*tor_stream_isolation=*/proxyRandomize);
        }

        if (!addrProxy.IsValid())
            return InitError(strprintf(_("Invalid -proxy address or hostname: '%s'"), proxyArg));

        SetProxy(NET_IPV4, addrProxy);
        SetProxy(NET_IPV6, addrProxy);
        SetProxy(NET_CJDNS, addrProxy);
        SetNameProxy(addrProxy);
        onion_proxy = addrProxy;
    }

    const bool onlynet_used_with_onion{!onlynets.empty() && g_reachable_nets.Contains(NET_ONION)};

    // -onion can be used to set only a proxy for .onion, or override normal proxy for .onion addresses
    // -noonion (or -onion=0) disables connecting to .onion entirely
    // An empty string is used to not override the onion proxy (in which case it defaults to -proxy set above, or none)
    std::string onionArg = args.GetArg("-onion", "");
    if (onionArg != "") {
        if (onionArg == "0") { // Handle -noonion/-onion=0
            onion_proxy = Proxy{};
            if (onlynet_used_with_onion) {
                return InitError(
                    _("Outbound connections restricted to Tor (-onlynet=onion) but the proxy for "
                      "reaching the Tor network is explicitly forbidden: -onion=0"));
            }
        } else {
            if (IsUnixSocketPath(onionArg)) {
                onion_proxy = Proxy(onionArg, /*tor_stream_isolation=*/proxyRandomize);
            } else {
                const std::optional<CService> addr{Lookup(onionArg, 9050, fNameLookup)};
                if (!addr.has_value() || !addr->IsValid()) {
                    return InitError(strprintf(_("Invalid -onion address or hostname: '%s'"), onionArg));
                }

                onion_proxy = Proxy(addr.value(), /*tor_stream_isolation=*/proxyRandomize);
            }
        }
    }

    if (onion_proxy.IsValid()) {
        SetProxy(NET_ONION, onion_proxy);
    } else {
        // If -listenonion is set, then we will (try to) connect to the Tor control port
        // later from the torcontrol thread and may retrieve the onion proxy from there.
        const bool listenonion_disabled{!args.GetBoolArg("-listenonion", DEFAULT_LISTEN_ONION)};
        if (onlynet_used_with_onion && listenonion_disabled) {
            return InitError(
                _("Outbound connections restricted to Tor (-onlynet=onion) but the proxy for "
                  "reaching the Tor network is not provided: none of -proxy, -onion or "
                  "-listenonion is given"));
        }
        g_reachable_nets.Remove(NET_ONION);
    }

    for (const std::string& strAddr : args.GetArgs("-externalip")) {
        const std::optional<CService> addrLocal{Lookup(strAddr, GetListenPort(), fNameLookup)};
        if (addrLocal.has_value() && addrLocal->IsValid())
            AddLocal(addrLocal.value(), LOCAL_MANUAL);
        else
            return InitError(ResolveErrMsg("externalip", strAddr));
    }

    // Build the external mining API only after config files have been parsed so
    // desktop defaults like -useextapi=0 actually take effect on first launch.
    if (gArgs.GetBoolArg("-useextapi", true) && chainparams.GetConsensus().external_api) {
        if (!node.expt_api) {
            node.expt_api = std::make_unique<node::ExtAPI>(node);
        }
        node.expt_api->Initialize();
    }

#ifdef ENABLE_ZMQ
    g_zmq_notification_interface = CZMQNotificationInterface::Create(
        [&chainman = node.chainman](std::vector<uint8_t>& block, const CBlockIndex& index) {
            assert(chainman);
            return chainman->m_blockman.ReadRawBlock(block, WITH_LOCK(cs_main, return index.GetBlockPos()));
        });

    if (g_zmq_notification_interface) {
        validation_signals.RegisterValidationInterface(g_zmq_notification_interface.get());
    }
#endif

    // ********************************************************* Step 7: load block chain

    node.notifications = std::make_unique<KernelNotifications>(Assert(node.shutdown_request), node.exit_status, *Assert(node.warnings));
    auto& kernel_notifications{*node.notifications};
    ReadNotificationArgs(args, kernel_notifications);

    // cache size calculations
    const auto [index_cache_sizes, kernel_cache_sizes] = CalculateCacheSizes(args, g_enabled_filter_types.size());

    LogInfo("Cache configuration:");
    LogInfo("* Using %.1f MiB for block index database", kernel_cache_sizes.block_tree_db * (1.0 / 1024 / 1024));
    if (args.GetBoolArg("-txindex", DEFAULT_TXINDEX)) {
        LogInfo("* Using %.1f MiB for transaction index database", index_cache_sizes.tx_index * (1.0 / 1024 / 1024));
    }
    for (BlockFilterType filter_type : g_enabled_filter_types) {
        LogInfo("* Using %.1f MiB for %s block filter index database",
                  index_cache_sizes.filter_index * (1.0 / 1024 / 1024), BlockFilterTypeName(filter_type));
    }
    LogInfo("* Using %.1f MiB for chain state database", kernel_cache_sizes.coins_db * (1.0 / 1024 / 1024));

    assert(!node.mempool);
    assert(!node.chainman);

    bool do_reindex{args.GetBoolArg("-reindex", false)};
    const bool do_reindex_chainstate{args.GetBoolArg("-reindex-chainstate", false)};

    // Chainstate initialization and loading may be retried once with reindexing by GUI users
    auto [status, error] = InitAndLoadChainstate(
        node,
        do_reindex,
        do_reindex_chainstate,
        kernel_cache_sizes,
        args);
    if (status == ChainstateLoadStatus::FAILURE && !do_reindex && !ShutdownRequested(node)) {
        // suggest a reindex
        bool do_retry = uiInterface.ThreadSafeQuestion(
            error + Untranslated(".\n\n") + _("Do you want to rebuild the databases now?"),
            error.original + ".\nPlease restart with -reindex or -reindex-chainstate to recover.",
            "", CClientUIInterface::MSG_ERROR | CClientUIInterface::BTN_ABORT);
        if (!do_retry) {
            return false;
        }
        do_reindex = true;
        if (!Assert(node.shutdown_signal)->reset()) {
            LogError("Internal error: failed to reset shutdown signal.\n");
        }
        std::tie(status, error) = InitAndLoadChainstate(
            node,
            do_reindex,
            do_reindex_chainstate,
            kernel_cache_sizes,
            args);
    }
    if (status != ChainstateLoadStatus::SUCCESS && status != ChainstateLoadStatus::INTERRUPTED) {
        return InitError(error);
    }

    // As LoadBlockIndex can take several minutes, it's possible the user
    // requested to kill the GUI during the last operation. If so, exit.
    if (ShutdownRequested(node)) {
        LogPrintf("Shutdown requested. Exiting.\n");
        return false;
    }

    ChainstateManager& chainman = *Assert(node.chainman);

    // Reorg-gate async hooks: the scheduler owns gate timeouts, a dedicated
    // manager thread owns the post-decision ActivateBestChain kick, so no
    // validation, RPC or scheduler thread ever parks on the gate (mask mode).
    // The snapshot hook feeds the decision-time raw-work guardrails. Hooks
    // are dropped in Shutdown before the scheduler/chainman are torn down.
    GetReorgGatingManager().SetAsyncHooks(
        /*schedule_fn=*/[&scheduler](std::function<void()> task, int64_t delay_secs) {
            scheduler.scheduleFromNow(std::move(task), std::chrono::seconds{delay_secs});
        },
        // Runs on the manager's dedicated kick thread. It must NOT run on the
        // scheduler thread: ActivateBestChain waits on the validation-interface
        // queue, which the scheduler thread drains (SerialTaskRunner), so
        // running it there self-deadlocks.
        /*kick_fn=*/[&chainman] {
            BlockValidationState state;
            if (!chainman.ActiveChainstate().ActivateBestChain(state)) {
                LogPrintf("REORG GATING: post-decision ActivateBestChain failed: %s\n", state.ToString());
            }
        },
        /*snapshot_fn=*/[&chainman](const uint256& candidate_tip_hash) {
            LOCK(cs_main);
            return ComputeReorgGateWorkSnapshot(chainman, candidate_tip_hash);
        });

    // g_ValidationApi is constructed inside InitAndLoadChainstate, so the
    // connman hookup must happen after it returns — wiring it next to the
    // CConnman construction above silently no-ops on a null g_ValidationApi
    // and leaves amber peer corroboration permanently disabled.
    if (auto* validation_api = dynamic_cast<ValidationAPI*>(g_ValidationApi.get())) {
        validation_api->SetConnman(node.connman.get());
    }

    if (g_modeldb) {
        bilingual_str modeldb_error;
        if (!RebuildModelDbFromActiveChain(chainman, chainparams.GetConsensus(), modeldb_error)) {
            return InitError(modeldb_error);
        }
    }

    assert(!node.peerman);
    node.peerman = PeerManager::make(*node.connman, *node.addrman,
                                     node.banman.get(), chainman,
                                     *node.mempool, *node.warnings,
                                     peerman_opts);
    validation_signals.RegisterValidationInterface(node.peerman.get());

    // ********************************************************* Step 8: start indexers

    if (args.GetBoolArg("-txindex", DEFAULT_TXINDEX)) {
        g_txindex = std::make_unique<TxIndex>(interfaces::MakeChain(node), index_cache_sizes.tx_index, false, do_reindex);
        node.indexes.emplace_back(g_txindex.get());
    }

    for (const auto& filter_type : g_enabled_filter_types) {
        InitBlockFilterIndex([&]{ return interfaces::MakeChain(node); }, filter_type, index_cache_sizes.filter_index, false, do_reindex);
        node.indexes.emplace_back(GetBlockFilterIndex(filter_type));
    }

    if (args.GetBoolArg("-coinstatsindex", DEFAULT_COINSTATSINDEX)) {
        g_coin_stats_index = std::make_unique<CoinStatsIndex>(interfaces::MakeChain(node), /*cache_size=*/0, false, do_reindex);
        node.indexes.emplace_back(g_coin_stats_index.get());
    }

    if (args.GetBoolArg("-icuacceptanceindex", DEFAULT_ICU_ACCEPTANCE_INDEX)) {
        g_icu_acceptance_index = std::make_unique<IcuAcceptanceIndex>(interfaces::MakeChain(node), /*cache_size=*/0, false, do_reindex);
        node.indexes.emplace_back(g_icu_acceptance_index.get());
    }

    // Init indexes
    for (auto index : node.indexes) if (!index->Init()) return false;

    // ********************************************************* Step 9: load wallet
    for (const auto& client : node.chain_clients) {
        if (!client->load()) {
            return false;
        }
    }

    // ********************************************************* Step 10: data directory maintenance

    // if pruning, perform the initial blockstore prune
    // after any wallet rescanning has taken place.
    if (chainman.m_blockman.IsPruneMode()) {
        if (chainman.m_blockman.m_blockfiles_indexed) {
            LOCK(cs_main);
            for (Chainstate* chainstate : chainman.GetAll()) {
                uiInterface.InitMessage(_("Pruning blockstore…"));
                chainstate->PruneAndFlush();
            }
        }
    } else {
        // Prior to setting NODE_NETWORK, check if we can provide historical blocks.
        if (!WITH_LOCK(chainman.GetMutex(), return chainman.BackgroundSyncInProgress())) {
            LogPrintf("Setting NODE_NETWORK on non-prune mode\n");
            g_local_services = ServiceFlags(g_local_services | NODE_NETWORK);
        } else {
            LogPrintf("Running node in NODE_NETWORK_LIMITED mode until snapshot background sync completes\n");
        }
    }

    // ********************************************************* Step 11: import blocks

    if (!CheckDiskSpace(args.GetDataDirNet())) {
        InitError(strprintf(_("Error: Disk space is low for %s"), fs::quoted(fs::PathToString(args.GetDataDirNet()))));
        return false;
    }
    if (!CheckDiskSpace(args.GetBlocksDirPath())) {
        InitError(strprintf(_("Error: Disk space is low for %s"), fs::quoted(fs::PathToString(args.GetBlocksDirPath()))));
        return false;
    }

    int chain_active_height = WITH_LOCK(cs_main, return chainman.ActiveChain().Height());

    // On first startup, warn on low block storage space
    if (!do_reindex && !do_reindex_chainstate && chain_active_height <= 1) {
        uint64_t assumed_chain_bytes{chainparams.AssumedBlockchainSize() * 1024 * 1024 * 1024};
        uint64_t additional_bytes_needed{
            chainman.m_blockman.IsPruneMode() ?
                std::min(chainman.m_blockman.GetPruneTarget(), assumed_chain_bytes) :
                assumed_chain_bytes};

        if (!CheckDiskSpace(args.GetBlocksDirPath(), additional_bytes_needed)) {
            InitWarning(strprintf(_(
                    "Disk space for %s may not accommodate the block files. " \
                    "Approximately %u GB of data will be stored in this directory."
                ),
                fs::quoted(fs::PathToString(args.GetBlocksDirPath())),
                chainparams.AssumedBlockchainSize()
            ));
        }
    }

#if HAVE_SYSTEM
    const std::string block_notify = args.GetArg("-blocknotify", "");
    if (!block_notify.empty()) {
        uiInterface.NotifyBlockTip_connect([block_notify](SynchronizationState sync_state, const CBlockIndex* pBlockIndex) {
            if (sync_state != SynchronizationState::POST_INIT || !pBlockIndex) return;
            std::string command = block_notify;
            ReplaceAll(command, "%s", pBlockIndex->GetBlockHash().GetHex());
            std::thread t(runCommand, command);
            t.detach(); // thread runs free
        });
    }
#endif

    std::vector<fs::path> vImportFiles;
    for (const std::string& strFile : args.GetArgs("-loadblock")) {
        vImportFiles.push_back(fs::PathFromString(strFile));
    }

    node.background_init_thread = std::thread(&util::TraceThread, "initload", [=, &chainman, &args, &node] {
        ScheduleBatchPriority();
        // Import blocks and ActivateBestChain()
        ImportBlocks(chainman, vImportFiles);
        if (args.GetBoolArg("-stopafterblockimport", DEFAULT_STOPAFTERBLOCKIMPORT)) {
            LogPrintf("Stopping after block import\n");
            if (!(Assert(node.shutdown_request))()) {
                LogError("Failed to send shutdown signal after finishing block import\n");
            }
            return;
        }

        // Start indexes initial sync
        if (!StartIndexBackgroundSync(node)) {
            bilingual_str err_str = _("Failed to start indexes, shutting down…");
            chainman.GetNotifications().fatalError(err_str);
            return;
        }
        // Load mempool from disk
        if (auto* pool{chainman.ActiveChainstate().GetMempool()}) {
            LoadMempool(*pool, ShouldPersistMempool(args) ? MempoolPath(args) : fs::path{}, chainman.ActiveChainstate(), {});
            pool->SetLoadTried(!chainman.m_interrupt);
        }
    });

    /*
     * Wait for genesis block to be processed. Typically kernel_notifications.m_tip_block
     * has already been set by a call to LoadChainTip() in CompleteChainstateInitialization().
     * But this is skipped if the chainstate doesn't exist yet or is being wiped:
     *
     * 1. first startup with an empty datadir
     * 2. reindex
     * 3. reindex-chainstate
     *
     * In these case it's connected by a call to ActivateBestChain() in the initload thread.
     */
    {
        WAIT_LOCK(kernel_notifications.m_tip_block_mutex, lock);
        kernel_notifications.m_tip_block_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(kernel_notifications.m_tip_block_mutex) {
            return kernel_notifications.TipBlock() || ShutdownRequested(node);
        });
    }

    if (ShutdownRequested(node)) {
        return false;
    }

    // ********************************************************* Step 12: start node

    int64_t best_block_time{};
    {
        LOCK(chainman.GetMutex());
        const auto& tip{*Assert(chainman.ActiveTip())};
        LogPrintf("block tree size = %u\n", chainman.BlockIndex().size());
        chain_active_height = tip.nHeight;
        best_block_time = tip.GetBlockTime();
        if (tip_info) {
            tip_info->block_height = chain_active_height;
            tip_info->block_time = best_block_time;
            tip_info->verification_progress = chainman.GuessVerificationProgress(&tip);
        }
        if (tip_info && chainman.m_best_header) {
            tip_info->header_height = chainman.m_best_header->nHeight;
            tip_info->header_time = chainman.m_best_header->GetBlockTime();
        }
    }
    LogPrintf("nBestHeight = %d\n", chain_active_height);
    if (node.peerman) node.peerman->SetBestBlock(chain_active_height, std::chrono::seconds{best_block_time});

    // Map ports with NAT-PMP
    StartMapPort(args.GetBoolArg("-natpmp", DEFAULT_NATPMP));

    CConnman::Options connOptions;
    connOptions.m_local_services = g_local_services;
    connOptions.m_max_automatic_connections = nMaxConnections;
    connOptions.uiInterface = &uiInterface;
    connOptions.m_banman = node.banman.get();
    connOptions.m_msgproc = node.peerman.get();
    connOptions.nSendBufferMaxSize = 1000 * args.GetIntArg("-maxsendbuffer", DEFAULT_MAXSENDBUFFER);
    connOptions.nReceiveFloodSize = 1000 * args.GetIntArg("-maxreceivebuffer", DEFAULT_MAXRECEIVEBUFFER);
    connOptions.m_added_nodes = args.GetArgs("-addnode");
    connOptions.nMaxOutboundLimit = *opt_max_upload;
    connOptions.m_peer_connect_timeout = peer_connect_timeout;
    connOptions.whitelist_forcerelay = args.GetBoolArg("-whitelistforcerelay", DEFAULT_WHITELISTFORCERELAY);
    connOptions.whitelist_relay = args.GetBoolArg("-whitelistrelay", DEFAULT_WHITELISTRELAY);

    // Port to bind to if `-bind=addr` is provided without a `:port` suffix.
    const uint16_t default_bind_port =
        static_cast<uint16_t>(args.GetIntArg("-port", Params().GetDefaultPort()));

    const uint16_t default_bind_port_onion = default_bind_port + 1;

    const auto BadPortWarning = [](const char* prefix, uint16_t port) {
        return strprintf(_("%s request to listen on port %u. This port is considered \"bad\" and "
                           "thus it is unlikely that any peer will connect to it. See "
                           "doc/p2p-bad-ports.md for details and a full list."),
                         prefix,
                         port);
    };

    for (const std::string& bind_arg : args.GetArgs("-bind")) {
        std::optional<CService> bind_addr;
        const size_t index = bind_arg.rfind('=');
        if (index == std::string::npos) {
            bind_addr = Lookup(bind_arg, default_bind_port, /*fAllowLookup=*/false);
            if (bind_addr.has_value()) {
                connOptions.vBinds.push_back(bind_addr.value());
                if (IsBadPort(bind_addr.value().GetPort())) {
                    InitWarning(BadPortWarning("-bind", bind_addr.value().GetPort()));
                }
                continue;
            }
        } else {
            const std::string network_type = bind_arg.substr(index + 1);
            if (network_type == "onion") {
                const std::string truncated_bind_arg = bind_arg.substr(0, index);
                bind_addr = Lookup(truncated_bind_arg, default_bind_port_onion, false);
                if (bind_addr.has_value()) {
                    connOptions.onion_binds.push_back(bind_addr.value());
                    continue;
                }
            }
        }
        return InitError(ResolveErrMsg("bind", bind_arg));
    }

    for (const std::string& strBind : args.GetArgs("-whitebind")) {
        NetWhitebindPermissions whitebind;
        bilingual_str error;
        if (!NetWhitebindPermissions::TryParse(strBind, whitebind, error)) return InitError(error);
        connOptions.vWhiteBinds.push_back(whitebind);
    }

    // If the user did not specify -bind= or -whitebind= then we bind
    // on any address - 0.0.0.0 (IPv4) and :: (IPv6).
    connOptions.bind_on_any = args.GetArgs("-bind").empty() && args.GetArgs("-whitebind").empty();

    // Emit a warning if a bad port is given to -port= but only if -bind and -whitebind are not
    // given, because if they are, then -port= is ignored.
    if (connOptions.bind_on_any && args.IsArgSet("-port")) {
        const uint16_t port_arg = args.GetIntArg("-port", 0);
        if (IsBadPort(port_arg)) {
            InitWarning(BadPortWarning("-port", port_arg));
        }
    }

    CService onion_service_target;
    if (!connOptions.onion_binds.empty()) {
        onion_service_target = connOptions.onion_binds.front();
    } else if (!connOptions.vBinds.empty()) {
        onion_service_target = connOptions.vBinds.front();
    } else {
        onion_service_target = DefaultOnionServiceTarget(default_bind_port_onion);
        connOptions.onion_binds.push_back(onion_service_target);
    }

    if (args.GetBoolArg("-listenonion", DEFAULT_LISTEN_ONION)) {
        if (connOptions.onion_binds.size() > 1) {
            InitWarning(strprintf(_("More than one onion bind address is provided. Using %s "
                                    "for the automatically created Tor onion service."),
                                  onion_service_target.ToStringAddrPort()));
        }
        StartTorControl(onion_service_target);
    }

    if (connOptions.bind_on_any) {
        // Only add all IP addresses of the machine if we would be listening on
        // any address - 0.0.0.0 (IPv4) and :: (IPv6).
        Discover();
    }

    for (const auto& net : args.GetArgs("-whitelist")) {
        NetWhitelistPermissions subnet;
        ConnectionDirection connection_direction;
        bilingual_str error;
        if (!NetWhitelistPermissions::TryParse(net, subnet, connection_direction, error)) return InitError(error);
        if (connection_direction & ConnectionDirection::In) {
            connOptions.vWhitelistedRangeIncoming.push_back(subnet);
        }
        if (connection_direction & ConnectionDirection::Out) {
            connOptions.vWhitelistedRangeOutgoing.push_back(subnet);
        }
    }

    connOptions.vSeedNodes = args.GetArgs("-seednode");

    const auto connect = args.GetArgs("-connect");
    if (!connect.empty() || args.IsArgNegated("-connect")) {
        // Do not initiate other outgoing connections when connecting to trusted
        // nodes, or when -noconnect is specified.
        connOptions.m_use_addrman_outgoing = false;

        if (connect.size() != 1 || connect[0] != "0") {
            connOptions.m_specified_outgoing = connect;
        }
        if (!connOptions.m_specified_outgoing.empty() && !connOptions.vSeedNodes.empty()) {
            LogPrintf("-seednode is ignored when -connect is used\n");
        }

        if (args.IsArgSet("-dnsseed") && args.GetBoolArg("-dnsseed", DEFAULT_DNSSEED) && args.IsArgSet("-proxy")) {
            LogPrintf("-dnsseed is ignored when -connect is used and -proxy is specified\n");
        }
    }

    const std::string& i2psam_arg = args.GetArg("-i2psam", "");
    if (!i2psam_arg.empty()) {
        const std::optional<CService> addr{Lookup(i2psam_arg, 7656, fNameLookup)};
        if (!addr.has_value() || !addr->IsValid()) {
            return InitError(strprintf(_("Invalid -i2psam address or hostname: '%s'"), i2psam_arg));
        }
        SetProxy(NET_I2P, Proxy{addr.value()});
    } else {
        if (!onlynets.empty() && g_reachable_nets.Contains(NET_I2P)) {
            return InitError(
                _("Outbound connections restricted to i2p (-onlynet=i2p) but "
                  "-i2psam is not provided"));
        }
        g_reachable_nets.Remove(NET_I2P);
    }

    connOptions.m_i2p_accept_incoming = args.GetBoolArg("-i2pacceptincoming", DEFAULT_I2P_ACCEPT_INCOMING);

    if (!node.connman->Start(scheduler, connOptions)) {
        return false;
    }

    // ********************************************************* Step 13: finished

    // At this point, the RPC is "started", but still in warmup, which means it
    // cannot yet be called. Before we make it callable, we need to make sure
    // that the RPC's view of the best block is valid and consistent with
    // ChainstateManager's active tip.
    SetRPCWarmupFinished();

    uiInterface.InitMessage(_("Done loading"));

    for (const auto& client : node.chain_clients) {
        client->start(scheduler);
    }

    BanMan* banman = node.banman.get();
    scheduler.scheduleEvery([banman]{
        banman->DumpBanlist();
    }, DUMP_BANS_INTERVAL);

    if (node.peerman) node.peerman->StartScheduledTasks(scheduler);

#if HAVE_SYSTEM
    StartupNotify(args);
#endif

    return true;
}

bool StartIndexBackgroundSync(NodeContext& node)
{
    // Find the oldest block among all indexes.
    // This block is used to verify that we have the required blocks' data stored on disk,
    // starting from that point up to the current tip.
    // indexes_start_block='nullptr' means "start from height 0".
    std::optional<const CBlockIndex*> indexes_start_block;
    std::string older_index_name;
    ChainstateManager& chainman = *Assert(node.chainman);
    const Chainstate& chainstate = WITH_LOCK(::cs_main, return chainman.GetChainstateForIndexing());
    const CChain& index_chain = chainstate.m_chain;

    for (auto index : node.indexes) {
        const IndexSummary& summary = index->GetSummary();
        if (summary.synced) continue;

        // Get the last common block between the index best block and the active chain
        LOCK(::cs_main);
        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(summary.best_block_hash);
        if (!index_chain.Contains(pindex)) {
            pindex = index_chain.FindFork(pindex);
        }

        if (!indexes_start_block || !pindex || pindex->nHeight < indexes_start_block.value()->nHeight) {
            indexes_start_block = pindex;
            older_index_name = summary.name;
            if (!pindex) break; // Starting from genesis so no need to look for earlier block.
        }
    };

    // Verify all blocks needed to sync to current tip are present.
    if (indexes_start_block) {
        LOCK(::cs_main);
        const CBlockIndex* start_block = *indexes_start_block;
        if (!start_block) start_block = chainman.ActiveChain().Genesis();
        if (!chainman.m_blockman.CheckBlockDataAvailability(*index_chain.Tip(), *Assert(start_block))) {
            return InitError(Untranslated(strprintf("%s best block of the index goes beyond pruned data. Please disable the index or reindex (which will download the whole blockchain again)", older_index_name)));
        }
    }

    // Start threads
    for (auto index : node.indexes) if (!index->StartBackgroundSync()) return false;
    return true;
}
