#include <chrono>
#include <common/args.h>
#include <key_io.h>
#include <modeldb.h>
#include <node/context.h>
#include <node/extapi.h>
#include <primitives/block.h>
#include <rpc/custom.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <sync.h>
#include <thread>
#include <uint256.h>
#include <univalue.h>
#include <zmq.hpp>
#include <validation.h>
#include <validationapi.h>
#include <validationapi_mock.h>
#include <node/miner.h>
#include <util/string.h>
#include <util/strencodings.h>
#include <wallet/context.h>
#include <wallet/wallet.h>
#include <wallet/rpc/util.h>
#include <outputtype.h>

using node::NodeContext;
using node::ClearMiningModelOverride;
using node::GetMiningModelOverride;
using node::SetMiningModelOverride;
using wallet::WalletContext;

static UniValue ModelRecordToUnivalue(const uint256& model_hash, const ModelRecord& rec)
{
    UniValue entry(UniValue::VOBJ);
    entry.pushKV("model_hash", model_hash.ToString());
    entry.pushKV("model_name", rec.metadata.model_name);
    entry.pushKV("model_commit", rec.metadata.model_commit);
    entry.pushKV("difficulty", rec.metadata.difficulty);
    entry.pushKV("status", static_cast<uint8_t>(rec.status));
    entry.pushKV("cid", rec.metadata.cid);
    entry.pushKV("extra", rec.metadata.extra);
    entry.pushKV("deposit_txid", rec.deposit_txid.ToString());
    entry.pushKV("deposit_vout", rec.deposit_vout);
    entry.pushKV("deposit_amount", rec.deposit_amount);
    entry.pushKV("owner_key_hash", rec.owner_key_hash.ToString());
    entry.pushKV("deposit_block_hash", rec.deposit_block_hash.ToString());
    entry.pushKV("deposit_block_height", rec.deposit_block_height);
    entry.pushKV("commit_txid", rec.commit_txid.ToString());
    entry.pushKV("commit_block_hash", rec.commit_block_hash.ToString());
    entry.pushKV("commit_block_height", rec.commit_block_height);
    entry.pushKV("burn_txid", rec.burn_txid.ToString());
    entry.pushKV("burn_vout", rec.burn_vout);
    entry.pushKV("burn_block_height", rec.burn_block_height);
    entry.pushKV("verification_code", rec.verification_code);
    entry.pushKV("verification_details", rec.verification_details);
    entry.pushKV("verification_event_height", rec.verification_event_height);
    entry.pushKV("successful_commit_count", rec.successful_commit_count);
    entry.pushKV("challenge_block_hash", rec.challenge_block_hash.ToString());
    entry.pushKV("challenge_deposit_txid", rec.challenge_deposit_txid.ToString());
    entry.pushKV("challenge_deposit_vout", rec.challenge_deposit_vout);
    entry.pushKV("challenge_deposit_height", rec.challenge_deposit_height);
    entry.pushKV("challenge_commit_count", rec.challenge_commit_count);
    entry.pushKV("challenge_verdict_height", rec.challenge_verdict_height);
    return entry;
}

// Forward declarations for mock RPC helpers (registered below)
static RPCHelpMan validationmockset();
static RPCHelpMan validationmockdefault();
static RPCHelpMan validationmockclear();
static RPCHelpMan validationmockrequests();
static RPCHelpMan setminermodel();

static UniValue SayHello(const JSONRPCRequest& request) {
    // NodeContext& node = EnsureAnyNodeContext(request.context);
    return UniValue("SayHello");
}

static UniValue StopMining(const JSONRPCRequest& request) {
    NodeContext& node = EnsureAnyNodeContext(request.context);
    return node.expt_api->StopMining();
}

static RPCHelpMan sayhello()
{
    return RPCHelpMan{"sayhello",
                "\nReturns a static greeting string.\n",
                {
                    {"model_name", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to send the newly generated cAIsh to."},
                    {"model_hash", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to send the newly generated cAIsh to."},
                },
                RPCResult{
                    RPCResult::Type::STR, "", "Greeting message"},
                RPCExamples{
                    HelpExampleCli("sayhello", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    return SayHello(request);
},
    };
}

static RPCHelpMan startmining()
{
    return RPCHelpMan{"startmining",
                "\nStart the mining thread and mine to a specified address\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to send the newly generated cAIsh to."},
                },
                RPCResult{
                    RPCResult::Type::STR, "", "Greeting message"},
                RPCExamples{
                    HelpExampleCli("startmining", "\"myaddress\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    // Read the flag directly so the mode guard fires even on chains where
    // ExtAPI isn't constructed (regtest has external_api=false, so
    // node.expt_api is null and the IsBrokerMode() side of the && would
    // never run). Operators who misconfigure -miningbrokermode=1 alongside
    // a stale systemd unit passing an address must see the mode error,
    // not the address-validation error, regardless of chain.
    if (gArgs.GetBoolArg("-miningbrokermode", false)) {
        throw JSONRPCError(RPC_MISC_ERROR,
            "startmining is refused: node is running in compute-broker mining mode "
            "(-miningbrokermode=1). Use create_mining_work_unit / submit_mining_response.");
    }

    CTxDestination destination = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    }

    CScript coinbase_output_script = GetScriptForDestination(destination);
    return node.expt_api->StartMining(coinbase_output_script);
},
    };
}

static RPCHelpMan stopmining()
{
    return RPCHelpMan{"stopmining",
                "\nStop the mining thread.\n",
                {},
                RPCResult{
                    RPCResult::Type::STR, "", "Greeting message"},
                RPCExamples{
                    HelpExampleCli("stopmining", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    return StopMining(request);
},
    };
}

static RPCHelpMan setminermodel()
{
    return RPCHelpMan{"setminermodel",
                "\nOverride or clear the miner model identifier at runtime (no restart needed).\n",
                {
                    {"model_identifier", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Model identifier in format name@commit. Ignored if clear=true."},
                    {"clear", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Clear the override and revert to defaults (default: false)."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "override", "Current override value (empty if none set)"},
                    }},
                RPCExamples{
                    HelpExampleCli("setminermodel", "\"Qwen/Qwen3-8B@deadbeef\"")
                    + HelpExampleCli("setminermodel", "\"\" true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const bool clear = request.params.size() > 1 ? request.params[1].get_bool() : false;
    const std::string raw = request.params.size() > 0 ? util::TrimString(request.params[0].get_str()) : "";

    if (clear || raw.empty()) {
        ClearMiningModelOverride();
    } else {
        if (raw.find('@') == std::string::npos) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "model_identifier must be in the form name@commit");
        }
        SetMiningModelOverride(raw);
    }

    UniValue obj(UniValue::VOBJ);
    if (auto current = GetMiningModelOverride()) {
        obj.pushKV("override", *current);
    } else {
        obj.pushKV("override", "");
    }
    return obj;
},
    };
}

static RPCHelpMan startminingwithrotation()
{
    return RPCHelpMan{"startminingwithrotation",
                "\nStart mining with automatic address rotation (generates new P2WPKH address for each block)\n",
                {},
                RPCResult{
                    RPCResult::Type::STR, "", "Status message"},
                RPCExamples{
                    HelpExampleCli("startminingwithrotation", "")
                    + HelpExampleRpc("startminingwithrotation", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    if (gArgs.GetBoolArg("-miningbrokermode", false)) {
        throw JSONRPCError(RPC_MISC_ERROR,
            "startminingwithrotation is refused: node is running in compute-broker mining mode "
            "(-miningbrokermode=1). Use create_mining_work_unit / submit_mining_response.");
    }

    // Get wallet once at RPC call time
    wallet::EnsureWalletContext(request.context);
    std::shared_ptr<wallet::CWallet> wallet = wallet::GetWalletForJSONRPCRequest(request);
    if (!wallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "No wallet available for mining");
    }

    // Create a callback that generates a new address for each block
    // Capture wallet by value (shared_ptr is thread-safe for this use)
    auto get_coinbase_script = [wallet]() -> CScript {
        try {
            // Generate new address
            LOCK(wallet->cs_wallet);
            auto result = wallet->GetNewDestination(OutputType::BECH32, "");
            if (!result) {
                throw std::runtime_error("Failed to get new address: " + util::ErrorString(result).original);
            }

            CTxDestination destination = *result;
            std::string address = EncodeDestination(destination);
            LogPrintf("Mining: Generated new coinbase address: %s\n", address);
            return GetScriptForDestination(destination);
        } catch (const std::exception& e) {
            LogPrintf("Mining: Failed to generate new address: %s, using fallback\n", e.what());
            // Fallback to OP_TRUE if wallet fails
            return CScript() << OP_TRUE;
        }
    };

    return node.expt_api->StartMiningWithCallback(get_coinbase_script);
},
    };
}

static RPCHelpMan getmodelslist()
{
    return RPCHelpMan{"getmodelslist",
                "\ngetmodelslist\n",
                {
                    {"short_view", RPCArg::Type::BOOL, RPCArg::Default{true}, "Display model hash, name and commit only"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR, "model_hash", "the model hash"},
                            {RPCResult::Type::STR, "model_name", "the model_name"},
                            {RPCResult::Type::STR, "model_commit", "the model_commit"},
                            {RPCResult::Type::NUM, "difficulty","The difficulty"},
                            {RPCResult::Type::NUM, "status","The model registration status"},
                            {RPCResult::Type::STR, "cid", /*optional=*/true, "The cid"},
                            {RPCResult::Type::STR, "extra", /*optional=*/true, "The extra"},
                            {RPCResult::Type::STR, "deposit_txid", /*optional=*/true, "The deposit txid"},
                            {RPCResult::Type::NUM, "deposit_vout", /*optional=*/true, "The deposit vout"},
                            {RPCResult::Type::NUM, "deposit_amount", /*optional=*/true, "The deposit amount"},
                            {RPCResult::Type::STR, "owner_key_hash", /*optional=*/true, "The key"},
                            {RPCResult::Type::STR, "deposit_block_hash", /*optional=*/true, "The deposit block hash"},
                            {RPCResult::Type::NUM, "deposit_block_height", /*optional=*/true, "The deposit block height"},
                            {RPCResult::Type::STR, "commit_txid", /*optional=*/true, "The commit txid"},
                            {RPCResult::Type::STR, "commit_block_hash", /*optional=*/true, "The commit block hash"},
                            {RPCResult::Type::NUM, "commit_block_height", /*optional=*/true, "The commit block height"},
                            {RPCResult::Type::NUM, "verification_code", /*optional=*/true, "The verification code"},
                            {RPCResult::Type::STR, "verification_details", /*optional=*/true, "The verification details"}
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getmodelslist", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!g_modeldb) {
        throw JSONRPCError(RPC_MISC_ERROR, "ModelDB not initialized");
    }

    bool short_view = request.params[0].isNull() || request.params[0].get_bool();

    UniValue result(UniValue::VARR);
    g_modeldb->ForEachModel([&result, &short_view](const uint256& key, const ModelRecord& rec) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("model_hash", key.ToString());
        entry.pushKV("model_name", rec.metadata.model_name);
        entry.pushKV("model_commit", rec.metadata.model_commit);
        entry.pushKV("difficulty", rec.metadata.difficulty);
        entry.pushKV("status", static_cast<uint8_t>(rec.status));
        if (!short_view) {
            entry.pushKV("cid", rec.metadata.cid);
            entry.pushKV("extra", rec.metadata.extra);
            entry.pushKV("deposit_txid", rec.deposit_txid.ToString());
            entry.pushKV("deposit_vout", rec.deposit_vout);
            entry.pushKV("deposit_amount", rec.deposit_amount);
            entry.pushKV("owner_key_hash", rec.owner_key_hash.ToString());
            entry.pushKV("deposit_block_hash", rec.deposit_block_hash.ToString());
            entry.pushKV("deposit_block_height", rec.deposit_block_height);
            entry.pushKV("commit_txid", rec.commit_txid.ToString());
            entry.pushKV("commit_block_hash", rec.commit_block_hash.ToString());
            entry.pushKV("commit_block_height", rec.commit_block_height);
            entry.pushKV("verification_code", rec.verification_code);
            entry.pushKV("verification_details", rec.verification_details);
        }
        result.push_back(entry);
    });

    return result;
},
    };
}

static RPCHelpMan getmodelinfo()
{
    return RPCHelpMan{"getmodelinfo",
                "\ngetmodelinfo\n",
                {
                    {"model_hash", RPCArg::Type::STR, RPCArg::Optional::NO, "Model hash."}
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "model_hash", "the model hash"},
                        {RPCResult::Type::STR, "model_name", "the model_name"},
                        {RPCResult::Type::STR, "model_commit", "the model_commit"},
                        {RPCResult::Type::NUM, "difficulty","The difficulty"},
                        {RPCResult::Type::NUM, "status","The model registration status"},
                        {RPCResult::Type::STR, "cid", "The cid"},
                        {RPCResult::Type::STR, "extra", "The extra"},
                        {RPCResult::Type::STR, "deposit_txid", "The deposit txid"},
                        {RPCResult::Type::NUM, "deposit_vout", "The deposit vout"},
                        {RPCResult::Type::NUM, "deposit_amount", "The deposit amount"},
                        {RPCResult::Type::STR, "owner_key_hash", "The key"},
                        {RPCResult::Type::STR, "deposit_block_hash", "The deposit block hash"},
                        {RPCResult::Type::NUM, "deposit_block_height", "The deposit block height"},
                        {RPCResult::Type::STR, "commit_txid", "The commit txid"},
                        {RPCResult::Type::STR, "commit_block_hash", "The commit block hash"},
                        {RPCResult::Type::NUM, "commit_block_height", "The commit block height"},
                        {RPCResult::Type::STR, "burn_txid", "The burn txid"},
                        {RPCResult::Type::NUM, "burn_vout", "The burn vout"},
                        {RPCResult::Type::NUM, "burn_block_height", "The burn block height"},
                        {RPCResult::Type::NUM, "verification_code", "The verification code"},
                        {RPCResult::Type::STR, "verification_details", "The verification details"},
                        {RPCResult::Type::NUM, "verification_event_height", "The verification event height"},
                        {RPCResult::Type::NUM, "successful_commit_count", "Number of successful commits"},
                        {RPCResult::Type::STR, "challenge_block_hash", "The challenge block hash"},
                        {RPCResult::Type::STR, "challenge_deposit_txid", "The challenge deposit txid"},
                        {RPCResult::Type::NUM, "challenge_deposit_vout", "The challenge deposit vout"},
                        {RPCResult::Type::NUM, "challenge_deposit_height", "The challenge deposit block height"},
                        {RPCResult::Type::NUM, "challenge_commit_count", "Number of commits during challenge"},
                        {RPCResult::Type::NUM, "challenge_verdict_height", "Height of the challenge verdict"},
                    }},
                RPCExamples{
                    HelpExampleCli("getmodelinfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!g_modeldb) {
        throw JSONRPCError(RPC_MISC_ERROR, "ModelDB not initialized");
    }

    auto model_hash{uint256::FromHex(request.params[0].get_str())};
    if (!model_hash) {
        throw std::runtime_error("invalid Model input model_hash");
    }
    ModelRecord model;
    if (g_modeldb->ReadModel(*model_hash, model)) {
        return ModelRecordToUnivalue(*model_hash, model);
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No model found");
    }
},
    };
}

static RPCHelpMan getminingmetrics()
{
    return RPCHelpMan{"getminingmetrics",
                "\nGet mining API metrics and statistics.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "solutions_received", "Total raw solution responses received from the mining API"},
                        {RPCResult::Type::NUM, "solutions_usable", "Total usable mining solutions decoded from the mining API"},
                        {RPCResult::Type::NUM, "solutions_invalid", "Total invalid mining responses rejected before submission"},
                        {RPCResult::Type::NUM, "solutions_duplicates", "Total late duplicate mining responses ignored after a solution was already submitted"},
                        {RPCResult::Type::NUM, "usable_rate", "Usable response rate percentage"},
                        {RPCResult::Type::NUM, "solutions_accepted", "Compatibility alias for solutions_usable"},
                        {RPCResult::Type::NUM, "solutions_rejected", "Compatibility alias for solutions_invalid"},
                        {RPCResult::Type::NUM, "acceptance_rate", "Compatibility alias for usable_rate"},
                        {RPCResult::Type::NUM, "rate_limited", "Number of rate-limited requests"},
                        {RPCResult::Type::NUM, "network_errors", "Number of network errors"},
                        {RPCResult::Type::NUM, "last_solution_time", "Unix timestamp of last solution"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getminingmetrics", "")
                    + HelpExampleRpc("getminingmetrics", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);

    if (!node.expt_api) {
        throw JSONRPCError(RPC_MISC_ERROR, "Mining API not initialized");
    }

    UniValue result(UniValue::VOBJ);

    const auto& metrics = node.expt_api->GetMetrics();

    uint64_t received = metrics.solutions_received.load();
    uint64_t usable = metrics.solutions_accepted.load();
    uint64_t invalid = metrics.solutions_rejected.load();
    uint64_t duplicates = metrics.solutions_duplicates.load();

    result.pushKV("solutions_received", received);
    result.pushKV("solutions_usable", usable);
    result.pushKV("solutions_invalid", invalid);
    result.pushKV("solutions_duplicates", duplicates);
    result.pushKV("solutions_accepted", usable);
    result.pushKV("solutions_rejected", invalid);

    // Keep the legacy acceptance_rate key as an alias for the usable rate.
    double usable_rate = 0.0;
    if (received > 0) {
        usable_rate = (static_cast<double>(usable) / received) * 100.0;
    }
    result.pushKV("usable_rate", usable_rate);
    result.pushKV("acceptance_rate", usable_rate);

    result.pushKV("rate_limited", metrics.rate_limited.load());
    result.pushKV("network_errors", metrics.network_errors.load());
    result.pushKV("last_solution_time", metrics.last_solution_time.load());

    return result;
},
    };
}

static RPCHelpMan getminingapiinfo()
{
    return RPCHelpMan{"getminingapiinfo",
                "\nGet mining API connection information and status.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "available", "Whether mining API is available"},
                        {RPCResult::Type::BOOL, "connection_healthy", "Connection health status"},
                        {RPCResult::Type::STR, "job_push_endpoint", "Job push ZMQ endpoint"},
                        {RPCResult::Type::STR, "solution_pull_endpoint", "Solution pull ZMQ endpoint"},
                        {RPCResult::Type::NUM, "timeout_ms", "ZMQ timeout in milliseconds"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getminingapiinfo", "")
                    + HelpExampleRpc("getminingapiinfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);

    UniValue result(UniValue::VOBJ);

    if (!node.expt_api) {
        result.pushKV("available", false);
        result.pushKV("connection_healthy", false);
        result.pushKV("job_push_endpoint", "");
        result.pushKV("solution_pull_endpoint", "");
        result.pushKV("timeout_ms", 0);
        return result;
    }

    result.pushKV("available", true);
    result.pushKV("connection_healthy", node.expt_api->IsConnectionHealthy());

    // Get endpoint information from config
    const auto& config = node.expt_api->GetConfig();
    result.pushKV("job_push_endpoint", config.getPushAddress());
    result.pushKV("solution_pull_endpoint", config.getPullAddress());
    result.pushKV("timeout_ms", ZMQ_TIMEOUT_MS);

    return result;
},
    };
}

static RPCHelpMan getrecentvalidations()
{
    return RPCHelpMan{"getrecentvalidations",
                "\nGet recent validation records for display.\n",
                {
                    {"count", RPCArg::Type::NUM, RPCArg::Default{20}, "Maximum number of records to return"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "block_hash", "Block hash"},
                                {RPCResult::Type::STR, "type", "Validation type (quick or full)"},
                                {RPCResult::Type::STR, "quick_status", "Quick validation status"},
                                {RPCResult::Type::STR, "smell_status", "Smell validation status"},
                                {RPCResult::Type::STR, "full_status", "Full validation status"},
                                {RPCResult::Type::NUM, "timestamp", "Unix timestamp"},
                            }
                        }
                    }
                },
                RPCExamples{
                    HelpExampleCli("getrecentvalidations", "")
                    + HelpExampleCli("getrecentvalidations", "10")
                    + HelpExampleRpc("getrecentvalidations", "20")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!g_ValidationApi) {
        throw JSONRPCError(RPC_MISC_ERROR, "Validation API not initialized");
    }

    size_t max_count = 20;
    if (!request.params[0].isNull()) {
        max_count = request.params[0].getInt<size_t>();
        if (max_count > 100) max_count = 100;  // Cap at 100
    }

    ValidationAPI* valApi = dynamic_cast<ValidationAPI*>(g_ValidationApi.get());
    if (!valApi) {
        // Mock doesn't track history
        return UniValue(UniValue::VARR);
    }

    auto records = valApi->GetRecentValidations(max_count);
    UniValue result(UniValue::VARR);

    auto statusToString = [](uint8_t status) -> std::string {
        switch (static_cast<ValidationResponseValue>(status)) {
            case ValidationResponseValue::Not_Checked: return "pending";
            case ValidationResponseValue::Quick_OK: return "ok";
            case ValidationResponseValue::Quick_Fail: return "fail";
            case ValidationResponseValue::Quick_OK_Smell_OK: return "ok";
            case ValidationResponseValue::Quick_OK_Smell_Fail: return "smell_fail";
            case ValidationResponseValue::Quick_Fail_Smell_OK: return "fail";
            case ValidationResponseValue::Quick_Fail_Smell_Fail: return "fail";
            case ValidationResponseValue::Full_Green: return "green";
            case ValidationResponseValue::Full_Amber: return "amber";
            case ValidationResponseValue::Full_Red: return "red";
            case ValidationResponseValue::Model_OK: return "ok";
            case ValidationResponseValue::Model_Fail: return "fail";
            default: return "unknown";
        }
    };

    for (const auto& rec : records) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("block_hash", rec.block_hash.ToString());
        entry.pushKV("type", rec.is_quick ? "quick" : "full");
        entry.pushKV("quick_status", statusToString(rec.quick_status));
        entry.pushKV("smell_status", statusToString(rec.smell_status));
        entry.pushKV("full_status", statusToString(rec.full_status));
        // Convert from milliseconds to seconds for Unix timestamp convention
        entry.pushKV("timestamp", static_cast<int64_t>(rec.timestamp / 1000));
        result.push_back(entry);
    }

    return result;
},
    };
}

static RPCHelpMan getvalidationqueues()
{
    return RPCHelpMan{"getvalidationqueues",
                "\nGet validation API queue counts.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "quick_pending", "Quick validation requests pending"},
                        {RPCResult::Type::NUM, "quick_smell_pending", "Quick smell validation requests pending"},
                        {RPCResult::Type::NUM, "full_pending", "Full validation requests pending"},
                        {RPCResult::Type::NUM, "model_pending", "Model validation requests pending"},
                        {RPCResult::Type::NUM, "challenge_pending", "Challenge validation requests pending"},
                        {RPCResult::Type::BOOL, "full_queue_empty", "Whether full validation queue is empty"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getvalidationqueues", "")
                    + HelpExampleRpc("getvalidationqueues", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!g_ValidationApi) {
        throw JSONRPCError(RPC_MISC_ERROR, "Validation API not initialized");
    }

    UniValue result(UniValue::VOBJ);

    // Access the ValidationAPI instance
    ValidationAPI* valApi = dynamic_cast<ValidationAPI*>(g_ValidationApi.get());
    if (!valApi) {
        // If it's a mock or other implementation, return zeros
        result.pushKV("quick_pending", 0);
        result.pushKV("quick_smell_pending", 0);
        result.pushKV("full_pending", 0);
        result.pushKV("model_pending", 0);
        result.pushKV("challenge_pending", 0);
        result.pushKV("full_queue_empty", true);
        return result;
    }

    result.pushKV("quick_pending", valApi->GetQuickQueueSize());
    result.pushKV("quick_smell_pending", valApi->GetQuickSmellQueueSize());
    result.pushKV("full_pending", valApi->GetFullQueueSize());
    result.pushKV("model_pending", valApi->GetModelQueueSize());
    result.pushKV("challenge_pending", valApi->GetChallengeQueueSize());
    result.pushKV("full_queue_empty", valApi->IsFullQueueEmpty());

    return result;
},
    };
}

static RPCHelpMan getvalidationapiinfo()
{
    return RPCHelpMan{"getvalidationapiinfo",
                "\nGet validation API connection information and status.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "available", "Whether validation API is available"},
                        {RPCResult::Type::BOOL, "active", "Whether validation API is active"},
                        {RPCResult::Type::BOOL, "connection_healthy", "Connection health status"},
                        {RPCResult::Type::STR, "mode", "Validation API mode: real, mock, or desktop"},
                        {RPCResult::Type::BOOL, "desktop_mode", "Whether running in desktop mode (HTTPS validation)"},
                        {RPCResult::Type::STR, "request_push_endpoint", "Request push ZMQ endpoint"},
                        {RPCResult::Type::STR, "result_pull_endpoint", "Result pull ZMQ endpoint"},
                        {RPCResult::Type::NUM, "request_delay_ms", "Delay between validation requests (ms)"},
                        {RPCResult::Type::NUM, "max_quick_attempts", "Max attempts for quick validation"},
                        {RPCResult::Type::NUM, "max_full_attempts", "Max attempts for full validation"},
                        {RPCResult::Type::NUM, "max_model_attempts", "Max attempts for model validation"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getvalidationapiinfo", "")
                    + HelpExampleRpc("getvalidationapiinfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue result(UniValue::VOBJ);

    if (!g_ValidationApi) {
        result.pushKV("available", false);
        result.pushKV("active", false);
        result.pushKV("connection_healthy", false);
        result.pushKV("mode", "none");
        result.pushKV("desktop_mode", false);
        result.pushKV("request_push_endpoint", "");
        result.pushKV("result_pull_endpoint", "");
        result.pushKV("request_delay_ms", 0);
        result.pushKV("max_quick_attempts", 0);
        result.pushKV("max_full_attempts", 0);
        result.pushKV("max_model_attempts", 0);
        return result;
    }

    ValidationAPI* valApi = dynamic_cast<ValidationAPI*>(g_ValidationApi.get());
    ValidationAPIMock* mockApi = dynamic_cast<ValidationAPIMock*>(g_ValidationApi.get());

    result.pushKV("available", true);

    if (valApi) {
        bool healthy = valApi->IsConnectionHealthy();
        result.pushKV("active", healthy);
        result.pushKV("connection_healthy", healthy);

        // Determine mode based on desktop_mode flag
        bool isDesktopMode = valApi->IsDesktopMode();
        result.pushKV("mode", isDesktopMode ? "desktop" : "real");
        result.pushKV("desktop_mode", isDesktopMode);

        // Get endpoint information from config
        const auto& config = valApi->GetConfig();
        result.pushKV("request_push_endpoint", config.getPushAddress());
        result.pushKV("result_pull_endpoint", config.getPullAddress());
    } else if (mockApi) {
        result.pushKV("active", true);
        result.pushKV("connection_healthy", true);
        result.pushKV("mode", "mock");
        result.pushKV("desktop_mode", false);
        result.pushKV("request_push_endpoint", "mock://in-process");
        result.pushKV("result_pull_endpoint", "mock://in-process");
    } else {
        result.pushKV("active", true);
        result.pushKV("connection_healthy", true);
        result.pushKV("mode", "unknown");
        result.pushKV("desktop_mode", false);
        result.pushKV("request_push_endpoint", "tcp://localhost:5000");
        result.pushKV("result_pull_endpoint", "tcp://*:5001");
    }

    result.pushKV("request_delay_ms", DELAY_BETWEEN_VALIDATION_REQUESTS);
    result.pushKV("max_quick_attempts", MAX_SHORT_VALIDATION_REQUEST_ATTEMPTS);
    result.pushKV("max_full_attempts", MAX_FULL_VALIDATION_REQUEST_ATTEMPTS);
    result.pushKV("max_model_attempts", MAX_MODEL_VALIDATION_REQUEST_ATTEMPTS);

    return result;
},
    };
}

static std::string FullValidationStatusToString(ValidationResponseValue status)
{
    switch (status) {
    case ValidationResponseValue::Full_Green:
        return "full_green";
    case ValidationResponseValue::Full_Amber:
        return "full_amber";
    case ValidationResponseValue::Full_Red:
        return "full_red";
    default:
        return "unknown";
    }
}

static ValidationResponseValue WaitForFullValidationResult(const uint256& block_hash, int64_t timeout_ms)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    ValidationResponseValue status;

    while (true) {
        if (g_ValidationApi->UsesRequestStatusForBlockProcessing()) {
            if (g_ValidationApi->GetRequestStatus(block_hash, ValidationReqType::Full, status)) {
                return status;
            }
        } else {
            status = static_cast<ValidationResponseValue>(g_ValidationApi->GetOwnFullStatus(block_hash));
            if (status != ValidationResponseValue::Not_Checked) {
                return status;
            }
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            throw JSONRPCError(RPC_MISC_ERROR, "Timed out waiting for full validation result");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

static std::string ApplyValidationChainAction(ChainstateManager& chainman, CBlockIndex& index, ValidationResponseValue status)
{
    BlockValidationState state;

    switch (status) {
    case ValidationResponseValue::Full_Green: {
        // Drop any existing failure flags and let the normal activation logic rebuild the tip.
        {
            LOCK(chainman.GetMutex());
            chainman.ActiveChainstate().ResetBlockFailureFlags(&index);
            const bool changed{chainman.SetBlockFullValidationRedStatus(&index, false)};
            chainman.RecalculateBlockIndexWorkForFullValidation(changed ? &index : nullptr);
        }

        if (!chainman.ActiveChainstate().ActivateBestChain(state)) {
            throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
        }
        return "accepted";
    }
    case ValidationResponseValue::Full_Red: {
        {
            LOCK(chainman.GetMutex());
            chainman.ActiveChainstate().ResetBlockFailureFlags(&index);
            const bool changed{chainman.SetBlockFullValidationRedStatus(&index, true)};
            chainman.RecalculateBlockIndexWorkForFullValidation(changed ? &index : nullptr);
        }
        if (!chainman.ActiveChainstate().ActivateBestChain(state)) {
            throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
        }
        return "zero_work_red";
    }
    case ValidationResponseValue::Full_Amber: {
        // Amber means the verifier could not reach a terminal verdict. It is
        // not evidence that the block is invalid, so leave the chain state
        // untouched and let corroboration or an operator adjudication resolve
        // it later.
        return "pending_amber";
    }
    default:
        throw JSONRPCError(RPC_MISC_ERROR, "Unexpected validation status");
    }
}

static RPCHelpMan revalidateblock()
{
    return RPCHelpMan{"revalidateblock",
                "\nRe-run external full validation for a block hash and rebuild the chain according to the result.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Block hash to revalidate"},
                    {"timeout_ms", RPCArg::Type::NUM, RPCArg::Default{60000}, "Maximum time to wait for the validation result"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "blockhash", "Validated block hash"},
                        {RPCResult::Type::STR, "validation_status", "Validation result: full_green|full_amber|full_red"},
                        {RPCResult::Type::STR, "chain_action", "Chain handling: accepted|pending_amber|zero_work_red"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("revalidateblock", "\"<blockhash>\"")
                    + HelpExampleRpc("revalidateblock", "\"<blockhash>\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!g_ValidationApi) {
        throw JSONRPCError(RPC_MISC_ERROR, "Validation API not initialized");
    }

    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    auto maybe_hash = uint256::FromHex(request.params[0].get_str());
    if (!maybe_hash) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block hash");
    }
    const uint256 block_hash = *maybe_hash;

    int64_t timeout_ms = 60000;
    if (request.params.size() > 1 && !request.params[1].isNull()) {
        timeout_ms = request.params[1].getInt<int64_t>();
    }
    if (timeout_ms <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "timeout_ms must be positive");
    }

    CBlockIndex* pindex{nullptr};
    {
        LOCK(chainman.GetMutex());
        pindex = chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    CBlock block;
    if (!chainman.m_blockman.ReadBlock(block, *pindex)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Failed to read block from disk");
    }

    // Force a fresh validation attempt.
    g_ValidationApi->RemoveRes_Full(block_hash);
    g_ValidationApi->SendApiRequest(block, ValidationReqType::Full, ValidationResponseBehavior::Nothing);

    const ValidationResponseValue status = WaitForFullValidationResult(block_hash, timeout_ms);
    const std::string chain_action = ApplyValidationChainAction(chainman, *pindex, status);

    UniValue result(UniValue::VOBJ);
    result.pushKV("blockhash", block_hash.ToString());
    result.pushKV("validation_status", FullValidationStatusToString(status));
    result.pushKV("chain_action", chain_action);
    return result;
},
    };
}

static RPCHelpMan adjudicatefullgreen()
{
    return RPCHelpMan{"adjudicatefullgreen",
                "\nPromote a previously Full_Amber block after an operator has verified independent Full_Green evidence.\n"
                "This recovery RPC is disabled unless -allowvalidationadjudication=1 is set.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Block hash to promote"},
                    {"evidence_sha256", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "SHA-256 of the persisted external attestation"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "blockhash", "Promoted block hash"},
                        {RPCResult::Type::STR_HEX, "evidence_sha256", "Evidence digest recorded in the node log"},
                        {RPCResult::Type::STR, "previous_status", "Previous local Full status"},
                        {RPCResult::Type::STR, "chain_action", "Chain handling: accepted|already_green"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("adjudicatefullgreen", "\"<blockhash>\" \"<evidence_sha256>\"")
                    + HelpExampleRpc("adjudicatefullgreen", "\"<blockhash>\", \"<evidence_sha256>\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!gArgs.GetBoolArg("-allowvalidationadjudication", false)) {
        throw JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE,
                           "Validation adjudication is disabled; start with -allowvalidationadjudication=1");
    }
    if (!g_ValidationApi) {
        throw JSONRPCError(RPC_MISC_ERROR, "Validation API not initialized");
    }

    auto maybe_hash = uint256::FromHex(request.params[0].get_str());
    if (!maybe_hash) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block hash");
    }
    const uint256 block_hash = *maybe_hash;
    const std::string evidence_sha256 = request.params[1].get_str();
    if (evidence_sha256.size() != 64 || !IsHex(evidence_sha256)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "evidence_sha256 must be 64 hexadecimal characters");
    }

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    CBlockIndex* pindex{nullptr};
    {
        LOCK(chainman.GetMutex());
        pindex = chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    CBlock block;
    if (!chainman.m_blockman.ReadBlock(block, *pindex)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Failed to read block from disk");
    }

    const ValidationResponseValue previous =
        static_cast<ValidationResponseValue>(g_ValidationApi->GetOwnFullStatus(block_hash));
    if (previous == ValidationResponseValue::Full_Green) {
        UniValue result(UniValue::VOBJ);
        result.pushKV("blockhash", block_hash.ToString());
        result.pushKV("evidence_sha256", evidence_sha256);
        result.pushKV("previous_status", FullValidationStatusToString(previous));
        result.pushKV("chain_action", "already_green");
        return result;
    }
    if (previous != ValidationResponseValue::Full_Amber) {
        throw JSONRPCError(RPC_MISC_ERROR,
                           "Block must have a previous Full_Amber verdict");
    }

    if (!g_ValidationApi->SetRequestStatus(block_hash, ValidationReqType::Full,
                                           ValidationResponseValue::Full_Green)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to persist adjudicated Full_Green status");
    }
    const std::string chain_action =
        ApplyValidationChainAction(chainman, *pindex, ValidationResponseValue::Full_Green);

    LogPrintf("Operator Full_Green adjudication block=%s previous=%s evidence_sha256=%s action=%s\n",
              block_hash.ToString(), FullValidationStatusToString(previous),
              evidence_sha256, chain_action);

    UniValue result(UniValue::VOBJ);
    result.pushKV("blockhash", block_hash.ToString());
    result.pushKV("evidence_sha256", evidence_sha256);
    result.pushKV("previous_status", FullValidationStatusToString(previous));
    result.pushKV("chain_action", chain_action);
    return result;
},
    };
}


void RegisterCustomRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"custom", &sayhello},
        {"custom", &startmining},
        {"custom", &stopmining},
        {"custom", &setminermodel},
        {"custom", &startminingwithrotation},
        {"custom", &getmodelslist},
        {"custom", &getmodelinfo},
        {"custom", &getminingmetrics},
        {"custom", &getminingapiinfo},
        {"custom", &getvalidationqueues},
        {"custom", &getvalidationapiinfo},
        {"custom", &revalidateblock},
        {"custom", &adjudicatefullgreen},
        {"custom", &getrecentvalidations},
        // Mock validation API controls (only active when -validationapi=mock)
        {"mock", &validationmockset},
        {"mock", &validationmockdefault},
        {"mock", &validationmockclear},
        {"mock", &validationmockrequests},
        };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}

// ---------------- Mock ValidationAPI RPC helpers (enabled when -validationapi=mock) ----------------

static ValidationAPIMock* EnsureMockApi()
{
    if (!g_ValidationApi) throw JSONRPCError(RPC_MISC_ERROR, "Validation API not initialized");
    auto* mock = dynamic_cast<ValidationAPIMock*>(g_ValidationApi.get());
    if (!mock) throw JSONRPCError(RPC_MISC_ERROR, "Validation API mock is not enabled (-validationapi=mock)");
    return mock;
}

static std::optional<ValidationReqType> ParseReqType(const std::string& s)
{
    const std::string v = ToLower(s);
    if (v == "quick" || v == "quick_smell") return ValidationReqType::Quick_Smell;
    if (v == "full") return ValidationReqType::Full;
    if (v == "model") return ValidationReqType::Model;
    if (v == "challenge") return ValidationReqType::Challenge;
    return std::nullopt;
}

static std::optional<ValidationResponseValue> ParseResp(const std::string& s, ValidationReqType type)
{
    const std::string v = ToLower(s);
    switch (type) {
        case ValidationReqType::Quick:
        case ValidationReqType::Quick_Smell:
            if (v == "quick_ok_smell_ok" || v == "ok" || v == "ok_ok") return ValidationResponseValue::Quick_OK_Smell_OK;
            if (v == "quick_ok_smell_fail" || v == "ok_fail") return ValidationResponseValue::Quick_OK_Smell_Fail;
            if (v == "quick_fail_smell_ok" || v == "fail_ok") return ValidationResponseValue::Quick_Fail_Smell_OK;
            if (v == "quick_fail_smell_fail" || v == "fail") return ValidationResponseValue::Quick_Fail_Smell_Fail;
            break;
        case ValidationReqType::Full:
            if (v == "full_green" || v == "green") return ValidationResponseValue::Full_Green;
            if (v == "full_amber" || v == "amber") return ValidationResponseValue::Full_Amber;
            if (v == "full_red" || v == "red") return ValidationResponseValue::Full_Red;
            break;
        case ValidationReqType::Model:
            if (v == "model_ok" || v == "ok") return ValidationResponseValue::Model_OK;
            if (v == "model_fail" || v == "fail") return ValidationResponseValue::Model_Fail;
            break;
        case ValidationReqType::Challenge:
            if (v == "challenge_ok" || v == "ok") return ValidationResponseValue::Challenge_OK;
            if (v == "challenge_fail" || v == "fail") return ValidationResponseValue::Challenge_Fail;
            break;
    }
    return std::nullopt;
}

static RPCHelpMan validationmockset()
{
    return RPCHelpMan{"validationmockset",
        "Set a mock validation response for a given id and type (mock backend only)",
        {
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Block hash or model id (hex)"},
            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Type: quick|full|model"},
            {"value", RPCArg::Type::STR, RPCArg::Optional::NO, "Response value (see help)"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "true if set"},
        RPCExamples{HelpExampleCli("validationmockset", "<id> full green")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            ValidationAPIMock* mock = EnsureMockApi();
            auto id = uint256::FromHex(request.params[0].get_str());
            if (!id) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid id");
            auto type = ParseReqType(request.params[1].get_str());
            if (!type) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid type");
            auto resp = ParseResp(request.params[2].get_str(), *type);
            if (!resp) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid value for type");
            const bool updated{mock->SetRequestStatus(*id, *type, *resp)};
            if (updated && *type == ValidationReqType::Full &&
                (*resp == ValidationResponseValue::Full_Green ||
                 *resp == ValidationResponseValue::Full_Red)) {
                ChainstateManager& chainman = EnsureAnyChainman(request.context);
                bool changed{false};
                bool activate_best_chain{false};
                {
                    LOCK(chainman.GetMutex());
                    CBlockIndex* pindex{chainman.SetBlockFullValidationRedStatus(*id, *resp == ValidationResponseValue::Full_Red, &changed)};
                    if (changed) {
                        chainman.RecalculateBlockIndexWorkForFullValidation(pindex);
                        activate_best_chain = chainman.ActiveTip() != nullptr;
                    }
                }
                if (activate_best_chain) {
                    BlockValidationState state;
                    if (!chainman.ActiveChainstate().ActivateBestChain(state)) {
                        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
                    }
                }
            }
            return UniValue(updated);
        }
    };
}

static RPCHelpMan validationmockdefault()
{
    return RPCHelpMan{"validationmockdefault",
        "Set a default mock response for a type (mock backend only)",
        {
            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Type: quick|full|model"},
            {"value", RPCArg::Type::STR, RPCArg::Optional::NO, "Default response"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "true if set"},
        RPCExamples{HelpExampleCli("validationmockdefault", "quick quick_ok_smell_ok")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            ValidationAPIMock* mock = EnsureMockApi();
            auto type = ParseReqType(request.params[0].get_str());
            if (!type) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid type");
            auto resp = ParseResp(request.params[1].get_str(), *type);
            if (!resp) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid value for type");
            mock->SetDefaultResponse(*type, *resp);
            return UniValue(true);
        }
    };
}

static RPCHelpMan validationmockclear()
{
    return RPCHelpMan{"validationmockclear",
        "Clear mock responses (all, or for a specific id optionally type)",
        {
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Block hash or model id (hex)"},
            {"type", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Type: quick|full|model"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "true if cleared"},
        RPCExamples{HelpExampleCli("validationmockclear", "")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            ValidationAPIMock* mock = EnsureMockApi();
            if (request.params.empty()) { mock->ClearAll(); return UniValue(true); }
            auto id = uint256::FromHex(request.params[0].get_str());
            if (!id) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid id");
            if (request.params.size() == 1) {
                // Clear all types for id by setting Not_Checked and removing Full specifically
                mock->RemoveRes_Full(*id);
                mock->SetRequestStatus(*id, ValidationReqType::Quick_Smell, ValidationResponseValue::Not_Checked);
                mock->SetRequestStatus(*id, ValidationReqType::Model, ValidationResponseValue::Not_Checked);
                return UniValue(true);
            }
            auto type = ParseReqType(request.params[1].get_str());
            if (!type) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid type");
            if (*type == ValidationReqType::Full) return UniValue(mock->RemoveRes_Full(*id));
            // Quick/Model: set to Not_Checked
            return UniValue(mock->SetRequestStatus(*id, *type, ValidationResponseValue::Not_Checked));
        }
    };
}

static RPCHelpMan validationmockrequests()
{
    return RPCHelpMan{"validationmockrequests",
        "Return captured mock validation requests",
        {},
        RPCResult{RPCResult::Type::ARR, "", "",
            { {RPCResult::Type::OBJ, "", "",
                {{RPCResult::Type::STR_HEX, "id", "hash or model id"}, {RPCResult::Type::STR, "type", "Quick_Smell|Full|Model"}, {RPCResult::Type::STR, "ts", "timestamp"}} }
            }
        },
        RPCExamples{HelpExampleCli("validationmockrequests", "")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            ValidationAPIMock* mock = EnsureMockApi();
            UniValue arr(UniValue::VARR);
            for (const auto& r : mock->GetCapturedRequests()) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("id", r.hash.ToString());
                std::string t = (r.type == ValidationReqType::Full) ? "Full" : (r.type == ValidationReqType::Model) ? "Model" : "Quick_Smell";
                o.pushKV("type", t);
                o.pushKV("ts", std::to_string(r.timestamp.time_since_epoch().count()));
                arr.push_back(o);
            }
            return arr;
        }
    };
}

// (No separate registrar; mock RPCs are registered above with custom RPCs)
