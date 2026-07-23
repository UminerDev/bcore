#include <chainparams.h>
#include <chrono>
#include <common/args.h>
#include <validationapi.h>
#include <primitives/block.h>
#include <primitives/proofblob.h>
#include <modeldb.h>
#include <rpc/validation_generated.h>
#include <rpc/server_util.h>
#include <thread>
#include <util/signalinterrupt.h>
#include <util/string.h>
#include <validation.h>
#include <verification/pow_v3.h>
#include <functional>
#include <verification/quick_verifier.h>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <univalue.h>
#include "uint256.h"
#include <fstream>
#include <tuple>
#include <array>
#include <optional>
#include <stdexcept>
#include <sync.h>
#include <algorithm>
#include <chain.h>
#include <net.h>
#include <netmessagemaker.h>

std::unique_ptr<IValidationAPI> g_ValidationApi = nullptr;

int GetFullValidationTipWindow()
{
    int window = gArgs.GetIntArg("-fullvalidationtipwindow", DEFAULT_FULL_VALIDATION_TIP_WINDOW);
    if (window < 0) {
        window = DEFAULT_FULL_VALIDATION_TIP_WINDOW;
    }
    return window;
}

namespace {
constexpr std::array<std::chrono::seconds, 4> AMBER_RETRY_DELAYS{
    std::chrono::seconds{0},
    std::chrono::seconds{1},
    std::chrono::seconds{60},
    std::chrono::seconds{120}};

std::string TrimCopy(std::string_view raw)
{
    const auto begin = raw.find_first_not_of(" \t\r\n");
    if (begin == std::string_view::npos) return {};
    const auto end = raw.find_last_not_of(" \t\r\n");
    return std::string{raw.substr(begin, end - begin + 1)};
}

std::vector<std::string> ParseCsvList(std::string_view raw)
{
    std::vector<std::string> values;
    for (const auto& part : util::SplitString(raw, ',')) {
        std::string value = TrimCopy(part);
        if (!value.empty()) {
            values.push_back(std::move(value));
        }
    }
    return values;
}

std::vector<std::string> ParseHttpBaseUrls(std::string_view raw)
{
    return ParseCsvList(raw);
}

std::vector<std::string> ParseHttpApiKeys(std::string_view raw)
{
    return ParseCsvList(raw);
}

struct ParsedHttpUrl {
    std::string scheme{"https"};
    std::string host;
    std::string port;
    std::string base_path;
};

std::optional<ParsedHttpUrl> ParseHttpBaseUrl(const std::string& raw)
{
    ParsedHttpUrl parsed;
    std::string hostport = TrimCopy(raw);
    if (hostport.empty()) return std::nullopt;

    const auto scheme_pos = hostport.find("://");
    if (scheme_pos != std::string::npos) {
        parsed.scheme = hostport.substr(0, scheme_pos);
        hostport = hostport.substr(scheme_pos + 3);
    }

    const auto slash_pos = hostport.find('/');
    if (slash_pos != std::string::npos) {
        parsed.base_path = hostport.substr(slash_pos);
        hostport = hostport.substr(0, slash_pos);
    }

    const auto colon_pos = hostport.find(':');
    if (colon_pos != std::string::npos) {
        parsed.host = hostport.substr(0, colon_pos);
        parsed.port = hostport.substr(colon_pos + 1);
    } else {
        parsed.host = hostport;
        parsed.port = (parsed.scheme == "http") ? "80" : "443";
    }

    if (parsed.host.empty() || parsed.port.empty()) return std::nullopt;
    return parsed;
}

bool StatusMatchesRequestedType(ValidationResponseValue st, ValidationReqType ty)
{
    switch (ty) {
    case ValidationReqType::Quick:
        return st == ValidationResponseValue::Quick_OK ||
               st == ValidationResponseValue::Quick_Fail;
    case ValidationReqType::Quick_Smell:
        return st == ValidationResponseValue::Quick_OK_Smell_OK ||
               st == ValidationResponseValue::Quick_OK_Smell_Fail ||
               st == ValidationResponseValue::Quick_Fail_Smell_OK ||
               st == ValidationResponseValue::Quick_Fail_Smell_Fail;
    case ValidationReqType::Full:
        return st == ValidationResponseValue::Full_Green ||
               st == ValidationResponseValue::Full_Amber ||
               st == ValidationResponseValue::Full_Red;
    case ValidationReqType::Challenge:
        return st == ValidationResponseValue::Challenge_OK ||
               st == ValidationResponseValue::Challenge_Fail;
    case ValidationReqType::Model:
        return st == ValidationResponseValue::Model_OK ||
               st == ValidationResponseValue::Model_Fail;
    }
    return false;
}
}

ValidationResponseValue ValidationAPI::BlockValidationDB::BlockValidationRecord_Quick::getQuick() const
{
    return static_cast<ValidationResponseValue>(QuickValidation);
}

ValidationResponseValue ValidationAPI::BlockValidationDB::BlockValidationRecord_Quick::getSmell() const
{
    return static_cast<ValidationResponseValue>(SmellValidation);
}

ValidationResponseValue ValidationAPI::BlockValidationDB::BlockValidationRecord_Full::getFull(const bool own) const
{
    if (own || FullValidation != static_cast<uint8_t>(ValidationResponseValue::Full_Amber))
        return static_cast<ValidationResponseValue>(FullValidation);
    if (nExtFull == 0)
        return ValidationResponseValue::Full_Red;
    uint8_t total_amber = 0;
    for (int i = 0; i < nExtFull; i++)
    {
        if (extFulls[i].second == static_cast<uint8_t>(ValidationResponseValue::Full_Red))
            return ValidationResponseValue::Full_Red;
        if (extFulls[i].second == static_cast<uint8_t>(ValidationResponseValue::Full_Amber))
            total_amber++;
    }
    if (total_amber > nExtFull / 5)
        return ValidationResponseValue::Full_Red;
    else
        return ValidationResponseValue::Full_Green;
}

bool ValidationAPI::BlockValidationDB::BlockValidationRecord_Full::addExtFull(const std::string& peerid, const ValidationResponseValue& value)
{
    if (value == ValidationResponseValue::Not_Checked) {
        return false;
    }
    for (uint8_t i = 0; i < nExtFull; ++i) {
        if (extFulls[i].first == peerid) {
            extFulls[i].second = static_cast<uint8_t>(value);
            return true;
        }
    }
    if (nExtFull >= EXPECTED_EXTFULL_SIZE) {
        return false;
    }
    extFulls[nExtFull] = {peerid, static_cast<uint8_t>(value)};
    ++nExtFull;
    return true;
}

ValidationAPI::BlockValidationDB::BlockValidationDB(const Consensus::Params& consensusParams, size_t cache_size, bool fMemory, bool fWipe){
    DBParams params_quick;
    params_quick.cache_bytes = cache_size;
    params_quick.memory_only = fMemory;
    params_quick.wipe_data = fWipe; 
    params_quick.path = gArgs.GetDataDirNet() / "blockvalidationdb_quick";
    DBParams params_full;
    params_full.cache_bytes = cache_size;
    params_full.memory_only = fMemory;
    params_full.wipe_data = fWipe; 
    params_full.path = gArgs.GetDataDirNet() / "blockvalidationdb_full";
    
    if (gArgs.GetBoolArg("-reindex", false)) {
        fs::remove_all(params_quick.path);
        fs::remove_all(params_full.path);
    }
    db_quick = std::make_unique<CDBWrapper>(params_quick);
    db_full = std::make_unique<CDBWrapper>(params_full);

    PruneToMax();

    LogPrintf("[BlockValidationDB] Initialized database at %s %s\n", params_quick.path.utf8string(), params_full.path.utf8string());
}

bool ValidationAPI::BlockValidationDB::UpdateRes_Quick(const uint256& pid, const ValidationResponseValue& value)
{
    BlockValidationRecord_Quick record(pid);
    bool existed_before = Exists_Quick(pid);
    if (existed_before) {
        db_quick->Read(pid, record);
    }
    switch (value){
    case ValidationResponseValue::Quick_OK:
    case ValidationResponseValue::Quick_Fail:
        record.QuickValidation = static_cast<uint8_t>(value);
        break;
    case ValidationResponseValue::Quick_OK_Smell_OK:
    case ValidationResponseValue::Quick_OK_Smell_Fail:
        record.QuickValidation = static_cast<uint8_t>(ValidationResponseValue::Quick_OK);
        record.SmellValidation = static_cast<uint8_t>(value);
        break;
    case ValidationResponseValue::Quick_Fail_Smell_OK:
    case ValidationResponseValue::Quick_Fail_Smell_Fail:
        record.QuickValidation = static_cast<uint8_t>(ValidationResponseValue::Quick_Fail);
        record.SmellValidation = static_cast<uint8_t>(value);
        break;
    default: 
        return false;
        break;
    }
    if (existed_before) {
        db_quick->Erase(pid);
    }
    bool ok = db_quick->Write(pid, record);
    if (!ok) return false;

    if (!existed_before) {
        std::unique_ptr<CDBIterator> it{db_quick->NewIterator()};
        it->SeekToFirst();
        size_t count = 0;
        uint64_t min_ts = std::numeric_limits<uint64_t>::max();
        uint256 oldest_key;
        while (it->Valid()) {
            uint256 key;
            BlockValidationRecord_Quick rec(pid);
            if (it->GetKey(key) && it->GetValue(rec)) {
                ++count;
                if (rec.ts < min_ts) {
                    min_ts = rec.ts;
                    oldest_key = key;
                }
            }
            it->Next();
        }
        if (count > BlockValidationDB::MAX_RECORDS) {
            db_quick->Erase(oldest_key);
        }
    }
    return true;
}

bool ValidationAPI::BlockValidationDB::UpdateRes_Full(const uint256& pid, const ValidationResponseValue& value)
{
    BlockValidationRecord_Full record(pid);
    bool existed_before = Exists_Full(pid);
    if (existed_before) {
        db_full->Read(pid, record);
    }
    // Amber never downgrades a terminal verdict. The validator caches its
    // Amber and re-serves it for as long as the block keeps being re-polled,
    // so a late redelivery would otherwise clobber the Green/Red the local
    // amber flow already finalized and restart the flow from scratch.
    if (existed_before &&
        value == ValidationResponseValue::Full_Amber &&
        (record.FullValidation == static_cast<uint8_t>(ValidationResponseValue::Full_Green) ||
         record.FullValidation == static_cast<uint8_t>(ValidationResponseValue::Full_Red))) {
        return false;
    }
    switch (value){
    case ValidationResponseValue::Full_Amber:
    case ValidationResponseValue::Full_Green:
    case ValidationResponseValue::Full_Red:
        record.FullValidation = static_cast<uint8_t>(value);
        break;
    default:
        return false;
        break;
    }
    if (existed_before) {
        db_full->Erase(pid);
    }
    bool ok = db_full->Write(pid, record);
    if (!ok) return false;

    if (!existed_before) {
        std::unique_ptr<CDBIterator> it{db_full->NewIterator()};
        it->SeekToFirst();
        size_t count = 0;
        uint64_t min_ts = std::numeric_limits<uint64_t>::max();
        uint256 oldest_key;
        while (it->Valid()) {
            uint256 key;
            BlockValidationRecord_Full rec(pid);
            if (it->GetKey(key) && it->GetValue(rec)) {
                ++count;
                if (rec.ts < min_ts) {
                    min_ts = rec.ts;
                    oldest_key = key;
                }
            }
            it->Next();
        }
        if (count > BlockValidationDB::MAX_RECORDS) {
            db_full->Erase(oldest_key);
        }
    }
    return true;
}

bool ValidationAPI::BlockValidationDB::UpdateExtFull(const uint256& pid, const std::string& peerid, const ValidationResponseValue& value)
{
    if (value == ValidationResponseValue::Not_Checked) {
        return false;
    }
    if (!Exists_Full(pid)) {
        return false;
    }
    BlockValidationRecord_Full record(pid);
    if (!db_full->Read(pid, record)) {
        return false;
    }
    if (static_cast<ValidationResponseValue>(record.FullValidation) != ValidationResponseValue::Full_Amber) {
        return false;
    }
    if (!record.addExtFull(peerid, value)) {
        return false;
    }
    db_full->Erase(pid);
    return db_full->Write(pid, record);
}
bool ValidationAPI::BlockValidationDB::RemoveRes_Full(const uint256& pid) {
    if (Exists_Full(pid)) {
        db_full->Erase(pid);
        return true;
    }
    return false;
}

void ValidationAPI::BlockValidationDB::PruneToMax()
{
    {
        std::unique_ptr<CDBIterator> it{db_quick->NewIterator()};
        it->SeekToFirst();
        std::vector<std::pair<uint64_t, uint256>> items;
        while (it->Valid()) {
            uint256 key;
            BlockValidationRecord_Quick rec(uint256::ZERO);
            if (it->GetKey(key) && it->GetValue(rec)) {
                items.emplace_back(rec.ts, key);
            }
            it->Next();
        }
        if (items.size() > MAX_RECORDS) {
            std::sort(items.begin(), items.end(), [](const auto& a, const auto& b){ return a.first < b.first; });
            const size_t to_erase = items.size() - MAX_RECORDS;
            for (size_t i = 0; i < to_erase; ++i) {
                db_quick->Erase(items[i].second);
            }
        }
    }

    {
        std::unique_ptr<CDBIterator> it{db_full->NewIterator()};
        it->SeekToFirst();
        std::vector<std::pair<uint64_t, uint256>> items;
        while (it->Valid()) {
            uint256 key;
            BlockValidationRecord_Full rec(uint256::ZERO);
            if (it->GetKey(key) && it->GetValue(rec)) {
                items.emplace_back(rec.ts, key);
            }
            it->Next();
        }
        if (items.size() > MAX_RECORDS) {
            std::sort(items.begin(), items.end(), [](const auto& a, const auto& b){ return a.first < b.first; });
            const size_t to_erase = items.size() - MAX_RECORDS;
            for (size_t i = 0; i < to_erase; ++i) {
                db_full->Erase(items[i].second);
            }
        }
    }
}

bool ValidationAPI::BlockValidationDB::ReadRes(const uint256& pid, BlockValidationRecord_Quick& record) const
{
    return db_quick->Read(pid, record);
}

bool ValidationAPI::BlockValidationDB::ReadRes(const uint256& pid, BlockValidationRecord_Full& record) const
{
    return db_full->Read(pid, record);
}

bool ValidationAPI::BlockValidationDB::Exists(const uint256& pid, const ValidationReqType& type) const
{
    switch (type){
    case ValidationReqType::Quick:
    case ValidationReqType::Quick_Smell:
        return Exists_Quick(pid);
    case ValidationReqType::Full:
        return Exists_Full(pid);
    case ValidationReqType::Challenge:
        return false;
    default: 
        return false;
        break;
    }
}

bool ValidationAPI::BlockValidationDB::Exists_Quick(const uint256& pid) const
{
    if (IsEmpty_Quick())
        return false;
    else
        return db_quick->Exists(pid);
}

bool ValidationAPI::BlockValidationDB::Exists_Full(const uint256& pid) const
{
    if (IsEmpty_Full())
        return false;
    else
        return db_full->Exists(pid);
}

bool ValidationAPI::BlockValidationDB::Erase(const uint256& pid, const ValidationReqType& type)
{
    switch (type){
    case ValidationReqType::Quick:
    case ValidationReqType::Quick_Smell:
        return Erase_Quick(pid);
    case ValidationReqType::Full:
        return Erase_Full(pid);
    case ValidationReqType::Challenge:
        return true;
    default: 
        return true;
        break;
    }
}

bool ValidationAPI::BlockValidationDB::Erase_Quick(const uint256& pid)
{
    return db_quick->Erase(pid);
}

bool ValidationAPI::BlockValidationDB::Erase_Full(const uint256& pid)
{
    return db_full->Erase(pid);
}

bool ValidationAPI::BlockValidationDB::IsEmpty(const ValidationReqType& type) const {
    switch (type){
    case ValidationReqType::Quick:
    case ValidationReqType::Quick_Smell:
        return IsEmpty_Quick();
    case ValidationReqType::Full:
        return IsEmpty_Full();
    case ValidationReqType::Challenge:
        return true;
    default: 
        return true;
        break;
    }
}

bool ValidationAPI::BlockValidationDB::IsEmpty_Quick() const {
    return db_quick->IsEmpty();
}

bool ValidationAPI::BlockValidationDB::IsEmpty_Full() const {
    return db_full->IsEmpty();
}

std::vector<ValidationAPI::BlockValidationDB::RecentValidation> ValidationAPI::BlockValidationDB::GetRecentRecords(size_t max_count) const
{
    std::vector<RecentValidation> results;
    results.reserve(max_count * 2);  // Reserve space for both quick and full

    // Collect from quick DB
    {
        std::unique_ptr<CDBIterator> it{db_quick->NewIterator()};
        for (it->SeekToFirst(); it->Valid(); it->Next()) {
            uint256 key;
            BlockValidationRecord_Quick record(uint256::ZERO);
            if (it->GetKey(key) && it->GetValue(record)) {
                RecentValidation rv;
                rv.block_hash = record.id;
                rv.quick_status = record.QuickValidation;
                rv.smell_status = record.SmellValidation;
                rv.full_status = 0;
                rv.timestamp = record.ts;
                rv.is_quick = true;
                results.push_back(rv);
            }
        }
    }

    // Collect from full DB
    {
        std::unique_ptr<CDBIterator> it{db_full->NewIterator()};
        for (it->SeekToFirst(); it->Valid(); it->Next()) {
            uint256 key;
            BlockValidationRecord_Full record(uint256::ZERO);
            if (it->GetKey(key) && it->GetValue(record)) {
                RecentValidation rv;
                rv.block_hash = record.id;
                rv.quick_status = 0;
                rv.smell_status = 0;
                rv.full_status = record.FullValidation;
                rv.timestamp = record.ts;
                rv.is_quick = false;
                results.push_back(rv);
            }
        }
    }

    // Sort by timestamp descending (most recent first)
    std::sort(results.begin(), results.end(), [](const RecentValidation& a, const RecentValidation& b) {
        return a.timestamp > b.timestamp;
    });

    // Truncate to max_count
    if (results.size() > max_count) {
        results.resize(max_count);
    }

    return results;
}

ValidationAPI::ValidationAPI(ChainstateManager& chainman, const Consensus::Params& consensusParams, bool desktop_mode)
    : m_chainman{chainman},
      m_validatedBlocks{consensusParams},
      config{EnvConfig::fromEnvironment("VALIDATOR", 6001, 7001)},
      http_config_{},
      m_http_mode{false},
      m_desktop_mode{desktop_mode},
      context{nullptr},
      reqPush{nullptr},
      solPull{nullptr},
      addressPush{config.getPushAddress()},
      addressPull{config.getPullAddress()},
      waitingApiAnswer{false},
      m_on{false},
      rateLimiter_{120},
      connection_healthy_{true},
      last_send_success_{std::chrono::steady_clock::now()},
      requestTracker{},
      reqThread{},
      solThread{},
      behThread{},
      behaviors{} {
    LogPrintf("ValidationAPI initialized with push=%s, pull=%s\n", addressPush, addressPull);
}

ValidationAPI::HttpRequestGuard::HttpRequestGuard(ValidationAPI& owner, std::function<void()> cancel)
    : owner_{owner}, token_{owner_.RegisterHttpCancellation(std::move(cancel))}
{
    if (token_ == 0) {
        throw std::runtime_error{"validation HTTP request interrupted during shutdown"};
    }
}

ValidationAPI::HttpRequestGuard::~HttpRequestGuard()
{
    if (token_ != 0) {
        owner_.UnregisterHttpCancellation(token_);
    }
}

uint64_t ValidationAPI::RegisterHttpCancellation(std::function<void()> cancel)
{
    std::lock_guard<std::mutex> lock(http_requests_mutex_);
    if (!m_on.load(std::memory_order_acquire)) {
        cancel();
        return 0;
    }
    const uint64_t token = ++next_http_request_token_;
    active_http_requests_.emplace(token, std::move(cancel));
    return token;
}

void ValidationAPI::UnregisterHttpCancellation(uint64_t token)
{
    std::lock_guard<std::mutex> lock(http_requests_mutex_);
    active_http_requests_.erase(token);
}

void ValidationAPI::CancelHttpRequests()
{
    std::lock_guard<std::mutex> lock(http_requests_mutex_);
    for (const auto& [token, cancel] : active_http_requests_) {
        (void)token;
        try {
            cancel();
        } catch (const std::exception& e) {
            LogWarning("VALIDATOR: failed to cancel an in-flight HTTP request: %s\n", e.what());
        }
    }
}

ValidationResponseValue ValidationAPI::RunLocalQuick(const CBlock& block)
{
    QuickVerifier verifier;
    // V3 prompt binding (TIP-0003): a nonce-bearing v3 proof folds the
    // admission nonce into every u (§7); without the v3 context the local quick
    // check would recompute u WITHOUT the nonce and spuriously fail the block
    // (U-value mismatch) even though it is consensus-valid. Mirror the same
    // context validation.cpp's pre-check uses: height = parent + 1 (dormant at
    // -1 if the parent is unknown), registered difficulty from modeldb.
    {
        const auto& pb = block.pow;
        const int proof_height = WITH_LOCK(::cs_main, {
            const CBlockIndex* pprev = m_chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
            return pprev ? pprev->nHeight + 1 : -1;
        });
        int64_t v3_difficulty{0};
        if (pb.version >= 3 && g_modeldb && !pb.model_identifier.empty()) {
            ModelRecord rec;
            if (g_modeldb->ReadModel(pb.GetModelHash(), rec)) {
                v3_difficulty = rec.metadata.difficulty;
            }
        }
        verifier.SetV3Context(m_chainman.GetConsensus(), proof_height, v3_difficulty);
    }
    // Version-keyed: enforces the reuse gate iff block.pow.version >= REUSE_GATE_VERSION.
    const auto res = verifier.QuickVerify(block.pow);
    switch (res) {
    case VerificationResult::Quick_OK:
    case VerificationResult::Quick_OK_Smell_OK:
        return ValidationResponseValue::Quick_OK_Smell_OK;
    case VerificationResult::Quick_OK_Smell_Fail:
        return ValidationResponseValue::Quick_OK_Smell_Fail;
    case VerificationResult::Quick_Fail:
    case VerificationResult::Quick_Fail_Smell_Fail:
    case VerificationResult::Quick_Fail_Model_Unregistered:
    default:
        return ValidationResponseValue::Quick_Fail_Smell_Fail;
    }
}

bool ValidationAPI::TrySetLocalQuickSmellFinalHashFailure(const CBlock& block)
{
    const CProofBlob& pb = block.pow;
    const bool has_final_hash_fields =
        !pb.chosen_tokens.empty() &&
        pb.header_prefix.size() == 76 &&
        !pb.hash.empty();
    if (!has_final_hash_fields) {
        return false;
    }

    QuickVerifier verifier;
    {
        const int proof_height = WITH_LOCK(::cs_main, {
            const CBlockIndex* pprev = m_chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
            return pprev ? pprev->nHeight + 1 : -1;
        });
        if (proof_height < 0 &&
            pb.version >= pow_v3::V3_PROOF_VERSION &&
            pow_v3::extract_admission_nonce_hex(pb.extra_flags)) {
            return false;
        }
        int64_t v3_difficulty{0};
        if (pb.version >= 3 && g_modeldb && !pb.model_identifier.empty()) {
            ModelRecord rec;
            if (g_modeldb->ReadModel(pb.GetModelHash(), rec)) {
                v3_difficulty = rec.metadata.difficulty;
            }
        }
        verifier.SetV3Context(m_chainman.GetConsensus(), proof_height, v3_difficulty);
    }

    if (verifier.VerifyFinalHashOnly(pb)) {
        return false;
    }

    LogWarning("VALIDATOR: Local final-hash precheck FAILED for %s: %s\n",
               block.GetHash().ToString().c_str(), verifier.GetLastError().c_str());
    SetRequestStatus(block.GetHash(), ValidationReqType::Quick_Smell,
                     ValidationResponseValue::Quick_Fail_Smell_Fail);
    return true;
}

bool ValidationAPI::Initialize() {
    try {
        // Validate configuration first
        config = EnvConfig::fromEnvironment("VALIDATOR", 6001, 7001);
        const char* http_urls_env = std::getenv("VALIDATOR_HTTP_URLS");
        const char* http_bases_env = std::getenv("VALIDATOR_BASE_URLS");
        const char* http_url_env = std::getenv("VALIDATOR_HTTP_URL");
        const char* http_base_env = std::getenv("VALIDATOR_BASE_URL");
        const char* http_keys_env = std::getenv("VALIDATOR_API_KEYS");
        const char* http_key_env = std::getenv("VALIDATOR_API_KEY");
        const char* http_timeout_env = std::getenv("VALIDATOR_HTTP_TIMEOUT_MS");
        const bool has_cli_url = gArgs.IsArgSet("-validatorhttpurl");
        const bool has_cli_keys = gArgs.IsArgSet("-validatorapikeys");
        const bool has_cli_key = gArgs.IsArgSet("-validatorapikey");
        if (http_urls_env || http_bases_env || http_url_env || http_base_env || has_cli_url || m_desktop_mode) {
            // Desktop wallet defaults to the public verification endpoint (no API key required).
            // Server deployments that set env vars will use those instead.
            const std::string desktop_default = "https://verify.tensorcash.org";
            const std::string raw_base_urls = has_cli_url ? gArgs.GetArg("-validatorhttpurl", "")
                : (http_urls_env ? std::string(http_urls_env)
                                 : (http_bases_env ? std::string(http_bases_env)
                                                   : (http_url_env ? std::string(http_url_env)
                                                                   : (http_base_env ? std::string(http_base_env)
                                                                                    : desktop_default))));
            http_config_.base_urls = ParseHttpBaseUrls(raw_base_urls);
            if (http_config_.base_urls.empty()) {
                LogError("VALIDATOR: HTTP mode enabled but no valid base URLs were configured\n");
                return false;
            }
            http_config_.base_url = http_config_.base_urls.front();
            http_config_.api_key = has_cli_key ? gArgs.GetArg("-validatorapikey", "")
                                               : (http_key_env ? std::string(http_key_env) : std::string());
            const std::vector<std::string> explicit_api_keys = has_cli_keys
                ? ParseHttpApiKeys(gArgs.GetArg("-validatorapikeys", ""))
                : (http_keys_env ? ParseHttpApiKeys(http_keys_env) : std::vector<std::string>{});
            http_config_.endpoints.clear();
            if (!explicit_api_keys.empty()) {
                if (explicit_api_keys.size() == 1) {
                    for (const auto& base_url : http_config_.base_urls) {
                        http_config_.endpoints.push_back(HttpEndpoint{base_url, explicit_api_keys.front()});
                    }
                    http_config_.api_key = explicit_api_keys.front();
                } else if (explicit_api_keys.size() == http_config_.base_urls.size()) {
                    for (size_t i = 0; i < http_config_.base_urls.size(); ++i) {
                        http_config_.endpoints.push_back(HttpEndpoint{http_config_.base_urls[i], explicit_api_keys[i]});
                    }
                    if (http_config_.api_key.empty()) {
                        http_config_.api_key = explicit_api_keys.front();
                    }
                } else {
                    const std::string fallback_key = !http_config_.api_key.empty() ? http_config_.api_key : explicit_api_keys.front();
                    LogWarning("VALIDATOR: HTTP URL count (%zu) and API key count (%zu) differ; using a shared fallback key for all endpoints\n",
                               http_config_.base_urls.size(), explicit_api_keys.size());
                    for (const auto& base_url : http_config_.base_urls) {
                        http_config_.endpoints.push_back(HttpEndpoint{base_url, fallback_key});
                    }
                    http_config_.api_key = fallback_key;
                }
            } else {
                for (const auto& base_url : http_config_.base_urls) {
                    http_config_.endpoints.push_back(HttpEndpoint{base_url, http_config_.api_key});
                }
            }
            if (http_timeout_env) {
                try {
                    http_config_.timeout = std::chrono::milliseconds{std::stoi(http_timeout_env)};
                } catch (const std::exception&) {
                    LogWarning("VALIDATOR_HTTP_TIMEOUT_MS invalid, using default 30000ms\n");
                }
            }
            m_http_mode = true;
        }
    } catch (const std::exception& e) {
        LogError("VALIDATOR: Configuration error: %s\n", e.what());
        return false;
    }

    // Desktop/http mode skips ZMQ sockets; threads handle HTTP dispatch.
    if (m_http_mode) {
        LogPrintf("Validation API using HTTP backend at %s%s (desktop_mode=%d)\n",
                  http_config_.base_url.c_str(),
                  http_config_.base_urls.size() > 1 ? " [+fallback_urls]" : "",
                  m_desktop_mode);
        if (!http_config_.endpoints.empty()) {
            size_t keyed_endpoints = 0;
            for (const auto& endpoint : http_config_.endpoints) {
                if (!endpoint.api_key.empty()) {
                    ++keyed_endpoints;
                }
            }
            if (keyed_endpoints > 0 && keyed_endpoints < http_config_.endpoints.size()) {
                LogWarning("VALIDATOR: Only %zu/%zu HTTP endpoints have API keys configured; endpoints without keys will be skipped for authenticated submit/status calls\n",
                           keyed_endpoints, http_config_.endpoints.size());
            }
        }
        if (!HasHttpApiKey()) {
            LogWarning("*** VALIDATOR WARNING: VALIDATOR_API_KEY is NOT set. "
                       "Status polling will use the public read-only endpoint "
                       "(/v1/public/status). Submission requests requiring auth will FAIL. ***\n");
        }
        StartThreads();
        return true;
    }

    // No HTTP mode and no ZMQ — warn loudly
    if (!m_desktop_mode) {
        LogWarning("*** VALIDATOR WARNING: VALIDATOR_BASE_URL is NOT set and no local "
                   "verification API is configured. Block validation will rely solely on "
                   "ZMQ transport. If ZMQ is not reachable, blocks will fail validation. ***\n");
    }

    assert(!context);
    context = zmq_ctx_new();
    if (!context) {
        LogError("Could not create the validation API context\n");
        return false;
    }

    assert(!reqPush);
    reqPush = zmq_socket(context, ZMQ_PUSH);
    if (!reqPush) {
        LogError("Could not create the validation API push socket\n");
        return false;
    }
    
    if (zmq_connect(reqPush, addressPush.c_str()) != 0) {
        LogError("Could not connect the validation API push socket: %s\n", zmq_strerror(errno));
        zmq_close(reqPush);
        reqPush = nullptr;
        return false;
    }

    assert(!solPull);
    solPull = zmq_socket(context, ZMQ_PULL);
    if (!solPull) {
        LogError("Could not create the validation API pull socket\n");
        return false;
    }
    
    if (zmq_bind(solPull, addressPull.c_str()) != 0) {
        LogError("Could not bind the validation API pull socket: %s\n", zmq_strerror(errno));
        zmq_close(solPull);
        solPull = nullptr;
        return false;
    }
    
    LogPrintf("Validation API sockets are connected\n");
    StartThreads();
    return true;
}

bool ValidationAPI::IsFullQueueEmpty() const {
    return requestTracker.full_requests_.empty();
}

size_t ValidationAPI::GetQuickQueueSize() const {
    std::shared_lock lock(requestTracker.mutex_);
    return requestTracker.short_requests_.size();
}

size_t ValidationAPI::GetQuickSmellQueueSize() const {
    std::shared_lock lock(requestTracker.mutex_);
    return requestTracker.short_smell_requests_.size();
}

size_t ValidationAPI::GetFullQueueSize() const {
    std::shared_lock lock(requestTracker.mutex_);
    return requestTracker.full_requests_.size();
}

size_t ValidationAPI::GetModelQueueSize() const {
    std::shared_lock lock(requestTracker.mutex_);
    return requestTracker.model_requests_.size();
}

size_t ValidationAPI::GetChallengeQueueSize() const {
    std::shared_lock lock(requestTracker.mutex_);
    return requestTracker.challenge_requests_.size();
}

ValidationAPI::~ValidationAPI() {
    StopThreads();
    if (context) {
        int linger = 0;
        if (solPull) {
            zmq_setsockopt(solPull, ZMQ_LINGER, &linger, sizeof(linger));
            zmq_close(solPull);
            solPull = nullptr;
        }
        
        if (reqPush) {
            zmq_setsockopt(reqPush, ZMQ_LINGER, &linger, sizeof(linger));
            zmq_close(reqPush);
            reqPush = nullptr;
        }

        zmq_ctx_term(context);
        context = nullptr;
    }
}

void ValidationAPI::checkNetworkHealth() {
    auto now = std::chrono::steady_clock::now();
    if (now - last_send_success_ > PARTITION_TIMEOUT) {
        if (connection_healthy_.exchange(false)) {
            LogError("VALIDATOR: Network partition detected - no successful sends for %d seconds\n", 
                     std::chrono::duration_cast<std::chrono::seconds>(PARTITION_TIMEOUT).count());
            
            // Attempt reconnection
            if (reqPush) {
                zmq_disconnect(reqPush, addressPush.c_str());
                zmq_connect(reqPush, addressPush.c_str());
            }
        }
    }
}

bool ValidationAPI::TryFetchPublicStatusSync(const uint256& req_id, const ValidationReqType& req_type)
{
    auto parse_status_value = [](const std::string& val) -> std::optional<ValidationResponseValue> {
        if (val == "Quick_OK") return ValidationResponseValue::Quick_OK;
        if (val == "Quick_Fail") return ValidationResponseValue::Quick_Fail;
        if (val == "Quick_OK_Smell_OK") return ValidationResponseValue::Quick_OK_Smell_OK;
        if (val == "Quick_OK_Smell_Fail") return ValidationResponseValue::Quick_OK_Smell_Fail;
        if (val == "Quick_Fail_Smell_OK") return ValidationResponseValue::Quick_Fail_Smell_OK;
        if (val == "Quick_Fail_Smell_Fail") return ValidationResponseValue::Quick_Fail_Smell_Fail;
        if (val == "Full_Green") return ValidationResponseValue::Full_Green;
        if (val == "Full_Amber") return ValidationResponseValue::Full_Amber;
        if (val == "Full_Red") return ValidationResponseValue::Full_Red;
        // NOTE: "Failed" is deliberately NOT mapped — it is a validator-side
        // infrastructure failure, not a consensus verdict. Callers treat it as
        // retryable/pending; mapping it to Full_Red would poison the block as
        // consensus-red on an infra outage.
        if (val == "Challenge_OK") return ValidationResponseValue::Challenge_OK;
        if (val == "Challenge_Fail") return ValidationResponseValue::Challenge_Fail;
        if (val == "Model_OK") return ValidationResponseValue::Model_OK;
        if (val == "Model_Fail") return ValidationResponseValue::Model_Fail;
        return std::nullopt;
    };

    auto get_type_string = [](ValidationReqType type) -> const char* {
        switch (type) {
        case ValidationReqType::Quick: return "quick";
        case ValidationReqType::Quick_Smell: return "quick_smell";
        case ValidationReqType::Full: return "full";
        case ValidationReqType::Challenge: return "challenge";
        case ValidationReqType::Model: return "model";
        default: return "unknown";
        }
    };

    namespace http = boost::beast::http;
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    for (const auto& base_url : http_config_.base_urls) {
        const auto endpoint = ParseHttpBaseUrl(base_url);
        if (!endpoint.has_value()) {
            continue;
        }

        const std::string path = (endpoint->base_path.empty() ? "" : endpoint->base_path) +
            "/v1/public/status/" + req_id.ToString() +
            "?verification_type=" + get_type_string(req_type);

        try {
            std::string body;
            net::io_context ioc;
            int status_code = 0;

            if (endpoint->scheme == "http") {
                tcp::resolver resolver{ioc};
                boost::beast::tcp_stream stream{ioc};
                HttpRequestGuard request_guard{*this, [&] {
                    boost::system::error_code ec;
                    resolver.cancel();
                    stream.socket().cancel(ec);
                    stream.socket().shutdown(tcp::socket::shutdown_both, ec);
                    stream.socket().close(ec);
                }};
                auto const results = resolver.resolve(endpoint->host, endpoint->port);
                stream.expires_after(http_config_.timeout);
                stream.connect(results);

                http::request<http::string_body> req_msg{http::verb::get, path, 11};
                req_msg.set(http::field::host, endpoint->host);
                req_msg.set(http::field::user_agent, "tensorcash/validationapi");
                http::write(stream, req_msg);

                boost::beast::flat_buffer buffer;
                http::response<http::string_body> res;
                http::read(stream, buffer, res);
                stream.socket().shutdown(tcp::socket::shutdown_both);
                status_code = res.result_int();
                body = res.body();
            } else {
                net::ssl::context ctx{net::ssl::context::tls_client};
                ctx.set_default_verify_paths();
                tcp::resolver resolver{ioc};
                boost::beast::ssl_stream<boost::beast::tcp_stream> stream{ioc, ctx};
                HttpRequestGuard request_guard{*this, [&] {
                    boost::system::error_code ec;
                    resolver.cancel();
                    auto& socket = boost::beast::get_lowest_layer(stream).socket();
                    socket.cancel(ec);
                    socket.shutdown(tcp::socket::shutdown_both, ec);
                    socket.close(ec);
                }};
                auto const results = resolver.resolve(endpoint->host, endpoint->port);
                if (!SSL_set_tlsext_host_name(stream.native_handle(), endpoint->host.c_str())) {
                    continue;
                }
                boost::beast::get_lowest_layer(stream).expires_after(http_config_.timeout);
                boost::beast::get_lowest_layer(stream).connect(results);
                stream.handshake(net::ssl::stream_base::client);

                http::request<http::string_body> req_msg{http::verb::get, path, 11};
                req_msg.set(http::field::host, endpoint->host);
                req_msg.set(http::field::user_agent, "tensorcash/validationapi");
                http::write(stream, req_msg);

                boost::beast::flat_buffer buffer;
                http::response<http::string_body> res;
                http::read(stream, buffer, res);
                boost::system::error_code ec;
                stream.shutdown(ec);
                status_code = res.result_int();
                body = res.body();
            }

            if (status_code < 200 || status_code >= 300) {
                continue;
            }

            UniValue root;
            if (!root.read(body)) {
                continue;
            }

            const UniValue& status_val = root.find_value("status");
            if (!status_val.isStr()) {
                continue;
            }

            const std::string status_str = status_val.get_str();
            if (status_str == "NAN" || status_str == "pending" || status_str == "Model_Pending_Review") {
                return false;
            }
            if (status_str == "Failed") {
                LogWarning("VALIDATOR HTTP public status sync: id=%s type=%d reported Failed (infra); treating as retryable, not consensus-red\n",
                           req_id.ToString().c_str(), static_cast<int>(req_type));
                return false;
            }

            auto status_opt = parse_status_value(status_str);
            if (!status_opt) {
                continue;
            }
            if (!StatusMatchesRequestedType(*status_opt, req_type)) {
                LogDebug(BCLog::VALIDATION,
                         "VALIDATOR HTTP public status sync ignoring status %s incompatible with type=%d for id=%s via %s\n",
                         status_str.c_str(), static_cast<int>(req_type),
                         req_id.ToString().c_str(), base_url.c_str());
                continue;
            }

            ValidationResponseValue cur;
            const bool inserted = SetRequestStatus(req_id, req_type, *status_opt);
            return inserted || GetRequestStatusImpl(req_id, req_type, cur);
        } catch (const std::exception&) {
            continue;
        }
    }

    return false;
}

// Synchronous authenticated batch-status probe used inline from the submit
// path. Bypasses the SolutionReceiverLoop entirely so a stuck or starved poll
// consumer cannot strand a request whose terminal answer is already cached on
// the validator. Best-effort: any HTTP/parse failure or non-terminal status
// returns false and the caller falls through to the normal submit retry path.
bool ValidationAPI::TryFetchAuthStatusSync(const uint256& req_id, const ValidationReqType& req_type)
{
    auto parse_status_value = [](const std::string& val) -> std::optional<ValidationResponseValue> {
        if (val == "Quick_OK") return ValidationResponseValue::Quick_OK;
        if (val == "Quick_Fail") return ValidationResponseValue::Quick_Fail;
        if (val == "Quick_OK_Smell_OK") return ValidationResponseValue::Quick_OK_Smell_OK;
        if (val == "Quick_OK_Smell_Fail") return ValidationResponseValue::Quick_OK_Smell_Fail;
        if (val == "Quick_Fail_Smell_OK") return ValidationResponseValue::Quick_Fail_Smell_OK;
        if (val == "Quick_Fail_Smell_Fail") return ValidationResponseValue::Quick_Fail_Smell_Fail;
        if (val == "Full_Green") return ValidationResponseValue::Full_Green;
        if (val == "Full_Amber") return ValidationResponseValue::Full_Amber;
        if (val == "Full_Red") return ValidationResponseValue::Full_Red;
        // NOTE: "Failed" is deliberately NOT mapped — it is a validator-side
        // infrastructure failure, not a consensus verdict. Callers treat it as
        // retryable/pending; mapping it to Full_Red would poison the block as
        // consensus-red on an infra outage.
        if (val == "Challenge_OK") return ValidationResponseValue::Challenge_OK;
        if (val == "Challenge_Fail") return ValidationResponseValue::Challenge_Fail;
        if (val == "Model_OK") return ValidationResponseValue::Model_OK;
        if (val == "Model_Fail") return ValidationResponseValue::Model_Fail;
        return std::nullopt;
    };

    auto get_type_string = [](ValidationReqType type) -> const char* {
        switch (type) {
        case ValidationReqType::Quick: return "quick";
        case ValidationReqType::Quick_Smell: return "quick-smell";
        case ValidationReqType::Full: return "full";
        case ValidationReqType::Challenge: return "challenge";
        case ValidationReqType::Model: return "model";
        default: return "unknown";
        }
    };

    namespace http = boost::beast::http;
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    const std::string body_json = std::string("{\"items\":[{\"hash_id\":\"") +
                                  req_id.ToString() +
                                  "\",\"verification_type\":\"" + get_type_string(req_type) +
                                  "\"}],\"wait_ms\":0}";

    for (const auto& endpoint_cfg : http_config_.endpoints) {
        if (endpoint_cfg.api_key.empty()) {
            continue;
        }
        const auto endpoint = ParseHttpBaseUrl(endpoint_cfg.base_url);
        if (!endpoint.has_value()) {
            continue;
        }
        const std::string path = (endpoint->base_path.empty() ? "" : endpoint->base_path) +
                                 "/v1/verify/status/batch";
        const std::string auth_header = std::string("Bearer ") + endpoint_cfg.api_key;

        try {
            std::string resp_body;
            net::io_context ioc;
            int status_code = 0;

            if (endpoint->scheme == "http") {
                tcp::resolver resolver{ioc};
                boost::beast::tcp_stream stream{ioc};
                HttpRequestGuard request_guard{*this, [&] {
                    boost::system::error_code ec;
                    resolver.cancel();
                    stream.socket().cancel(ec);
                    stream.socket().shutdown(tcp::socket::shutdown_both, ec);
                    stream.socket().close(ec);
                }};
                auto const results = resolver.resolve(endpoint->host, endpoint->port);
                stream.expires_after(http_config_.timeout);
                stream.connect(results);

                http::request<http::string_body> req_msg{http::verb::post, path, 11};
                req_msg.set(http::field::host, endpoint->host);
                req_msg.set(http::field::user_agent, "tensorcash/validationapi");
                req_msg.set(http::field::authorization, auth_header);
                req_msg.set(http::field::content_type, "application/json");
                req_msg.body() = body_json;
                req_msg.prepare_payload();
                http::write(stream, req_msg);

                boost::beast::flat_buffer buffer;
                http::response<http::string_body> res;
                http::read(stream, buffer, res);
                stream.socket().shutdown(tcp::socket::shutdown_both);
                status_code = res.result_int();
                resp_body = res.body();
            } else {
                net::ssl::context ctx{net::ssl::context::tls_client};
                ctx.set_default_verify_paths();
                tcp::resolver resolver{ioc};
                boost::beast::ssl_stream<boost::beast::tcp_stream> stream{ioc, ctx};
                HttpRequestGuard request_guard{*this, [&] {
                    boost::system::error_code ec;
                    resolver.cancel();
                    auto& socket = boost::beast::get_lowest_layer(stream).socket();
                    socket.cancel(ec);
                    socket.shutdown(tcp::socket::shutdown_both, ec);
                    socket.close(ec);
                }};
                auto const results = resolver.resolve(endpoint->host, endpoint->port);
                if (!SSL_set_tlsext_host_name(stream.native_handle(), endpoint->host.c_str())) {
                    continue;
                }
                boost::beast::get_lowest_layer(stream).expires_after(http_config_.timeout);
                boost::beast::get_lowest_layer(stream).connect(results);
                stream.handshake(net::ssl::stream_base::client);

                http::request<http::string_body> req_msg{http::verb::post, path, 11};
                req_msg.set(http::field::host, endpoint->host);
                req_msg.set(http::field::user_agent, "tensorcash/validationapi");
                req_msg.set(http::field::authorization, auth_header);
                req_msg.set(http::field::content_type, "application/json");
                req_msg.body() = body_json;
                req_msg.prepare_payload();
                http::write(stream, req_msg);

                boost::beast::flat_buffer buffer;
                http::response<http::string_body> res;
                http::read(stream, buffer, res);
                boost::system::error_code ec;
                stream.shutdown(ec);
                status_code = res.result_int();
                resp_body = res.body();
            }

            if (status_code < 200 || status_code >= 300) {
                LogDebug(BCLog::VALIDATION,
                         "VALIDATOR HTTP submit-path probe non-2xx (status=%d) for id=%s type=%d via %s\n",
                         status_code, req_id.ToString().c_str(), static_cast<int>(req_type),
                         endpoint_cfg.base_url.c_str());
                continue;
            }

            UniValue root;
            if (!root.read(resp_body)) {
                LogDebug(BCLog::VALIDATION,
                         "VALIDATOR HTTP submit-path probe parse failed for id=%s type=%d via %s (body_size=%zu)\n",
                         req_id.ToString().c_str(), static_cast<int>(req_type),
                         endpoint_cfg.base_url.c_str(), resp_body.size());
                continue;
            }

            const UniValue& completed = root.find_value("completed");
            if (!completed.isArray() || completed.empty()) {
                return false;
            }

            for (const UniValue& item : completed.getValues()) {
                const UniValue& hash_val = item.find_value("hash_id");
                const UniValue& status_val = item.find_value("status");
                const UniValue& vtype_val = item.find_value("verification_type");
                if (!hash_val.isStr() || !status_val.isStr()) {
                    continue;
                }
                if (hash_val.get_str() != req_id.ToString()) {
                    continue;
                }
                // The validator may store multiple verification_types for the
                // same hash. Only consume a terminal whose verification_type
                // matches what we asked for.
                if (vtype_val.isStr()) {
                    const std::string& got = vtype_val.get_str();
                    const std::string want_dash = get_type_string(req_type);
                    std::string want_under = want_dash;
                    std::replace(want_under.begin(), want_under.end(), '-', '_');
                    if (got != want_dash && got != want_under) {
                        LogDebug(BCLog::VALIDATION,
                                 "VALIDATOR HTTP submit-path probe ignoring cross-type terminal id=%s want=%s got=%s via %s\n",
                                 req_id.ToString().c_str(), want_dash.c_str(), got.c_str(),
                                 endpoint_cfg.base_url.c_str());
                        continue;
                    }
                }
                const std::string status_str = status_val.get_str();
                if (status_str == "NAN" || status_str == "pending" || status_str == "Model_Pending_Review") {
                    return false;
                }
                if (status_str == "Failed") {
                    LogWarning("VALIDATOR HTTP submit-path probe: id=%s type=%d reported Failed (infra); treating as retryable, not consensus-red\n",
                               req_id.ToString().c_str(), static_cast<int>(req_type));
                    return false;
                }
                auto status_opt = parse_status_value(status_str);
                if (!status_opt) {
                    return false;
                }
                if (!StatusMatchesRequestedType(*status_opt, req_type)) {
                    LogDebug(BCLog::VALIDATION,
                             "VALIDATOR HTTP submit-path probe ignoring status %s incompatible with type=%d for id=%s via %s\n",
                             status_str.c_str(), static_cast<int>(req_type),
                             req_id.ToString().c_str(), endpoint_cfg.base_url.c_str());
                    continue;
                }

                ValidationResponseValue cur;
                const bool inserted = SetRequestStatus(req_id, req_type, *status_opt);
                if (inserted || GetRequestStatusImpl(req_id, req_type, cur)) {
                    ClearStatusQueueEntry(StatusKey{req_id, req_type});
                    LogPrintf("VALIDATOR HTTP submit-path cache hit id=%s type=%d status=%s via %s; skipping submit\n",
                              req_id.ToString().c_str(),
                              static_cast<int>(req_type),
                              status_str.c_str(),
                              endpoint_cfg.base_url.c_str());
                    return true;
                }
                return false;
            }
            return false;
        } catch (const std::exception& e) {
            LogDebug(BCLog::VALIDATION,
                     "VALIDATOR HTTP submit-path probe exception for id=%s type=%d via %s: %s\n",
                     req_id.ToString().c_str(), static_cast<int>(req_type),
                     endpoint_cfg.base_url.c_str(), e.what());
            continue;
        }
    }

    return false;
}

uint16_t ValidationAPI::SendHttpRequest(const uint256& req_id,
                                                           const std::vector<uint8_t>& payload,
                                                           const ValidationReqType& req_type)
{
    std::string target;
    switch(req_type){
    case ValidationReqType::Quick:
        target = "/v1/verify/quick/request/submit";
        break;
    case ValidationReqType::Quick_Smell:
        target = "/v1/verify/quick-smell/request/submit";
        break;
    case ValidationReqType::Full:
        target = "/v1/verify/full/request/submit";
        break;
    case ValidationReqType::Challenge:
        target = "/v1/verify/challenge/request/submit";
        break;
    case ValidationReqType::Model:
        target = "/v1/verify/model/request/submit";
        break;
    default:
        target = "";
        break;
    }
    // The status cache is the source of truth once a request id exists. Queue
    // polling before submit so a lost/rejected submit response cannot strand a
    // request that the validator has already completed.
    EnqueueStatusRequest(req_id, req_type);

    // Submit-path cache probe: if the validator already has a terminal answer
    // for {req_id, req_type}, write it to the local store and skip the submit
    // entirely. This bypasses any failure where SolutionReceiverLoop is
    // starved/stalled and stops applying batch results, which would otherwise
    // strand the request in an infinite submit-retry loop. Bounded by
    // http_config_.timeout per endpoint, so cannot hang JobSchedulerLoop.
    if (HasHttpApiKey() && TryFetchAuthStatusSync(req_id, req_type)) {
        return 200;
    }

    if (!HasHttpApiKey()) {
        if (TryFetchPublicStatusSync(req_id, req_type)) {
            LogPrintf("VALIDATOR: public status hit id=%s type=%d; using synchronous public result\n",
                      req_id.ToString(), static_cast<int>(req_type));
            return 200;
        }
        LogPrintf("VALIDATOR: No API key for id=%s type=%d; skipping submit and polling public status\n",
                  req_id.ToString(), static_cast<int>(req_type));
        return 0;
    }

    namespace http = boost::beast::http;
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    uint16_t last_status{0};
    bool queued_public_fallback{false};

    for (const auto& endpoint_cfg : http_config_.endpoints) {
        if (endpoint_cfg.api_key.empty()) {
            LogWarning("VALIDATOR HTTP submit skipped %s because no API key is configured for that endpoint\n",
                       endpoint_cfg.base_url.c_str());
            queued_public_fallback = true;
            continue;
        }
        const auto endpoint = ParseHttpBaseUrl(endpoint_cfg.base_url);
        if (!endpoint.has_value()) {
            LogError("VALIDATOR HTTP submit skipped invalid base URL: %s\n", endpoint_cfg.base_url.c_str());
            queued_public_fallback = true;
            continue;
        }

        const std::string path = (endpoint->base_path.empty() ? "" : endpoint->base_path) + target;

        try {
            net::io_context ioc;
            uint16_t status_code{0};

            if (endpoint->scheme == "http") {
                tcp::resolver resolver{ioc};
                boost::beast::tcp_stream stream{ioc};
                HttpRequestGuard request_guard{*this, [&] {
                    boost::system::error_code ec;
                    resolver.cancel();
                    stream.socket().cancel(ec);
                    stream.socket().shutdown(tcp::socket::shutdown_both, ec);
                    stream.socket().close(ec);
                }};
                auto const results = resolver.resolve(endpoint->host, endpoint->port);
                stream.expires_after(http_config_.timeout);
                stream.connect(results);

                http::request<http::vector_body<uint8_t>> req{http::verb::post, path, 11};
                req.set(http::field::host, endpoint->host);
                req.set(http::field::user_agent, "tensorcash/validationapi");
                req.set(http::field::content_type, "application/octet-stream");
                req.set(http::field::accept, "application/json");
                if (!endpoint_cfg.api_key.empty()) {
                    req.set(http::field::authorization, "Bearer " + endpoint_cfg.api_key);
                }
                req.body() = payload;
                req.prepare_payload();

                http::write(stream, req);

                boost::beast::flat_buffer buffer;
                http::response<http::string_body> res;
                http::read(stream, buffer, res);
                stream.socket().shutdown(tcp::socket::shutdown_both);
                status_code = static_cast<uint16_t>(res.result());
            } else {
                net::ssl::context ctx{net::ssl::context::tls_client};
                ctx.set_default_verify_paths();
                tcp::resolver resolver{ioc};
                boost::beast::ssl_stream<boost::beast::tcp_stream> stream{ioc, ctx};
                HttpRequestGuard request_guard{*this, [&] {
                    boost::system::error_code ec;
                    resolver.cancel();
                    auto& socket = boost::beast::get_lowest_layer(stream).socket();
                    socket.cancel(ec);
                    socket.shutdown(tcp::socket::shutdown_both, ec);
                    socket.close(ec);
                }};
                auto const results = resolver.resolve(endpoint->host, endpoint->port);
                if (!SSL_set_tlsext_host_name(stream.native_handle(), endpoint->host.c_str())) {
                    boost::system::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
                    LogError("VALIDATOR HTTP SSL error for %s: %s\n", endpoint_cfg.base_url.c_str(), ec.message());
                    queued_public_fallback = true;
                    continue;
                }
                boost::beast::get_lowest_layer(stream).expires_after(http_config_.timeout);
                boost::beast::get_lowest_layer(stream).connect(results);
                stream.handshake(net::ssl::stream_base::client);

                http::request<http::vector_body<uint8_t>> req{http::verb::post, path, 11};
                req.set(http::field::host, endpoint->host);
                req.set(http::field::user_agent, "tensorcash/validationapi");
                req.set(http::field::content_type, "application/octet-stream");
                req.set(http::field::accept, "application/json");
                if (!endpoint_cfg.api_key.empty()) {
                    req.set(http::field::authorization, "Bearer " + endpoint_cfg.api_key);
                }
                req.body() = payload;
                req.prepare_payload();

                http::write(stream, req);

                boost::beast::flat_buffer buffer;
                http::response<http::string_body> res;
                http::read(stream, buffer, res);
                boost::system::error_code ec;
                stream.shutdown(ec);
                status_code = static_cast<uint16_t>(res.result());
            }

            last_status = status_code;
            if (status_code >= 200 && status_code < 300) {
                EnqueueStatusRequest(req_id, req_type);
                // A successful submit transfers ownership to the validator.
                // Mark it pending immediately instead of waiting for the next
                // status poll; otherwise the scheduler can resend the same
                // expensive Full request during that observation gap.
                MarkHttpStatusAcceptedPending(StatusKey{req_id, req_type});
                return status_code;
            }

            queued_public_fallback = true;
            LogWarning("VALIDATOR HTTP submit returned status=%u for id=%s type=%d via %s; falling back to public status polling\n",
                       status_code, req_id.ToString(), static_cast<int>(req_type), endpoint_cfg.base_url.c_str());
        } catch (const std::exception& e) {
            queued_public_fallback = true;
            LogError("VALIDATOR HTTP submit failed via %s: %s\n", endpoint_cfg.base_url.c_str(), e.what());
        }
    }

    if (queued_public_fallback) {
        EnqueueStatusRequest(req_id, req_type);
    }
    return last_status;
}

void ValidationAPI::EnqueueStatusRequest(const uint256& req_id, const ValidationReqType& req_type)
{
    std::lock_guard<std::mutex> lock(status_queue_mutex_);
    StatusKey key{req_id, req_type};
    const uint64_t now_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
    if (status_queue_set_.insert(key).second) {
        status_queue_.push_back(key);
    }
    auto& meta = status_queue_meta_[key];
    if (meta.first_seen_ms == 0) {
        meta.first_seen_ms = now_ms;
    }
    if (meta.next_poll_ms == 0) {
        meta.next_poll_ms = now_ms;
    }
}

void ValidationAPI::ReconcileHttpStatusQueueWithTrackedRequests(uint64_t now_ms)
{
    std::vector<StatusKey> tracked;
    {
        std::shared_lock lock(requestTracker.mutex_);
        tracked.reserve(requestTracker.short_requests_.size() +
                        requestTracker.short_smell_requests_.size() +
                        requestTracker.full_requests_.size() +
                        requestTracker.challenge_requests_.size() +
                        requestTracker.model_requests_.size());
        for (const auto& entry : requestTracker.short_requests_) {
            tracked.push_back(StatusKey{entry.first, ValidationReqType::Quick});
        }
        for (const auto& entry : requestTracker.short_smell_requests_) {
            tracked.push_back(StatusKey{entry.first, ValidationReqType::Quick_Smell});
        }
        for (const auto& entry : requestTracker.full_requests_) {
            tracked.push_back(StatusKey{entry.first, ValidationReqType::Full});
        }
        for (const auto& entry : requestTracker.challenge_requests_) {
            tracked.push_back(StatusKey{entry.first, ValidationReqType::Challenge});
        }
        for (const auto& entry : requestTracker.model_requests_) {
            tracked.push_back(StatusKey{entry.first, ValidationReqType::Model});
        }
    }

    if (tracked.empty()) {
        return;
    }

    size_t repaired{0};
    {
        std::lock_guard<std::mutex> lock(status_queue_mutex_);
        for (const auto& key : tracked) {
            const bool in_queue = std::find(status_queue_.begin(), status_queue_.end(), key) != status_queue_.end();
            const bool in_set = status_queue_set_.find(key) != status_queue_set_.end();
            if (!in_set) {
                status_queue_set_.insert(key);
            }
            if (!in_queue) {
                status_queue_.push_back(key);
            }
            if (!in_set || !in_queue) {
                ++repaired;
            }

            auto& meta = status_queue_meta_[key];
            if (meta.first_seen_ms == 0) {
                meta.first_seen_ms = now_ms;
            }
            if (meta.next_poll_ms == 0) {
                meta.next_poll_ms = now_ms;
            }
        }
    }

    if (repaired > 0) {
        LogWarning("VALIDATOR HTTP status queue repaired %zu tracked request(s) before polling\n", repaired);
    }
}

ValidationResponseBehavior ValidationAPI::GettHttpStatus(uint256& req_id, ValidationReqType& req_type)
{
    const uint64_t now_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
    std::vector<StatusKey> snapshot;

    auto parse_type_name = [](const std::string& val) -> std::optional<ValidationReqType> {
        if (val == "quick") return ValidationReqType::Quick;
        if (val == "quick_smell" || val == "quick-smell") return ValidationReqType::Quick_Smell;
        if (val == "full") return ValidationReqType::Full;
        if (val == "challenge") return ValidationReqType::Challenge;
        if (val == "model") return ValidationReqType::Model;
        return std::nullopt;
    };

    auto parse_status_value = [](const std::string& val) -> std::optional<ValidationResponseValue> {
        if (val == "Quick_OK") return ValidationResponseValue::Quick_OK;
        if (val == "Quick_Fail") return ValidationResponseValue::Quick_Fail;
        if (val == "Quick_OK_Smell_OK") return ValidationResponseValue::Quick_OK_Smell_OK;
        if (val == "Quick_OK_Smell_Fail") return ValidationResponseValue::Quick_OK_Smell_Fail;
        if (val == "Quick_Fail_Smell_OK") return ValidationResponseValue::Quick_Fail_Smell_OK;
        if (val == "Quick_Fail_Smell_Fail") return ValidationResponseValue::Quick_Fail_Smell_Fail;
        if (val == "Full_Green") return ValidationResponseValue::Full_Green;
        if (val == "Full_Amber") return ValidationResponseValue::Full_Amber;
        if (val == "Full_Red") return ValidationResponseValue::Full_Red;
        // NOTE: "Failed" is deliberately NOT mapped — it is a validator-side
        // infrastructure failure, not a consensus verdict. Callers treat it as
        // retryable/pending; mapping it to Full_Red would poison the block as
        // consensus-red on an infra outage.
        if (val == "Challenge_OK") return ValidationResponseValue::Challenge_OK;
        if (val == "Challenge_Fail") return ValidationResponseValue::Challenge_Fail;
        if (val == "Model_OK") return ValidationResponseValue::Model_OK;
        if (val == "Model_Fail") return ValidationResponseValue::Model_Fail;
        // NOTE: Model_Pending_Review is deliberately NOT here — it is non-terminal
        // and must never reach SetRequestStatus. It is handled earlier in the
        // public status and batch paths as a "pending" response.
        return std::nullopt;
    };

    auto sync_pending_snapshot = [&](const UniValue& root) {
        std::unordered_set<StatusKey, StatusKeyHasher> pending_keys;
        std::unordered_set<StatusKey, StatusKeyHasher> review_pending_keys;
        const UniValue& still_pending = root.find_value("still_pending");
        if (still_pending.isArray()) {
            for (const UniValue& item : still_pending.getValues()) {
                const UniValue& hash_val = item.find_value("hash_id");
                const UniValue& type_val = item.find_value("verification_type");
                if (!hash_val.isStr() || !type_val.isStr()) {
                    continue;
                }
                auto type_opt = parse_type_name(type_val.get_str());
                if (!type_opt) {
                    continue;
                }
                auto id_opt = uint256::FromHex(hash_val.get_str());
                if (!id_opt.has_value()) {
                    id_opt = uint256::FromUserHex(hash_val.get_str());
                }
                if (!id_opt.has_value()) {
                    continue;
                }
                const StatusKey skey{*id_opt, *type_opt};
                pending_keys.insert(skey);
                // Check if this pending item is specifically in operator review
                const UniValue& state_val = item.find_value("state");
                if (state_val.isStr() && state_val.get_str() == "pending_operator_review") {
                    review_pending_keys.insert(skey);
                }
            }
        }
        for (const auto& key : snapshot) {
            if (pending_keys.count(key) > 0) {
                MarkHttpStatusAcceptedPending(key);
                if (review_pending_keys.count(key) > 0) {
                    std::lock_guard<std::mutex> lock(status_queue_mutex_);
                    model_review_pending_.insert(key);
                }
            } else {
                ClearHttpStatusAcceptedPending(key);
            }
        }
    };

    // The batch endpoint uses hyphens ("quick-smell"), the public query param uses underscores ("quick_smell")
    auto get_type_string = [](ValidationReqType type, bool use_underscore = false) -> const char* {
        switch (type) {
        case ValidationReqType::Quick: return "quick";
        case ValidationReqType::Quick_Smell: return use_underscore ? "quick_smell" : "quick-smell";
        case ValidationReqType::Full: return "full";
        case ValidationReqType::Challenge: return "challenge";
        case ValidationReqType::Model: return "model";
        default: return "unknown";
        }
    };

    auto lookup_behavior = [&](const StatusKey& item) -> ValidationResponseBehavior {
        req_id = item.id;
        req_type = item.type;
        std::shared_lock lock(requestTracker.mutex_);
        switch (item.type) {
        case ValidationReqType::Full: {
            auto it = requestTracker.full_requests_.find(item.id);
            if (it != requestTracker.full_requests_.end()) {
                return it->second.second.behavior;
            }
            break;
        }
        case ValidationReqType::Quick: {
            auto it = requestTracker.short_requests_.find(item.id);
            if (it != requestTracker.short_requests_.end()) {
                return it->second.second.behavior;
            }
            break;
        }
        case ValidationReqType::Quick_Smell: {
            auto it = requestTracker.short_smell_requests_.find(item.id);
            if (it != requestTracker.short_smell_requests_.end()) {
                return it->second.second.behavior;
            }
            break;
        }
        case ValidationReqType::Challenge: {
            auto it = requestTracker.challenge_requests_.find(item.id);
            if (it != requestTracker.challenge_requests_.end()) {
                return it->second.second.behavior;
            }
            break;
        }
        case ValidationReqType::Model:
            return ValidationResponseBehavior::Nothing;
        }
        return ValidationResponseBehavior::Unknown;
    };

    auto poll_public_with_backoff = [&]() -> ValidationResponseBehavior {
        // ── Public endpoint fallback (no API key) ──
        // Poll individual /v1/public/status/{hash_id} endpoints instead of
        // the authenticated batch endpoint. Process exactly one queued item per
        // cycle so a single permanent NAN does not poison the whole queue.
        const auto err_bo = public_error_backoff_ms_.load();
        if (err_bo > 0) {
            const auto last_pub = static_cast<uint64_t>(last_public_poll_ms_.load());
            if (last_pub > 0 && (now_ms - last_pub) < static_cast<uint64_t>(err_bo)) {
                return ValidationResponseBehavior::Unknown;
            }
        }

        std::optional<StatusKey> selected_item;
        std::vector<StatusKey> expired_items;
        {
            std::lock_guard<std::mutex> lock(status_queue_mutex_);
            size_t remaining = status_queue_.size();
            while (remaining-- > 0) {
                const StatusKey item = status_queue_.front();
                status_queue_.pop_front();

                auto& meta = status_queue_meta_[item];
                if (meta.first_seen_ms == 0) {
                    meta.first_seen_ms = now_ms;
                }
                if (meta.next_poll_ms == 0) {
                    meta.next_poll_ms = now_ms;
                }

                const bool expired_age = now_ms >= meta.first_seen_ms &&
                    (now_ms - meta.first_seen_ms) >= HttpPublicNanMaxAgeMs(item.type);
                const bool expired_misses = meta.nan_miss_count >= HttpPublicNanMaxPolls(item.type);
                if (expired_age || expired_misses) {
                    status_queue_set_.erase(item);
                    http_status_accepted_pending_.erase(item);
                    http_status_accepted_pending_since_.erase(item);
                    status_queue_meta_.erase(item);
                    expired_items.push_back(item);
                    continue;
                }

                if (meta.next_poll_ms > now_ms) {
                    status_queue_.push_back(item);
                    continue;
                }

                selected_item = item;
                break;
            }
        }

        for (const auto& item : expired_items) {
            LogWarning("VALIDATOR HTTP public status: dropping stale NAN request id=%s type=%d after repeated cache misses\n",
                       item.id.ToString().c_str(), static_cast<int>(item.type));
        }

        if (!selected_item.has_value()) {
            return ValidationResponseBehavior::Unknown;
        }

        const StatusKey item = *selected_item;
        ValidationResponseValue cur;
        if (GetRequestStatusImpl(item.id, item.type, cur)) {
            ClearStatusQueueEntry(item);
            public_error_backoff_ms_.store(0);
            return lookup_behavior(item);
        }

        enum class PublicOutcome { terminal, nan_miss, rate_limited, transport_error };
        PublicOutcome outcome = PublicOutcome::nan_miss;
        last_public_poll_ms_.store(now_ms);

        auto handle_public_result = [&](const std::string& body) -> ValidationResponseBehavior {
            UniValue root;
            if (!root.read(body)) {
                outcome = PublicOutcome::transport_error;
                return ValidationResponseBehavior::Unknown;
            }

            const UniValue& status_val = root.find_value("status");
            if (!status_val.isStr() || status_val.get_str() == "NAN") {
                return ValidationResponseBehavior::Unknown;
            }

            // Handle non-terminal "pending" and "Model_Pending_Review" responses.
            // These must NOT reach parse_status_value/SetRequestStatus — they are
            // not terminal and would permanently poison the status if stored.
            const std::string& status_str = status_val.get_str();
            if (status_str == "pending" || status_str == "Model_Pending_Review") {
                const UniValue& state_val = root.find_value("state");
                const bool is_review = (status_str == "Model_Pending_Review") ||
                                       (state_val.isStr() && state_val.get_str() == "pending_operator_review");
                MarkHttpStatusAcceptedPending(item);
                if (is_review) {
                    std::lock_guard<std::mutex> lock(status_queue_mutex_);
                    model_review_pending_.insert(item);
                }
                // Reset NAN miss counter — this is a valid response, just not terminal.
                // Set next poll 10s out to avoid hammering during review.
                {
                    std::lock_guard<std::mutex> lock(status_queue_mutex_);
                    auto& meta = status_queue_meta_[item];
                    meta.nan_miss_count = 0;
                    meta.next_poll_ms = now_ms + 10000;
                    status_queue_.push_back(item);
                }
                public_error_backoff_ms_.store(0);
                return ValidationResponseBehavior::Unknown;
            }

            if (status_str == "Failed") {
                // Validator-side infrastructure failure, not a consensus
                // verdict. Leave outcome as nan_miss so the normal
                // backoff/eviction ladder applies and the request stays
                // deferred for future retries instead of storing Full_Red.
                LogWarning("VALIDATOR HTTP public status: id=%s type=%d reported Failed (infra); treating as retryable, not consensus-red\n",
                           item.id.ToString().c_str(), static_cast<int>(item.type));
                return ValidationResponseBehavior::Unknown;
            }

            auto status_opt = parse_status_value(status_str);
            if (!status_opt) {
                outcome = PublicOutcome::transport_error;
                return ValidationResponseBehavior::Unknown;
            }
            if (!StatusMatchesRequestedType(*status_opt, item.type)) {
                // Wrong-family terminal for this request type: do not store it
                // and do not clear the queue entry. Leave outcome as nan_miss
                // so the per-item backoff/eviction ladder bounds the retries.
                LogDebug(BCLog::VALIDATION,
                         "VALIDATOR HTTP public status ignoring status %s incompatible with type=%d for id=%s\n",
                         status_str.c_str(), static_cast<int>(item.type), item.id.ToString().c_str());
                return ValidationResponseBehavior::Unknown;
            }

            // Terminal response — clear any review-pending state for this item
            {
                std::lock_guard<std::mutex> lock(status_queue_mutex_);
                model_review_pending_.erase(item);
            }

            req_id = item.id;
            req_type = item.type;
            const bool inserted = SetRequestStatus(req_id, req_type, *status_opt);
            outcome = PublicOutcome::terminal;
            ClearStatusQueueEntry(item);
            if (!inserted && !GetRequestStatusImpl(req_id, req_type, cur)) {
                return ValidationResponseBehavior::Unknown;
            }
            public_error_backoff_ms_.store(0);
            return lookup_behavior(item);
        };

        try {
            namespace http = boost::beast::http;
            namespace net = boost::asio;
            using tcp = net::ip::tcp;

            for (const auto& base_url : http_config_.base_urls) {
                const auto endpoint = ParseHttpBaseUrl(base_url);
                if (!endpoint.has_value()) {
                    LogError("VALIDATOR HTTP public status skipped invalid base URL: %s\n", base_url.c_str());
                    outcome = PublicOutcome::transport_error;
                    continue;
                }

                const std::string path = (endpoint->base_path.empty() ? "" : endpoint->base_path) +
                    "/v1/public/status/" + item.id.ToString() +
                    "?verification_type=" + get_type_string(item.type, /*use_underscore=*/true);

                std::string body;
                net::io_context ioc;
                if (endpoint->scheme == "http") {
                    tcp::resolver resolver{ioc};
                    boost::beast::tcp_stream stream{ioc};
                    HttpRequestGuard request_guard{*this, [&] {
                        boost::system::error_code ec;
                        resolver.cancel();
                        stream.socket().cancel(ec);
                        stream.socket().shutdown(tcp::socket::shutdown_both, ec);
                        stream.socket().close(ec);
                    }};
                    auto const results = resolver.resolve(endpoint->host, endpoint->port);
                    stream.expires_after(http_config_.timeout);
                    stream.connect(results);

                    http::request<http::string_body> req_msg{http::verb::get, path, 11};
                    req_msg.set(http::field::host, endpoint->host);
                    req_msg.set(http::field::user_agent, "tensorcash/validationapi");
                    http::write(stream, req_msg);

                    boost::beast::flat_buffer buffer;
                    http::response<http::string_body> res;
                    http::read(stream, buffer, res);
                    stream.socket().shutdown(tcp::socket::shutdown_both);
                    const auto status_code = res.result_int();
                    if (status_code == 429 || status_code == 403) {
                        LogWarning("VALIDATOR HTTP public status: rate limited (%u) by %s, trying next URL\n",
                                   status_code, base_url.c_str());
                        outcome = PublicOutcome::rate_limited;
                        continue;
                    }
                    body = res.body();
                } else {
                    net::ssl::context ctx{net::ssl::context::tls_client};
                    ctx.set_default_verify_paths();
                    tcp::resolver resolver{ioc};
                    boost::beast::ssl_stream<boost::beast::tcp_stream> stream{ioc, ctx};
                    HttpRequestGuard request_guard{*this, [&] {
                        boost::system::error_code ec;
                        resolver.cancel();
                        auto& socket = boost::beast::get_lowest_layer(stream).socket();
                        socket.cancel(ec);
                        socket.shutdown(tcp::socket::shutdown_both, ec);
                        socket.close(ec);
                    }};
                    auto const results = resolver.resolve(endpoint->host, endpoint->port);
                    if (!SSL_set_tlsext_host_name(stream.native_handle(), endpoint->host.c_str())) {
                        outcome = PublicOutcome::transport_error;
                        continue;
                    }
                    boost::beast::get_lowest_layer(stream).expires_after(http_config_.timeout);
                    boost::beast::get_lowest_layer(stream).connect(results);
                    stream.handshake(net::ssl::stream_base::client);

                    http::request<http::string_body> req_msg{http::verb::get, path, 11};
                    req_msg.set(http::field::host, endpoint->host);
                    req_msg.set(http::field::user_agent, "tensorcash/validationapi");
                    http::write(stream, req_msg);

                    boost::beast::flat_buffer buffer;
                    http::response<http::string_body> res;
                    http::read(stream, buffer, res);
                    boost::system::error_code ec;
                    stream.shutdown(ec);
                    const auto status_code = res.result_int();
                    if (status_code == 429 || status_code == 403) {
                        LogWarning("VALIDATOR HTTP public status: rate limited (%u) by %s, trying next URL\n",
                                   status_code, base_url.c_str());
                        outcome = PublicOutcome::rate_limited;
                        continue;
                    }
                    body = res.body();
                }

                auto behavior = handle_public_result(body);
                if (outcome == PublicOutcome::terminal) {
                    return behavior;
                }
            }
        } catch (const std::exception& e) {
            LogError("VALIDATOR HTTP public status request failed: %s\n", e.what());
            outcome = PublicOutcome::transport_error;
        }

        uint64_t retry_delay_ms{0};
        bool dropped = false;
        {
            std::lock_guard<std::mutex> lock(status_queue_mutex_);
            auto meta_it = status_queue_meta_.find(item);
            if (meta_it == status_queue_meta_.end()) {
                status_queue_meta_[item] = StatusQueueMeta{now_ms, now_ms, 0, 0};
                meta_it = status_queue_meta_.find(item);
            }
            auto& meta = meta_it->second;
            if (meta.first_seen_ms == 0) {
                meta.first_seen_ms = now_ms;
            }

            switch (outcome) {
            case PublicOutcome::nan_miss: {
                meta.nan_miss_count = std::min<uint16_t>(meta.nan_miss_count + 1, std::numeric_limits<uint16_t>::max());
                meta.nan_backoff_ms = meta.nan_backoff_ms == 0
                    ? HTTP_PUBLIC_NAN_INITIAL_BACKOFF_MS
                    : std::min<uint64_t>(meta.nan_backoff_ms * 2, HTTP_PUBLIC_NAN_MAX_BACKOFF_MS);
                retry_delay_ms = meta.nan_backoff_ms;
                const bool expired_age = now_ms >= meta.first_seen_ms &&
                    (now_ms - meta.first_seen_ms) >= HttpPublicNanMaxAgeMs(item.type);
                const bool expired_misses = meta.nan_miss_count >= HttpPublicNanMaxPolls(item.type);
                if (expired_age || expired_misses) {
                    status_queue_set_.erase(item);
                    http_status_accepted_pending_.erase(item);
                    http_status_accepted_pending_since_.erase(item);
                    status_queue_meta_.erase(item);
                    dropped = true;
                    break;
                }
                break;
            }
            case PublicOutcome::rate_limited: {
                auto cur_bo = public_error_backoff_ms_.load();
                cur_bo = (cur_bo == 0) ? 1000 : std::min<int64_t>(cur_bo * 2, 10000);
                public_error_backoff_ms_.store(cur_bo);
                retry_delay_ms = static_cast<uint64_t>(cur_bo);
                break;
            }
            case PublicOutcome::transport_error: {
                auto cur_bo = public_error_backoff_ms_.load();
                cur_bo = (cur_bo == 0) ? 500 : std::min<int64_t>(cur_bo * 2, 10000);
                public_error_backoff_ms_.store(cur_bo);
                retry_delay_ms = static_cast<uint64_t>(cur_bo);
                break;
            }
            case PublicOutcome::terminal:
                break;
            }

            if (!dropped) {
                meta.next_poll_ms = now_ms + retry_delay_ms;
                status_queue_.push_back(item);
            }
        }

        if (dropped) {
            LogWarning("VALIDATOR HTTP public status: evicting id=%s type=%d after repeated NAN responses; request remains deferred for future retries\n",
                       item.id.ToString().c_str(), static_cast<int>(item.type));
        }
        return ValidationResponseBehavior::Unknown;
    };

    ReconcileHttpStatusQueueWithTrackedRequests(now_ms);

    if (!HasHttpApiKey()) {
        return poll_public_with_backoff();
    }

    {
        std::lock_guard<std::mutex> lock(status_queue_mutex_);
        if (status_queue_.empty()) {
            return ValidationResponseBehavior::Unknown;
        }
        snapshot.assign(status_queue_.begin(), status_queue_.end());
    }

    std::string json = "{\"items\":[";
    for (size_t i = 0; i < snapshot.size(); ++i) {
        const auto& item = snapshot[i];
        if (i != 0) {
            json += ",";
        }
        const char* verification_type = get_type_string(item.type);
        json += "{\"hash_id\":\"";
        json += item.id.ToString();
        json += "\",\"verification_type\":\"";
        json += verification_type;
        json += "\"}";
    }
    json += "],\"wait_ms\":1000}";

    namespace http = boost::beast::http;
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    auto handle_batch_body = [&](const std::string& body,
                                 const std::string& base_url,
                                 int status_code) -> std::optional<ValidationResponseBehavior> {
        UniValue root;
        if (!root.read(body)) {
            LogError("VALIDATOR HTTP status batch parse failed (HTTP %u via %s, body_size=%zu, body_preview=%.200s)\n",
                     status_code, base_url.c_str(), body.size(), body.c_str());
            return std::nullopt;
        }
        sync_pending_snapshot(root);
        const UniValue& completed = root.find_value("completed");
        if (!completed.isArray() || completed.empty()) {
            return ValidationResponseBehavior::Unknown;
        }
        const UniValue& still_pending = root.find_value("still_pending");
        const size_t still_pending_count = still_pending.isArray() ? still_pending.getValues().size() : 0;
        LogPrintf("VALIDATOR HTTP status batch completed=%zu still_pending=%zu snapshot=%zu via %s\n",
                  completed.getValues().size(), still_pending_count, snapshot.size(), base_url.c_str());

        // Entries the server reports as completed but that we refuse to store
        // (infra "Failed", wrong-family statuses, unrequested keys). If the
        // batch yields nothing else, returning nullopt lets the caller
        // escalate the auth error backoff instead of resetting it — otherwise
        // a persistently bad entry re-polls at the receiver loop's 50ms
        // cadence forever.
        bool saw_retryable = false;
        // Only accept terminals for {hash_id, verification_type} keys we
        // actually asked about in this batch: type_opt comes from the server
        // response, so a buggy/stale server could otherwise answer a different
        // type for the same hash (e.g. we asked {hash, quick-smell}, it
        // answers {hash, full, Full_Green}) and pass the family gate.
        const std::unordered_set<StatusKey, StatusKeyHasher> snapshot_keys(snapshot.begin(), snapshot.end());
        for (const UniValue& item : completed.getValues()) {
            const UniValue& hash_val = item.find_value("hash_id");
            const UniValue& type_val = item.find_value("verification_type");
            const UniValue& status_val = item.find_value("status");
            if (!hash_val.isStr() || !type_val.isStr() || !status_val.isStr()) {
                continue;
            }

            const auto type_opt = parse_type_name(type_val.get_str());
            if (status_val.get_str() == "Failed") {
                LogWarning("VALIDATOR HTTP status batch: id=%s type=%s reported Failed (infra); treating as retryable, not consensus-red\n",
                           hash_val.get_str().c_str(), type_val.get_str().c_str());
                saw_retryable = true;
                continue;
            }
            const auto status_opt = parse_status_value(status_val.get_str());
            if (!type_opt || !status_opt) {
                continue;
            }
            if (!StatusMatchesRequestedType(*status_opt, *type_opt)) {
                LogDebug(BCLog::VALIDATION,
                         "VALIDATOR HTTP status batch ignoring status %s incompatible with type=%s for id=%s\n",
                         status_val.get_str().c_str(), type_val.get_str().c_str(), hash_val.get_str().c_str());
                saw_retryable = true;
                continue;
            }

            auto id_opt = uint256::FromHex(hash_val.get_str());
            if (!id_opt.has_value()) {
                id_opt = uint256::FromUserHex(hash_val.get_str());
            }
            if (!id_opt.has_value()) {
                continue;
            }

            const StatusKey key{*id_opt, *type_opt};
            if (snapshot_keys.count(key) == 0) {
                LogWarning("VALIDATOR HTTP status batch ignoring unrequested completed entry id=%s type=%s status=%s via %s\n",
                           hash_val.get_str().c_str(), type_val.get_str().c_str(),
                           status_val.get_str().c_str(), base_url.c_str());
                saw_retryable = true;
                continue;
            }
            req_id = *id_opt;
            req_type = *type_opt;

            // Terminal response — clear any review-pending state
            {
                std::lock_guard<std::mutex> lock(status_queue_mutex_);
                model_review_pending_.erase(key);
            }

            ValidationResponseValue cur;
            const bool inserted = SetRequestStatus(req_id, req_type, *status_opt);
            if (!inserted && !GetRequestStatusImpl(req_id, req_type, cur)) {
                LogWarning("VALIDATOR HTTP status batch could not store terminal id=%s type=%d status=%s inserted=%d via %s; continuing batch\n",
                           req_id.ToString().c_str(), static_cast<int>(req_type), status_val.get_str().c_str(),
                           inserted ? 1 : 0, base_url.c_str());
                continue;
            }
            const ValidationResponseBehavior behavior = lookup_behavior(key);
            LogPrintf("VALIDATOR HTTP status batch terminal id=%s type=%d status=%s inserted=%d behavior=%d via %s\n",
                      req_id.ToString().c_str(), static_cast<int>(req_type), status_val.get_str().c_str(),
                      inserted ? 1 : 0, static_cast<int>(behavior), base_url.c_str());
            ClearStatusQueueEntry(key);
            if (behavior == ValidationResponseBehavior::Unknown) {
                LogWarning("VALIDATOR HTTP status batch terminal id=%s type=%d had no tracked request behavior; continuing batch\n",
                           req_id.ToString().c_str(), static_cast<int>(req_type));
                continue;
            }
            return behavior;
        }

        if (saw_retryable) {
            // Nothing usable came out of this batch and at least one entry was
            // a refused terminal — signal failure so the caller escalates the
            // auth backoff (500ms→10s) instead of resetting it to 0.
            return std::nullopt;
        }
        return ValidationResponseBehavior::Unknown;
    };

    // ── Auth batch error backoff ──
    // If all auth endpoints fast-failed last time, back off before retrying
    // so we don't hammer at 50ms intervals on a sick service.
    {
        const auto auth_backoff = auth_batch_error_backoff_ms_.load();
        if (auth_backoff > 0) {
            const auto last_err = static_cast<uint64_t>(last_auth_batch_error_ms_.load());
            if (last_err > 0 && (now_ms - last_err) < static_cast<uint64_t>(auth_backoff)) {
                return poll_public_with_backoff();
            }
        }
    }

    for (const auto& endpoint_cfg : http_config_.endpoints) {
        if (endpoint_cfg.api_key.empty()) {
            LogWarning("VALIDATOR HTTP status batch skipped %s because no API key is configured for that endpoint\n",
                       endpoint_cfg.base_url.c_str());
            continue;
        }

        const auto endpoint = ParseHttpBaseUrl(endpoint_cfg.base_url);
        if (!endpoint.has_value()) {
            LogError("VALIDATOR HTTP status batch skipped invalid base URL: %s\n", endpoint_cfg.base_url.c_str());
            continue;
        }

        const std::string path = (endpoint->base_path.empty() ? "" : endpoint->base_path) + "/v1/verify/status/batch";

        try {
            net::io_context ioc;
            if (endpoint->scheme == "http") {
                tcp::resolver resolver{ioc};
                boost::beast::tcp_stream stream{ioc};
                HttpRequestGuard request_guard{*this, [&] {
                    boost::system::error_code ec;
                    resolver.cancel();
                    stream.socket().cancel(ec);
                    stream.socket().shutdown(tcp::socket::shutdown_both, ec);
                    stream.socket().close(ec);
                }};
                auto const results = resolver.resolve(endpoint->host, endpoint->port);
                stream.expires_after(http_config_.timeout);
                stream.connect(results);

                http::request<http::string_body> req{http::verb::post, path, 11};
                req.set(http::field::host, endpoint->host);
                req.set(http::field::user_agent, "tensorcash/validationapi");
                req.set(http::field::content_type, "application/json");
                req.set(http::field::authorization, "Bearer " + endpoint_cfg.api_key);
                req.body() = json;
                req.prepare_payload();

                http::write(stream, req);

                boost::beast::flat_buffer buffer;
                http::response<http::string_body> res;
                http::read(stream, buffer, res);
                stream.socket().shutdown(tcp::socket::shutdown_both);

                const int status_code = res.result_int();
                if (status_code < 200 || status_code >= 300) {
                    if (status_code == 401 || status_code == 403) {
                        LogWarning("VALIDATOR HTTP status batch returned HTTP %u via %s; stopping authenticated failover and falling back to public status polling\n",
                                   status_code, endpoint_cfg.base_url.c_str());
                        break;
                    }
                    LogWarning("VALIDATOR HTTP status batch returned HTTP %u via %s; trying next endpoint\n",
                               status_code, endpoint_cfg.base_url.c_str());
                    continue;
                }

                if (auto behavior = handle_batch_body(res.body(), endpoint_cfg.base_url, status_code)) {
                    auth_batch_error_backoff_ms_.store(0);
                    return *behavior;
                }
                continue;
            }

            net::ssl::context ctx{net::ssl::context::tls_client};
            ctx.set_default_verify_paths();
            tcp::resolver resolver{ioc};
            boost::beast::ssl_stream<boost::beast::tcp_stream> stream{ioc, ctx};
            HttpRequestGuard request_guard{*this, [&] {
                boost::system::error_code ec;
                resolver.cancel();
                auto& socket = boost::beast::get_lowest_layer(stream).socket();
                socket.cancel(ec);
                socket.shutdown(tcp::socket::shutdown_both, ec);
                socket.close(ec);
            }};
            auto const results = resolver.resolve(endpoint->host, endpoint->port);
            if (!SSL_set_tlsext_host_name(stream.native_handle(), endpoint->host.c_str())) {
                boost::system::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
                LogError("VALIDATOR HTTP SSL error for %s: %s\n", endpoint_cfg.base_url.c_str(), ec.message());
                continue;
            }
            boost::beast::get_lowest_layer(stream).expires_after(http_config_.timeout);
            boost::beast::get_lowest_layer(stream).connect(results);
            stream.handshake(net::ssl::stream_base::client);

            http::request<http::string_body> req{http::verb::post, path, 11};
            req.set(http::field::host, endpoint->host);
            req.set(http::field::user_agent, "tensorcash/validationapi");
            req.set(http::field::content_type, "application/json");
            req.set(http::field::authorization, "Bearer " + endpoint_cfg.api_key);
            req.body() = json;
            req.prepare_payload();

            http::write(stream, req);

            boost::beast::flat_buffer buffer;
            http::response<http::string_body> res;
            http::read(stream, buffer, res);
            boost::system::error_code ec;
            stream.shutdown(ec);

            const int status_code = res.result_int();
            if (status_code < 200 || status_code >= 300) {
                if (status_code == 401 || status_code == 403) {
                    LogWarning("VALIDATOR HTTPS status batch returned HTTP %u via %s; stopping authenticated failover and falling back to public status polling\n",
                               status_code, endpoint_cfg.base_url.c_str());
                    break;
                }
                LogWarning("VALIDATOR HTTPS status batch returned HTTP %u via %s; trying next endpoint\n",
                           status_code, endpoint_cfg.base_url.c_str());
                continue;
            }

            if (auto behavior = handle_batch_body(res.body(), endpoint_cfg.base_url, status_code)) {
                auth_batch_error_backoff_ms_.store(0);
                return *behavior;
            }
        } catch (const std::exception& e) {
            LogError("VALIDATOR HTTP status request failed via %s: %s\n", endpoint_cfg.base_url.c_str(), e.what());
        }
    }

    // All auth endpoints failed — escalate backoff so we don't retry at 50ms
    {
        auto cur = auth_batch_error_backoff_ms_.load();
        cur = (cur == 0) ? 500 : std::min(cur * 2, (int64_t)10000);
        auth_batch_error_backoff_ms_.store(cur);
        last_auth_batch_error_ms_.store(now_ms);
    }

    return poll_public_with_backoff();
}

void ValidationAPI::JobSchedulerLoop() {
    
    uint64_t lastHealthCheck = 0;
    uint64_t now = 0;
    
    LogPrintf("VALIDATOR: JobSchedulerLoop thread was started\n");

    while (m_on && !m_chainman.m_interrupt) {
        now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        if (!m_http_mode) {
            if (now - lastHealthCheck > 60000) {
                int opt = 0;
                size_t opt_len = sizeof(opt);
                if (zmq_getsockopt(reqPush, ZMQ_EVENTS, &opt, &opt_len) < 0) {
                    LogError("VALIDATOR: Socket health check failed\n");
                }
                lastHealthCheck = now;
            }
        }

        // ── Phase 1: inspect queues under lock, build action lists ──────
        // Deferred actions that require blocking I/O (HTTP sends) or heavy
        // work are collected here and executed OUTSIDE the lock so the
        // SolutionReceiverLoop is never starved.

        struct SendAction { uint256 id; CBlock block; ValidationReqType type; };
        struct ModelSendAction { uint256 id; ModelRecord model; };
        struct LocalQuickAction { uint256 id; CBlock block; ValidationReqType origin_type; };
        struct DefaultAction { uint256 id; ValidationReqType type; ValidationResponseValue status; };
        struct AmberAction { uint256 id; CBlock block; ValidationResponseBehavior behavior; };

        std::vector<SendAction> to_send;
        std::vector<ModelSendAction> to_model_send;
        std::vector<LocalQuickAction> to_local_quick;
        std::vector<DefaultAction> to_default;
        std::vector<AmberAction> to_amber;
        auto should_snooze_http_pending = [&](const uint256& id, const ValidationReqType type) {
            if (!UseHttpTransport() || !IsHttpStatusAcceptedPending(id, type)) {
                return false;
            }
            if (IsHttpStatusAcceptedPendingStale(id, type)) {
                LogWarning("VALIDATOR HTTP status pending expired for %s type=%d after %llums; resuming retries\n",
                           id.ToString().c_str(),
                           static_cast<int>(type),
                           static_cast<unsigned long long>(HttpPendingMaxAgeMs(type)));
                ClearHttpStatusAcceptedPending(StatusKey{id, type});
                return false;
            }
            return true;
        };

        {
            std::unique_lock lock(requestTracker.mutex_);

            // ── Quick requests ──
            for (auto it = requestTracker.short_requests_.begin(); it != requestTracker.short_requests_.end();)
            {
                if (it->second.second.readyToUpdate(now))
                {
                    ValidationResponseValue cur;
                    StatusKey key{it->first, ValidationReqType::Quick};
                    if (GetRequestStatusImpl(it->first, ValidationReqType::Quick, cur)) {
                        if (m_http_mode) {
                            ClearStatusQueueEntry(key);
                        }
                        it = requestTracker.short_requests_.erase(it);
                        continue;
                    }
                    if (UseLocalQuick()) {
                        to_local_quick.push_back({it->first, it->second.first, ValidationReqType::Quick});
                        it++;
                        continue;
                    }
                    // Check pending guard BEFORE burning an attempt
                    if (should_snooze_http_pending(it->first, ValidationReqType::Quick)) {
                        it->second.second.snooze(now);
                        it++;
                    }
                    else if (it->second.second.canAttempt()) {
                        to_send.push_back({it->first, it->second.first, ValidationReqType::Quick});
                        it->second.second.snooze(now); // claim: prevent re-pick next iteration
                        it++;
                    }
                    else {
                        to_default.push_back({it->first, ValidationReqType::Quick, ValidationResponseValue::Quick_Fail});
                        it++;
                    }
                }
                else
                    it++;
            }

            // ── Quick_Smell requests ──
            for (auto it = requestTracker.short_smell_requests_.begin(); it != requestTracker.short_smell_requests_.end();)
            {
                if (it->second.second.readyToUpdate(now))
                {
                    ValidationResponseValue cur;
                    if (GetRequestStatusImpl(it->first, ValidationReqType::Quick_Smell, cur)) {
                        if (m_http_mode) {
                            StatusKey key{it->first, ValidationReqType::Quick_Smell};
                            ClearStatusQueueEntry(key);
                        }
                        it = requestTracker.short_smell_requests_.erase(it);
                        continue;
                    }
                    if (should_snooze_http_pending(it->first, ValidationReqType::Quick_Smell)) {
                        it->second.second.snooze(now);
                        it++;
                    }
                    else if (it->second.second.canAttempt()) {
                        to_send.push_back({it->first, it->second.first, ValidationReqType::Quick_Smell});
                        it->second.second.snooze(now);
                        it++;
                    }
                    else {
                        // Retry exhaustion — run local QuickVerifier as fallback.
                        // Only fail the block if local quick also fails; otherwise
                        // keep retrying (the remote validator may catch up).
                        if (UseLocalQuick()) {
                            to_local_quick.push_back({it->first, it->second.first, ValidationReqType::Quick_Smell});
                            it++;
                        } else {
                            to_default.push_back({it->first, ValidationReqType::Quick_Smell, ValidationResponseValue::Quick_Fail_Smell_Fail});
                            it++;
                        }
                    }
                }
                else
                    it++;
            }

            // ── Full requests ──
            // Full requests stay in the queue — receiver's finishRequest() is
            // the real cleanup path. The it++ on status-found is intentional.
            for (auto it = requestTracker.full_requests_.begin(); it != requestTracker.full_requests_.end();)
            {
                if (it->second.second.readyToUpdate(now))
                {
                    ValidationResponseValue cur;
                    if (GetRequestStatusImpl(it->first, ValidationReqType::Full, cur)) {
                        if (m_http_mode) {
                            StatusKey key{it->first, ValidationReqType::Full};
                            ClearHttpStatusAcceptedPending(key);
                        }
                        it++;
                        continue;
                    }

                    if (should_snooze_http_pending(it->first, ValidationReqType::Full)) {
                        it->second.second.snooze(now);
                        it++;
                    }
                    else if (it->second.second.canAttempt()) {
                        to_send.push_back({it->first, it->second.first, ValidationReqType::Full});
                        it->second.second.snooze(now);
                        it++;
                    }
                    else {
                        if (ShouldDeferMissingFullValidation()) {
                            LogPrintf("VALIDATOR: Full %s still unresolved in public-status mode; recycling retry budget\n",
                                      it->first.ToString());
                            it->second.second = RequestTracker::LiveMeter(ValidationReqType::Full, it->second.second.behavior);
                            it->second.second.snooze(now);
                        } else {
                            to_amber.push_back({it->first, it->second.first, it->second.second.behavior});
                        }
                        it++;
                    }
                }
                else
                    it++;
            }

            // ── Challenge requests ──
            for (auto it = requestTracker.challenge_requests_.begin(); it != requestTracker.challenge_requests_.end();)
            {
                if (it->second.second.readyToUpdate(now))
                {
                    ValidationResponseValue cur;
                    if (GetRequestStatusImpl(it->first, ValidationReqType::Challenge, cur)) {
                        if (m_http_mode) {
                            StatusKey key{it->first, ValidationReqType::Challenge};
                            ClearStatusQueueEntry(key);
                        }
                        ClearOperatorReviewPending(it->first, ValidationReqType::Challenge);
                        it = requestTracker.challenge_requests_.erase(it);
                        continue;
                    }

                    // Challenge under operator review — snooze with fixed 30s interval,
                    // don't burn retry attempts. Re-send to poll for a decision.
                    if (IsOperatorReviewPending(it->first, ValidationReqType::Challenge)) {
                        to_send.push_back({it->first, it->second.first, ValidationReqType::Challenge});
                        it->second.second.attempt_time = now;
                        it->second.second.delay = 30000;  // Fixed 30s re-poll
                        it++;
                        continue;
                    }

                    if (should_snooze_http_pending(it->first, ValidationReqType::Challenge)) {
                        it->second.second.snooze(now);
                        it++;
                    }
                    else if (it->second.second.canAttempt()) {
                        to_send.push_back({it->first, it->second.first, ValidationReqType::Challenge});
                        it->second.second.snooze(now);
                        it++;
                    }
                    else {
                        to_default.push_back({it->first, ValidationReqType::Challenge, ValidationResponseValue::Challenge_Fail});
                        it++;
                    }
                }
                else
                    it++;
            }

            // ── Model requests ──
            for (auto it = requestTracker.model_requests_.begin(); it != requestTracker.model_requests_.end();)
            {
                if (it->second.second.readyToUpdate(now))
                {
                    ValidationResponseValue cur;
                    if (GetRequestStatusImpl(it->first, ValidationReqType::Model, cur)) {
                        if (m_http_mode) {
                            StatusKey key{it->first, ValidationReqType::Model};
                            ClearStatusQueueEntry(key);
                        }
                        ClearModelReviewPending(it->first);
                        it = requestTracker.model_requests_.erase(it);
                        continue;
                    }

                    // Model under operator review — snooze with fixed 30s interval,
                    // don't burn retry attempts. Re-send to poll for a decision.
                    if (IsModelReviewPending(it->first)) {
                        to_model_send.push_back({it->first, it->second.first});
                        it->second.second.attempt_time = now;
                        it->second.second.delay = 30000;  // Fixed 30s re-poll
                        it++;
                        continue;
                    }

                    if (should_snooze_http_pending(it->first, ValidationReqType::Model)) {
                        it->second.second.snooze(now);
                        it++;
                    }
                    else if (it->second.second.canAttempt()) {
                        to_model_send.push_back({it->first, it->second.first});
                        it->second.second.snooze(now);
                        it++;
                    }
                    else {
                        to_default.push_back({it->first, ValidationReqType::Model, ValidationResponseValue::Model_Fail});
                        it++;
                    }
                }
                else
                    it++;
            }
        } // ── lock released ──

        // ── Phase 2: execute deferred actions without holding the lock ──
        // Re-check status before each action to avoid overwriting a real
        // result that the receiver wrote while we were outside the lock.

        for (const auto& action : to_local_quick) {
            ValidationResponseValue cur;
            if (GetRequestStatusImpl(action.id, action.origin_type, cur)) {
                // Real result arrived in the gap — skip local exec
                requestTracker.finishRequest(action.id, action.origin_type);
                continue;
            }
            auto status = RunLocalQuick(action.block);

            if (action.origin_type == ValidationReqType::Quick_Smell) {
                // Quick_Smell fallback: local quick can only do Quick-level check.
                // If local quick PASSES → block is likely valid, keep retrying
                // remote validator (infinite loop) so we eventually get a real
                // Quick_Smell result. If local quick FAILS → block is bad, fail it.
                if (status == ValidationResponseValue::Quick_Fail_Smell_Fail ||
                    status == ValidationResponseValue::Quick_Fail) {
                    LogWarning("VALIDATOR: Local QuickVerifier FAILED for %s — failing block\n",
                              action.id.ToString().c_str());
                    SetRequestStatus(action.id, ValidationReqType::Quick_Smell,
                                     ValidationResponseValue::Quick_Fail_Smell_Fail);
                    if (m_http_mode) {
                        ClearStatusQueueEntry(StatusKey{action.id, ValidationReqType::Quick_Smell});
                    }
                    requestTracker.finishRequest(action.id, ValidationReqType::Quick_Smell);
                } else {
                    // Local quick passed — block looks valid. Re-enqueue for
                    // remote Quick_Smell with fresh retry budget.
                    LogPrintf("VALIDATOR: Local QuickVerifier PASSED for %s — "
                              "re-enqueueing Quick_Smell for remote validation\n",
                              action.id.ToString().c_str());
                    std::unique_lock lock(requestTracker.mutex_);
                    auto it = requestTracker.short_smell_requests_.find(action.id);
                    if (it != requestTracker.short_smell_requests_.end()) {
                        it->second.second = RequestTracker::LiveMeter(ValidationReqType::Quick_Smell, it->second.second.behavior);
                    }
                }
            } else {
                // Original Quick path — finish immediately with local result
                SetRequestStatus(action.id, ValidationReqType::Quick, status);
                if (m_http_mode) {
                    ClearStatusQueueEntry(StatusKey{action.id, ValidationReqType::Quick});
                }
                requestTracker.finishRequest(action.id, ValidationReqType::Quick);
            }
        }

        for (const auto& action : to_send) {
            // If result arrived while we were outside the lock, skip the send
            ValidationResponseValue cur;
            if (!GetRequestStatusImpl(action.id, action.type, cur)) {
                SendApiRequest(action.id, action.block, action.type);
                // Commit the attempt now that we actually sent
                std::unique_lock lock(requestTracker.mutex_);
                auto* map = action.type == ValidationReqType::Quick ? &requestTracker.short_requests_
                          : action.type == ValidationReqType::Quick_Smell ? &requestTracker.short_smell_requests_
                          : action.type == ValidationReqType::Full ? &requestTracker.full_requests_
                          : &requestTracker.challenge_requests_;
                auto it = map->find(action.id);
                if (it != map->end()) {
                    it->second.second.newAttempt(now);
                }
            }
        }

        for (const auto& action : to_model_send) {
            ValidationResponseValue cur;
            if (!GetRequestStatusImpl(action.id, ValidationReqType::Model, cur)) {
                SendApiRequestInternal(action.id, action.model, ValidationReqType::Model);
                std::unique_lock lock(requestTracker.mutex_);
                auto it = requestTracker.model_requests_.find(action.id);
                if (it != requestTracker.model_requests_.end()) {
                    it->second.second.newAttempt(now);
                }
            }
        }

        for (const auto& action : to_default) {
            // If a real result landed in the gap, don't overwrite it
            ValidationResponseValue cur;
            if (GetRequestStatusImpl(action.id, action.type, cur)) {
                requestTracker.finishRequest(action.id, action.type);
                continue;
            }
            SetRequestStatus(action.id, action.type, action.status);
            if (m_http_mode) {
                ClearStatusQueueEntry(StatusKey{action.id, action.type});
            }
            LogPrintf("VALIDATOR: default status set for type=%d id=%s status=%d\n",
                      static_cast<int>(action.type), action.id.ToString(), static_cast<int>(action.status));
            requestTracker.finishRequest(action.id, action.type);
        }

        for (const auto& action : to_amber) {
            // If a real Full result landed in the gap, don't overwrite with Amber
            ValidationResponseValue cur;
            if (GetRequestStatusImpl(action.id, ValidationReqType::Full, cur)) {
                // Real result exists — receiver will handle it via finishRequest
                continue;
            }
            SetRequestStatus(action.id, ValidationReqType::Full, ValidationResponseValue::Full_Amber);
            if (m_http_mode) {
                ClearStatusQueueEntry(StatusKey{action.id, ValidationReqType::Full});
            }
            StartAmberFlow(action.id, action.block, action.behavior);
            requestTracker.finishRequest(action.id, ValidationReqType::Full);
        }

        ProcessAmberRequests();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    LogPrintf("VALIDATOR: JobSchedulerLoop thread was finished\n");
}

void ValidationAPI::SolutionReceiverLoop() {
    LogPrintf("VALIDATOR: SolutionReceiverLoop thread was started\n");
    uint256 id;
    ValidationReqType type;
    ValidationResponseValue status;
    ValidationResponseBehavior behavior;
    while (m_on.load() && !m_chainman.m_interrupt) {
        behavior = GetApiAnswer(id, type);
        if (behavior == ValidationResponseBehavior::Unknown) {
            if (UseHttpTransport()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            continue;
        }

        LogPrintf("VALIDATOR: Get an answer\n");

        // Ensure the status is present in the DB before acting
        if (!GetRequestStatus(id, type, status)) {
            // If status isn't readable yet, skip this loop; it will be retried
            continue;
        }

        // For synchronous paths (behavior == Nothing) or non-Full validations
        // we just finish and remove the tracked request.
        if (behavior == ValidationResponseBehavior::Nothing || type != ValidationReqType::Full) {
            requestTracker.finishRequest(id, type);
            continue;
        }

        // Full validations with actionable behavior: capture block and enqueue behavior
        std::optional<CBlock> blockOpt;
        {
            std::shared_lock lock(requestTracker.mutex_);
            blockOpt = requestTracker.getBlockForId(id, type);
        }
        if (!blockOpt.has_value()) {
            LogError("%s: No block found for request ID: %s\n", __func__, id.ToString());
            requestTracker.finishRequest(id, type);
            continue;
        }
        if (status == ValidationResponseValue::Full_Amber || status == ValidationResponseValue::Full_Red) {
            StartAmberFlow(id, *blockOpt, behavior, status);
            requestTracker.finishRequest(id, type);
            continue;
        }
        {
            std::unique_lock lock(behmutex);
            behaviors.emplace_back(id, type, behavior, *blockOpt);
        }
        behcv.notify_one();
        requestTracker.finishRequest(id, type);
    }
    LogPrintf("VALIDATOR: SolutionReceiverLoop thread was finished\n");
}

void ValidationAPI::BehaviorLoop() {
    LogPrintf("VALIDATOR: BehaviorLoop thread was started\n");
    std::vector<std::tuple<uint256, ValidationReqType, ValidationResponseBehavior, CBlock>>::iterator it;
    uint256 beh_id;
    ValidationResponseBehavior behavior;
    CBlock beh_block;
    while (m_on.load() && !m_chainman.m_interrupt) {
        {
            std::unique_lock lock(behmutex);
            // Wait until there is work, or we are shutting down. The timeout bounds
            // shutdown latency in case a notify is ever missed.
            behcv.wait_for(lock, std::chrono::milliseconds(200), [&] {
                return !behaviors.empty() || !m_on.load() || m_chainman.m_interrupt;
            });
            if (behaviors.empty()) {
                continue;  // spurious/timeout wake, or shutdown — re-check loop condition
            }
            it = behaviors.begin();
            beh_id = std::get<0>(*it);
            behavior = std::get<2>(*it);
            beh_block = std::get<3>(*it);
            behaviors.erase(it);
        }
        CBlockIndex* pindex = nullptr;
        auto blockPtr = std::make_shared<const CBlock>(beh_block);
        BlockValidationState state;
        switch (behavior) {
        case ValidationResponseBehavior::AcceptBlock: {
            LOCK(cs_main);
            if (!m_chainman.AcceptBlock(blockPtr, state, &pindex, /*force_processing=*/true, nullptr, nullptr, /*min_pow_checked=*/true, /*verifying=*/true)) {
                LogError("%s: AcceptBlock FAILED (%s)\n", __func__, state.ToString());
            }
            break;
        }
        case ValidationResponseBehavior::ProcessNewBlock:
            if (!m_chainman.ProcessNewBlock(blockPtr, /*force_processing=*/true, /*min_pow_checked=*/true, nullptr)) {
                LogError("%s: ProcessNewBlock FAILED (%s)\n", __func__, state.ToString());
            }
            break;
        default:
            break;
        }
    }
    LogPrintf("VALIDATOR: BehaviorLoop thread was finished\n");
}

void ValidationAPI::SendApiRequest(const CBlock& block, const ValidationReqType& type, const ValidationResponseBehavior& behavior) {
    if (type != ValidationReqType::Quick && type != ValidationReqType::Quick_Smell &&
        type != ValidationReqType::Full && type != ValidationReqType::Challenge) {
        LogError("VALIDATOR: wrong request type\n");
        return;
    }

    if (type == ValidationReqType::Quick_Smell && TrySetLocalQuickSmellFinalHashFailure(block)) {
        return;
    }

    // Desktop/http mode: run Quick locally and enqueue Full for HTTP worker
    if (UseLocalQuick() && type == ValidationReqType::Quick) {
        const auto status = RunLocalQuick(block);
        SetRequestStatus(block.GetHash(), type, status);
        return;
    }
    
    uint256 req_id;
    if (requestTracker.makeNewRequest(block, type, req_id, behavior)) {
        LogPrintf("%s: Validation type : %d, %s prepare the validation request\n", __func__, static_cast<uint8_t>(type), req_id.ToString());
        SendApiRequest(req_id, block, type);
    }
}

void ValidationAPI::SendApiRequest(const uint256& req_id, const ModelRecord& model, const ValidationReqType& type) {
    if (type != ValidationReqType::Model) {
        LogError("VALIDATOR: wrong request type\n");
        return;
    }
    if (requestTracker.makeNewRequest(req_id, model, type)) {
        SendApiRequestInternal(req_id, model, type);
    }
}

void ValidationAPI::EnqueueApiRequest(const CBlock& block, const ValidationReqType& type, const ValidationResponseBehavior& behavior) {
    if (type != ValidationReqType::Quick && type != ValidationReqType::Quick_Smell &&
        type != ValidationReqType::Full && type != ValidationReqType::Challenge) {
        LogError("VALIDATOR: wrong request type\n");
        return;
    }

    if (type == ValidationReqType::Quick_Smell && TrySetLocalQuickSmellFinalHashFailure(block)) {
        return;
    }

    if (UseLocalQuick() && type == ValidationReqType::Quick) {
        const auto status = RunLocalQuick(block);
        SetRequestStatus(block.GetHash(), type, status);
        return;
    }

    // A cached Full_Amber (e.g. persisted before a restart) has no live
    // corroboration flow, and the scheduler skips requests whose status
    // already reads as present — so a deferred block would never converge.
    // Kick the amber flow here; try_emplace makes this a no-op if the flow
    // is already tracked, and StartAmberFlow ignores behavior == Nothing.
    if (type == ValidationReqType::Full &&
        static_cast<ValidationResponseValue>(GetOwnFullStatus(block.GetHash())) == ValidationResponseValue::Full_Amber) {
        StartAmberFlow(block.GetHash(), block, behavior);
    }

    uint256 req_id;
    if (requestTracker.makeNewRequest(block, type, req_id, behavior)) {
        if (UseHttpTransport()) {
            EnqueueStatusRequest(req_id, type);
        }
        LogPrintf("%s: queued deferred validation request type=%d id=%s\n",
                  __func__, static_cast<int>(type), req_id.ToString());
    }
}

void ValidationAPI::EnqueueApiRequest(const uint256& req_id, const ModelRecord& model, const ValidationReqType& type) {
    if (type != ValidationReqType::Model) {
        LogError("VALIDATOR: wrong request type\n");
        return;
    }

    if (requestTracker.makeNewRequest(req_id, model, type)) {
        if (UseHttpTransport()) {
            EnqueueStatusRequest(req_id, type);
        }
        LogPrintf("%s: queued deferred model validation request id=%s\n",
                  __func__, req_id.ToString());
    }
}

bool ValidationAPI::TryLocalQuickVerdict(const CBlock& block, ValidationResponseValue& status)
{
    if (!UseLocalQuick()) {
        return false;
    }
    status = RunLocalQuick(block);
    return true;
}

int64_t V3AdvertisedDifficulty(int height, const Consensus::Params& params,
                               int64_t registered_difficulty) {
    if (height < 0 || !params.IsV3Active(height)) return 0;
    // Defensive clamp to the documented "no usable difficulty => 0" contract:
    // only a strictly-positive registered difficulty is a valid admission
    // target / v3-active signal. A 0/negative value (unregistered or
    // malformed record) advertises 0, i.e. the verifier replays under v2.
    return registered_difficulty > 0 ? registered_difficulty : 0;
}

bool IsV3ActivationConfigSound(int v3_activation_height, bool external_api,
                               bool is_mockable_chain) {
    // TIP-0003: B_cred tiering is consensus-fast-path evidence
    // computed from the proof's SUBMITTED top-k, so its free tier is only sound
    // when the full-replay / red-block enforcement path (external_api) rejects
    // forged high-entropy evidence. The plan is explicit: "v3 MUST NOT activate
    // unless red-block enforcement is active for v3 proofs." So a finite
    // V3ActivationHeight is only a valid config when external_api is on.
    //
    // Mockable (regtest / mock testnet) chains are exempt: they deliberately
    // exercise the fast path in isolation — the functional acceptance test
    // activates v3 via -v3activationheight WITHOUT external_api to pin the
    // QuickVerifier tier/admission mechanics directly.
    if (v3_activation_height == std::numeric_limits<int>::max()) return true;  // v3 disabled
    if (is_mockable_chain) return true;                                        // test harness
    return external_api;
}

bool IsV3TierParamsVendored(int v3_activation_height,
                            uint64_t v3_bfloor_bits, uint64_t v3_bfree_bits) {
    // The tier thresholds are part of the cross-language golden-vector
    // contract: the external Python verifier scores tiers with the compiled
    // pow_v3 defaults (proof_verifier.py tier_for_b_cred_units), so chain
    // params that diverge from B_FLOOR_BITS/B_FREE_BITS would silently split
    // bcore consensus from the verification fleet. Recalibration must ship as
    // a coordinated constants change in BOTH languages, never a params edit.
    //
    // Enforced at startup (not per-proof in PrepareV3) so unit tests remain
    // free to parameterize the thresholds when steering B_cred tiers.
    if (v3_activation_height == std::numeric_limits<int>::max()) return true;  // v3 disabled
    return v3_bfloor_bits == pow_v3::B_FLOOR_BITS &&
           v3_bfree_bits == pow_v3::B_FREE_BITS;
}

bool IsV3AdmissionVerifyCapable(int v3_activation_height, bool argon2_compiled) {
    // libargon2 is an optional build dependency (desktop cross/depends
    // toolchains lack it), and pow_v3::argon2id_digest() throws at runtime in
    // an argonless build. That is fine for a binary that never sees v3 rules —
    // but at a v3-active height every claimed admission nonce must be
    // Argon2-verified, and the throw is mapped to proof-invalid, so an
    // argonless full node would reject every consensus-valid admission-band
    // block and fork off the network. Refuse the config at startup instead.
    //
    // Unlike IsV3ActivationConfigSound there is NO mockable exemption: an
    // argonless binary cannot verify a claimed nonce on regtest either, and
    // every test image installs libargon2 — an argonless regtest run with a
    // finite activation height would only produce confusing admission-band
    // rejections, so failing fast is correct there too.
    if (v3_activation_height == std::numeric_limits<int>::max()) return true;  // v3 disabled
    return argon2_compiled;
}

void ValidationAPI::SendApiRequest(const uint256 &req_id, const CBlock& block, const ValidationReqType& type) {
    if (type != ValidationReqType::Quick && type != ValidationReqType::Quick_Smell &&
        type != ValidationReqType::Full && type != ValidationReqType::Challenge) {
        LogError("VALIDATOR: wrong request type\n");
        return;
    }
    flatbuffers::FlatBufferBuilder builder;

    auto reqtype = proof::ValidationType_Quick;
    switch (type) {
    case ValidationReqType::Quick:
        reqtype = proof::ValidationType_Quick;
        break;
    case ValidationReqType::Quick_Smell:
        reqtype = proof::ValidationType_Quick_Smell;
        break;
    case ValidationReqType::Full:
        reqtype = proof::ValidationType_Full;
        break;
    case ValidationReqType::Challenge:
        reqtype = proof::ValidationType_Challenge;
        break;
    default:
        break;
    }
    
    auto merkle_vec = builder.CreateVector(block.hashMerkleRoot.begin(), EXPECTED_HASH_SIZE);
    auto hashPrevBlock_vec = builder.CreateVector(block.hashPrevBlock.begin(), EXPECTED_HASH_SIZE);
    auto hashPow_vec = builder.CreateVector(block.hashPoW.begin(), EXPECTED_HASH_SIZE);
    auto hashShort_vec = builder.CreateVector(block.GetShortHash().begin(), EXPECTED_HASH_SIZE);
    auto hashLong_vec = builder.CreateVector(req_id.begin(), EXPECTED_HASH_SIZE);
    auto proofBlob_fb = block.pow.ToFlatBuffer(builder);

    // Registered model difficulty from the record active at this block's
    // height (modeldb is undo/reorg-safe), so the verification service can
    // derive the v3 admission target (TIP-0003) without its own
    // registry mirror. 0 = not provided (appended, wire-compatible field);
    // bcore consensus remains authoritative for the admission check itself.
    //
    // Option 2 (no v3_active wire field): difficulty doubles as the
    // verifier's v3-ACTIVE signal. It must therefore only be advertised
    // once v3 rules are ACTIVE at this block's height. Pre-activation a
    // version>=3 blob is judged under v2 rules by consensus (the admission
    // nonce is NOT folded into the u preimage); if we advertised a nonzero
    // difficulty the verifier would treat version>=3 && difficulty>0 as v3,
    // fold the nonce into u, and diverge from consensus. Height is the
    // block's own height (prev height + 1), so historical re-validation
    // below V3ActivationHeight stays v2 even when the tip is past it.
    int64_t model_difficulty{0};
    if (g_modeldb && !block.pow.model_identifier.empty()) {
        int height{-1};
        {
            LOCK(cs_main);
            const CBlockIndex* prev =
                m_chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
            if (prev) height = prev->nHeight + 1;
        }
        int64_t registered{0};
        if (height >= 0) {
            ModelRecord rec;
            if (g_modeldb->ReadModel(block.pow.GetModelHash(), rec)) {
                registered = rec.metadata.difficulty;
            }
        }
        model_difficulty = V3AdvertisedDifficulty(
            height, m_chainman.GetConsensus(), registered);
    }

    auto req_body = proof::CreateBlockValidation(builder,
                                            block.nVersion, hashShort_vec, hashPrevBlock_vec, merkle_vec,
                                            block.nTime, block.nBits, block.nNonce, hashPow_vec, block.nAdjBits, proofBlob_fb,
                                            model_difficulty);

    auto req_fb = proof::CreateValidationRequest(builder, hashLong_vec, reqtype, proof::ValidationUnion_BlockValidation, req_body.Union());
    
    builder.Finish(req_fb);

    if (UseHttpTransport()) {
        std::vector<uint8_t> payload(builder.GetSize());
        memcpy(payload.data(), builder.GetBufferPointer(), builder.GetSize());
        LogPrintf("VALIDATOR: HTTP transport send id=%s type=%d payload=%u\n",
                  req_id.ToString(), static_cast<int>(type),
                  static_cast<unsigned>(payload.size()));

        SendHttpRequest(req_id, payload, type);
        return;
    }
    
    zmq_msg_t request;
    if (zmq_msg_init_size(&request, builder.GetSize()) != 0) {
        LogError("Failed to initialize ZMQ message\n");
        return;
    }
    
    memcpy(zmq_msg_data(&request), builder.GetBufferPointer(), builder.GetSize());
    
    int rc = -1;
    if (!reqPush) {
        LogError("VALIDATOR: NO API socket (deferred send)\n");
    } else {
        rc = zmq_sendmsg(reqPush, &request, ZMQ_DONTWAIT);
    }
    zmq_msg_close(&request);
    
    if (rc != -1) {
        LogPrintf("VALIDATOR: ZMQ send ok id=%s type=%d bytes=%u\n",
                  req_id.ToString(), static_cast<int>(type),
                  static_cast<unsigned>(builder.GetSize()));
        last_send_success_ = std::chrono::steady_clock::now();
        connection_healthy_.store(true);
    } else {
        checkNetworkHealth();
        if (errno == EAGAIN) {
            LogPrintf("Validation queue full, skipping\n");
        } else {
            LogError("zmq_sendmsg error: %s\n", zmq_strerror(errno));
        }
    }
}

void ValidationAPI::SendApiRequestInternal(const uint256 &req_id, const ModelRecord& model, const ValidationReqType& type) {
    if (type != ValidationReqType::Model) {
        LogError("VALIDATOR: wrong request type\n");
        return;
    }
    flatbuffers::FlatBufferBuilder builder;

    auto hastTx_vec = builder.CreateVector(model.commit_txid.begin(), EXPECTED_HASH_SIZE);
    auto hashBlock_vec = builder.CreateVector(model.commit_block_hash.begin(), EXPECTED_HASH_SIZE);
    auto hash_vec = builder.CreateVector(req_id.begin(), EXPECTED_HASH_SIZE);
    auto model_name = builder.CreateString(model.metadata.model_name);
    auto model_commit = builder.CreateString(model.metadata.model_commit);
    auto cid = builder.CreateString(model.metadata.cid);
    auto extra = builder.CreateString(model.metadata.extra);

    auto req_body = proof::CreateModelValidation(builder, 
                                            model_name, model_commit, model.metadata.difficulty, cid, extra,
                                            hastTx_vec, hashBlock_vec, model.commit_block_height);

    auto req_fb = proof::CreateValidationRequest(builder, hash_vec, proof::ValidationType_Model, proof::ValidationUnion_ModelValidation, req_body.Union());
    
    builder.Finish(req_fb);

    if (UseHttpTransport()) {
        std::vector<uint8_t> payload(builder.GetSize());
        memcpy(payload.data(), builder.GetBufferPointer(), builder.GetSize());

        SendHttpRequest(req_id, payload, type);
        // if (status_opt.has_value()) {
        //     SetRequestStatus(req_id, type, *status_opt);
        // }
        return;
    }
    
    zmq_msg_t request;
    if (zmq_msg_init_size(&request, builder.GetSize()) != 0) {
        LogError("Failed to initialize ZMQ message\n");
        return;
    }
    
    memcpy(zmq_msg_data(&request), builder.GetBufferPointer(), builder.GetSize());
    
    int rc = -1;
    if (!reqPush) {
        LogError("VALIDATOR: NO API socket (deferred send)\n");
    } else {
        rc = zmq_sendmsg(reqPush, &request, ZMQ_DONTWAIT);
    }
    zmq_msg_close(&request);
    
    if (rc != -1) {
        last_send_success_ = std::chrono::steady_clock::now();
        connection_healthy_.store(true);
    } else {
        checkNetworkHealth();
        if (errno == EAGAIN) {
            LogPrintf("Validation queue full, skipping\n");
        } else {
            LogError("zmq_sendmsg error: %s\n", zmq_strerror(errno));
        }
    }
}

ValidationResponseBehavior ValidationAPI::GetApiAnswer(uint256 &id, ValidationReqType& type) {
    if (UseHttpTransport()){
        return GettHttpStatus(id, type);
    }
    if (!solPull) {
        LogError("NO solPull socket\n");
        return ValidationResponseBehavior::Unknown;
    }

    // Rate limiting check
    // if (!rateLimiter_.allowRequest()) {
    //     zmq_msg_t drain_msg;
    //     zmq_msg_init(&drain_msg);
    //     while (zmq_recvmsg(solPull, &drain_msg, ZMQ_DONTWAIT) != -1) {
    //         zmq_msg_close(&drain_msg);
    //         zmq_msg_init(&drain_msg);
    //     }
    //     zmq_msg_close(&drain_msg);
    //     return false;
    // }

    zmq_msg_t reply;
    zmq_msg_init(&reply);
    
    struct MessageGuard {
        zmq_msg_t* msg;
        ~MessageGuard() { if (msg) zmq_msg_close(msg); }
    } guard{&reply};

    try {
        waitingApiAnswer.store(true);
        
        // Use blocking receive - solutions can take hours
        auto received = zmq_recvmsg(solPull, &reply, 0);
        if (received == -1) {
            LogError("Solution receive error: %s\n", zmq_strerror(errno));
            waitingApiAnswer.store(false);
            return ValidationResponseBehavior::Unknown;
        }

        // Log to stdout when response received
        LogPrintf("Validation solution received, size: %zu bytes\n", zmq_msg_size(&reply));

        if (zmq_msg_size(&reply) < sizeof(flatbuffers::uoffset_t)) {
            LogError("Invalid message size\n");
            waitingApiAnswer.store(false);
            return ValidationResponseBehavior::Unknown;
        }

        auto resp = flatbuffers::GetRoot<proof::ValidationResponse>(zmq_msg_data(&reply));
        if (resp->hash_identifier() && resp->hash_identifier()->size() == 32) {
            std::memcpy(id.begin(), resp->hash_identifier()->data(), 32);
        } else {
            return ValidationResponseBehavior::Unknown;
        }
        ValidationResponseValue result;
        switch (resp->enum_response()){
        case proof::ResponseValue_Quick_OK:
            result = ValidationResponseValue::Quick_OK;
            type = ValidationReqType::Quick;
            break;
        case proof::ResponseValue_Quick_Fail:
            result = ValidationResponseValue::Quick_Fail;
            type = ValidationReqType::Quick;
            break;
        case proof::ResponseValue_Quick_OK_Smell_OK:
            result = ValidationResponseValue::Quick_OK_Smell_OK;
            type = ValidationReqType::Quick_Smell;
            break;
        case proof::ResponseValue_Quick_OK_Smell_Fail:
            result = ValidationResponseValue::Quick_OK_Smell_Fail;
            type = ValidationReqType::Quick_Smell;
            break;
        case proof::ResponseValue_Quick_Fail_Smell_OK:
            result = ValidationResponseValue::Quick_Fail_Smell_OK;
            type = ValidationReqType::Quick_Smell;
            break;
        case proof::ResponseValue_Quick_Fail_Smell_Fail:
            result = ValidationResponseValue::Quick_Fail_Smell_Fail;
            type = ValidationReqType::Quick_Smell;
            break;
        case proof::ResponseValue_Full_Amber:
            result = ValidationResponseValue::Full_Amber;
            type = ValidationReqType::Full;
            break;
        case proof::ResponseValue_Full_Green:
            result = ValidationResponseValue::Full_Green;
            type = ValidationReqType::Full;
            break;
        case proof::ResponseValue_Full_Red:
            result = ValidationResponseValue::Full_Red;
            type = ValidationReqType::Full;
            break;
        case proof::ResponseValue_Model_Pending_Review: {
            // NON-TERMINAL: do NOT call SetRequestStatus (would make it permanent).
            // Mark as review-pending so the retry loop snoozes instead of burning attempts.
            {
                std::lock_guard<std::mutex> lock(status_queue_mutex_);
                model_review_pending_.insert(StatusKey{id, ValidationReqType::Model});
            }
            waitingApiAnswer.store(false);
            LogPrintf("VALIDATOR: Model %s pending operator review\n", id.ToString().c_str());
            return ValidationResponseBehavior::Nothing;
        }
        case proof::ResponseValue_Model_OK:
            result = ValidationResponseValue::Model_OK;
            type = ValidationReqType::Model;
            ClearModelReviewPending(id);
            break;
        case proof::ResponseValue_Model_Fail:
            result = ValidationResponseValue::Model_Fail;
            type = ValidationReqType::Model;
            ClearModelReviewPending(id);
            break;
        case proof::ResponseValue_Challenge_OK:
            result = ValidationResponseValue::Challenge_OK;
            type = ValidationReqType::Challenge;
            break;
        case proof::ResponseValue_Challenge_Fail:
            result = ValidationResponseValue::Challenge_Fail;
            type = ValidationReqType::Challenge;
            break;
        default: 
            waitingApiAnswer.store(false);
            return ValidationResponseBehavior::Unknown;
            break;
        }
        LogPrintf("Validation solution received, response %d\n", static_cast<uint8_t>(resp->enum_response()));
        // Log response details to stdout
        // LogPrintf("Solution details: req_id=%u, nonce=%u, adjusted_bits=%u\n", 
        //           resp->req_id(), resp->nonce(), resp->adjusted_bits());

        waitingApiAnswer.store(false);
        if (SetRequestStatus(id, type, result)) {
            std::unique_lock lock(requestTracker.mutex_);
            switch (type) {
            case ValidationReqType::Full: {
                auto it = requestTracker.full_requests_.find(id);
                if (it != requestTracker.full_requests_.end()) {
                    return it->second.second.behavior;
                }
                break; }
            case ValidationReqType::Quick: {
                auto it = requestTracker.short_requests_.find(id);
                if (it != requestTracker.short_requests_.end()) {
                    return it->second.second.behavior;
                }
                break; }
            case ValidationReqType::Quick_Smell: {
                auto it = requestTracker.short_smell_requests_.find(id);
                if (it != requestTracker.short_smell_requests_.end()) {
                    return it->second.second.behavior;
                }
                break; }
            case ValidationReqType::Challenge: {
                auto it = requestTracker.challenge_requests_.find(id);
                if (it != requestTracker.challenge_requests_.end()) {
                    return it->second.second.behavior;
                }
                break; }
            case ValidationReqType::Model:
                return ValidationResponseBehavior::Nothing;
            }
        }
        return ValidationResponseBehavior::Unknown;
        
    } catch (const std::exception& e) {
        LogError("Exception in GetApiAnswer: %s\n", e.what());
        waitingApiAnswer.store(false);
        return ValidationResponseBehavior::Unknown;
    }
}

bool ValidationAPI::SetRequestStatus(const uint256 &id, const ValidationReqType& type, const ValidationResponseValue& status) {
    switch (type){
    case ValidationReqType::Quick:
    case ValidationReqType::Quick_Smell:{
        return m_validatedBlocks.UpdateRes_Quick(id, status);
        break;}
    case ValidationReqType::Full:{
        if (status == ValidationResponseValue::Full_Green ||
            status == ValidationResponseValue::Full_Red) {
            AssertLockNotHeld(cs_main);
        }
        const bool updated{m_validatedBlocks.UpdateRes_Full(id, status)};
        if (updated && (status == ValidationResponseValue::Full_Green ||
                        status == ValidationResponseValue::Full_Red)) {
            bool changed{false};
            bool activate_best_chain{false};
            {
                LOCK(cs_main);
                CBlockIndex* pindex{m_chainman.SetBlockFullValidationRedStatus(id, status == ValidationResponseValue::Full_Red, &changed)};
                if (changed) {
                    m_chainman.RecalculateBlockIndexWorkForFullValidation(pindex);
                    activate_best_chain = !m_chainman.GetAll().empty() && m_chainman.ActiveTip() != nullptr;
                }
            }
            if (activate_best_chain) {
                BlockValidationState state;
                if (!m_chainman.ActiveChainstate().ActivateBestChain(state)) {
                    LogError("%s: ActivateBestChain after Full validation chainwork replay FAILED (%s)\n",
                             __func__, state.ToString());
                }
            }
        }
        return updated;
        break;}
    case ValidationReqType::Challenge: {
        challenge_status_[id] = status;
        break; }
    case ValidationReqType::Model: {
        auto it = model_status_.find(id);
        if (it != model_status_.end())
            return false;
        model_status_[id] = status;
        break; 
    }
    default: return false;
    }
    return true;
}

bool ValidationAPI::RemoveRes_Full(const uint256& pid) {
    return m_validatedBlocks.RemoveRes_Full(pid);
}

void ValidationAPI::RecordPeerFullStatus(const uint256& id, const std::string& peer_id, ValidationResponseValue peer_status)
{
    switch (peer_status) {
    case ValidationResponseValue::Full_Green:
    case ValidationResponseValue::Full_Amber:
    case ValidationResponseValue::Full_Red:
        break;
    default:
        return;
    }

    if (!m_validatedBlocks.UpdateExtFull(id, peer_id, peer_status)) {
        return;
    }

    std::optional<AmberRequest> finalized;
    {
        std::lock_guard<std::mutex> lock(amber_mutex_);
        auto it = amber_requests_.find(id);
        // While a getheaders dispatch is in flight the expected-peer count is
        // not yet recorded (expected_peers still 0), so a fast Red vote would
        // finalize as if no peers had been polled. The vote itself was
        // recorded above; it is re-evaluated on the next
        // ProcessAmberRequests() pass or the next vote after the dispatch
        // loop records expected_peers.
        if (it != amber_requests_.end() && !it->second.dispatch_in_flight &&
            ShouldFinalizeAmber(id, it->second, false)) {
            finalized.emplace(std::move(it->second));
            amber_requests_.erase(it);
        }
    }

    if (finalized.has_value()) {
        FinalizeAmber(id, std::move(*finalized));
    }
}

void ValidationAPI::StartAmberFlow(const uint256& id, const CBlock& block, ValidationResponseBehavior behavior, ValidationResponseValue initial_status)
{
    if (behavior == ValidationResponseBehavior::Nothing) {
        return;
    }

    AmberRequest request;
    request.block = block;
    request.behavior = behavior;
    request.initial_status = initial_status;
    request.first_seen = std::chrono::steady_clock::now();
    request.next_send = request.first_seen;
    request.attempts = 0;
    request.expected_peers = 0;
    request.force_finalize = false;

    {
        std::lock_guard<std::mutex> lock(amber_mutex_);
        // A follow-up flow for this id may already be in flight: while the
        // block stays pending, every re-submission re-polls the validator,
        // whose cached Amber is re-delivered here. Overwriting the tracked
        // request would reset attempts/first_seen/finalize_deadline, so the
        // no-peer fallback ladder in ProcessAmberRequests() never completes
        // and the height stays wedged until the validator cache expires.
        if (!amber_requests_.try_emplace(id, std::move(request)).second) {
            return;
        }
    }
    LogPrintf("VALIDATOR: Full validation amber for %s, awaiting peer corroboration%s\n",
              id.ToString(), m_connman ? "" : " (connman unavailable)");
}

bool ValidationAPI::ShouldFinalizeAmber(const uint256& id, const AmberRequest& request, bool force_finalize) const
{
    BlockValidationDB::BlockValidationRecord_Full record(id);
    if (!m_validatedBlocks.ReadRes(id, record)) {
        return force_finalize;
    }

    const auto own_status = static_cast<ValidationResponseValue>(record.FullValidation);
    if (own_status == ValidationResponseValue::Full_Red) {
        const bool all_responded = request.expected_peers > 0 && record.nExtFull >= request.expected_peers;
        if (force_finalize) {
            return true;
        }
        if (request.expected_peers == 0) {
            return true;
        }
        return all_responded;
    }
    if (own_status != ValidationResponseValue::Full_Amber) {
        return true;
    }

    bool has_red = false;
    int amber_count = 0;
    for (uint8_t i = 0; i < record.nExtFull; ++i) {
        auto peer_val = static_cast<ValidationResponseValue>(record.extFulls[i].second);
        if (peer_val == ValidationResponseValue::Full_Red) {
            has_red = true;
            break;
        }
        if (peer_val == ValidationResponseValue::Full_Amber) {
            ++amber_count;
        }
    }

    const bool enough_amber = amber_count >= 5;
    const bool all_responded = request.expected_peers > 0 && record.nExtFull >= request.expected_peers;
    if (!force_finalize && request.expected_peers > 0 && record.nExtFull < request.expected_peers && (has_red || enough_amber)) {
        return false;
    }
    return has_red || enough_amber || all_responded || force_finalize;
}

int ValidationAPI::DispatchAmberGetHeaders(const uint256& id)
{
    // MUST be called without amber_mutex_ held: this takes cs_main for the
    // locator, and block-processing paths call StartAmberFlow (amber_mutex_)
    // while holding cs_main — dispatching under amber_mutex_ is an ABBA
    // deadlock (observed as feature_validation_amber_http.py wedging).
    CConnman* connman = m_connman;
    if (!connman) {
        return 0;
    }

    CBlockLocator locator;
    {
        LOCK(cs_main);
        locator = m_chainman.ActiveChain().GetLocator();
    }

    int dispatched = 0;
    connman->ForEachNode([&](CNode* node) {
        connman->PushMessage(node, NetMsg::Make(NetMsgType::GETHEADERS, locator, id));
        ++dispatched;
    });

    if (dispatched == 0) {
        LogPrintf("VALIDATOR: Amber follow-up %s has no peers to query\n", id.ToString());
    } else {
        LogPrintf("VALIDATOR: Amber follow-up %s dispatched getheaders to %d peers\n", id.ToString(), dispatched);
    }
    return dispatched;
}

void ValidationAPI::ProcessAmberRequests()
{
    std::vector<std::pair<uint256, AmberRequest>> finalize;
    std::vector<std::pair<uint256, AmberRequest>> revalidate;
    std::vector<uint256> dispatch;
    const auto now = std::chrono::steady_clock::now();

    auto count_peer_votes = [](const BlockValidationDB::BlockValidationRecord_Full& record) {
        int greens = 0;
        int ambers = 0;
        int reds = 0;
        for (uint8_t i = 0; i < record.nExtFull; ++i) {
            auto peer_val = static_cast<ValidationResponseValue>(record.extFulls[i].second);
            switch (peer_val) {
            case ValidationResponseValue::Full_Green:
                ++greens;
                break;
            case ValidationResponseValue::Full_Amber:
                ++ambers;
                break;
            case ValidationResponseValue::Full_Red:
                ++reds;
                break;
            default:
                break;
            }
        }
        return std::tuple<int, int, int>{greens, ambers, reds};
    };

    {
        std::lock_guard<std::mutex> lock(amber_mutex_);
        for (auto it = amber_requests_.begin(); it != amber_requests_.end(); ) {
            AmberRequest& request = it->second;

            if (request.finalize_deadline && now >= *request.finalize_deadline) {
                request.force_finalize = true;
                request.finalize_deadline.reset();
            }

            BlockValidationDB::BlockValidationRecord_Full record(it->first);
            const bool has_record = m_validatedBlocks.ReadRes(it->first, record);

            if (has_record) {
                const auto [green_count, amber_count, red_count] = count_peer_votes(record);
                (void)amber_count;
                const bool polled_peers = request.expected_peers > 0;
                const bool all_responded = polled_peers && record.nExtFull >= request.expected_peers;
                const bool ready_to_decide = all_responded || request.force_finalize;
                const bool already_revalidated = revalidation_attempted_.count(it->first) > 0;

                if (ready_to_decide && polled_peers && record.nExtFull > 0 && !already_revalidated) {
                    const bool greens_majority = green_count * 2 >= static_cast<int>(record.nExtFull);
                    if (request.initial_status == ValidationResponseValue::Full_Amber) {
                        const auto projected = record.getFull(false);
                        if (projected == ValidationResponseValue::Full_Red && greens_majority) {
                            revalidation_attempted_.insert(it->first);
                            revalidate.emplace_back(it->first, std::move(request));
                            it = amber_requests_.erase(it);
                            continue;
                        }
                    } else if (request.initial_status == ValidationResponseValue::Full_Red) {
                        if (red_count == 0 && greens_majority) {
                            revalidation_attempted_.insert(it->first);
                            revalidate.emplace_back(it->first, std::move(request));
                            it = amber_requests_.erase(it);
                            continue;
                        }
                    }
                }
            }

            if (ShouldFinalizeAmber(it->first, request, false)) {
                finalize.emplace_back(it->first, std::move(request));
                it = amber_requests_.erase(it);
                continue;
            }

            bool dispatched_final_attempt = false;
            if (request.attempts < static_cast<int>(AMBER_RETRY_DELAYS.size()) && now >= request.next_send) {
                const int attempt_index = request.attempts;
                // Defer the actual getheaders send to after amber_mutex_ is
                // released: DispatchAmberGetHeaders takes cs_main, and
                // cs_main holders call StartAmberFlow (amber_mutex_), so
                // dispatching here inverts the lock order and deadlocks.
                // Mark the dispatch as in flight until the post-mutex loop
                // records the peer count: in that window expected_peers is
                // still 0, and a fast peer response through
                // RecordPeerFullStatus() would otherwise finalize as if no
                // peers had been polled.
                request.dispatch_in_flight = true;
                dispatch.push_back(it->first);
                const auto next_delay = AMBER_RETRY_DELAYS[std::min(attempt_index, static_cast<int>(AMBER_RETRY_DELAYS.size()) - 1)];
                request.next_send = now + next_delay;
                ++request.attempts;
                if (request.attempts >= static_cast<int>(AMBER_RETRY_DELAYS.size())) {
                    request.finalize_deadline = now;
                    dispatched_final_attempt = true;
                }
            }

            if (dispatched_final_attempt) {
                ++it;
                continue;
            }

            if (request.force_finalize && ShouldFinalizeAmber(it->first, request, true)) {
                finalize.emplace_back(it->first, std::move(request));
                it = amber_requests_.erase(it);
                continue;
            }

            ++it;
        }
    }

    for (const uint256& id : dispatch) {
        const int dispatched = DispatchAmberGetHeaders(id);
        std::lock_guard<std::mutex> lock(amber_mutex_);
        auto it = amber_requests_.find(id);
        if (it != amber_requests_.end()) {
            it->second.expected_peers = dispatched;
            // Clear even when dispatched == 0: the send-vs-record window is
            // over, so vote-driven finalization may resume.
            it->second.dispatch_in_flight = false;
        }
    }

    for (auto& item : revalidate) {
        SendApiRequest(item.second.block, ValidationReqType::Full, item.second.behavior);
        LogPrintf("VALIDATOR: Revalidating %s after peer review (initial=%d)\n",
                  item.first.ToString(), static_cast<int>(item.second.initial_status));
    }

    for (auto& item : finalize) {
        FinalizeAmber(item.first, std::move(item.second));
    }
}

void ValidationAPI::FinalizeAmber(const uint256& id, AmberRequest&& request)
{
    const bool force_mock_external = gArgs.GetBoolArg("-mockval-force-external", false) &&
        g_ValidationApi != nullptr &&
        g_ValidationApi->UsesRequestStatusForBlockProcessing();

    ValidationResponseValue final_status = ValidationResponseValue::Full_Amber;
    BlockValidationDB::BlockValidationRecord_Full record(id);
    if (m_validatedBlocks.ReadRes(id, record)) {
        final_status = record.getFull(false);
    }

    if (force_mock_external && final_status == ValidationResponseValue::Full_Amber) {
        final_status = ValidationResponseValue::Full_Red;
    }

    SetRequestStatus(id, ValidationReqType::Full, final_status);

    {
        std::unique_lock lock(behmutex);
        behaviors.emplace_back(id, ValidationReqType::Full, request.behavior, request.block);
    }
    behcv.notify_one();

    LogPrintf("VALIDATOR: Amber resolution for %s final status=%d\n", id.ToString(), static_cast<int>(final_status));
}

void ValidationAPI::SetConnman(CConnman* connman)
{
    m_connman = connman;
    if (connman) {
        LogPrintf("VALIDATOR: connman attached; amber peer corroboration enabled\n");
    }
}

bool ValidationAPI::GetRequestStatus(const uint256 &id, const ValidationReqType& type, ValidationResponseValue& status, bool async) const {
    if (async)
        return GetRequestStatusImpl(id, type, status);
    // Bounded wait. The block-connection path no longer blocks here — it enqueues
    // and defers — but a synchronous caller remains: the block-submission RPC
    // checks whether Quick has already reached a verdict. An UNBOUNDED spin would
    // hang that caller indefinitely if the external validator is slow or
    // rate-limiting (HTTP 429) and the status never becomes terminal. Cap the wait
    // and, on timeout, return whatever GetRequestStatusImpl reports (non-terminal
    // -> false). Returning false is already a normal, safely handled outcome: the
    // async path (async=true) returns false while pending and callers defer +
    // re-check on the next pass; we reuse that contract instead of hanging.
    constexpr auto kMaxBlockingWait = std::chrono::seconds(5);
    const auto deadline = std::chrono::steady_clock::now() + kMaxBlockingWait;
    while (!GetRequestStatusImpl(id, type, status))
    {
        if (std::chrono::steady_clock::now() >= deadline) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return true;
}

bool ValidationAPI::GetRequestStatusImpl(const uint256 &id, const ValidationReqType& type, ValidationResponseValue& status) const {
    switch (type){
    case ValidationReqType::Quick:
        if (m_validatedBlocks.Exists_Quick(id))
        {
            BlockValidationDB::BlockValidationRecord_Quick record(id);
            m_validatedBlocks.ReadRes(id, record);
            status = record.getQuick();
            return status != ValidationResponseValue::Not_Checked;
        }
        break;
    case ValidationReqType::Quick_Smell:
        if (m_validatedBlocks.Exists_Quick(id))
        {
            BlockValidationDB::BlockValidationRecord_Quick record(id);
            m_validatedBlocks.ReadRes(id, record);
            status = record.getSmell();
            return status != ValidationResponseValue::Not_Checked;
        }
        break;
    case ValidationReqType::Full:
        if (m_validatedBlocks.Exists_Full(id))
        {
            BlockValidationDB::BlockValidationRecord_Full record(id);
            m_validatedBlocks.ReadRes(id, record);
            status = record.getFull();
            return status != ValidationResponseValue::Not_Checked;
        }
        break;
    case ValidationReqType::Challenge: {
        auto it = challenge_status_.find(id);
        if (it != challenge_status_.end()) {
            status = it->second;
            return true;
        }
        break;
    }
    case ValidationReqType::Model: {
        auto it = model_status_.find(id);
        if (it != model_status_.end()){
            status = it->second;
            return true;
        }
        break;
    }
    default: return false;
    }
    return false;
}

uint8_t ValidationAPI::GetOwnFullStatus(const uint256 &id) const {

    if (m_validatedBlocks.Exists_Full(id))
    {
        ValidationResponseValue status;
        BlockValidationDB::BlockValidationRecord_Full record(id);
        m_validatedBlocks.ReadRes(id, record);
        status = record.getFull(true);
        return static_cast<uint8_t>(status);
    }
    else
        return static_cast<uint8_t>(ValidationResponseValue::Not_Checked);
}

void ValidationAPI::StartThreads() {
    if (m_on.load()) {
        LogPrintf("ValidationAPI is started already");
        return;
    }

    m_on.store(true);

    reqThread = std::thread([this]() {
        this->JobSchedulerLoop();
    });

    solThread = std::thread([this]() {
        this->SolutionReceiverLoop();
    });

    behThread = std::thread([this]() {
        this->BehaviorLoop();
    });

    LogPrintf("ValidationAPI threads were started\n");
}

void ValidationAPI::StopThreads() {
    if (!m_on.load()) {
        LogPrintf("ValidationAPI is stopped already");
        return;
    }

    m_on.store(false);
    CancelHttpRequests();
    behcv.notify_all();  // wake BehaviorLoop now instead of waiting out its timeout

    // Interrupt the blocking receive
    if (!m_http_mode && context) {
        zmq_ctx_shutdown(context);
    }

    if (reqThread.joinable()) reqThread.join();
    if (solThread.joinable()) solThread.join();
    if (behThread.joinable()) behThread.join();

    LogPrintf("ValidationAPI threads were joined\n");
}
