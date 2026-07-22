#ifndef BITCOIN_NODE_VALIDATIONAPI_H
#define BITCOIN_NODE_VALIDATIONAPI_H

#include <apicomponents.h>
#include <array>
#include <atomic>
#include <algorithm>
#include <chrono>
#include <consensus/params.h>
#include <dbwrapper.h>
#include <crypto/sha256.h>
#include <deque>
#include <functional>
#include <limits>
#include <logging.h>
#include <condition_variable>
#include <memory>
#include <modeldb.h>
#include <mutex>
#include <optional>
#include <primitives/block.h>
#include <queue>
#include <rpc/blockheader_generated.h>
#include <script/script.h>
#include <serialize.h>
#include <shared_mutex>
#include <string.h>
#include <string>
#include <typeindex>
#include <uint256.h>
#include <unordered_map>
#include <unordered_set>
#include <util/fs.h>
#include <validation.h>
#include <vector>
#include <zmq.hpp>

static constexpr int DEFAULT_FULL_VALIDATION_TIP_WINDOW = 400;
static constexpr auto DELAY_BETWEEN_VALIDATION_REQUESTS = 1000;
static const uint16_t MAX_SHORT_VALIDATION_REQUEST_ATTEMPTS{10}; // Before failing
static const uint16_t MAX_MODEL_VALIDATION_REQUEST_ATTEMPTS{15}; // Before failing
static const uint16_t MAX_FULL_VALIDATION_REQUEST_ATTEMPTS{20}; // Before failing
static const uint16_t MAX_CHALLENGE_VALIDATION_REQUEST_ATTEMPTS{15}; // Before failing
// static constexpr auto DELAY_BETWEEN_VALIDATION_REQUESTS = 100;
// static const uint16_t MAX_SHORT_VALIDATION_REQUEST_ATTEMPTS{2}; // Before failing
// static const uint16_t MAX_MODEL_VALIDATION_REQUEST_ATTEMPTS{2}; // Before failing
// static const uint16_t MAX_FULL_VALIDATION_REQUEST_ATTEMPTS{5}; // Before failing

/** Option-2 advertised-difficulty decision (TIP-0003), factored
 *  out of ValidationAPI::SendApiRequest as a pure function for testability.
 *  The verification service reads BlockValidation.difficulty as BOTH the
 *  admission-target input AND the v3-active signal, so bcore advertises the
 *  registered model difficulty ONLY when v3 rules are active at the block's
 *  OWN height; otherwise 0 (the block is judged under v2 rules, byte-identical
 *  to consensus). `height < 0` (unknown parent in a precheck path) => 0. */
int64_t V3AdvertisedDifficulty(int height, const Consensus::Params& params,
                               int64_t registered_difficulty);

/** Startup soundness check for the v3 activation config (TIP-0003
 *  §5/§9): a finite V3ActivationHeight is only valid when red-block enforcement
 *  (external_api full replay) is on, since v3's fast-path B_cred free tier is
 *  unsound without it. Mockable/regtest chains are exempt (they test the fast
 *  path in isolation). Returns false for a config that must fail startup. */
bool IsV3ActivationConfigSound(int v3_activation_height, bool external_api,
                               bool is_mockable_chain);

/** Startup capability check: a finite V3ActivationHeight requires a binary
 *  whose pow_v3::argon2id_digest() is functional (built with libargon2) —
 *  an argonless node at a v3-active height rejects every consensus-valid
 *  admission-band block and forks off. No mockable exemption: argonless
 *  regtest with v3 active would misbehave identically. Returns false for a
 *  config that must fail startup. */
bool IsV3AdmissionVerifyCapable(int v3_activation_height, bool argon2_compiled);

/** Startup cross-language contract check: with a finite V3ActivationHeight,
 *  the chain's V3BFloorBits/V3BFreeBits must equal the compiled pow_v3
 *  constants the external Python verifier scores with — a params-only
 *  recalibration would silently split bcore from the verification fleet.
 *  Enforced at startup (not per-proof) so unit tests can parameterize the
 *  thresholds. Returns false for a config that must fail startup. */
bool IsV3TierParamsVendored(int v3_activation_height,
                            uint64_t v3_bfloor_bits, uint64_t v3_bfree_bits);

struct Hasher {
    std::size_t operator()(const uint256& val) const noexcept {
        return std::hash<std::string_view>()(
            std::string_view(reinterpret_cast<const char*>(&val), sizeof(val))
        );
    }
};

enum class ValidationReqType: uint8_t
{
    Quick = 0,
    Quick_Smell = 1,
    Full = 2,
    Model = 3,
    Challenge = 4
};

enum class ValidationResponseValue: uint8_t
{
    Not_Checked = 0,
    Quick_OK,
    Quick_Fail,
    Quick_OK_Smell_OK,
    Quick_OK_Smell_Fail,
    Quick_Fail_Smell_OK,
    Quick_Fail_Smell_Fail,
    Full_Green,
    Full_Amber,
    Full_Red,
    Model_OK,
    Model_Fail,
    Challenge_OK,
    Challenge_Fail,
    Model_Pending_Review
};

enum class ValidationResponseBehavior: uint8_t
{
    Unknown = 0,
    Nothing,
    AcceptBlock,
    ProcessNewBlock
};

//! Number of blocks from each best tip that non-live nodes fully validate.
//! Returns 0 when external Full validation should apply to every block.
int GetFullValidationTipWindow();

// Forward declarations
class ChainstateManager;
class CBlock;
struct ModelRecord;
class CConnman;

// Abstract interface for validation API - allows mocking in tests
class IValidationAPI {
public:
    virtual ~IValidationAPI() = default;
    
    // Core validation methods used by the codebase
    virtual void SendApiRequest(const CBlock& block, const ValidationReqType& type, const ValidationResponseBehavior& behavior) = 0;
    virtual void SendApiRequest(const uint256& req_id, const ModelRecord& model, const ValidationReqType& type) = 0;
    virtual void EnqueueApiRequest(const CBlock& block, const ValidationReqType& type, const ValidationResponseBehavior& behavior) {
        SendApiRequest(block, type, behavior);
    }
    virtual void EnqueueApiRequest(const uint256& req_id, const ModelRecord& model, const ValidationReqType& type) {
        SendApiRequest(req_id, model, type);
    }
    virtual bool TryLocalQuickVerdict(const CBlock&, ValidationResponseValue&) {
        return false;
    }
    virtual bool GetRequestStatus(const uint256& id, const ValidationReqType& type, ValidationResponseValue& status, bool async = true) const = 0;
    virtual bool SetRequestStatus(const uint256& id, const ValidationReqType& type, const ValidationResponseValue& status) = 0;
    virtual uint8_t GetOwnFullStatus(const uint256& id) const = 0;
    virtual bool RemoveRes_Full(const uint256& pid) = 0;
    virtual void RecordPeerFullStatus(const uint256& id, const std::string& peer_id, ValidationResponseValue peer_status) = 0;
    virtual bool Initialize() = 0;
    virtual bool IsFullQueueEmpty() const = 0;
    virtual bool ShouldDeferMissingFullValidation() const = 0;
    //! In-process mocks use GetRequestStatus() so configured defaults are honored.
    virtual bool UsesRequestStatusForBlockProcessing() const { return false; }
};

class ValidationAPI : public IValidationAPI {
private:
    struct HttpEndpoint {
        std::string base_url;
        std::string api_key;
    };
    struct HttpConfig {
        std::string base_url;
        std::vector<std::string> base_urls;
        std::string api_key;
        std::vector<HttpEndpoint> endpoints;
        std::chrono::milliseconds timeout{30000};
        bool https{true};
    };
    class BlockValidationDB{
    public:
        static constexpr size_t MAX_RECORDS = 1000; // maximum records to keep in the db
    public:
        struct BlockValidationRecord_Quick {
        public:
            BlockValidationRecord_Quick(const uint256& pid): 
                        id{pid}, QuickValidation{static_cast<uint8_t>(ValidationResponseValue::Not_Checked)},
                        SmellValidation{static_cast<uint8_t>(ValidationResponseValue::Not_Checked)} {
                ts = duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            }
            ValidationResponseValue getQuick() const;
            ValidationResponseValue getSmell() const;
            SERIALIZE_METHODS(BlockValidationRecord_Quick, obj) {
                READWRITE(obj.id, obj.QuickValidation, obj.SmellValidation, obj.ts);
            }
            
            uint256 id;
            uint8_t QuickValidation;
            uint8_t SmellValidation;
            uint64_t ts;
        };
        struct BlockValidationRecord_Full {
        public:
            BlockValidationRecord_Full(const uint256& pid): 
                        id{pid}, FullValidation{static_cast<uint8_t>(ValidationResponseValue::Not_Checked)}, nExtFull(0), extFulls{} {
                ts = duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            }
            ValidationResponseValue getFull(const bool own = false) const;
            bool addExtFull(const std::string& peerid, const ValidationResponseValue& value);
            SERIALIZE_METHODS(BlockValidationRecord_Full, obj) {
                READWRITE(obj.id, obj.FullValidation, obj.ts, obj.nExtFull);
                for (uint8_t i = 0; i < EXPECTED_EXTFULL_SIZE; i++)
                    READWRITE(obj.extFulls[i].first, obj.extFulls[i].second);
            }
            
            uint256 id;
            uint8_t FullValidation;
            uint64_t ts;
            uint8_t nExtFull;
            static constexpr uint8_t EXPECTED_EXTFULL_SIZE = 100;
            std::array<std::pair<std::string, uint8_t>, EXPECTED_EXTFULL_SIZE> extFulls;
        };
    private:
        std::unique_ptr<CDBWrapper> db_full;
        std::unique_ptr<CDBWrapper> db_quick;

    public:
        explicit BlockValidationDB(const Consensus::Params& consensusParams, size_t cache_size = 1 << 20, bool fMemory = false, bool fWipe = false);
    
        bool UpdateRes_Quick(const uint256& pid, const ValidationResponseValue& value);
        bool UpdateRes_Full(const uint256& pid, const ValidationResponseValue& value);
        bool UpdateExtFull(const uint256& pid, const std::string& peerid, const ValidationResponseValue& value);
        bool RemoveRes_Full(const uint256& pid);
        bool ReadRes(const uint256& pid, BlockValidationRecord_Quick& record) const;
        bool ReadRes(const uint256& pid, BlockValidationRecord_Full& record) const;
        bool Exists(const uint256& pid, const ValidationReqType& type) const;
        bool Exists_Quick(const uint256& pid) const;
        bool Exists_Full(const uint256& pid) const;
        bool Erase(const uint256& pid, const ValidationReqType& type);
        bool Erase_Quick(const uint256& pid);
        bool Erase_Full(const uint256& pid);
        bool IsEmpty(const ValidationReqType& type) const;
        bool IsEmpty_Quick() const;
        bool IsEmpty_Full() const;
        void PruneToMax();

        // Get recent validation records (for GUI display)
        struct RecentValidation {
            uint256 block_hash;
            uint8_t quick_status;
            uint8_t smell_status;
            uint8_t full_status;
            uint64_t timestamp;
            bool is_quick;  // true = quick record, false = full record
        };
        std::vector<RecentValidation> GetRecentRecords(size_t max_count = 20) const;
    };
    // Thread-safe request tracker
    class RequestTracker {
    public:
        struct LiveMeter
        {
            uint16_t n_attempts;
            uint64_t delay;
            uint64_t attempt_time;
            ValidationResponseBehavior behavior;
            LiveMeter() = default;
            explicit LiveMeter (const ValidationReqType& type, const ValidationResponseBehavior& pbehavior) {
                attempt_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                delay = DELAY_BETWEEN_VALIDATION_REQUESTS;
                switch (type) {
                case ValidationReqType::Quick:
                case ValidationReqType::Quick_Smell: 
                    n_attempts = MAX_SHORT_VALIDATION_REQUEST_ATTEMPTS;                 
                    break;
                case ValidationReqType::Full: 
                    n_attempts = MAX_FULL_VALIDATION_REQUEST_ATTEMPTS;
                    break;
                case ValidationReqType::Model: 
                    n_attempts = MAX_MODEL_VALIDATION_REQUEST_ATTEMPTS;
                    break;
                case ValidationReqType::Challenge:
                    n_attempts = MAX_CHALLENGE_VALIDATION_REQUEST_ATTEMPTS;
                    break;
                default:
                    n_attempts = 0;
                    delay = 0;
                    break;
                }
                behavior = pbehavior;
            }

            inline bool readyToUpdate(const uint64_t& now){
                if (std::numeric_limits<uint64_t>::max() - delay < attempt_time) {
                    return true;
                }
                return now >= attempt_time + delay;
            }

            inline bool canAttempt() const {
                return n_attempts > 0;
            }

            inline bool newAttempt(const uint64_t& now){
                if (n_attempts == 0)
                    return false;
                n_attempts--;
                delay = delay * 2;
                attempt_time = now;
                return true;
            }

            // Defer without burning an attempt — resets the timer so we don't
            // spin every 100ms on requests the server already accepted as pending.
            inline void snooze(const uint64_t& now){
                attempt_time = now;
            }
        };
        mutable std::shared_mutex mutex_;
        std::unordered_map<uint256, std::pair<CBlock, LiveMeter>, Hasher> short_requests_;
        std::unordered_map<uint256, std::pair<CBlock, LiveMeter>, Hasher> short_smell_requests_;
        std::unordered_map<uint256, std::pair<CBlock, LiveMeter>, Hasher> full_requests_;
        std::unordered_map<uint256, std::pair<CBlock, LiveMeter>, Hasher> challenge_requests_;
        std::unordered_map<uint256, std::pair<ModelRecord, LiveMeter>, Hasher> model_requests_;

        bool makeNewRequest(const CBlock& newRequest, const ValidationReqType& type, uint256& req_id, const ValidationResponseBehavior& behavior) {
            if (type != ValidationReqType::Full && type != ValidationReqType::Quick && type != ValidationReqType::Quick_Smell && type != ValidationReqType::Challenge) {
                req_id = uint256::ZERO;
                return false;
            }
            std::unique_lock lock(mutex_);
            
            uint256 new_id = newRequest.GetHash();
            std::unordered_map<uint256, std::pair<CBlock, LiveMeter>, Hasher>& current_queue =
                type == ValidationReqType::Full ? full_requests_
                                                : (type == ValidationReqType::Quick
                                                       ? short_requests_
                                                       : (type == ValidationReqType::Quick_Smell ? short_smell_requests_ : challenge_requests_));
            
            req_id = new_id;
            auto it = current_queue.find(new_id);
            if (it != current_queue.end()) {
                // Upgrade passive polling requests to an actionable callback
                // when a later caller needs the block reprocessed asynchronously.
                if (it->second.second.behavior == ValidationResponseBehavior::Nothing &&
                    behavior != ValidationResponseBehavior::Nothing) {
                    it->second.second.behavior = behavior;
                }
                return false;
            }
            current_queue[new_id] = {newRequest, LiveMeter(type, behavior)}; 
            return true;
        }

        bool makeNewRequest(const uint256& req_id, const ModelRecord& newRequest, const ValidationReqType& type) {
            if (type != ValidationReqType::Model) {
                return false;
            }
            std::unique_lock lock(mutex_);

            auto it = model_requests_.find(req_id);
            if (it != model_requests_.end()) {
                return false;
            }
            model_requests_[req_id] = {newRequest, LiveMeter(type, ValidationResponseBehavior::Nothing)};
            return true;
        }

        ValidationResponseBehavior finishRequest(const uint256& id, const ValidationReqType& type) {
            std::unique_lock lock(mutex_);
        
            switch (type){
            case ValidationReqType::Quick: {
                    auto it = short_requests_.find(id);
                    if (it != short_requests_.end()) {
                        ValidationResponseBehavior behavior = it->second.second.behavior;
                        short_requests_.erase(it);
                        return behavior;
                    }
                }
                break;
            case ValidationReqType::Quick_Smell: {
                    auto it = short_smell_requests_.find(id);
                    if (it != short_smell_requests_.end()) {
                        ValidationResponseBehavior behavior = it->second.second.behavior;
                        short_smell_requests_.erase(it);
                        return behavior;
                    }
                }
                break;
            case ValidationReqType::Full: {
                    auto it = full_requests_.find(id);
                    if (it != full_requests_.end()){
                        ValidationResponseBehavior behavior = it->second.second.behavior;
                        full_requests_.erase(it);
                        return behavior;
                    }
                }
                break;
            case ValidationReqType::Challenge: {
                    auto it = challenge_requests_.find(id);
                    if (it != challenge_requests_.end()){
                        ValidationResponseBehavior behavior = it->second.second.behavior;
                        challenge_requests_.erase(it);
                        return behavior;
                    }
                }
                break;
            case ValidationReqType::Model: {
                    auto it = model_requests_.find(id);
                    if (it != model_requests_.end()){
                        ValidationResponseBehavior behavior = it->second.second.behavior;
                        model_requests_.erase(it);
                        return behavior;
                    }
                }
                break;
            }
            return ValidationResponseBehavior::Unknown;
        }

        std::optional<CBlock> getBlockForId(uint256 id, const ValidationReqType& type) const {
            if (type != ValidationReqType::Full && type != ValidationReqType::Quick && type != ValidationReqType::Quick_Smell && type != ValidationReqType::Challenge) {
                return std::nullopt;
            }
            const auto& current_queue = (type == ValidationReqType::Full)
                                            ? full_requests_
                                            : (type == ValidationReqType::Quick
                                                   ? short_requests_
                                                   : (type == ValidationReqType::Quick_Smell ? short_smell_requests_ : challenge_requests_));
            auto it = current_queue.find(id);
            if (it != current_queue.end()) {
                return it->second.first;
            }
            return std::nullopt;
        }
    };

    struct AmberRequest {
        CBlock block;
        ValidationResponseBehavior behavior{ValidationResponseBehavior::Nothing};
        ValidationResponseValue initial_status{ValidationResponseValue::Full_Amber};
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point next_send;
        int attempts{0};
        int expected_peers{0};
        // Set while a getheaders dispatch has been queued but its peer count
        // is not yet recorded in expected_peers (the send happens outside
        // amber_mutex_). Peer votes must not finalize against an unrecorded
        // expected-peer set: with expected_peers still 0 a single fast Red
        // response would read as "no peers were polled" and finalize alone.
        bool dispatch_in_flight{false};
        bool force_finalize{false};
        std::optional<std::chrono::steady_clock::time_point> finalize_deadline;
    };
public:
    ValidationAPI(ChainstateManager& chainman, const Consensus::Params& consensusParams, bool desktop_mode = false);
    ~ValidationAPI() override;

    void SendApiRequest(const CBlock& block, const ValidationReqType& type, const ValidationResponseBehavior& behavior) override;
    void SendApiRequest(const uint256& req_id, const ModelRecord& model, const ValidationReqType& type) override;
    void EnqueueApiRequest(const CBlock& block, const ValidationReqType& type, const ValidationResponseBehavior& behavior) override;
    void EnqueueApiRequest(const uint256& req_id, const ModelRecord& model, const ValidationReqType& type) override;
    bool TryLocalQuickVerdict(const CBlock& block, ValidationResponseValue& status) override;
    void SendApiRequest(const uint256 &req_id, const CBlock& block, const ValidationReqType& type);
    void SendApiRequestInternal(const uint256 &req_id, const ModelRecord& model, const ValidationReqType& type);
    bool GetRequestStatus(const uint256 &id, const ValidationReqType& type, ValidationResponseValue& status, bool async = true) const override;
    bool GetRequestStatusImpl(const uint256 &id, const ValidationReqType& type, ValidationResponseValue& status) const;
    uint8_t GetOwnFullStatus(const uint256 &id) const override;
    bool SetRequestStatus(const uint256 &id, const ValidationReqType& type, const ValidationResponseValue& status) override;
    bool RemoveRes_Full(const uint256& pid) override;
    void RecordPeerFullStatus(const uint256& id, const std::string& peer_id, ValidationResponseValue peer_status) override;
    ValidationResponseBehavior GetApiAnswer(uint256 &id, ValidationReqType& type);
    void StartThreads();
    void StopThreads();
    bool Initialize() override;
    bool IsFullQueueEmpty() const override;
    bool ShouldDeferMissingFullValidation() const override { return m_http_mode && !HasHttpApiKey(); }
    void SetConnman(CConnman* connman);

    // Getters for monitoring
    bool IsConnectionHealthy() const { return connection_healthy_.load(); }
    bool IsDesktopMode() const { return m_desktop_mode; }
    const EnvConfig& GetConfig() const { return config; }
    size_t GetQuickQueueSize() const;
    size_t GetQuickSmellQueueSize() const;
    size_t GetFullQueueSize() const;
    size_t GetModelQueueSize() const;
    size_t GetChallengeQueueSize() const;
    std::vector<BlockValidationDB::RecentValidation> GetRecentValidations(size_t max_count = 20) const {
        return m_validatedBlocks.GetRecentRecords(max_count);
    }

private:
    // Helpers
    ValidationResponseValue RunLocalQuick(const CBlock& block);
    bool TrySetLocalQuickSmellFinalHashFailure(const CBlock& block);
    bool TryFetchPublicStatusSync(const uint256& req_id, const ValidationReqType& req_type);
    bool TryFetchAuthStatusSync(const uint256& req_id, const ValidationReqType& req_type);
    uint16_t SendHttpRequest(const uint256& req_id,
                                const std::vector<uint8_t>& payload,
                                const ValidationReqType& req_type);
    ValidationResponseBehavior GettHttpStatus(uint256& req_id, ValidationReqType& req_type);
    void EnqueueStatusRequest(const uint256& req_id, const ValidationReqType& req_type);
    void ReconcileHttpStatusQueueWithTrackedRequests(uint64_t now_ms);
    bool UseHttpTransport() const { return m_http_mode; }
    bool UseLocalQuick() const { return m_desktop_mode || m_http_mode; }
    bool HasHttpApiKey() const {
        if (!http_config_.api_key.empty()) {
            return true;
        }
        return std::any_of(http_config_.endpoints.begin(), http_config_.endpoints.end(),
                           [](const HttpEndpoint& endpoint) { return !endpoint.api_key.empty(); });
    }

    void JobSchedulerLoop();
    void SolutionReceiverLoop();
    void BehaviorLoop();
    void checkNetworkHealth();
    void StartAmberFlow(const uint256& id, const CBlock& block, ValidationResponseBehavior behavior, ValidationResponseValue initial_status = ValidationResponseValue::Full_Amber);
    void ProcessAmberRequests();
    bool ShouldFinalizeAmber(const uint256& id, const AmberRequest& request, bool force_finalize) const;
    int DispatchAmberGetHeaders(const uint256& id);
    void FinalizeAmber(const uint256& id, AmberRequest&& request);

    // std::unordered_map<uint256, ValidationResponseValue, Hasher> short_status_;
    // std::unordered_map<uint256, ValidationResponseValue, Hasher> full_status_;
    std::unordered_map<uint256, ValidationResponseValue, Hasher> model_status_;
    
    ChainstateManager& m_chainman;
    BlockValidationDB m_validatedBlocks;
    EnvConfig config;
    HttpConfig http_config_;
    bool m_http_mode{false};
    bool m_desktop_mode{false};
    void* context{nullptr};
    void* reqPush{nullptr};
    void* solPull{nullptr};
    std::string addressPush;
    std::string addressPull;

    std::atomic<bool> waitingApiAnswer{false};
    std::atomic<bool> m_on{false};
    
    // New members for monitoring and protection
    RateLimiter rateLimiter_;
    std::atomic<bool> connection_healthy_{true};
    std::chrono::steady_clock::time_point last_send_success_;
    static constexpr auto PARTITION_TIMEOUT = std::chrono::seconds(30);
    static constexpr uint64_t HTTP_PENDING_MAX_AGE_SHORT_MS = 30 * 1000;
    static constexpr uint64_t HTTP_PENDING_MAX_AGE_LONG_MS = 5 * 60 * 1000;
    static constexpr uint64_t HTTP_PENDING_MAX_AGE_MODEL_REVIEW_MS = 24ULL * 60 * 60 * 1000;  // 24h for operator review
    static constexpr uint64_t HTTP_PUBLIC_NAN_INITIAL_BACKOFF_MS = 100;
    static constexpr uint64_t HTTP_PUBLIC_NAN_MAX_BACKOFF_MS = 1000;
    static constexpr uint64_t HTTP_PUBLIC_NAN_MAX_AGE_SHORT_MS = 30 * 1000;
    static constexpr uint64_t HTTP_PUBLIC_NAN_MAX_AGE_LONG_MS = 60 * 60 * 1000;
    static constexpr uint16_t HTTP_PUBLIC_NAN_MAX_POLLS_SHORT = 16;
    static constexpr uint16_t HTTP_PUBLIC_NAN_MAX_POLLS_LONG = 4096;
    
    RequestTracker requestTracker;
    struct StatusKey {
        uint256 id;
        ValidationReqType type;
        bool operator==(const StatusKey& other) const { return id == other.id && type == other.type; }
    };
    struct StatusQueueMeta {
        uint64_t first_seen_ms{0};
        uint64_t next_poll_ms{0};
        uint64_t nan_backoff_ms{0};
        uint16_t nan_miss_count{0};
    };
    struct StatusKeyHasher {
        size_t operator()(const StatusKey& key) const noexcept {
            size_t h = Hasher{}(key.id);
            h ^= static_cast<size_t>(key.type) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
            return h;
        }
    };
    bool IsHttpStatusAcceptedPending(const uint256& req_id, const ValidationReqType& req_type) const {
        std::lock_guard<std::mutex> lock(status_queue_mutex_);
        return http_status_accepted_pending_.count(StatusKey{req_id, req_type}) > 0;
    }
    static constexpr uint64_t HttpPendingMaxAgeMs(const ValidationReqType& req_type) {
        switch (req_type) {
        case ValidationReqType::Quick:
        case ValidationReqType::Quick_Smell:
            return HTTP_PENDING_MAX_AGE_SHORT_MS;
        case ValidationReqType::Full:
        case ValidationReqType::Challenge:
        case ValidationReqType::Model:
            return HTTP_PENDING_MAX_AGE_LONG_MS;
        default:
            return HTTP_PENDING_MAX_AGE_SHORT_MS;
        }
    }
    static constexpr uint64_t HttpPublicNanMaxAgeMs(const ValidationReqType& req_type) {
        switch (req_type) {
        case ValidationReqType::Quick:
        case ValidationReqType::Quick_Smell:
            return HTTP_PUBLIC_NAN_MAX_AGE_SHORT_MS;
        case ValidationReqType::Full:
        case ValidationReqType::Challenge:
        case ValidationReqType::Model:
            return HTTP_PUBLIC_NAN_MAX_AGE_LONG_MS;
        default:
            return HTTP_PUBLIC_NAN_MAX_AGE_SHORT_MS;
        }
    }
    static constexpr uint16_t HttpPublicNanMaxPolls(const ValidationReqType& req_type) {
        switch (req_type) {
        case ValidationReqType::Quick:
        case ValidationReqType::Quick_Smell:
            return HTTP_PUBLIC_NAN_MAX_POLLS_SHORT;
        case ValidationReqType::Full:
        case ValidationReqType::Challenge:
        case ValidationReqType::Model:
            return HTTP_PUBLIC_NAN_MAX_POLLS_LONG;
        default:
            return HTTP_PUBLIC_NAN_MAX_POLLS_SHORT;
        }
    }
    bool IsHttpStatusAcceptedPendingStale(const uint256& req_id, const ValidationReqType& req_type) {
        std::lock_guard<std::mutex> lock(status_queue_mutex_);
        const StatusKey key{req_id, req_type};
        if (http_status_accepted_pending_.count(key) == 0) {
            return false;
        }
        const auto it = http_status_accepted_pending_since_.find(key);
        if (it == http_status_accepted_pending_since_.end()) {
            return false;
        }
        const auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - it->second);
        if (age.count() < 0) return false;
        // Operator-review-pending entries get a much longer timeout (24h vs 5min)
        if (model_review_pending_.count(key) > 0) {
            if (static_cast<uint64_t>(age.count()) >= HTTP_PENDING_MAX_AGE_MODEL_REVIEW_MS) {
                model_review_pending_.erase(key);
                return true;  // Expired — retries resume, caller applies req-type default
            }
            return false;  // Still within 24h review window
        }
        return static_cast<uint64_t>(age.count()) >= HttpPendingMaxAgeMs(req_type);
    }
    bool IsOperatorReviewPending(const uint256& id, const ValidationReqType& req_type) const {
        std::lock_guard<std::mutex> lock(status_queue_mutex_);
        return model_review_pending_.count(StatusKey{id, req_type}) > 0;
    }
    void ClearOperatorReviewPending(const uint256& id, const ValidationReqType& req_type) {
        std::lock_guard<std::mutex> lock(status_queue_mutex_);
        model_review_pending_.erase(StatusKey{id, req_type});
    }
    bool IsModelReviewPending(const uint256& id) const {
        return IsOperatorReviewPending(id, ValidationReqType::Model);
    }
    void ClearModelReviewPending(const uint256& id) {
        ClearOperatorReviewPending(id, ValidationReqType::Model);
    }
    void MarkHttpStatusAcceptedPending(const StatusKey& key) {
        std::lock_guard<std::mutex> lock(status_queue_mutex_);
        http_status_accepted_pending_.insert(key);
        http_status_accepted_pending_since_.try_emplace(key, std::chrono::steady_clock::now());
    }
    void ClearStatusQueueEntry(const StatusKey& key) {
        std::lock_guard<std::mutex> lock(status_queue_mutex_);
        auto qit = std::find(status_queue_.begin(), status_queue_.end(), key);
        if (qit != status_queue_.end()) {
            status_queue_.erase(qit);
        }
        status_queue_set_.erase(key);
        http_status_accepted_pending_.erase(key);
        http_status_accepted_pending_since_.erase(key);
        status_queue_meta_.erase(key);
    }
    void ClearHttpStatusAcceptedPending(const StatusKey& key) {
        std::lock_guard<std::mutex> lock(status_queue_mutex_);
        http_status_accepted_pending_.erase(key);
        http_status_accepted_pending_since_.erase(key);
    }
    mutable std::mutex status_queue_mutex_;
    std::deque<StatusKey> status_queue_;
    std::unordered_set<StatusKey, StatusKeyHasher> status_queue_set_;
    std::unordered_map<StatusKey, StatusQueueMeta, StatusKeyHasher> status_queue_meta_;
    std::unordered_set<StatusKey, StatusKeyHasher> http_status_accepted_pending_;
    std::unordered_map<StatusKey, std::chrono::steady_clock::time_point, StatusKeyHasher> http_status_accepted_pending_since_;
    std::unordered_set<StatusKey, StatusKeyHasher> model_review_pending_;  // Requests awaiting operator review (24h timeout)
    // Auth batch error backoff: escalates on fast failures (5xx, connection error),
    // resets on any successful long-poll response.
    std::atomic<int64_t> last_auth_batch_error_ms_{0};
    std::atomic<int64_t> auth_batch_error_backoff_ms_{0};
    // Public-path adaptive backoff only for transport/rate-limit failures.
    std::atomic<int64_t> last_public_poll_ms_{0};
    std::atomic<int64_t> public_error_backoff_ms_{0};
    
    std::thread reqThread;
    std::thread solThread;
    std::thread behThread;
    mutable std::shared_mutex behmutex;
    std::condition_variable_any behcv;  // wakes BehaviorLoop on enqueue/shutdown; replaces busy-poll
    std::vector<std::tuple<uint256, ValidationReqType, ValidationResponseBehavior, CBlock>> behaviors;
    std::unordered_map<uint256, ValidationResponseValue, Hasher> challenge_status_;
    
    std::mutex amber_mutex_;
    std::unordered_map<uint256, AmberRequest, Hasher> amber_requests_;
    std::unordered_set<uint256, Hasher> revalidation_attempted_;
    CConnman* m_connman{nullptr};

    // Validation constants
    static constexpr size_t EXPECTED_HASH_SIZE = 32;
};

extern std::unique_ptr<IValidationAPI> g_ValidationApi;

#endif // BITCOIN_NODE_VALIDATIONAPI_H
