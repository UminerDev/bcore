#ifndef BITCOIN_NODE_EXTAPI_H
#define BITCOIN_NODE_EXTAPI_H

#include <apicomponents.h>
#include <atomic>
#include <functional>
#include <memory>
#include <primitives/block.h>
#include <rpc/blockheader_generated.h>
#include <script/script.h>
#include <string.h>
#include <typeindex>
#include <univalue.h>
#include <zmq.hpp>
#include <shared_mutex>
#include <optional>
#include <limits>
#include <stdexcept>
#include <logging.h>
#include <algorithm>
#include <unordered_map>
#include <chrono>
#include <queue>
#include <mutex>

static const uint64_t DELAY_BETWEEN_MINING_REQUESTS{10000};
// Default for -maxminingworkunits: outstanding work units tracked per
// RequestTracker before the oldest is evicted. Must exceed the number of
// work units minted per REQUEST_EXPIRY window, or solutions for evicted
// units are rejected as unknown_req_id — a pool minting one unit per
// connected miner per tip needs this above (miners x blocks per window).
static const uint32_t DEFAULT_MAX_MINING_WORK_UNITS{1024};
static const uint32_t MAX_REQUEST_ID{10000000}; // Prevent unbounded growth
static_assert(MAX_REQUEST_ID > 1, "Static MAX_REQUEST_ID const must be greater than 1");
static const uint32_t MAX_REQUEST_ID_RESET_VALUE{MAX_REQUEST_ID - 1}; // Prevent unbounded growth
static const int ZMQ_TIMEOUT_MS{600000}; // 10 minutes

namespace node {

// -maxminingworkunits from gArgs, clamped to >= 1 (default
// DEFAULT_MAX_MINING_WORK_UNITS). Shared by ExtAPI's tracker and the
// broker work-unit tracker in rpc/mining.cpp.
uint32_t MaxMiningWorkUnitsFromArgs();

// Thread-safe request tracker
class RequestTracker {
private:
    enum class RequestState {
        Open,
        Submitted,
    };

    struct RequestEntry {
        CBlock block;
        std::chrono::steady_clock::time_point created_at;
        RequestState state{RequestState::Open};
        std::optional<uint256> submitted_hash;
    };

public:
    enum class LookupState {
        Missing,
        Available,
        Submitted,
    };

    struct LookupResult {
        LookupState state{LookupState::Missing};
        std::optional<CBlock> block;
        std::optional<uint256> submitted_hash;
    };

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<uint32_t, RequestEntry> requests_;
    uint32_t current_id_{0};
    uint32_t max_open_{DEFAULT_MAX_MINING_WORK_UNITS};
    static constexpr auto REQUEST_EXPIRY = std::chrono::minutes(10);

public:
    // Bound on tracked entries before oldest-first eviction (-maxminingworkunits).
    // Clamped to >= 1 so the entry minted by the current insert always survives it.
    void setMaxOpenRequests(uint32_t max_open) {
        std::unique_lock lock(mutex_);
        max_open_ = std::max<uint32_t>(max_open, 1);
    }

    uint32_t incrementAndStore(const CBlock& newRequest) {
        std::unique_lock lock(mutex_);
        
        // Clean old entries
        auto now = std::chrono::steady_clock::now();
        for (auto it = requests_.begin(); it != requests_.end();) {
            if (now - it->second.created_at > REQUEST_EXPIRY) {
                it = requests_.erase(it);
            } else {
                ++it;
            }
        }
        
        // Add new request
        uint32_t new_id = (current_id_ % MAX_REQUEST_ID) + 1;
        current_id_ = new_id;
        requests_[new_id] = RequestEntry{
            newRequest, now, RequestState::Open, std::nullopt};

        // Keep size bounded: evict oldest first. Ties on created_at (bulk
        // minting within one clock tick) break on id so eviction order is
        // deterministic and follows insertion order.
        while (requests_.size() > max_open_) {
            auto oldest = std::min_element(requests_.begin(), requests_.end(),
                [](const auto& a, const auto& b) {
                    if (a.second.created_at != b.second.created_at) return a.second.created_at < b.second.created_at;
                    return a.first < b.first;
                });
            requests_.erase(oldest);
        }

        return new_id;
    }

    // Restore or insert a caller-owned durable identifier. Broker mode uses
    // this after fsyncing the corresponding work-unit journal entry, so a
    // node restart cannot make a still-valid solution unrecoverable.
    void storeWithId(uint32_t id, const CBlock& request) {
        std::unique_lock lock(mutex_);
        if (id == 0 || id >= MAX_REQUEST_ID) {
            throw std::invalid_argument("request id outside durable tracker range");
        }
        auto now = std::chrono::steady_clock::now();
        requests_[id] = RequestEntry{
            request, now, RequestState::Open, std::nullopt};
        while (requests_.size() > max_open_) {
            auto oldest = std::min_element(requests_.begin(), requests_.end(),
                [](const auto& a, const auto& b) {
                    if (a.second.created_at != b.second.created_at) return a.second.created_at < b.second.created_at;
                    return a.first < b.first;
                });
            requests_.erase(oldest);
        }
    }

    LookupResult getRequestForSolution(uint32_t id) const {
        std::shared_lock lock(mutex_);
        auto it = requests_.find(id);
        if (it == requests_.end()) {
            return {};
        }

        if (it->second.state == RequestState::Submitted) {
            return LookupResult{
                LookupState::Submitted, std::nullopt, it->second.submitted_hash};
        }

        return LookupResult{LookupState::Available, it->second.block, std::nullopt};
    }

    bool markSubmitted(uint32_t id, std::optional<uint256> submitted_hash = std::nullopt) {
        std::unique_lock lock(mutex_);
        auto it = requests_.find(id);
        if (it == requests_.end()) {
            return false;
        }
        it->second.state = RequestState::Submitted;
        it->second.submitted_hash = submitted_hash;
        return true;
    }

    // Returns true iff an entry with this id existed and was erased.
    // Idempotent: a second call for the same id (or any unknown id)
    // returns false without throwing. Callers that don't care about
    // the distinction may ignore the return.
    bool remove(uint32_t id) {
        std::unique_lock lock(mutex_);
        return requests_.erase(id) > 0;
    }
};

// Add metrics struct
struct MiningMetrics {
    std::atomic<uint64_t> solutions_received{0};
    std::atomic<uint64_t> solutions_accepted{0};
    std::atomic<uint64_t> solutions_rejected{0};
    std::atomic<uint64_t> solutions_duplicates{0};
    std::atomic<uint64_t> rate_limited{0};
    std::atomic<uint64_t> network_errors{0};
    std::atomic<uint64_t> last_solution_time{0};
    // Miner proxy stats
    std::atomic<uint64_t> jobs_sent{0};           // Jobs/tokens sent to miner proxy
    std::atomic<uint64_t> jobs_sent_failed{0};    // Jobs that failed to send
};

class ExtAPI {
public:
    ExtAPI(NodeContext& node);
    ~ExtAPI();

    void SendApiRequest(CBlock& block);
    bool GetApiAnswer(CBlock& block, const bool wait_answer, uint32_t* request_id_out = nullptr);
    UniValue StartMining(CScript& coinbase_output_script);
    UniValue StartMiningWithCallback(std::function<CScript()> get_coinbase_script);
    UniValue StopMining();
    bool Initialize();

    // Getters for monitoring
    const MiningMetrics& GetMetrics() const { return metrics_; }
    bool IsConnectionHealthy() const { return connection_healthy_.load(); }
    const EnvConfig& GetConfig() const { return config; }
    // True when -miningbrokermode=1 at startup. Mutually exclusive with
    // sovereign self-hosted mining; the broker drives work via
    // create_mining_work_unit / submit_mining_response RPCs and the MINER
    // PUSH/PULL transport must not be bound.
    bool IsBrokerMode() const { return m_broker_mode; }

private:
    enum class MiningResponseDisposition {
        Valid,
        Stale,
        Invalid,
    };

    bool EnsureSockets();
    void JobSchedulerLoop();
    void SolutionReceiverLoop();
    MiningResponseDisposition ValidateMiningResponse(
        const proof::MiningResponse* resp,
        CBlock& block,
        uint32_t* request_id_out
    );
    void checkNetworkHealth();
    void publishMetrics() const;
    
    NodeContext& m_node;
    EnvConfig config;
    // Fixed at construction from gArgs("-miningbrokermode"). When true, the
    // sovereign mining transport (PUSH job loop + PULL solution socket) is
    // never started; the compute-broker RPCs are the only path.
    const bool m_broker_mode;
    void* context{nullptr};
    void* jobPush{nullptr};
    void* solPull{nullptr};
    std::string addressMinerPush;
    std::string addressMinerPull;
    CScript m_coinbase_output_script;
    std::function<CScript()> m_get_coinbase_script;  // Callback for rotating addresses
    bool m_use_callback{false};

    std::atomic<bool> waitingApiAnswer{false};
    std::atomic<bool> mining_on{false};
    
    // New members for monitoring and protection
    MiningMetrics metrics_;
    RateLimiter rateLimiter_;
    std::atomic<bool> connection_healthy_{true};
    std::chrono::steady_clock::time_point last_send_success_;
    static constexpr auto PARTITION_TIMEOUT = std::chrono::seconds(30);
    
    RequestTracker requestTracker;
    
    std::thread jobThread;
    std::thread solThread;
    
    // Validation constants
    static constexpr size_t EXPECTED_HASH_SIZE = 32;
};

}

#endif // BITCOIN_NODE_EXTAPI_H
