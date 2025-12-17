#pragma once

#include <atomic>
#include <boost/unordered_map.hpp>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <queue>
#include <shared_mutex>
#include <thread>

#include "core.h"


namespace pepctl 
{


/*
    Policy evaluation result
*/
struct PolicyEvaluationResult
{
    PolicyAction action;
    std::string policy_id;
    bool rate_limited;
    uint64_t rate_limit_bps;

    PolicyEvaluationResult() : action(PolicyAction::ALLOW), rate_limited(false), rate_limit_bps(0)
    {

    }

    PolicyEvaluationResult(PolicyAction act, const std::string& id) :
        action(act),
        policy_id(id),
        rate_limited(false),
        rate_limit_bps(0)
    {

    }
};

/*
    Policy hash key for efficient lookup
*/
struct PolicyKey
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    Protocol protocol;

    PolicyKey() = default;

    PolicyKey(const NetworkAddress& src, const NetworkAddress& dst) :
        src_ip(src.ip),
        dst_ip(dst.ip),
        src_port(src.port),
        dst_port(dst.port),
        protocol(src.protocol)
    {

    }

    bool operator==(const PolicyKey& other) const
    {
        return src_ip == other.src_ip && dst_ip == other.dst_ip && src_port == other.src_port
               && dst_port == other.dst_port && protocol == other.protocol;
    }
};

/*
    Hash function for PolicyKey
*/
struct PolicyKeyHash
{
    std::size_t operator()(const PolicyKey& key) const
    {
        std::size_t h1 = std::hash<uint32_t>{}(key.src_ip);
        std::size_t h2 = std::hash<uint32_t>{}(key.dst_ip);
        std::size_t h3 = std::hash<uint16_t>{}(key.src_port);
        std::size_t h4 = std::hash<uint16_t>{}(key.dst_port);
        std::size_t h5 = std::hash<uint8_t>{}(static_cast<uint8_t>(key.protocol));

        // Combine hashes
        return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3) ^ (h5 << 4);
    }
};

/*
    Policy update operations for lock-free updates
*/
enum class PolicyOperation
{
    ADD,
    UPDATE,
    REMOVE
};

struct PolicyUpdate
{
    PolicyOperation operation;
    std::shared_ptr<Policy> policy;
    std::string policy_id;

    PolicyUpdate() = default;

    PolicyUpdate(PolicyOperation op, std::shared_ptr<Policy> pol) :
        operation(op),
        policy(std::move(pol))
    {

    }

    PolicyUpdate(PolicyOperation op, const std::string& id) : operation(op), policy_id(id) 
    {

    }
};

/*
    Rate limiting state
*/
struct RateLimitState
{
    std::atomic<uint64_t> bytes_this_second{0};
    std::atomic<std::chrono::seconds::rep> last_reset_time{0};
    uint64_t limit_bps;

    RateLimitState(uint64_t limit) : limit_bps(limit)
    {
        last_reset_time.store(std::chrono::duration_cast<std::chrono::seconds>(
                                  std::chrono::system_clock::now().time_since_epoch())
                                  .count());
    }
};

/*
    Main PolicyEngine class
*/
class PolicyEngine
{
  public:
    PolicyEngine();
    virtual ~PolicyEngine();

    /*
        Initialization
    */
    bool initialize(size_t capacity = defaultPolicyCapacity);
    void shutdown();

    /*
        Policy management (thread-safe)
    */
    static bool addPolicy(const Policy& policy);
    static bool updatePolicy(const std::string& policy_id, const Policy& policy);
    static bool removePolicy(const std::string& policy_id);
    static std::shared_ptr<Policy> getPolicy(const std::string& policy_id);
    static std::vector<std::shared_ptr<Policy>> getAllPolicies();

    /*
        Policy evaluation (high-performance, lock-free)
    */
    static PolicyEvaluationResult evaluatePacket(const PacketInfo& packet);

    /*
        JSON serialization
    */
    static bool loadPoliciesFromJson(const std::string& json_str);
    static bool loadPoliciesFromFile(const std::string& filename);
    static std::string exportPoliciesToJson();
    static bool savePoliciesToFile(const std::string& filename);

    /*
        Statistics
    */
    static size_t getPolicyCount();
    static void cleanupExpiredPolicies();

    /*
        Rate limiting
    */
    static bool isRateLimited(const PolicyKey& key, uint32_t packet_size, uint64_t limit_bps);

  private:
    /*
        Lock-free policy storage
    */
    using PolicyMap = boost::unordered_map<std::string, std::shared_ptr<Policy>>;
    using PolicyLookupMap = boost::unordered_map<PolicyKey, std::string, PolicyKeyHash>;
    using RateLimitMap =
        boost::unordered_map<PolicyKey, std::unique_ptr<RateLimitState>, PolicyKeyHash>;

    /*
        Thread-safe policy storage with RCU-like semantics
    */
    mutable std::shared_mutex m_policiesMutex;
    std::unique_ptr<PolicyMap> m_policies;
    std::unique_ptr<PolicyLookupMap> m_policyLookup;

    /*
        Rate limiting storage
    */
    mutable std::shared_mutex m_rateLimitMutex;
    std::unique_ptr<RateLimitMap> m_rateLimits;

    /*
        Thread-safe update queue (replaces lockfree queue)
    */
    std::queue<PolicyUpdate> m_updateQueue;
    std::mutex m_updateQueueMutex;
    std::condition_variable m_updateQueueCv;

    /*
        Background processing
    */
    std::atomic<bool> m_isRunning;
    std::thread m_updateProcessorThread;
    std::thread m_cleanupThread;

    /*
        Configuration
    */
    size_t m_capacity{};
    std::chrono::seconds m_cleanupInterval{};

    /*
        Private methods
    */
    void processUpdates();
    void processSingleUpdate(const PolicyUpdate& update);
    static PolicyKey createPolicyKey(const PacketInfo& packet);
    std::shared_ptr<Policy> findMatchingPolicy(const PolicyKey& key) const;
    void rebuildLookupMap();
    void periodicCleanup();
    static bool matchesPolicy(const Policy& policy, const PolicyKey& key);

    /*
        JSON helpers
    */
    static nlohmann::json policyToJson(const Policy& policy);
    static std::optional<Policy> jsonToPolicy(const nlohmann::json& json);
};


}  // namespace pepctl