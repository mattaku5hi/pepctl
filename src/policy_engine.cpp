#include <algorithm>
#include <boost/core/ignore_unused.hpp>
#include <chrono>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <optional>

#include "pepctl/logger.h"
#include "pepctl/policy_engine.h"


namespace pepctl
{

/*
    Global instance for static methods
*/
static PolicyEngine* gPolicyEngineInstance = nullptr;

PolicyEngine::PolicyEngine() :
    m_policies(std::make_unique<PolicyMap>()),
    m_policyLookup(std::make_unique<PolicyLookupMap>()),
    m_rateLimits(std::make_unique<RateLimitMap>()),
    m_isRunning(false),
    m_cleanupInterval(std::chrono::seconds(300))
{
    /*
        Initialize the maps
    */
    m_policyLookup = std::make_unique<PolicyLookupMap>();
    m_rateLimits = std::make_unique<RateLimitMap>();

    /*
        Set global instance for static methods (raw pointer to avoid double ownership)
    */
    gPolicyEngineInstance = this;
}

/*
    Destructor
*/
PolicyEngine::~PolicyEngine()
{
    /*
        Clear global instance first
    */
    gPolicyEngineInstance = nullptr;
    shutdown();
}

auto PolicyEngine::initialize(size_t capacity) -> bool
{
    std::unique_lock<std::shared_mutex> lock(m_policiesMutex);

    m_capacity = capacity;
    m_policies->reserve(capacity);
    m_policyLookup->reserve(capacity);

    /*
        Start background threads
    */
    m_isRunning.store(true);
    m_updateProcessorThread = std::thread(&PolicyEngine::processUpdates, this);
    m_cleanupThread = std::thread(&PolicyEngine::periodicCleanup, this);

    if(gLogger)
    {
        gLogger->info(
            LogContext(LogCategory::POLICY).withField("capacity", std::to_string(capacity)),
            "Policy engine initialized successfully");
    }

    return true;
}

/*
    Shutdown the policy engine
*/
void PolicyEngine::shutdown()
{
    if(m_isRunning.load() == false)
    {
        std::cout << "PolicyEngine::shutdown() - already shut down, returning early" << '\n';
        return;
    }

    std::cout << "PolicyEngine::shutdown() - stopping background threads..." << '\n';
    m_isRunning.store(false);

    /*
        Notify update processor
    */
    {
        std::lock_guard<std::mutex> lock(m_updateQueueMutex);
        m_updateQueueCv.notify_all();
    }
    std::cout << "PolicyEngine::shutdown() - notified update processor" << '\n';

    /*
        Wait for threads to finish
    */
    if(m_updateProcessorThread.joinable())
    {
        std::cout << "PolicyEngine::shutdown() - joining update processor thread..." << '\n';
        m_updateProcessorThread.join();
        std::cout << "PolicyEngine::shutdown() - update processor thread joined" << '\n';
    }
    if(m_cleanupThread.joinable())
    {
        std::cout << "PolicyEngine::shutdown() - joining cleanup thread..." << '\n';
        m_cleanupThread.join();
        std::cout << "PolicyEngine::shutdown() - cleanup thread joined" << '\n';
    }

    /*
        Clear all data
    */
    {
        std::unique_lock<std::shared_mutex> lock(m_policiesMutex);
        m_policies->clear();
        m_policyLookup->clear();
    }

    /*
        Clear rate limiting data
    */
    {
        std::unique_lock<std::shared_mutex> lock(m_rateLimitMutex);
        m_rateLimits->clear();
    }

    std::cout << "PolicyEngine::shutdown() - completed successfully" << '\n';
    if(gLogger)
    {
        gLogger->info(LogContext(LogCategory::POLICY), "Policy engine shut down");
    }
}

/*
    Add a policy
*/
auto PolicyEngine::addPolicy(const Policy& policy) -> bool
{
    if(gPolicyEngineInstance == nullptr)
    {
        return false;
    }

    /*
        Validate policy
    */
    if(policy.id.empty() == true)
    {
        if(gLogger)
        {
            gLogger->error(LogContext(LogCategory::POLICY), "Policy ID cannot be empty");
        }
        return false;
    }

    /*
        Queue the update
    */
    PolicyUpdate update(PolicyOperation::ADD, std::make_shared<Policy>(policy));
    {
        std::lock_guard<std::mutex> lock(gPolicyEngineInstance->m_updateQueueMutex);
        gPolicyEngineInstance->m_updateQueue.push(update);
        gPolicyEngineInstance->m_updateQueueCv.notify_one();
    }

    if(gLogger)
    {
        gLogger->debug(LogContext(LogCategory::POLICY).withPolicy(policy.id),
                       "Policy add operation queued");
    }

    return true;
}

/*
    Update a policy
*/
auto PolicyEngine::updatePolicy(const std::string& policy_id, const Policy& policy) -> bool
{
    /*
        Runtime statement (input param but not defined variable)
    */
    boost::ignore_unused(policy_id);

    if(gPolicyEngineInstance == nullptr)
    {
        return false;
    }

    if(policy.id.empty() == true)
    {
        return false;
    }

    /*
        Queue the update
    */
    PolicyUpdate update(PolicyOperation::UPDATE, std::make_shared<Policy>(policy));
    {
        std::lock_guard<std::mutex> lock(gPolicyEngineInstance->m_updateQueueMutex);
        gPolicyEngineInstance->m_updateQueue.push(update);
        gPolicyEngineInstance->m_updateQueueCv.notify_one();
    }

    return true;
}

/*
    Remove a policy
*/
auto PolicyEngine::removePolicy(const std::string& policy_id) -> bool
{
    if(gPolicyEngineInstance == nullptr)
    {
        return false;
    }

    if(policy_id.empty() == true)
    {
        return false;
    }

    /*
        Queue the removal
    */
    PolicyUpdate update(PolicyOperation::REMOVE, policy_id);
    {
        std::lock_guard<std::mutex> lock(gPolicyEngineInstance->m_updateQueueMutex);
        gPolicyEngineInstance->m_updateQueue.push(update);
        gPolicyEngineInstance->m_updateQueueCv.notify_one();
    }

    return true;
}

/*
    Get a policy
*/
auto PolicyEngine::getPolicy(const std::string& policy_id) -> std::shared_ptr<Policy>
{
    if(gPolicyEngineInstance == nullptr)
    {
        return nullptr;
    }

    std::shared_lock<std::shared_mutex> lock(gPolicyEngineInstance->m_policiesMutex);

    auto it = gPolicyEngineInstance->m_policies->find(policy_id);
    if(it != gPolicyEngineInstance->m_policies->end())
    {
        return it->second;
    }

    return nullptr;
}

/*
    Get all policies
*/
auto PolicyEngine::getAllPolicies() -> std::vector<std::shared_ptr<Policy>>
{
    if(gPolicyEngineInstance == nullptr)
    {
        return {};
    }

    std::shared_lock<std::shared_mutex> lock(gPolicyEngineInstance->m_policiesMutex);

    std::vector<std::shared_ptr<Policy>> policies;
    policies.reserve(gPolicyEngineInstance->m_policies->size());

    for(const auto& pair : *gPolicyEngineInstance->m_policies)
    {
        policies.push_back(pair.second);
    }

    return policies;
}

/*
    Evaluate a packet
*/
auto PolicyEngine::evaluatePacket(const PacketInfo& packet) -> PolicyEvaluationResult
{
    if(gPolicyEngineInstance == nullptr)
    {
        return PolicyEvaluationResult();
    }

    /*
        Create policy key for lookup
    */
    PolicyKey key = gPolicyEngineInstance->createPolicyKey(packet);

    /*
        Find matching policy
    */
    std::shared_ptr<Policy> policy = gPolicyEngineInstance->findMatchingPolicy(key);

    if(policy == nullptr)
    {
        // No policy found, default to ALLOW
        return PolicyEvaluationResult(PolicyAction::ALLOW, "default");
    }

    /*
        Check rate limiting if applicable
    */
    bool rateLimited = false;
    if(policy->action == PolicyAction::RATE_LIMIT && policy->rateLimitBps > 0)
    {
        rateLimited = isRateLimited(key, packet.size, policy->rateLimitBps);
    }

    /*
        Update policy statistics
        It's standard C++17 cross-compilation feature (not only GCC extension!)
        For defined variables

    */
    [[maybe_unused]] auto oldHitCount = policy->hitCount.fetch_add(1);
    [[maybe_unused]] auto oldBytes = policy->bytesProcessed.fetch_add(packet.size);

    PolicyEvaluationResult result;
    result.policy_id = policy->id;
    result.rate_limited = rateLimited;
    result.rate_limit_bps = policy->rateLimitBps;
    result.action =
        policy->action;  // Keep original action, let core daemon handle rate_limited flag

    return result;
}

/*
    Load policies from JSON
*/
auto PolicyEngine::loadPoliciesFromJson(const std::string& json_str) -> bool
{
    if(gPolicyEngineInstance == nullptr)
    {
        return false;
    }

    try
    {
        nlohmann::json jsonData = nlohmann::json::parse(json_str);

        if(jsonData.is_array() == false)
        {
            if(gLogger)
            {
                gLogger->error(LogContext(LogCategory::POLICY),
                               "JSON must be an array of policies");
            }
            return false;
        }

        size_t loadedCount = 0;
        for(const auto& policyJson : jsonData)
        {
            auto policyOpt = gPolicyEngineInstance->jsonToPolicy(policyJson);
            if(policyOpt.has_value() == true)
            {
                if(addPolicy(policyOpt.value()))
                {
                    loadedCount++;
                }
            }
        }

        if(gLogger)
        {
            gLogger->info(LogContext(LogCategory::POLICY)
                              .withField("loaded", std::to_string(loadedCount))
                              .withField("total", std::to_string(jsonData.size())),
                          "Policies loaded from JSON");
        }

        return loadedCount > 0;
    }
    catch(const std::exception& e)
    {
        if(gLogger)
        {
            gLogger->error(LogContext(LogCategory::POLICY).withField("error", e.what()),
                           "Failed to parse JSON policies");
        }
        return false;
    }
}

/*
    Load policies from file
*/
auto PolicyEngine::loadPoliciesFromFile(const std::string& filename) -> bool
{
    std::ifstream file(filename);
    if(file.is_open() == false)
    {
        if(gLogger)
        {
            gLogger->error(LogContext(LogCategory::POLICY).withField("filename", filename),
                           "Failed to open policy file");
        }
        return false;
    }

    std::string jsonContent((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
    file.close();

    return loadPoliciesFromJson(jsonContent);
}

/*
    Export policies to JSON
*/
auto PolicyEngine::exportPoliciesToJson() -> std::string
{
    if(gPolicyEngineInstance == nullptr)
    {
        return "[]";
    }

    nlohmann::json jsonArray = nlohmann::json::array();

    auto policies = getAllPolicies();
    for(const auto& policy : policies)
    {
        if(policy)
        {
            jsonArray.push_back(gPolicyEngineInstance->policyToJson(*policy));
        }
    }

    return jsonArray.dump(4);  // Pretty print with 4 spaces
}

/*
    Save policies to file
*/
auto PolicyEngine::savePoliciesToFile(const std::string& filename) -> bool
{
    std::string jsonContent = exportPoliciesToJson();

    std::ofstream file(filename);
    if(file.is_open() == false)
    {
        if(gLogger)
        {
            gLogger->error(LogContext(LogCategory::POLICY).withField("filename", filename),
                           "Failed to open file for writing");
        }
        return false;
    }

    file << jsonContent;
    file.close();

    if(gLogger)
    {
        gLogger->info(LogContext(LogCategory::POLICY).withField("filename", filename),
                      "Policies saved to file");
    }

    return true;
}

/*
    Get the number of policies
*/
auto PolicyEngine::getPolicyCount() -> size_t
{
    if(gPolicyEngineInstance == nullptr)
    {
        return 0;
    }

    std::shared_lock<std::shared_mutex> lock(gPolicyEngineInstance->m_policiesMutex);
    return gPolicyEngineInstance->m_policies->size();
}

/*
    Cleanup expired policies
*/
void PolicyEngine::cleanupExpiredPolicies()
{
    if(gPolicyEngineInstance == nullptr)
    {
        return;
    }

    auto now = std::chrono::system_clock::now();
    std::vector<std::string> expiredPolicies;

    {
        std::shared_lock<std::shared_mutex> lock(gPolicyEngineInstance->m_policiesMutex);

        for(const auto& pair : *gPolicyEngineInstance->m_policies)
        {
            const auto& policy = pair.second;
            if(policy && policy->expiresAt != std::chrono::system_clock::time_point{}
               && policy->expiresAt < now)
            {
                expiredPolicies.push_back(policy->id);
            }
        }
    }

    // Remove expired policies
    for(const auto& policyId : expiredPolicies)
    {
        removePolicy(policyId);
    }

    if(expiredPolicies.empty() == false && gLogger)
    {
        gLogger->info(LogContext(LogCategory::POLICY)
                          .withField("expired_count", std::to_string(expiredPolicies.size())),
                      "Expired policies cleaned up");
    }
}

/*
    Check if a policy is rate limited
*/
auto PolicyEngine::isRateLimited(const PolicyKey& key,
                                 uint32_t packet_size,
                                 uint64_t limit_bps) -> bool
{
    if(gPolicyEngineInstance == nullptr)
    {
        return false;
    }

    auto now = std::chrono::system_clock::now();
    auto currentSecond = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch());

    std::unique_lock<std::shared_mutex> lock(gPolicyEngineInstance->m_rateLimitMutex);

    auto it = gPolicyEngineInstance->m_rateLimits->find(key);
    if(it == gPolicyEngineInstance->m_rateLimits->end())
    {
        /*
            Create new rate limit state
        */
        auto rateState = std::make_unique<RateLimitState>(limit_bps);
        rateState->bytes_this_second.store(packet_size);
        rateState->last_reset_time.store(currentSecond.count());
        gPolicyEngineInstance->m_rateLimits->emplace(key, std::move(rateState));
        return false;  // First packet is always allowed
    }

    auto& rateState = it->second;
    auto lastReset = rateState->last_reset_time.load();

    /*
        Check if we need to reset the counter
    */
    if(currentSecond.count() > lastReset)
    {
        rateState->bytes_this_second.store(packet_size);
        rateState->last_reset_time.store(currentSecond.count());
        return false;
    }

    /*
        Check if adding this packet would exceed the limit
    */
    uint64_t currentBytes = rateState->bytes_this_second.load();
    if(currentBytes + packet_size > limit_bps)
    {
        return true;  // Rate limited
    }

    /*
        Update byte count
    */
    rateState->bytes_this_second.fetch_add(packet_size);
    return false;
}

/*
    Process updates
*/
void PolicyEngine::processUpdates()
{
    while(m_isRunning.load())
    {
        std::unique_lock<std::mutex> lock(m_updateQueueMutex);

        /*
            Wait for updates or shutdown
        */
        m_updateQueueCv.wait(lock,
                             [this] {
                                return m_updateQueue.empty() == false || m_isRunning.load() == false;
                             });

        if(m_isRunning.load() == false)
        {
            break;
        }

        /*
            Process all pending updates
        */
        while(m_updateQueue.empty() == false)
        {
            PolicyUpdate update = m_updateQueue.front();
            m_updateQueue.pop();
            lock.unlock();

            processSingleUpdate(update);

            lock.lock();
        }
    }
}

/*
    Process a single update
*/
void PolicyEngine::processSingleUpdate(const PolicyUpdate& update)
{
    std::unique_lock<std::shared_mutex> lock(m_policiesMutex);

    switch(update.operation)
    {
        case PolicyOperation::ADD:
        case PolicyOperation::UPDATE:
            if(update.policy != nullptr)
            {
                /*
                    Check capacity
                */
                if(m_policies->size() >= m_capacity
                   && m_policies->find(update.policy->id) == m_policies->end())
                {
                    if(gLogger)
                    {
                        gLogger->warn(LogContext(LogCategory::POLICY).withPolicy(update.policy->id),
                                      "Policy capacity exceeded");
                    }
                    return;
                }

                (*m_policies)[update.policy->id] = update.policy;

                /*
                    Update lookup map
                */
                PolicyKey key(update.policy->src, update.policy->dst);
                (*m_policyLookup)[key] = update.policy->id;

                if(gLogger)
                {
                    gLogger->debug(LogContext(LogCategory::POLICY).withPolicy(update.policy->id),
                                   "Policy added/updated successfully");
                }
            }
            break;

        case PolicyOperation::REMOVE:
            {
                auto it = m_policies->find(update.policy_id);
                if(it != m_policies->end())
                {
                    /*
                        Remove from lookup map
                    */
                    PolicyKey key(it->second->src, it->second->dst);
                    m_policyLookup->erase(key);

                    /*
                        Remove from main map
                    */
                    m_policies->erase(it);

                    if(gLogger)
                    {
                        gLogger->debug(LogContext(LogCategory::POLICY).withPolicy(update.policy_id),
                                       "Policy removed successfully");
                    }
                }
            }
            break;
    }

    /*
        Rebuild lookup map periodically for consistency
    */
    if(m_policies->size() % 100 == 0)
    {
        rebuildLookupMap();
    }
}

/*
    Create a policy key
*/
auto PolicyEngine::createPolicyKey(const PacketInfo& packet) -> PolicyKey
{
    return PolicyKey(packet.src, packet.dst);
}

/*
    Find a matching policy
*/
auto PolicyEngine::findMatchingPolicy(const PolicyKey& key) const -> std::shared_ptr<Policy>
{
    std::shared_lock<std::shared_mutex> lock(m_policiesMutex);

    /*
        Direct lookup first
    */
    auto lookupIt = m_policyLookup->find(key);
    if(lookupIt != m_policyLookup->end())
    {
        auto policyIt = m_policies->find(lookupIt->second);
        if(policyIt != m_policies->end())
        {
            return policyIt->second;
        }
    }

    /*
        Fallback: iterate through all policies for wildcard matching
    */
    for(const auto& pair : *m_policies)
    {
        if(matchesPolicy(*pair.second, key))
        {
            return pair.second;
        }
    }

    return nullptr;
}

/*
    Rebuild the lookup map
*/
void PolicyEngine::rebuildLookupMap()
{
    m_policyLookup->clear();
    for(const auto& pair : *m_policies)
    {
        PolicyKey key(pair.second->src, pair.second->dst);
        (*m_policyLookup)[key] = pair.first;
    }

    if(gLogger)
    {
        gLogger->debug(LogContext(LogCategory::POLICY)
                           .withField("policies", std::to_string(m_policies->size())),
                       "Policy lookup map rebuilt");
    }
}

/*
    Periodic cleanup
*/
void PolicyEngine::periodicCleanup()
{
    std::cout << "PolicyEngine::periodicCleanup() - thread started" << '\n';

    while(m_isRunning.load())
    {
        /*
            Use interruptible sleep - check every 100ms instead of sleeping for 5 minutes
        */
        auto sleepStart = std::chrono::steady_clock::now();
        while(m_isRunning.load())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            auto elapsed = std::chrono::steady_clock::now() - sleepStart;
            if(elapsed >= m_cleanupInterval)
            {
                break;  // Time to do cleanup
            }
        }

        if(m_isRunning.load() == false)
        {
            std::cout << "PolicyEngine::periodicCleanup() - shutdown requested, exiting" << '\n';
            break;
        }

        std::cout << "PolicyEngine::periodicCleanup() - performing cleanup..." << '\n';
        cleanupExpiredPolicies();

        /*
            Cleanup old rate limit entries
        */
        {
            std::unique_lock<std::shared_mutex> lock(m_rateLimitMutex);
            auto now = std::chrono::system_clock::now();
            auto cutoff =
                std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count()
                - 60;  // Remove entries older than 1 minute

            auto it = m_rateLimits->begin();
            while(it != m_rateLimits->end())
            {
                if(it->second->last_reset_time.load() < cutoff)
                {
                    it = m_rateLimits->erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }
        std::cout << "PolicyEngine::periodicCleanup() - cleanup completed" << '\n';
    }

    std::cout << "PolicyEngine::periodicCleanup() - thread exiting" << '\n';
}

auto PolicyEngine::matchesPolicy(const Policy& policy, const PolicyKey& key) -> bool
{
    /*
        Exact match
    */
    if(policy.src.ip == key.src_ip && policy.dst.ip == key.dst_ip && policy.src.port == key.src_port
       && policy.dst.port == key.dst_port
       && (policy.src.protocol == key.protocol || policy.src.protocol == Protocol::ANY))
    {
        return true;
    }

    /*
        Wildcard matching (0 means any)
    */
    bool srcMatch = (policy.src.ip == 0 || policy.src.ip == key.src_ip)
                    && (policy.src.port == 0 || policy.src.port == key.src_port);

    bool dstMatch = (policy.dst.ip == 0 || policy.dst.ip == key.dst_ip)
                    && (policy.dst.port == 0 || policy.dst.port == key.dst_port);

    bool protoMatch = (policy.src.protocol == Protocol::ANY || policy.src.protocol == key.protocol);

    return srcMatch && dstMatch && protoMatch;
}

/*
    Convert a policy to JSON
*/
auto PolicyEngine::policyToJson(const Policy& policy) -> nlohmann::json
{
    nlohmann::json j;

    j["id"] = policy.id;
    j["action"] = policyActionToString(policy.action);

    j["src"] = {
        {      "ip",       uint32ToIpString(policy.src.ip)},
        {    "port",                       policy.src.port},
        {"protocol", protocolToString(policy.src.protocol)}
    };

    j["dst"] = {
        {      "ip",       uint32ToIpString(policy.dst.ip)},
        {    "port",                       policy.dst.port},
        {"protocol", protocolToString(policy.dst.protocol)}
    };

    if(policy.rateLimitBps > 0)
    {
        j["rate_limit_bps"] = policy.rateLimitBps;
    }

    /*
        Timestamps
    */
    auto createdTimeT = std::chrono::system_clock::to_time_t(policy.createdAt);
    j["created_at"] = std::to_string(createdTimeT);

    if(policy.expiresAt != std::chrono::system_clock::time_point{})
    {
        auto expiresTimeT = std::chrono::system_clock::to_time_t(policy.expiresAt);
        j["expires_at"] = std::to_string(expiresTimeT);
    }

    /*
        Statistics
    */
    j["hit_count"] = policy.hitCount.load();
    j["bytes_processed"] = policy.bytesProcessed.load();

    return j;
}

auto PolicyEngine::jsonToPolicy(const nlohmann::json& json) -> std::optional<Policy>
{
    try
    {
        Policy policy;

        /*
            Required fields
        */
        if(json.contains("id") == false || json.contains("action") == false
           || json.contains("src") == false || json.contains("dst") == false)
        {
            return std::nullopt;
        }

        policy.id = json["id"];
        policy.action = stringToPolicyAction(json["action"]);

        /*
            Source
        */
        const auto& src = json["src"];
        policy.src.ip = ipStringToUint32(src["ip"]);
        policy.src.port = src["port"];
        policy.src.protocol = stringToProtocol(src["protocol"]);

        /*
            Destination
        */
        const auto& dst = json["dst"];
        policy.dst.ip = ipStringToUint32(dst["ip"]);
        policy.dst.port = dst["port"];
        policy.dst.protocol = stringToProtocol(dst["protocol"]);

        /*
            Optional fields
        */
        if(json.contains("rate_limit_bps") == true)
        {
            policy.rateLimitBps = json["rate_limit_bps"];
        }

        if(json.contains("created_at") == true)
        {
            auto timeVal = std::stoll(json["created_at"].get<std::string>());
            policy.createdAt = std::chrono::system_clock::from_time_t(timeVal);
        }
        else
        {
            policy.createdAt = std::chrono::system_clock::now();
        }

        if(json.contains("expires_at") == true)
        {
            auto timeVal = std::stoll(json["expires_at"].get<std::string>());
            policy.expiresAt = std::chrono::system_clock::from_time_t(timeVal);
        }

        return policy;
    }
    catch(const std::exception& e)
    {
        if(gLogger)
        {
            gLogger->error(LogContext(LogCategory::POLICY).withField("error", e.what()),
                           "Failed to parse policy from JSON");
        }
        return std::nullopt;
    }
}


}  // namespace pepctl