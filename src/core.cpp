
#include <arpa/inet.h>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include "pepctl/core.h"
#include "pepctl/ebpf_manager.h"
#include "pepctl/logger.h"
#include "pepctl/metrics_server.h"
#include "pepctl/policy_engine.h"


namespace pepctl
{


class PepctlDaemon : public IPepctlDaemon
{
  public:
    explicit PepctlDaemon(std::shared_ptr<Logger> logger) :
        m_isRunning(false),
        m_isInitialized(false),
        m_logger(std::move(logger)),
        m_policyEngine(std::make_unique<PolicyEngine>(m_logger)),
        m_ebpfManager(std::make_unique<EbpfManager>(m_logger)),
        m_metricsServer(std::make_unique<MetricsServer>(m_logger))
    {
        if(m_logger == nullptr)
        {
            throw std::invalid_argument("Logger must not be null");
        }
    }

    ~PepctlDaemon() override
    {
        m_logger->info(LogContext(LogCategory::SYSTEM), "PepctlDaemon destructor called");
        stop();
        m_logger->info(LogContext(LogCategory::SYSTEM),
                       "PepctlDaemon destructor - after stop()");

        // Manually destroy member objects in controlled order to prevent hanging
        try
        {
            std::cout << __func__ << ": Manually destroying member objects..." << '\n';

            if(m_cleanupTimer != nullptr)
            {
                std::cout << __func__ << ": Resetting cleanup timer..." << '\n';
                m_cleanupTimer.reset();
            }

            if(m_metricsServer != nullptr)
            {
                std::cout << __func__ << ": Resetting metrics server..." << '\n';
                m_metricsServer.reset();
            }

            if(m_ebpfManager != nullptr)
            {
                std::cout << __func__ << ": Resetting eBPF manager..." << '\n';
                m_ebpfManager.reset();
            }

            // Destroy policy engine
            if(m_policyEngine != nullptr)
            {
                std::cout << __func__ << ": Resetting policy engine..." << '\n';
                m_policyEngine.reset();
            }

            std::cout << __func__ << ": All member objects destroyed successfully" << '\n';
        }
        catch(const std::exception& e)
        {
            std::cerr << "Error destroying member objects: " << e.what() << '\n';
        }
        catch(...)
        {
            std::cerr << "Unknown error destroying member objects" << '\n';
        }

        // Safely reset the logger with error handling
        try
        {
            m_logger->flush();
        }
        catch(const std::exception& e)
        {
            std::cerr << "Error during logger cleanup (non-fatal): " << e.what() << '\n';
        }
        catch(...)
        {
            std::cerr << "Unknown error during logger cleanup (non-fatal)" << '\n';
        }

        std::cout << __func__ << ": destructor completed" << '\n';
    }

    auto initialize(const Config& config) -> bool override
    {
        if(m_isInitialized)
        {
            return true;
        }

        m_config = config;

        // Initialize logger first
        m_logger->setLevel(stringToLogLevel(config.logLevel));
        m_logger->info(LogContext(LogCategory::SYSTEM), "PEPCTL daemon starting...");

        // Initialize policy engine
        if(m_policyEngine->initialize(config.policyCapacity) == false)
        {
            m_logger->error(LogContext(LogCategory::SYSTEM),
                            "Failed to initialize policy engine");
            return false;
        }

        // Initialize eBPF manager
        EbpfProgramType programType = stringToEbpfProgramType(config.ebpfProgramType);
        if(m_ebpfManager->initialize(config.interfaceName, programType) == false)
        {
            m_logger->error(LogContext(LogCategory::SYSTEM),
                            "Failed to initialize eBPF manager");
            return false;
        }

        // Load eBPF program if specified
        if(config.ebpfProgramPath.empty() == false)
        {
            if(std::filesystem::exists(config.ebpfProgramPath) == false)
            {
                m_logger->error(
                    LogContext(LogCategory::SYSTEM).withField("path", config.ebpfProgramPath),
                    "eBPF program file does not exist");
                return false;
            }

            if(std::filesystem::is_regular_file(config.ebpfProgramPath) == false)
            {
                m_logger->error(
                    LogContext(LogCategory::SYSTEM).withField("path", config.ebpfProgramPath),
                    "eBPF program path is not a regular file");
                return false;
            }

            m_logger->info(LogContext(LogCategory::SYSTEM).withField("path", config.ebpfProgramPath),
                           "eBPF program file found, attempting to load");

            if(m_ebpfManager->loadProgram(config.ebpfProgramPath) == false)
            {
                m_logger->error(
                    LogContext(LogCategory::SYSTEM).withField("path", config.ebpfProgramPath),
                    "Failed to load eBPF program");
                return false;
            }
        }

        // Initialize metrics server if enabled
        if(config.enableMetrics)
        {
            if(m_metricsServer->initialize(config.metricsPort) == false)
            {
                m_logger->error(LogContext(LogCategory::SYSTEM)
                                   .withField("port", std::to_string(config.metricsPort)),
                               "Failed to initialize metrics server");
                return false;
            }

            // Setup default endpoints (metrics, health, stats, policies)
            m_metricsServer->setupDefaultEndpoints();

            // Pass references to metrics server for statistics collection
            m_metricsServer->setPolicyEngine(m_policyEngine.get());
            m_metricsServer->setEbpfManager(m_ebpfManager.get());
            m_metricsServer->setDaemonMetrics(&m_metrics);
        }

        // Load policies from file if specified
        if(config.policiesFile.empty() == false)
        {
            m_logger->info(
                LogContext(LogCategory::POLICY).withField("policies_file", config.policiesFile),
                "Loading policies from config file");

            if(PolicyEngine::loadPoliciesFromFile(config.policiesFile) == true)
            {
                // Synchronize policies with eBPF map
                auto policies = PolicyEngine::getAllPolicies();
                if(m_ebpfManager->updatePolicyMap(policies) == false)
                {
                    m_logger->warn(LogContext(LogCategory::POLICY),
                                   "Failed to synchronize policies with eBPF map");
                }
                else
                {
                    m_logger->info(
                        LogContext(LogCategory::POLICY)
                            .withField("policy_count", std::to_string(policies.size())),
                        "Policies loaded and synchronized with eBPF map");
                }
            }
            else
            {
                m_logger->error(
                    LogContext(LogCategory::POLICY).withField("policies_file", config.policiesFile),
                    "Failed to load policies from file");
                return false;
            }
        }

        m_isInitialized = true;
        m_logger->info(LogContext(LogCategory::SYSTEM),
                       "PEPCTL daemon initialized successfully");
        return true;
    }

    auto start() -> bool override
    {
        if(m_isInitialized == false)
        {
            return false;
        }

        if(m_isRunning.load())
        {
            return true;
        }

        m_logger->info(LogContext(LogCategory::SYSTEM), "Starting daemon components...");

        // Start metrics server
        if(m_config.enableMetrics && m_metricsServer->start() == false)
        {
            m_logger->error(LogContext(LogCategory::SYSTEM),
                            "Failed to start metrics server");
            m_logger->info(LogContext(LogCategory::SYSTEM),
                           "Calling metricsServer->stop() after failed start");
            m_metricsServer->stop();
            return false;
        }

        // Set enhanced packet callback for direct eBPF action processing
        m_ebpfManager->setEbpfPacketCallback(
            [this](const PacketInfo& packet, uint32_t ebpf_action) {
                this->handleEbpfPacket(packet, ebpf_action);
            });

        // Attach eBPF program
        if(m_ebpfManager->attachProgram() == false)
        {
            m_logger->error(LogContext(LogCategory::SYSTEM),
                            "Failed to attach eBPF program");
            if(m_config.enableMetrics)
            {
                m_logger->info(LogContext(LogCategory::SYSTEM),
                               "Calling metricsServer->stop() after failed eBPF attach");
                m_metricsServer->stop();
            }
            // Reset initialization state since we failed to start
            m_logger->info(LogContext(LogCategory::SYSTEM),
                           "Returning from start() after failed eBPF attach");
            m_isInitialized = false;
            return false;
        }

        // Notify the instance that the program is attached
        m_ebpfManager->notifyProgramAttached();

        // Start packet processing
        if(m_ebpfManager->startPacketProcessing() == false)
        {
            m_logger->error(LogContext(LogCategory::SYSTEM),
                            "Failed to start packet processing");
            m_ebpfManager->detachProgram();
            m_ebpfManager->notifyProgramDetached();
            if(m_config.enableMetrics)
            {
                m_logger->info(
                    LogContext(LogCategory::SYSTEM),
                    "Calling metricsServer->stop() after failed packet processing start");
                m_metricsServer->stop();
                m_logger->debug(LogContext(LogCategory::SYSTEM), "Metrics server stopped");
            }

            // Stop cleanup timer
            if(m_cleanupTimer != nullptr && m_cleanupTimer->joinable())
            {
                m_logger->info(LogContext(LogCategory::SYSTEM),
                               "Joining cleanup timer thread...");
                m_cleanupTimer->join();
                m_logger->debug(LogContext(LogCategory::SYSTEM),
                                "Cleanup timer thread joined");
            }

            m_isInitialized = false;
            m_logger->info(LogContext(LogCategory::SYSTEM), "PepctlDaemon::stop() completed");

            return false;
        }

        m_isRunning.store(true);

        // Start cleanup timer thread
        if(m_cleanupTimer == nullptr)
        {
            m_cleanupTimer = std::make_unique<std::thread>(&PepctlDaemon::cleanupLoop, this);
        }

        return true;
    }

    void stop() override
    {
        if(m_isRunning.load() == false && m_cleanupTimer == nullptr)
        {
            return;
        }

        m_logger->info(LogContext(LogCategory::SYSTEM), "PepctlDaemon::stop() - begin");

        m_isRunning.store(false);

        // Stop packet processing and detach program
        try
        {
            if(m_ebpfManager != nullptr)
            {
                m_ebpfManager->stopPacketProcessing();
                (void)m_ebpfManager->detachProgram();
                m_ebpfManager->notifyProgramDetached();
                m_ebpfManager->shutdown();
            }
        }
        catch(const std::exception& e)
        {
            m_logger->error(LogContext(LogCategory::EBPF).withField("error", e.what()),
                            "Error stopping eBPF manager");
        }

        // Stop metrics server
        try
        {
            if(m_metricsServer != nullptr)
            {
                m_metricsServer->stop();
            }
        }
        catch(const std::exception& e)
        {
            m_logger->error(LogContext(LogCategory::METRICS).withField("error", e.what()),
                            "Error stopping metrics server");
        }

        // Stop cleanup thread
        try
        {
            if(m_cleanupTimer != nullptr && m_cleanupTimer->joinable())
            {
                m_logger->info(LogContext(LogCategory::SYSTEM), "Joining cleanup timer thread...");
                m_cleanupTimer->join();
            }
            m_cleanupTimer.reset();
        }
        catch(const std::exception& e)
        {
            m_logger->error(LogContext(LogCategory::SYSTEM).withField("error", e.what()),
                            "Error stopping cleanup thread");
        }

        // Shutdown policy engine
        try
        {
            if(m_policyEngine != nullptr)
            {
                m_policyEngine->shutdown();
            }
        }
        catch(const std::exception& e)
        {
            m_logger->error(LogContext(LogCategory::POLICY).withField("error", e.what()),
                            "Error shutting down policy engine");
        }

        m_isInitialized = false;

        m_logger->info(LogContext(LogCategory::SYSTEM), "PepctlDaemon::stop() - end");
    }

    auto isRunning() const -> bool override 
    {
        return m_isRunning.load();
    }

    auto getPolicyEngine() -> PolicyEngine& override
    {
        if(m_policyEngine == nullptr)
        {
            throw std::runtime_error("PolicyEngine is not initialized or has been destroyed");
        }
        return *m_policyEngine; 
    }

    auto getEbpfManager() -> EbpfManager& override 
    {
        if(m_ebpfManager == nullptr) 
        {
            throw std::runtime_error("EbpfManager is not initialized or has been destroyed");
        }
        return *m_ebpfManager;
    }

    auto getMetricsServer() -> MetricsServer& override
    { 
        if(m_metricsServer == nullptr)
        {
            throw std::runtime_error("MetricsServer is not initialized or has been destroyed");
        }
        return *m_metricsServer; 
    }

    auto getLogger() -> Logger& override 
    { 
        return *m_logger; 
    }

    auto getMetrics() -> Metrics& override 
    { 
        return m_metrics; 
    }

  private:
    Config m_config;
    std::atomic<bool> m_isRunning;
    bool m_isInitialized;
    Metrics m_metrics;

    std::shared_ptr<Logger> m_logger;

    // Core components
    std::unique_ptr<PolicyEngine> m_policyEngine;
    std::unique_ptr<EbpfManager> m_ebpfManager;
    std::unique_ptr<MetricsServer> m_metricsServer;

    // Background threads
    std::unique_ptr<std::thread> m_cleanupTimer;

    void handlePacket(const PacketInfo& packet)
    {
        // Update metrics
        m_metrics.packetsProcessed.fetch_add(1);
        m_metrics.bytesProcessed.fetch_add(packet.size);
        // Evaluate packet against policies
        auto result = PolicyEngine::evaluatePacket(packet);

        // Log packet processing based on action
        LogContext ctx(LogCategory::NETWORK);
        ctx.withField("src", packet.src.toString())
            .withField("dst", packet.dst.toString())
            .withField("size", std::to_string(packet.size))
            .withField("action", policyActionToString(result.action))
            .withField("policy_id", result.policy_id);

        // Process metrics based on action
        switch(result.action)
        {
            case PolicyAction::ALLOW:
            {
                m_metrics.packetsAllowed.fetch_add(1);
                if(m_config.logLevel == "debug")
                {
                    if(m_logger != nullptr)
                    {
                        m_logger->debug(ctx, "Packet allowed");
                    }
                }
                break;
            }

            case PolicyAction::BLOCK:
            {
                m_metrics.packetsBlocked.fetch_add(1);
                m_logger->warn(ctx, "Packet blocked");
                break;
            }

            case PolicyAction::LOG_ONLY:
            {
                m_metrics.packetsLogged.fetch_add(1);  // Track logged packets separately
                m_logger->info(ctx, "Packet logged (allowed)");
                break;
            }

            case PolicyAction::RATE_LIMIT:
            {
                if(result.rate_limited)
                {
                    m_metrics.packetsRateLimited.fetch_add(1);  // Track rate limited packets
                    m_logger->warn(
                        ctx.withField("rateLimitBytesPerSecond",
                                      std::to_string(result.rate_limit_bytes_per_second)),
                        "Packet rate limited (blocked)");
                }
                else
                {
                    m_metrics.packetsAllowed.fetch_add(1);
                    if(m_config.logLevel == "debug")
                    {
                        m_logger->debug(ctx, "Packet within rate limit (allowed)");
                    }
                }
                break;
            }

            default:
            {
                break;
            }
        }

        // Log security events for blocked packets
        if(result.action == PolicyAction::BLOCK
           || (result.action == PolicyAction::RATE_LIMIT && result.rate_limited))
        {
            m_logger->logSecurityEvent("packet_blocked",
                                       packet.src.toString(),
                                       "Packet blocked by policy " + result.policy_id,
                                       LogLevel::WARN);
        }
    }

    void handleEbpfPacket(const PacketInfo& packet, uint32_t ebpf_action)
    {
        // Update metrics
        m_metrics.packetsProcessed.fetch_add(1);
        m_metrics.bytesProcessed.fetch_add(packet.size);

        // Convert eBPF action to PolicyAction
        // eBPF actions: 0=ALLOW, 1=BLOCK, 2=LOG_ONLY, 3=RATE_LIMIT
        PolicyAction action = static_cast<PolicyAction>(ebpf_action);

        // Find the policy that matched in eBPF (for logging)
        auto result = PolicyEngine::evaluatePacket(packet);
        std::string policyId = result.policy_id;

        // Log packet processing based on eBPF action
        LogContext ctx(LogCategory::NETWORK);
        ctx.withField("src", packet.src.toString())
            .withField("dst", packet.dst.toString())
            .withField("size", std::to_string(packet.size))
            .withField("action", policyActionToString(action))
            .withField("policy_id", policyId);

        // Process metrics based on eBPF action (this is the key fix!)
        switch(action)
        {
            case PolicyAction::ALLOW:
            {
                m_metrics.packetsAllowed.fetch_add(1);
                if(m_config.logLevel == "debug")
                {
                    m_logger->debug(ctx, "Packet allowed by eBPF");
                }
                break;
            }

            case PolicyAction::BLOCK:
            {
                m_metrics.packetsBlocked.fetch_add(1);
                m_logger->warn(ctx, "Packet blocked by eBPF");
                break;
            }

            case PolicyAction::LOG_ONLY:
            {
                m_metrics.packetsLogged.fetch_add(1);
                m_logger->info(ctx, "Packet logged by eBPF (allowed)");
                break;
            }

            case PolicyAction::RATE_LIMIT:
            {
                if(result.rate_limited)
                {
                    m_metrics.packetsRateLimited.fetch_add(1);
                    m_logger->warn(ctx, "Packet rate limited by eBPF");
                }
                else
                {
                    m_metrics.packetsAllowed.fetch_add(1);
                    if(m_config.logLevel == "debug")
                    {
                        m_logger->debug(ctx, "Packet within rate limit by eBPF (allowed)");
                    }
                }
                break;
            }

            default:
            {
                break;
            }
        }

        // Log security events for blocked packets
        if(action == PolicyAction::BLOCK || (action == PolicyAction::RATE_LIMIT && result.rate_limited))
        {
            m_logger->logSecurityEvent("packet_blocked_ebpf",
                                       packet.src.toString(),
                                       "Packet blocked by eBPF policy " + policyId,
                                       LogLevel::WARN);
        }
    }

    void cleanupLoop()
    {
        while(m_isRunning.load() == true)
        {
            // Use interruptible sleep - check every 100ms instead of sleeping for 5 minutes
            auto sleepStart = std::chrono::steady_clock::now();
            while(m_isRunning.load() == true)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                auto elapsed = std::chrono::steady_clock::now() - sleepStart;
                if(elapsed >= m_config.policyCleanupInterval)
                {
                    break;  // Time to do cleanup
                }
            }

            if(m_isRunning.load() == false)
            {
                break;
            }

            try
            {
                // Clean up expired policies
                m_policyEngine->cleanupExpiredPolicies();

                // Reset eBPF statistics
                m_ebpfManager->resetStats();

                // Log system health
                auto policyCount = PolicyEngine::getPolicyCount();
                m_logger->debug(LogContext(LogCategory::SYSTEM)
                                   .withField("active_policies", std::to_string(policyCount))
                                   .withField("packets_processed",
                                              std::to_string(m_metrics.packetsProcessed.load()))
                                   .withField("packets_allowed",
                                              std::to_string(m_metrics.packetsAllowed.load()))
                                   .withField("packets_blocked",
                                              std::to_string(m_metrics.packetsBlocked.load())),
                               "System health check");
            }
            catch(const std::exception& e)
            {
                m_logger->error(LogContext(LogCategory::SYSTEM).withField("error", e.what()),
                                "Error during cleanup");
            }
        }
    }

    static auto stringToLogLevel(const std::string& level) -> LogLevel
    {
        if(level == "trace")
        {
            return LogLevel::TRACE;
        }
        if(level == "debug")
        {
            return LogLevel::DBG;
        }
        if(level == "info")
        {
            return LogLevel::INFO;
        }
        if(level == "warn")
        {
            return LogLevel::WARN;
        }
        if(level == "error")
        {
            return LogLevel::ERROR;
        }
        if(level == "critical")
        {
            return LogLevel::CRITICAL;
        }
        return LogLevel::INFO;  // Default
    }
};

auto createDaemon(std::shared_ptr<Logger> logger) -> std::unique_ptr<IPepctlDaemon>
{
    return std::make_unique<PepctlDaemon>(std::move(logger));
}

auto stringToEbpfProgramType(const std::string& str) -> EbpfProgramType
{
    if(str == "tc_ingress")
    {
        return EbpfProgramType::TC_INGRESS;
    }
    if(str == "tc_egress")
    {
        return EbpfProgramType::TC_EGRESS;
    }
    else if(str == "xdp")
    {
        return EbpfProgramType::XDP;
    }
    else
    {
        // Default to XDP for unknown values
        return EbpfProgramType::XDP;
    }
}


}  // namespace pepctl