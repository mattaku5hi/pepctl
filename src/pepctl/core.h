#pragma once


#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>


namespace pepctl 
{

// Forward declarations
class PolicyEngine;
class EbpfManager;
class MetricsServer;
class Logger;

// Version information
constexpr const char* version = "1.0.0";
constexpr uint32_t versionMajor = 1;
constexpr uint32_t versionMinor = 0;
constexpr uint32_t versionPatch = 0;

// Network constants
constexpr uint16_t defaultAdminPort = 8080;
constexpr uint16_t defaultMetricsPort = 9090;
constexpr size_t maxPacketSize = 65535;
constexpr size_t defaultPolicyCapacity = 10000;

// Policy actions
enum class PolicyAction : uint32_t
{
    ALLOW = 0,
    BLOCK = 1,      // completely block the packet, no response sent
    LOG_ONLY = 2,   // allow but log the packet
    RATE_LIMIT = 3  // block if rate limit is exceeded
};

// Protocol types due to IANA RFC 791
enum class Protocol : uint8_t
{
    TCP = 6,
    UDP = 17,
    ICMP = 1,
    ANY = 255
};

// Network address structure
struct NetworkAddress
{
    uint32_t ip;
    uint16_t port;
    Protocol protocol;

    NetworkAddress() : ip(0), port(0), protocol(Protocol::ANY) {}

    NetworkAddress(uint32_t ip_addr, uint16_t port_num, Protocol proto) :
        ip(ip_addr),
        port(port_num),
        protocol(proto)
    {}

    std::string toString() const;
};

// Policy structure for lock-free operations
struct Policy
{
    std::string id;
    PolicyAction action;
    NetworkAddress src;
    NetworkAddress dst;
    uint64_t rateLimitBps{};
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point expiresAt;
    std::atomic<uint64_t> hitCount{0};
    std::atomic<uint64_t> bytesProcessed{0};

    Policy() = default;

    Policy(const Policy& other) :
        id(other.id),
        action(other.action),
        src(other.src),
        dst(other.dst),
        rateLimitBps(other.rateLimitBps),
        createdAt(other.createdAt),
        expiresAt(other.expiresAt)
    {
        hitCount.store(other.hitCount.load());
        bytesProcessed.store(other.bytesProcessed.load());
    }
};

// Packet info structure
struct PacketInfo
{
    NetworkAddress src;
    NetworkAddress dst;
    uint32_t size{};
    std::chrono::system_clock::time_point timestamp;
    std::string interfaceName;
};

template <std::size_t Shards>
class ShardedCounterU64
{
  public:
    ShardedCounterU64() = default;

    auto fetch_add(uint64_t value,
                   std::memory_order order = std::memory_order_relaxed) noexcept -> uint64_t
    {
        return shardForUpdate().fetch_add(value, order);
    }

    auto load(std::memory_order order = std::memory_order_relaxed) const noexcept -> uint64_t
    {
        uint64_t sum = 0;
        for(const auto& shard : m_shards)
        {
            sum += shard.value.load(order);
        }
        return sum;
    }

    void store(uint64_t value, std::memory_order order = std::memory_order_relaxed) noexcept
    {
        m_shards[0].value.store(value, order);
        for(std::size_t i = 1; i < Shards; ++i)
        {
            m_shards[i].value.store(0, order);
        }
    }

  private:
    struct alignas(64) PaddedAtomicU64
    {
        std::atomic<uint64_t> value{0};
    };

    std::array<PaddedAtomicU64, Shards> m_shards{};

    static auto nextThreadIndex() noexcept -> std::size_t
    {
        static std::atomic<std::size_t> next{0};
        return next.fetch_add(1, std::memory_order_relaxed) % Shards;
    }

    static auto threadIndex() noexcept -> std::size_t
    {
        thread_local std::size_t idx = nextThreadIndex();
        return idx;
    }

    auto shardForUpdate() noexcept -> std::atomic<uint64_t>&
    {
        return m_shards[threadIndex()].value;
    }
};

// Metrics structure
struct Metrics
{
    ShardedCounterU64<64> packetsProcessed;
    ShardedCounterU64<64> packetsAllowed;
    ShardedCounterU64<64> packetsBlocked;
    ShardedCounterU64<64> packetsLogged;
    ShardedCounterU64<64> packetsRateLimited;
    ShardedCounterU64<64> policiesLoaded;
    ShardedCounterU64<64> bytesProcessed;
    std::chrono::system_clock::time_point startTime;

    Metrics() : startTime(std::chrono::system_clock::now()) {}
};

// Configuration structure
struct Config
{
    std::string configFilePath;
    std::string logLevel = "info";
    std::string logFilePath;
    uint16_t adminPort = defaultAdminPort;
    uint16_t metricsPort = defaultMetricsPort;
    std::string interfaceName = "eth0";
    bool daemonMode = false;
    bool enableMetrics = true;
    size_t policyCapacity = defaultPolicyCapacity;
    std::string ebpfProgramPath;
    std::string ebpfProgramType = "xdp";  // "xdp", "tc_ingress", "tc_egress"
    std::string policiesFile;             // Path to JSON policies file to load at startup
    std::chrono::seconds policyCleanupInterval{300};  // 5 minutes
};

// Main daemon class interface
class IPepctlDaemon
{
  public:
    virtual ~IPepctlDaemon() = default;

    virtual bool initialize(const Config& config) = 0;
    virtual bool start() = 0;
    virtual void stop() = 0;
    virtual bool isRunning() const = 0;

    virtual PolicyEngine& getPolicyEngine() = 0;
    virtual EbpfManager& getEbpfManager() = 0;
    virtual MetricsServer& getMetricsServer() = 0;
    virtual Logger& getLogger() = 0;
    virtual Metrics& getMetrics() = 0;
};


/// @brief Create a new IPepctlDaemon instance
/// @param logger A shared pointer to the Logger instance
/// @return A unique pointer to the IPepctlDaemon instance
///
std::unique_ptr<IPepctlDaemon> createDaemon(std::shared_ptr<Logger> logger);

/// @brief Convert a PolicyAction enum value to a string
/// @param action The PolicyAction enum value
/// @return A string representation of the PolicyAction
///
std::string policyActionToString(PolicyAction action);

/// @brief Convert a string to a PolicyAction enum value
/// @param str The string to convert
/// @return The PolicyAction enum value
///
PolicyAction stringToPolicyAction(const std::string& str);

/// @brief Convert a Protocol enum value to a string
/// @param proto The Protocol enum value
/// @return A string representation of the Protocol
///
std::string protocolToString(Protocol proto);

/// @brief Convert a string to a Protocol enum value
/// @param str The string to convert
/// @return The Protocol enum value
///
Protocol stringToProtocol(const std::string& str);

/// @brief Convert an IP string to a uint32_t value
/// @param ip_str The IP string to convert
/// @return The uint32_t value of the IP

uint32_t ipStringToUint32(const std::string& ip_str);

/// @brief Convert a uint32_t value to an IP string
/// @param ip The uint32_t value to convert
/// @return The IP string
///
std::string uint32ToIpString(uint32_t ip);

/// @brief Convert a string to an EbpfProgramType enum value
/// @param str The string to convert ("xdp", "tc_ingress", "tc_egress")
/// @return The EbpfProgramType enum value
///
enum class EbpfProgramType;  // Forward declaration
EbpfProgramType stringToEbpfProgramType(const std::string& str);

}  // namespace pepctl

