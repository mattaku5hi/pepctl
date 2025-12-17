#pragma once


#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include <fmt/format.h>
#include <spdlog/fmt/ostr.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/syslog_sink.h>
#include <spdlog/sinks/systemd_sink.h>
#include <spdlog/spdlog.h>

#include "core.h"

namespace pepctl {


/**
 * @brief
 */
enum class LogLevel
{
    TRACE = 0,
    DBG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    CRITICAL = 5,
    OFF = 6
};

/**
 * @brief Log categories for structured logging
 */
enum class LogCategory
{
    SYSTEM,      // System-level events
    POLICY,      // Policy-related events
    EBPF,        // eBPF-related events
    NETWORK,     // Network events
    METRICS,     // Metrics and monitoring
    SECURITY,    // Security events
    PERFORMANCE  // Performance-related events
};

/**
 * @brief Log context for structured logging
 */
struct LogContext
{
    LogCategory category;
    std::string component;
    std::string sessionId;
    std::string clientIp;
    std::string policyId;
    std::unordered_map<std::string, std::string>
        extraFields;  // hash map for O(1) lookup and insertion

    LogContext(LogCategory cat = LogCategory::SYSTEM) : category(cat) {}

    LogContext& withComponent(const std::string& comp)
    {
        component = comp;
        return *this;
    }

    LogContext& withSession(const std::string& session)
    {
        sessionId = session;
        return *this;
    }

    LogContext& withClientIp(const std::string& ip)
    {
        clientIp = ip;
        return *this;
    }

    LogContext& withPolicy(const std::string& policy)
    {
        policyId = policy;
        return *this;
    }

    LogContext& withField(const std::string& key, const std::string& value)
    {
        extraFields[key] = value;
        return *this;
    }
};

/**
 * @brief Logger configuration
 */
struct LoggerConfig
{
    LogLevel level = LogLevel::INFO;
    std::string logFilePath;
    std::string pattern = "[%Y-%m-%d %H:%M:%S.%e] [%l] [%n] %v";
    bool consoleOutput = true;
    bool fileOutput = false;
    bool syslogOutput = false;
    bool systemdOutput = true;              // Default to systemd journal on Linux
    size_t maxFileSize = 10 * 1024 * 1024;  // 10MiB
    size_t maxFiles = 5;                    // Number of rotated files to keep
    bool structuredLogging = true;
    std::string logFormat = "json";  // "json" or "text"
};

/**
 * @brief Main Logger class
 */
class Logger
{
  public:
    Logger();
    virtual ~Logger();

    /**
     * @brief Initialize the logger
     * @param config The logger configuration
     * @return True if the logger was initialized successfully, false otherwise
     */
    bool initialize(const LoggerConfig& config);

    /**
     * @brief Shutdown the logger
     */
    void shutdown();

    /**
     * @brief Log a message with context
     * @param ctx The log context
     * @param message The message to log
     */
    void trace(const LogContext& ctx, const std::string& message);
    void debug(const LogContext& ctx, const std::string& message);
    void info(const LogContext& ctx, const std::string& message);
    void warn(const LogContext& ctx, const std::string& message);
    void error(const LogContext& ctx, const std::string& message);
    void critical(const LogContext& ctx, const std::string& message);

    /**
     * @brief Template logging methods for format strings
     * @param ctx The log context
     * @param format The format string
     * @param args The arguments to format
     */
    template <typename... Args>
    void trace(const LogContext& ctx, const std::string& format, Args&&... args)
    {
        logFormatted(LogLevel::TRACE, ctx, format, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void debug(const LogContext& ctx, const std::string& format, Args&&... args)
    {
        logFormatted(LogLevel::DBG, ctx, format, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void info(const LogContext& ctx, const std::string& format, Args&&... args)
    {
        logFormatted(LogLevel::INFO, ctx, format, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void warn(const LogContext& ctx, const std::string& format, Args&&... args)
    {
        logFormatted(LogLevel::WARN, ctx, format, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void error(const LogContext& ctx, const std::string& format, Args&&... args)
    {
        logFormatted(LogLevel::ERROR, ctx, format, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void critical(const LogContext& ctx, const std::string& format, Args&&... args)
    {
        logFormatted(LogLevel::CRITICAL, ctx, format, std::forward<Args>(args)...);
    }

    void trace(const std::string& message);
    void debug(const std::string& message);
    void info(const std::string& message);
    void warn(const std::string& message);
    void error(const std::string& message);
    void critical(const std::string& message);

    /**
     * @brief Set the log level
     * @param level The log level
     */
    void setLevel(LogLevel level);

    /**
     * @brief Get the current log level
     * @return The current log level
     */
    LogLevel getLevel() const { return m_currentLevel; }

    /**
     * @brief Set the log pattern
     * @param pattern The log pattern
     */
    void setPattern(const std::string& pattern);

    /**
     * @brief Log a policy event
     * @param policy_id The policy ID
     * @param action The action
     * @param client_ip The client IP
     * @param details The details of the event
     */
    void logPolicyEvent(const std::string& policy_id,
                        const std::string& action,
                        const std::string& client_ip,
                        const std::string& details);

    /**
     * @brief Log a security event
     * @param event_type The event type
     * @param client_ip The client IP
     * @param details The details of the event
     * @param level The log level
     */
    void logSecurityEvent(const std::string& event_type,
                          const std::string& client_ip,
                          const std::string& details,
                          LogLevel level = LogLevel::WARN);

    /**
     * @brief Log a performance event
     * @param operation The operation
     * @param duration_ms The duration in milliseconds
     * @param metrics The metrics
     */
    void logPerformanceEvent(const std::string& operation,
                             double duration_ms,
                             const std::unordered_map<std::string, std::string>& metrics);

    /**
     * @brief Log a network event
     * @param interface The interface
     * @param event The event
     * @param packet_info The packet information
     */
    void logNetworkEvent(const std::string& interface,
                         const std::string& event,
                         const PacketInfo& packet_info);

    /**
     * @brief Log an eBPF event
     * @param operation The operation
     * @param success The success flag
     * @param details The details of the event
     */
    void logEbpfEvent(const std::string& operation, bool success, const std::string& details);

    /**
     * @brief Log statistics
     */
    struct LogStats
    {
        uint64_t totalMessages{};
        uint64_t messagesByLevel[7]{};     // One for each LogLevel
        uint64_t messagesByCategory[7]{};  // One for each LogCategory
        std::chrono::system_clock::time_point lastMessageTime;
    };

    /**
     * @brief Get the log statistics
     * @return The log statistics
     */
    LogStats getStats() const;

    /**
     * @brief Reset the log statistics
     */
    void resetStats();

    /**
     * @brief Flush the logs
     */
    void flush();
    /**
     * @brief Rotate the logs
     */
    void rotateLogs();

  private:
    // spdlog logger instances
    std::shared_ptr<spdlog::logger> m_mainLogger;
    std::shared_ptr<spdlog::logger> m_structuredLogger;

    LoggerConfig m_config;
    LogLevel m_currentLevel{LogLevel::INFO};

    mutable std::mutex m_statsMutex;
    LogStats m_stats;

    /**
     * @brief Log a message with context
     * @param level The log level
     * @param ctx The log context
     * @param message The message to log
     */
    void logWithContext(LogLevel level, const LogContext& ctx, const std::string& message);
    /**
     * @brief Format a structured message
     * @param ctx The log context
     * @param message The message to format
     * @return The formatted message
     */
    static std::string formatStructuredMessage(const LogContext& ctx, const std::string& message);
    /**
     * @brief Format a JSON message
     * @param ctx The log context
     * @param message The message to format
     * @return The formatted message
     */
    static std::string formatJsonMessage(const LogContext& ctx, const std::string& message);
    /**
     * @brief Convert a log category to a string
     * @param category The log category
     * @return The string representation of the log category
     */
    static std::string categoryToString(LogCategory category);
    /**
     * @brief Convert a log level to a string
     * @param level The log level
     * @return The string representation of the log level
     */
    static std::string levelToString(LogLevel level);

    /**
     * @brief Convert a log level to a spdlog level
     * @param level The log level
     * @return The spdlog level
     */
    static spdlog::level::level_enum toSpdlogLevel(LogLevel level);

    /**
     * @brief Log a formatted message
     * @param level The log level
     * @param ctx The log context
     * @param format The format string
     * @param args The arguments to format
     */
    template <typename... Args>
    void logFormatted(LogLevel level,
                      const LogContext& ctx,
                      const std::string& format,
                      Args&&... args)
    {
        if(level < m_currentLevel)
        {
            return;
        }

        try
        {
            std::string formattedMessage =
                fmt::format(fmt::runtime(format), std::forward<Args>(args)...);
            logWithContext(level, ctx, formattedMessage);
        }
        catch(const std::exception& e)
        {
            /*
                Fallback to unformatted message if formatting fails
            */
            logWithContext(LogLevel::ERROR,
                           LogContext(LogCategory::SYSTEM),
                           "Log formatting error: " + std::string(e.what())
                               + ". Original format: " + format);
        }
    }

    /**
     * @brief Update the statistics
     * @param level The log level
     * @param category The log category
     */
    void updateStats(LogLevel level, LogCategory category);

    void setupSinks();
    void setupConsoleSink();
    void setupFileSink();
    void setupSyslogSink();
    void setupSystemdSink();
};

/**
 * @brief Global logger instance and convenience macros
 */
extern std::unique_ptr<Logger> gLogger;


/**
 * @brief Convenience macros for common logging patterns
 */
#define PEPCTL_LOG_TRACE(ctx, msg) \
    if(pepctl::gLogger != nullptr) \
    pepctl::gLogger->trace(ctx, msg)
#define PEPCTL_LOG_DEBUG(ctx, msg) \
    if(pepctl::gLogger != nullptr) \
    pepctl::gLogger->debug(ctx, msg)
#define PEPCTL_LOG_INFO(ctx, msg)  \
    if(pepctl::gLogger != nullptr) \
    pepctl::gLogger->info(ctx, msg)
#define PEPCTL_LOG_WARN(ctx, msg)  \
    if(pepctl::gLogger != nullptr) \
    pepctl::gLogger->warn(ctx, msg)
#define PEPCTL_LOG_ERROR(ctx, msg) \
    if(pepctl::gLogger != nullptr) \
    pepctl::gLogger->error(ctx, msg)
#define PEPCTL_LOG_CRITICAL(ctx, msg) \
    if(pepctl::gLogger != nullptr)    \
    pepctl::gLogger->critical(ctx, msg)

/**
 * @brief Formatted logging macros
 */
#define PEPCTL_LOG_TRACE_FMT(ctx, fmt, ...) \
    if(pepctl::gLogger != nullptr)          \
    pepctl::gLogger->trace(ctx, fmt, __VA_ARGS__)
#define PEPCTL_LOG_DEBUG_FMT(ctx, fmt, ...) \
    if(pepctl::gLogger != nullptr)          \
    pepctl::gLogger->debug(ctx, fmt, __VA_ARGS__)
#define PEPCTL_LOG_INFO_FMT(ctx, fmt, ...) \
    if(pepctl::gLogger != nullptr)         \
    pepctl::gLogger->info(ctx, fmt, __VA_ARGS__)
#define PEPCTL_LOG_WARN_FMT(ctx, fmt, ...) \
    if(pepctl::gLogger != nullptr)         \
    pepctl::gLogger->warn(ctx, fmt, __VA_ARGS__)
#define PEPCTL_LOG_ERROR_FMT(ctx, fmt, ...) \
    if(pepctl::gLogger != nullptr)          \
    pepctl::gLogger->error(ctx, fmt, __VA_ARGS__)
#define PEPCTL_LOG_CRITICAL_FMT(ctx, fmt, ...) \
    if(pepctl::gLogger != nullptr)             \
    pepctl::gLogger->critical(ctx, fmt, __VA_ARGS__)

/**
 * @brief Simple logging without context
 */
#define PEPCTL_LOG_SIMPLE_TRACE(msg) \
    if(pepctl::gLogger != nullptr)   \
    pepctl::gLogger->trace(msg)
#define PEPCTL_LOG_SIMPLE_DEBUG(msg) \
    if(pepctl::gLogger != nullptr)   \
    pepctl::gLogger->debug(msg)
#define PEPCTL_LOG_SIMPLE_INFO(msg) \
    if(pepctl::gLogger != nullptr)  \
    pepctl::gLogger->info(msg)
#define PEPCTL_LOG_SIMPLE_WARN(msg) \
    if(pepctl::gLogger != nullptr)  \
    pepctl::gLogger->warn(msg)
#define PEPCTL_LOG_SIMPLE_ERROR(msg) \
    if(pepctl::gLogger != nullptr)   \
    pepctl::gLogger->error(msg)
#define PEPCTL_LOG_SIMPLE_CRITICAL(msg) \
    if(pepctl::gLogger != nullptr)      \
    pepctl::gLogger->critical(msg)


}  // namespace pepctl