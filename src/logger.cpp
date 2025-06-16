#include <iomanip>
#include <iostream>
#include <nlohmann/json.hpp>
#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/syslog_sink.h>
#include <spdlog/sinks/systemd_sink.h>
#include <sstream>

#include "pepctl/logger.h"


namespace pepctl 
{

std::unique_ptr<Logger> gLogger;

Logger::Logger() : m_config{}, m_currentLevel(LogLevel::INFO), m_stats{}
{
    /*
        Initialize statistics
    */
    m_stats.totalMessages = 0;
    for(int i = 0; i < 7; ++i)
    {
        m_stats.messagesByLevel[i] = 0;
        m_stats.messagesByCategory[i] = 0;
    }
}

Logger::~Logger()
{
    shutdown();
}

auto Logger::initialize(const LoggerConfig& config) -> bool
{
    try
    {
        m_config = config;
        m_currentLevel = config.level;

        /*
            Setup spdlog loggers
        */
        setupSinks();

        if(m_mainLogger != nullptr)
        {
            m_mainLogger->set_level(toSpdlogLevel(m_currentLevel));
            m_mainLogger->set_pattern(m_config.pattern);
        }

        if(m_structuredLogger != nullptr)
        {
            m_structuredLogger->set_level(toSpdlogLevel(m_currentLevel));
            m_structuredLogger->set_pattern("%v");
        }

        info("Logger initialized successfully");
        return true;
    }
    catch(const std::exception& e)
    {
        std::cerr << "Failed to initialize logger: " << e.what() << '\n';
        return false;
    }
}

void Logger::shutdown()
{
    try
    {
        /*
            Flush all pending log messages first
        */
        if(m_mainLogger != nullptr)
        {
            m_mainLogger->flush();
        }
        if(m_structuredLogger != nullptr)
        {
            m_structuredLogger->flush();
        }

        /*
            Reset our logger references first
        */
        m_mainLogger.reset();
        m_structuredLogger.reset();

        /*
            Then drop all spdlog loggers
            This should be safe now since we've released our references
        */
        spdlog::drop_all();

        /*
            Shutdown spdlog's thread pool if using async logging
        */
        spdlog::shutdown();
    }
    catch(const std::exception& e)
    {
        /*
            If shutdown fails, don't hang - just continue
        */
        std::cerr << "Logger shutdown error (non-fatal): " << e.what() << '\n';
    }
    catch(...)
    {
        /*
            Catch any other exceptions to prevent hanging
        */
        std::cerr << "Logger shutdown unknown error (non-fatal)" << '\n';
    }
}

void Logger::trace(const LogContext& ctx, const std::string& message)
{
    logWithContext(LogLevel::TRACE, ctx, message);
}

void Logger::debug(const LogContext& ctx, const std::string& message)
{
    logWithContext(LogLevel::DBG, ctx, message);
}

void Logger::info(const LogContext& ctx, const std::string& message)
{
    logWithContext(LogLevel::INFO, ctx, message);
}

void Logger::warn(const LogContext& ctx, const std::string& message)
{
    logWithContext(LogLevel::WARN, ctx, message);
}

void Logger::error(const LogContext& ctx, const std::string& message)
{
    logWithContext(LogLevel::ERROR, ctx, message);
}

void Logger::critical(const LogContext& ctx, const std::string& message)
{
    logWithContext(LogLevel::CRITICAL, ctx, message);
}

void Logger::trace(const std::string& message)
{
    trace(LogContext(), message);
}

void Logger::debug(const std::string& message)
{
    debug(LogContext(), message);
}

void Logger::info(const std::string& message)
{
    info(LogContext(), message);
}

void Logger::warn(const std::string& message)
{
    warn(LogContext(), message);
}

void Logger::error(const std::string& message)
{
    error(LogContext(), message);
}

void Logger::critical(const std::string& message)
{
    critical(LogContext(), message);
}

void Logger::setLevel(LogLevel level)
{
    m_currentLevel = level;

    auto spdLevel = toSpdlogLevel(level);
    if(m_mainLogger != nullptr)
    {
        m_mainLogger->set_level(spdLevel);
    }
    if(m_structuredLogger != nullptr)
    {
        m_structuredLogger->set_level(spdLevel);
    }
}

void Logger::setPattern(const std::string& pattern)
{
    m_config.pattern = pattern;
    if(m_mainLogger != nullptr)
    {
        m_mainLogger->set_pattern(pattern);
    }
}

void Logger::logPolicyEvent(const std::string& policy_id,
                            const std::string& action,
                            const std::string& client_ip,
                            const std::string& details)
{
    LogContext ctx(LogCategory::POLICY);
    ctx.withPolicy(policy_id).withClientIp(client_ip).withField("action", action);
    info(ctx, "Policy " + action + ": " + details);
}

void Logger::logSecurityEvent(const std::string& event_type,
                              const std::string& client_ip,
                              const std::string& details,
                              LogLevel level)
{
    LogContext ctx(LogCategory::SECURITY);
    ctx.withClientIp(client_ip).withField("event_type", event_type);
    logWithContext(level, ctx, details);
}

void Logger::logPerformanceEvent(const std::string& operation,
                                 double duration_ms,
                                 const std::unordered_map<std::string, std::string>& metrics)
{
    LogContext ctx(LogCategory::PERFORMANCE);
    ctx.withField("operation", operation).withField("duration_ms", std::to_string(duration_ms));
    for(const auto& metric : metrics)
    {
        ctx.withField(metric.first, metric.second);
    }
    info(ctx, "Performance: " + operation + " completed in " + std::to_string(duration_ms) + "ms");
}

void Logger::logNetworkEvent(const std::string& interface,
                             const std::string& event,
                             const PacketInfo& packet_info)
{
    LogContext ctx(LogCategory::NETWORK);
    /*
        Add fields to the log context
        Use chaining pattern for that
        Because withField member function returns reference to the LogContext (*this) object
        Similar to builder pattern
        or auto encrichedCtx = ctx.withField(...) .withField(...) .withField(...)
        Basically method chaining is used for stream operation of kind:
        std::cout << "Hello" << 42 << " world!" << std::endl;
        because each operator returns reference to the object - std::cout&
    */
    ctx.withField("interface", interface)
        .withField("event", event)
        .withField("src_ip", packet_info.src.toString())
        .withField("dst_ip", packet_info.dst.toString())
        .withField("protocol", std::to_string(static_cast<int>(packet_info.src.protocol)))
        .withField("packet_size", std::to_string(packet_info.size));
    info(ctx, "Network event: " + event + " on interface " + interface);
}

void Logger::logEbpfEvent(const std::string& operation, bool success, const std::string& details)
{
    LogContext ctx(LogCategory::EBPF);
    ctx.withField("operation", operation).withField("success", success ? "true" : "false");
    if(success)
    {
        info(ctx, "eBPF " + operation + ": " + details);
    }
    else
    {
        error(ctx, "eBPF " + operation + " failed: " + details);
    }
}

auto Logger::getStats() const -> Logger::LogStats
{
    std::lock_guard<std::mutex> lock(m_statsMutex);
    return m_stats;
}

void Logger::resetStats()
{
    std::lock_guard<std::mutex> lock(m_statsMutex);
    m_stats.totalMessages = 0;
    for(int i = 0; i < 7; ++i)
    {
        m_stats.messagesByLevel[i] = 0;
        m_stats.messagesByCategory[i] = 0;
    }
}

void Logger::flush()
{
    if(m_mainLogger != nullptr)
    {
        m_mainLogger->flush();
    }
    if(m_structuredLogger != nullptr)
    {
        m_structuredLogger->flush();
    }
}

void Logger::rotateLogs()
{
    /*
        Force rotation by flushing and recreating file sinks
    */
    if(m_config.fileOutput && !m_config.logFilePath.empty())
    {
        flush();
        info("Log rotation triggered");
    }
}

void Logger::logWithContext(LogLevel level, const LogContext& ctx, const std::string& message)
{
    if(level < m_currentLevel)
    {
        return;
    }

    updateStats(level, ctx.category);

    auto spdLevel = toSpdlogLevel(level);

    /*
        Log to main logger
    */
    if(m_mainLogger != nullptr)
    {
        std::string contextPrefix = "[" + categoryToString(ctx.category) + "]";
        if(ctx.component.empty() == false)
        {
            contextPrefix += "[" + ctx.component + "]";
        }
        if(ctx.clientIp.empty() == false)
        {
            contextPrefix += "[" + ctx.clientIp + "]";
        }

        m_mainLogger->log(spdLevel, "{} {}", contextPrefix, message);
    }

    /*
        Log structured data if enabled
    */
    if(m_structuredLogger != nullptr && m_config.structuredLogging)
    {
        std::string structuredMsg;
        if(m_config.logFormat == "json")
        {
            structuredMsg = formatJsonMessage(ctx, message);
        }
        else
        {
            structuredMsg = formatStructuredMessage(ctx, message);
        }
        m_structuredLogger->log(spdLevel, structuredMsg);
    }
}

auto Logger::formatStructuredMessage(const LogContext& ctx,
                                     const std::string& message) -> std::string
{
    /*
        Format structured message using string stream
        It is type safe and provides automatic type conversion
        It manages internal buffer more efficiently than string concatenation causing multiple
        memory reallocations 
        for(int i = 0; i < 1000; ++i) 
        { 
            result += "Item " + std::to_string(i) + "\n";  // Multiple reallocations, O(n^2) complexity 
            oss << "Item " << i << "\n";  // O(n) complexity
        }
        std::string result = oss.str();
    */
    std::ostringstream oss;
    auto now = std::chrono::system_clock::now();
    auto timeT = std::chrono::system_clock::to_time_t(now);

    oss << std::put_time(std::localtime(&timeT), "%Y-%m-%d %H:%M:%S");
    oss << " category=" << categoryToString(ctx.category);

    if(ctx.component.empty() == false)
    {
        oss << " component=" << ctx.component;
    }
    if(ctx.sessionId.empty() == false)
    {
        oss << " session=" << ctx.sessionId;
    }
    if(ctx.clientIp.empty() == false)
    {
        oss << " client_ip=" << ctx.clientIp;
    }
    if(ctx.policyId.empty() == false)
    {
        oss << " policy_id=" << ctx.policyId;
    }

    for(const auto& field : ctx.extraFields)
    {
        oss << " " << field.first << "=" << field.second;
    }

    oss << " message=\"" << message << "\"";
    return oss.str();
}

auto Logger::formatJsonMessage(const LogContext& ctx, const std::string& message) -> std::string
{
    nlohmann::json jsonTemp;

    auto now = std::chrono::system_clock::now();
    auto timeT = std::chrono::system_clock::to_time_t(now);
    std::ostringstream timeStream;
    timeStream << std::put_time(std::gmtime(&timeT), "%Y-%m-%dT%H:%M:%SZ");

    jsonTemp["timestamp"] = timeStream.str();
    jsonTemp["message"] = message;
    jsonTemp["category"] = categoryToString(ctx.category);

    if(ctx.component.empty() == false)
    {
        jsonTemp["component"] = ctx.component;
    }
    if(ctx.sessionId.empty() == false)
    {
        jsonTemp["session_id"] = ctx.sessionId;
    }
    if(ctx.clientIp.empty() == false)
    {
        jsonTemp["client_ip"] = ctx.clientIp;
    }
    if(ctx.policyId.empty() == false)
    {
        jsonTemp["policy_id"] = ctx.policyId;
    }

    if(ctx.extraFields.empty() == false)
    {
        jsonTemp["fields"] = ctx.extraFields;
    }

    /*
        Convert to JSON std::string
    */
    return jsonTemp.dump();
}

auto Logger::categoryToString(LogCategory category) -> std::string
{
    switch(category)
    {
        case LogCategory::SYSTEM:
            {
                return "SYSTEM";
            }
        case LogCategory::POLICY:
            {
                return "POLICY";
            }
        case LogCategory::EBPF:
            {
                return "EBPF";
            }
        case LogCategory::NETWORK:
            {
                return "NETWORK";
            }
        case LogCategory::METRICS:
            {
                return "METRICS";
            }
        case LogCategory::SECURITY:
            {
                return "SECURITY";
            }
        case LogCategory::PERFORMANCE:
            {
                return "PERFORMANCE";
            }
        default:
            {
                return "UNKNOWN";
            }
    }
}

auto Logger::levelToString(LogLevel level) -> std::string
{
    switch(level)
    {
        case LogLevel::TRACE:
            {
                return "TRACE";
            }
        case LogLevel::DBG:
            {
                return "DEBUG";
            }
        case LogLevel::INFO:
            {
                return "INFO";
            }
        case LogLevel::WARN:
            {
                return "WARN";
            }
        case LogLevel::ERROR:
            {
                return "ERROR";
            }
        case LogLevel::CRITICAL:
            {
                return "CRITICAL";
            }
        default:
            {
                return "UNKNOWN";
            }
    }
}

auto Logger::toSpdlogLevel(LogLevel level) -> spdlog::level::level_enum
{
    switch(level)
    {
        case LogLevel::TRACE:
            {
                return spdlog::level::trace;
            }
        case LogLevel::DBG:
            {
                return spdlog::level::debug;
            }
        case LogLevel::INFO:
            {
                return spdlog::level::info;
            }
        case LogLevel::WARN:
            {
                return spdlog::level::warn;
            }
        case LogLevel::ERROR:
            {
                return spdlog::level::err;
            }
        case LogLevel::CRITICAL:
            {
                return spdlog::level::critical;
            }
        default:
            {
                return spdlog::level::off;
            }
    }
}

void Logger::updateStats(LogLevel level, LogCategory category)
{
    std::lock_guard<std::mutex> lock(m_statsMutex);
    m_stats.totalMessages++;
    m_stats.messagesByLevel[static_cast<int>(level)]++;
    m_stats.messagesByCategory[static_cast<int>(category)]++;
    m_stats.lastMessageTime = std::chrono::system_clock::now();
}

void Logger::setupSinks()
{
    std::vector<spdlog::sink_ptr> sinks;
    std::vector<spdlog::sink_ptr> structuredSinks;

    /*
        Console output
    */
    if(m_config.consoleOutput == true)
    {
        setupConsoleSink();
        auto consoleSink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        sinks.push_back(consoleSink);
    }

    /*
        File output
    */
    if(m_config.fileOutput == true && m_config.logFilePath.empty() == false)
    {
        setupFileSink();
        auto fileSink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            m_config.logFilePath, m_config.maxFileSize, m_config.maxFiles);
        sinks.push_back(fileSink);
        structuredSinks.push_back(fileSink);
    }

    /*
        Syslog output
    */
    if(m_config.syslogOutput == true)
    {
        setupSyslogSink();
        auto syslogSink =
            std::make_shared<spdlog::sinks::syslog_sink_mt>("pepctl", LOG_PID, LOG_USER, true);
        sinks.push_back(syslogSink);
    }

    /*
        Systemd Journal output (default on Linux)
    */
    if(m_config.systemdOutput == true)
    {
        setupSystemdSink();
        auto systemdSink = std::make_shared<spdlog::sinks::systemd_sink_mt>("pepctl");
        sinks.push_back(systemdSink);
        structuredSinks.push_back(systemdSink);
    }

    /*
        Create main logger
    */
    if(sinks.empty() == false)
    {
        m_mainLogger = std::make_shared<spdlog::logger>("pepctl", sinks.begin(), sinks.end());
        spdlog::register_logger(m_mainLogger);
    }

    /*
        Create structured logger for JSON output
    */
    if(structuredSinks.empty() == false && m_config.structuredLogging == true)
    {
        m_structuredLogger = std::make_shared<spdlog::logger>(
            "pepctl-structured", structuredSinks.begin(), structuredSinks.end());
        spdlog::register_logger(m_structuredLogger);
    }
}

void Logger::setupConsoleSink()
{
    // Console sink is created in setupSinks() - no additional setup needed
}

void Logger::setupFileSink()
{
    // File sink is created in setupSinks() - no additional setup needed
}

void Logger::setupSyslogSink()
{
    // Syslog sink is created in setupSinks() - no additional setup needed
}

void Logger::setupSystemdSink()
{
    // Systemd sink is created in setupSinks() - no additional setup needed
}


}  // namespace pepctl