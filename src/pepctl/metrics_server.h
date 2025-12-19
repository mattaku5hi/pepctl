#pragma once

#include <atomic>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include "pepctl/core.h"
#include "pepctl/ebpf_manager.h"
#include "pepctl/policy_engine.h"


namespace pepctl 
{

class Listener;  // Forward declaration for shared_ptr

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

/// @brief Metric types for Prometheus
enum class MetricType
{
    COUNTER,
    GAUGE,
    HISTOGRAM,
    SUMMARY
};

/// @brief Individual metric entry
struct MetricEntry
{
    MetricType type;
    std::string name;
    std::string help;
    std::unordered_map<std::string, std::string> labels;
    double value{};
    std::chrono::system_clock::time_point timestamp;

    MetricEntry() = default;

    MetricEntry(MetricType t, const std::string& n, const std::string& h, double v = 0.0) :
        type(t),
        name(n),
        help(h),
        value(v),
        timestamp(std::chrono::system_clock::now())
    {}
};

/// @brief HTTP request context
struct HttpRequestContext
{
    std::string method;
    std::string target;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
    std::unordered_map<std::string, std::string> query_params;
};

/// @brief HTTP response
struct HttpResponse
{
    http::status status;
    std::string contentType;
    std::string body;
    std::unordered_map<std::string, std::string> headers;

    HttpResponse() : status(http::status::ok), contentType("text/plain") {}

    HttpResponse(http::status st, const std::string& ct, const std::string& b) :
        status(st),
        contentType(ct),
        body(b)
    {}
};

/// @brief Request handler interface
using RequestHandler = std::function<HttpResponse(const HttpRequestContext&)>;

/// @brief Main MetricsServer class
class MetricsServer
{
  public:
    explicit MetricsServer(std::shared_ptr<Logger> logger);
    virtual ~MetricsServer();

    Logger& getLogger() { return *m_logger; }

    /// @brief Initialization and lifecycle
    bool initialize(uint16_t port, const std::string& bind_address = "0.0.0.0");
    bool start();
    void stop();

    /// @brief Check if the server is running
    bool isRunning() const { return m_running.load(); }

    /// @brief Metric registration and updates
    void registerMetric(const std::string& name, MetricType type, const std::string& help);
    void setGauge(const std::string& name,
                  double value,
                  const std::unordered_map<std::string, std::string>& labels = {});
    void incrementCounter(const std::string& name,
                          double value = 1.0,
                          const std::unordered_map<std::string, std::string>& labels = {});
    void setCounter(const std::string& name,
                    double value,
                    const std::unordered_map<std::string, std::string>& labels = {});
    static void observeHistogram(const std::string& name,
                                 double value,
                                 const std::unordered_map<std::string, std::string>& labels = {});

    /// @brief Register an HTTP endpoint
    void registerEndpoint(const std::string& path,
                          const std::string& method,
                          const RequestHandler& handler);

    /// @brief Register a static endpoint
    void registerStaticEndpoint(const std::string& path,
                                const std::string& content,
                                const std::string& content_type = "text/html");

    /// @brief Setup default endpoints
    void setupDefaultEndpoints();

    /// @brief Set the policy engine
    void setPolicyEngine(PolicyEngine* engine) { m_policyEngine = engine; }

    /// @brief Set the eBPF manager
    void setEbpfManager(EbpfManager* manager) { m_ebpfManager = manager; }

    /// @brief Set the daemon metrics
    void setDaemonMetrics(Metrics* metrics) { m_daemonMetrics = metrics; }

    /// @brief Set the metrics prefix
    void setMetricsPrefix(const std::string& prefix) { m_metricsPrefix = prefix; }

    /// @brief Set the update interval
    void setUpdateInterval(std::chrono::seconds interval) { m_updateInterval = interval; }

    /// @brief Enable CORS
    void enableCors(bool enable) { m_corsEnabled = enable; }

    /// @brief Public HTTP processing member function for HttpSession
    void processHttpRequest(const http::request<http::string_body>& req,
                            http::response<http::string_body>& res);

  private:
    net::io_context m_ioc;
    tcp::acceptor m_acceptor;
    std::atomic<bool> m_running;
    std::shared_ptr<Logger> m_logger;
    uint16_t m_port;
    std::string m_bindAddress;
    std::string m_metricsPrefix;
    std::chrono::seconds m_updateInterval;
    bool m_corsEnabled{false};
    std::thread m_serverThread;
    net::steady_timer m_updateTimer;
    std::atomic<bool> m_updateRunning;
    std::mutex m_metricsMutex;
    std::unordered_map<std::string, MetricEntry> m_metrics;
    std::mutex m_endpointsMutex;
    std::unordered_map<std::string, RequestHandler> m_endpoints;
    std::shared_ptr<Listener> m_listener;
    PolicyEngine* m_policyEngine{nullptr};
    EbpfManager* m_ebpfManager{nullptr};
    Metrics* m_daemonMetrics{nullptr};

    /// @brief Private methods
    void serverLoop();
    void handleAccept();
    void handleRequest(tcp::socket socket);

    /// @brief Request processing helpers
    HttpRequestContext parseRequest(const http::request<http::string_body>& req);
    static void buildResponse(const HttpResponse& response, http::response<http::string_body>& res);
    static std::unordered_map<std::string, std::string> parseQueryParams(const std::string& target);

    /// @brief Built-in handlers
    HttpResponse handleMetrics(const HttpRequestContext& ctx);
    static HttpResponse handleHealth(const HttpRequestContext& ctx);
    HttpResponse handleInfo(const HttpRequestContext& ctx);
    HttpResponse handlePolicies(const HttpRequestContext& ctx);
    HttpResponse handlePolicyAdd(const HttpRequestContext& ctx);
    HttpResponse handlePolicyRemove(const HttpRequestContext& ctx);
    HttpResponse handleStats(const HttpRequestContext& ctx);
    HttpResponse handleDashboard(const HttpRequestContext& ctx);
    HttpResponse handleReset(const HttpRequestContext& ctx);

    /// @brief Metrics formatting
    std::string formatMetricEntry(const MetricEntry& entry);
    static std::string escapeLabelValue(const std::string& value);

    /// @brief Metric updates
    void updateSystemMetrics();
    void updatePolicyMetrics();
    void startUpdateTimer();

    /// @brief Utility functions
    static void createErrorResponse(http::status status,
                                    const std::string& message,
                                    http::response<http::string_body>& res);
    static double getUptimeSeconds();

    /// @brief Default metric setup
    void registerDefaultMetrics();

    /// @brief System integration
    void addCorsHeaders(http::response<http::string_body>& res) const;
    static std::string getDashboardHtml();
    static std::string getCurrentTimestampIso();

    /// @brief Static utility methods for system metrics
    static std::unordered_map<std::string, double> collectNetworkMetrics(
        const std::string& interface);
    static std::unordered_map<std::string, double> collectProcessMetrics();

    /// @brief Static system reading functions
    static double readProcStatValue(const std::string& field);
    static double readProcMeminfoValue(const std::string& field);
    static double readSysClassNetValue(const std::string& interface, const std::string& field);
};

/// @brief Utility class for metric collection
class MetricsCollector
{
  public:
    static std::unordered_map<std::string, double> collectSystemMetrics();
    static std::unordered_map<std::string, double> collectNetworkMetrics(
        const std::string& interface);
    static std::unordered_map<std::string, double> collectProcessMetrics();

  private:
    static double readProcStatValue(const std::string& field);
    static double readProcMeminfoValue(const std::string& field);
    static double readSysClassNetValue(const std::string& interface, const std::string& field);
};


}  // namespace pepctl
