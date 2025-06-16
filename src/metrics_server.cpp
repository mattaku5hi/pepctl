#include <boost/asio/dispatch.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <nlohmann/json.hpp>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <unistd.h>

#include "pepctl/ebpf_manager.h"
#include "pepctl/logger.h"
#include "pepctl/metrics_server.h"
#include "pepctl/policy_engine.h"


namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

namespace pepctl 
{

/*
    Use enable_shared_from_this to allow shared_ptr to access the object's methods
    We need this to provide safe asynnc operations
*/
class HttpSession : public std::enable_shared_from_this<HttpSession>
{
  public:
    HttpSession(tcp::socket&& socket, MetricsServer* server) :
        m_stream(std::move(socket)),
        m_server(server)
    {

    }

    void run()
    {
        boost::asio::dispatch(m_stream.get_executor(),
                              beast::bind_front_handler(&HttpSession::doRead, shared_from_this()));
    }

  private:
    beast::tcp_stream m_stream;
    beast::flat_buffer m_buffer;
    http::request<http::string_body> m_req;
    MetricsServer* m_server;

    void doRead()
    {
        m_req = {};

        m_stream.expires_after(std::chrono::seconds(30));

        /* 
            We create another HttpSession object consumer - shared pointer
            to guarantee the object is alive before async read is completed
        */
        http::async_read(m_stream,
                         m_buffer,
                         m_req,
                         beast::bind_front_handler(&HttpSession::onRead, shared_from_this()));
    }

    void onRead(beast::error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if(ec == http::error::end_of_stream)
        {
            return doClose();
        }

        if(ec.value() != 0)
        {
            if(gLogger != nullptr)
            {
                gLogger->debug(LogContext(LogCategory::NETWORK).withField("error", ec.message()),
                               "HTTP read error");
            }
            return;
        }

        handleRequest();
    }

    void handleRequest()
    {
        http::response<http::string_body> response;
        m_server->processHttpRequest(m_req, response);

        auto sp = std::make_shared<http::response<http::string_body>>(std::move(response));

        http::async_write(m_stream,
                          *sp,
                          beast::bind_front_handler(&HttpSession::onWrite, shared_from_this(), sp));
    }

    void onWrite(const std::shared_ptr<http::response<http::string_body>>& response,
                 beast::error_code ec,
                 std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if(ec.value() != 0)
        {
            if(gLogger != nullptr)
            {
                gLogger->debug(LogContext(LogCategory::NETWORK).withField("error", ec.message()),
                               "HTTP write error");
            }
            return;
        }

        /*
            Whether to close connection after write
            It's keep_alive option in the request HTTP header
        */
        if(response->need_eof())
        {
            return doClose();
        }

        doRead();
    }

    void doClose()
    {
        beast::error_code ec;
        m_stream.socket().shutdown(tcp::socket::shutdown_send, ec);
    }
};

/*
    Listener class
    This class is responsible for accepting incoming connections and creating HttpSession objects
*/
class Listener : public std::enable_shared_from_this<Listener>
{
  public:
    Listener(net::io_context& ioc, const tcp::endpoint& endpoint, MetricsServer* server) :
        m_ioc(ioc),
        m_acceptor(ioc),
        m_server(server)
    {
        beast::error_code ec;

        m_acceptor.open(endpoint.protocol(), ec);
        if(ec.value() != 0)
        {
            if(gLogger != nullptr)
            {
                gLogger->error(LogContext(LogCategory::NETWORK).withField("error", ec.message()),
                               "Failed to open acceptor");
            }
            return;
        }

        m_acceptor.set_option(net::socket_base::reuse_address(true), ec);
        if(ec.value() != 0)
        {
            if(gLogger != nullptr)
            {
                gLogger->error(LogContext(LogCategory::NETWORK).withField("error", ec.message()),
                               "Failed to set socket options");
            }
            return;
        }

        m_acceptor.bind(endpoint, ec);
        if(ec.value() != 0)
        {
            if(gLogger != nullptr)
            {
                gLogger->error(LogContext(LogCategory::NETWORK).withField("error", ec.message()),
                               "Failed to bind acceptor");
            }
            return;
        }

        m_acceptor.listen(net::socket_base::max_listen_connections, ec);
        if(ec)
        {
            if(gLogger != nullptr)
            {
                gLogger->error(LogContext(LogCategory::NETWORK).withField("error", ec.message()),
                               "Failed to listen");
            }
            return;
        }
    }

    void run() 
    { 
        doAccept(); 
    }

  private:
    net::io_context& m_ioc;
    tcp::acceptor m_acceptor;
    MetricsServer* m_server;

    void doAccept()
    {
        m_acceptor.async_accept(boost::asio::make_strand(m_ioc),
                                beast::bind_front_handler(&Listener::onAccept, shared_from_this()));
    }

    void onAccept(beast::error_code ec, tcp::socket socket)
    {
        if(ec.value() != 0)
        {
            if(gLogger != nullptr)
            {
                gLogger->debug(LogContext(LogCategory::NETWORK).withField("error", ec.message()),
                               "Accept error");
            }
        }
        else
        {
            std::make_shared<HttpSession>(std::move(socket), m_server)->run();
        }

        doAccept();
    }
};

/*
    MetricsServer class
    This class is responsible for serving metrics and health checks
*/
MetricsServer::MetricsServer() :
    m_ioc(),
    m_acceptor(m_ioc),
    m_running(false),
    m_port(8080),
    m_bindAddress("0.0.0.0"),
    m_metricsPrefix("pepctl_"),
    m_updateInterval(std::chrono::seconds(10)),
    m_corsEnabled(false),
    m_serverThread(),
    m_updateTimer(m_ioc),
    m_updateRunning(false),
    m_metricsMutex(),
    m_metrics(),
    m_endpointsMutex(),
    m_endpoints(),
    m_listener(),
    m_policyEngine(nullptr),
    m_ebpfManager(nullptr),
    m_daemonMetrics(nullptr)
{
    // Initialize basic structures
}

MetricsServer::~MetricsServer()
{
    stop();
}

auto MetricsServer::initialize(uint16_t port, const std::string& bind_address) -> bool
{
    m_port = port;
    m_bindAddress = bind_address;

    if(gLogger != nullptr)
    {
        gLogger->info(LogContext(LogCategory::SYSTEM)
                          .withField("port", std::to_string(port))
                          .withField("address", bind_address),
                      "Metrics server initialized");
    }

    return true;
}

auto MetricsServer::start() -> bool
{
    if(m_running.load() == true)
    {
        return true;
    }

    try
    {
        auto const address = net::ip::make_address(m_bindAddress);
        auto const port = m_port;

        m_listener = std::make_shared<Listener>(m_ioc, tcp::endpoint{address, port}, this);
        m_listener->run();

        /*
            Start the IO context in a separate thread
        */
        m_serverThread = std::thread([this]() { 
            try
            {
                m_ioc.run();
            }
            catch(const std::exception& e)
            {
                if(gLogger != nullptr)
                {
                    gLogger->error(LogContext(LogCategory::SYSTEM).withField("error", e.what()),
                                   "Failed to run metrics server");
                }
            }
        });

        /*
            Start metrics update timer
        */
        startUpdateTimer();

        m_running.store(true);

        if(gLogger != nullptr)
        {
            gLogger->info(LogContext(LogCategory::SYSTEM)
                              .withField("port", std::to_string(m_port))
                              .withField("address", m_bindAddress),
                          "Metrics server started");
        }

        return true;
    }
    catch(const std::exception& e)
    {
        if(gLogger != nullptr)
        {
            gLogger->error(LogContext(LogCategory::SYSTEM).withField("error", e.what()),
                           "Failed to start metrics server");
        }
        return false;
    }
}

void MetricsServer::stop()
{
    if(m_running.load() == false && m_serverThread.joinable() == false)
    {
        return;
    }

    if(gLogger != nullptr)
    {
        gLogger->info(LogContext(LogCategory::SYSTEM), "MetricsServer::stop() - begin");
    }

    /*
        Cancel update timer to ensure no pending async handlers
    */
    boost::system::error_code ec;
    m_updateTimer.cancel(ec);
    if(gLogger != nullptr)
    {
        gLogger->debug(LogContext(LogCategory::SYSTEM),
                       "MetricsServer::stop() - updateTimer canceled");
    }

    /*
        Reset listener to cancel all async operations before stopping io_context
    */
    m_listener.reset();
    if(gLogger != nullptr)
    {
        gLogger->debug(LogContext(LogCategory::SYSTEM), "MetricsServer::stop() - listener reset");
    }

    /*
        Stop running flags
    */
    m_running.store(false);
    m_updateRunning.store(false);

    /*
        Stop IO context
    */
    m_ioc.stop();
    if(gLogger != nullptr)
    {
        gLogger->debug(LogContext(LogCategory::SYSTEM),
                       "MetricsServer::stop() - io_context stopped");
    }

    /*
        Wait for IO thread to finish
    */
    if(m_serverThread.joinable() == true)
    {
        if(gLogger != nullptr)
        {
            gLogger->info(LogContext(LogCategory::SYSTEM), "Joining metrics server IO thread...");
        }
        m_serverThread.join();
        if(gLogger != nullptr)
        {
            gLogger->info(LogContext(LogCategory::SYSTEM), "Metrics server IO thread joined");
        }
    }

    /*
        Now safe to reset io_context
    */
    m_ioc.reset();
    if(gLogger != nullptr)
    {
        gLogger->debug(LogContext(LogCategory::SYSTEM), "MetricsServer::stop() - io_context reset");
    }

    /*
        Reset thread object to avoid accidental reuse
    */
    m_serverThread = std::thread();

    if(gLogger != nullptr)
    {
        gLogger->info(LogContext(LogCategory::SYSTEM), "Metrics server stopped");
        gLogger->info(LogContext(LogCategory::SYSTEM), "MetricsServer::stop() - end");
    }
}

void MetricsServer::registerMetric(const std::string& name,
                                   MetricType type,
                                   const std::string& help)
{
    std::lock_guard<std::mutex> lock(m_metricsMutex);

    MetricEntry entry(type, name, help);
    m_metrics[name] = entry;
}

void MetricsServer::setGauge(const std::string& name,
                             double value,
                             const std::unordered_map<std::string, std::string>& labels)
{
    std::lock_guard<std::mutex> lock(m_metricsMutex);

    auto it = m_metrics.find(name);
    if(it != m_metrics.end())
    {
        it->second.value = value;
        it->second.labels = labels;
        it->second.timestamp = std::chrono::system_clock::now();
    }
    else
    {
        /*
            Auto-register gauge if not found
        */
        MetricEntry entry(MetricType::GAUGE, name, "");
        entry.value = value;
        entry.labels = labels;
        entry.timestamp = std::chrono::system_clock::now();
        m_metrics[name] = entry;
    }
}

void MetricsServer::incrementCounter(const std::string& name,
                                     double value,
                                     const std::unordered_map<std::string, std::string>& labels)
{
    std::lock_guard<std::mutex> lock(m_metricsMutex);

    auto it = m_metrics.find(name);
    if(it != m_metrics.end())
    {
        it->second.value += value;
        it->second.labels = labels;
        it->second.timestamp = std::chrono::system_clock::now();
    }
    else
    {
        /*
            Auto-register counter if not found
        */
        MetricEntry entry(MetricType::COUNTER, name, "");
        entry.value = value;
        entry.labels = labels;
        entry.timestamp = std::chrono::system_clock::now();
        m_metrics[name] = entry;
    }
}

void MetricsServer::setCounter(const std::string& name,
                               double value,
                               const std::unordered_map<std::string, std::string>& labels)
{
    std::lock_guard<std::mutex> lock(m_metricsMutex);

    auto it = m_metrics.find(name);
    if(it != m_metrics.end())
    {
        /*
            Preserve the original type (should be COUNTER)
        */
        it->second.value = value;
        it->second.labels = labels;
        it->second.timestamp = std::chrono::system_clock::now();
    }
    else
    {
        /*
            Auto-register counter if not found
        */
        MetricEntry entry(MetricType::COUNTER, name, "");
        entry.value = value;
        entry.labels = labels;
        entry.timestamp = std::chrono::system_clock::now();
        m_metrics[name] = entry;
    }
}

void MetricsServer::observeHistogram(const std::string& name,
                                     double value,
                                     const std::unordered_map<std::string, std::string>& labels)
{
    boost::ignore_unused(name, value, labels);
    // Simple implementation - could be enhanced with proper histogram buckets
}

void MetricsServer::registerEndpoint(const std::string& path,
                                     const std::string& method,
                                     const RequestHandler& handler)
{
    std::lock_guard<std::mutex> lock(m_endpointsMutex);
    std::string key = method + " " + path;  // Include method in key
    m_endpoints[key] = handler;
}

void MetricsServer::registerStaticEndpoint(const std::string& path,
                                           const std::string& content,
                                           const std::string& content_type)
{
    registerEndpoint(path, "GET", [content, content_type](const HttpRequestContext&) {
        return HttpResponse(http::status::ok, content_type, content);
    });
}

void MetricsServer::setupDefaultEndpoints()
{
    /*
        Register default metrics first
    */
    registerDefaultMetrics();

    /*
        Metrics endpoint
    */
    registerEndpoint("/metrics", "GET", [this](const HttpRequestContext&) {
        return handleMetrics(HttpRequestContext{});
    });

    /*
        Health check endpoint
    */
    registerEndpoint("/health", "GET", [this](const HttpRequestContext&) {
        return handleHealth(HttpRequestContext{});
    });

    /*
        Stats endpoint
    */
    registerEndpoint("/stats", "GET", [this](const HttpRequestContext&) {
        return handleStats(HttpRequestContext{});
    });

    /*
        Policy info endpoint (GET)
    */
    registerEndpoint("/policies", "GET", [this](const HttpRequestContext&) {
        return handlePolicies(HttpRequestContext{});
    });

    /*
        Policy management endpoint (POST)
    */
    registerEndpoint("/policies", "POST", [this](const HttpRequestContext& ctx) {
        return handlePolicyAdd(ctx);
    });

    /*
        Policy removal endpoint (DELETE)
    */
    registerEndpoint("/policies", "DELETE", [this](const HttpRequestContext& ctx) {
        return handlePolicyRemove(ctx);
    });

    /*
        Reset statistics endpoint (POST)
    */
    registerEndpoint(
        "/reset", "POST", [this](const HttpRequestContext& ctx) { return handleReset(ctx); });

    if(gLogger != nullptr)
    {
        gLogger->info(LogContext(LogCategory::SYSTEM), "Default endpoints configured");
    }
}

void MetricsServer::processHttpRequest(const http::request<http::string_body>& req,
                                       http::response<http::string_body>& res)
{
    std::string target = std::string(req.target());
    std::string method = std::string(req.method_string());

    /*
        Remove query parameters for endpoint matching
    */
    auto queryPos = target.find('?');
    if(queryPos != std::string::npos)
    {
        target = target.substr(0, queryPos);
    }

    /*
        Log request
    */
    if(gLogger != nullptr)
    {
        gLogger->debug(
            LogContext(LogCategory::NETWORK).withField("method", method).withField("path", target),
            "HTTP request received");
    }

    /*
        Find endpoint handler
    */
    {
        std::lock_guard<std::mutex> lock(m_endpointsMutex);
        std::string key = method + " " + target;  // Include method in lookup key
        auto it = m_endpoints.find(key);
        if(it != m_endpoints.end())
        {
            try
            {
                HttpRequestContext ctx = parseRequest(req);
                HttpResponse response = it->second(ctx);
                buildResponse(response, res);
                return;
            }
            catch(const std::exception& e)
            {
                if(gLogger != nullptr)
                {
                    gLogger->error(LogContext(LogCategory::NETWORK).withField("error", e.what()),
                                   "Error handling request");
                }
                createErrorResponse(
                    http::status::internal_server_error, "Internal server error", res);
                return;
            }
        }
    }

    /*
        Not found
    */
    createErrorResponse(http::status::not_found, "Endpoint not found", res);
}

HttpRequestContext MetricsServer::parseRequest(const http::request<http::string_body>& req)
{
    HttpRequestContext ctx;
    ctx.method = std::string(req.method_string());
    ctx.target = std::string(req.target());
    ctx.body = req.body();

    /*
        Parse headers
    */
    for(auto const& field : req)
    {
        ctx.headers[std::string(field.name_string())] = std::string(field.value());
    }

    /*
        Parse query parameters
    */
    ctx.query_params = parseQueryParams(ctx.target);

    return ctx;
}

void MetricsServer::buildResponse(const HttpResponse& response,
                                  http::response<http::string_body>& res)
{
    res.result(response.status);
    res.set(http::field::server, "PEPCTL/1.0");
    res.set(http::field::content_type, response.contentType);
    res.body() = response.body;

    /*
        Add custom headers
    */
    for(const auto& [key, value] : response.headers)
    {
        res.set(key, value);
    }

    res.prepare_payload();
}

std::unordered_map<std::string, std::string> MetricsServer::parseQueryParams(
    const std::string& target)
{
    std::unordered_map<std::string, std::string> params;

    auto queryPos = target.find('?');
    if(queryPos == std::string::npos)
    {
        return params;
    }

    std::string query = target.substr(queryPos + 1);
    std::istringstream ss(query);
    std::string param;

    while(std::getline(ss, param, '&'))
    {
        auto eqPos = param.find('=');
        if(eqPos != std::string::npos)
        {
            std::string key = param.substr(0, eqPos);
            std::string value = param.substr(eqPos + 1);
            params[key] = value;
        }
    }

    return params;
}

HttpResponse MetricsServer::handleMetrics(const HttpRequestContext& /*unused*/)
{
    std::ostringstream oss;

    /*
        Update metrics before serving
    */
    updateSystemMetrics();

    std::lock_guard<std::mutex> lock(m_metricsMutex);

    /*
        Write metric definitions and values
    */
    for(const auto& [name, entry] : m_metrics)
    {
        oss << formatMetricEntry(entry) << "\n";
    }

    return HttpResponse(http::status::ok, "text/plain; version=0.0.4; charset=utf-8", oss.str());
}

HttpResponse MetricsServer::handleHealth(const HttpRequestContext& /*unused*/)
{
    return HttpResponse(http::status::ok,
                        "application/json",
                        R"({"status":"healthy","service":"pepctl","version":"1.0"})");
}

HttpResponse MetricsServer::handleStats(const HttpRequestContext& /*unused*/)
{
    std::ostringstream oss;

    oss << "{\n";
    oss << "  \"service\": \"pepctl\",\n";
    oss << "  \"version\": \"1.0\",\n";
    oss << "  \"uptime_seconds\": " << getUptimeSeconds() << ",\n";

    /*
        Policy engine stats
    */
    if(m_policyEngine != nullptr)
    {
        oss << "  \"policies\": {\n";
        oss << "    \"total_count\": " << PolicyEngine::getPolicyCount() << "\n";
        oss << "  },\n";
    }

    /*
        eBPF manager stats
    */
    if(m_ebpfManager != nullptr)
    {
        auto ebpfStats = m_ebpfManager->getStats();
        oss << "  \"ebpf\": {\n";
        oss << "    \"packets_processed\": " << ebpfStats.packets_processed << "\n";
        oss << "  },\n";
    }

    /*
        Daemon metrics
    */
    if(m_daemonMetrics != nullptr)
    {
        oss << "  \"daemon\": {\n";
        oss << "    \"packets_processed\": " << m_daemonMetrics->packetsProcessed.load() << ",\n";
        oss << "    \"packets_allowed\": " << m_daemonMetrics->packetsAllowed.load() << ",\n";
        oss << "    \"packets_blocked\": " << m_daemonMetrics->packetsBlocked.load() << ",\n";
        oss << "    \"packets_logged\": " << m_daemonMetrics->packetsLogged.load() << ",\n";
        oss << "    \"packets_rate_limited\": " << m_daemonMetrics->packetsRateLimited.load()
            << ",\n";
        oss << "    \"bytes_processed\": " << m_daemonMetrics->bytesProcessed.load() << "\n";
        oss << "  }\n";
    }
    else
    {
        oss << "  \"daemon\": null\n";
    }

    oss << "}\n";

    return HttpResponse(http::status::ok, "application/json", oss.str());
}

HttpResponse MetricsServer::handlePolicies(const HttpRequestContext& /*unused*/)
{
    std::string jsonContent = "[]";

    if(m_policyEngine != nullptr)
    {
        jsonContent = PolicyEngine::exportPoliciesToJson();
    }

    return HttpResponse(http::status::ok, "application/json", jsonContent);
}

void MetricsServer::createErrorResponse(http::status status,
                                        const std::string& message,
                                        http::response<http::string_body>& res)
{
    res.result(status);
    res.set(http::field::server, "PEPCTL/1.0");
    res.set(http::field::content_type, "text/plain");
    res.body() = message;
    res.prepare_payload();
}

void MetricsServer::updateSystemMetrics()
{
    if(m_running.load() == false)
    {
        return;
    }

    /*
        Update system metrics
    */
    setGauge("pepctl_uptime_seconds", getUptimeSeconds());

    /*
        Update policy engine metrics
    */
    if(m_policyEngine != nullptr)
    {
        setGauge("pepctl_policies_total", static_cast<double>(PolicyEngine::getPolicyCount()));
    }

    /*
        Update eBPF manager metrics and sync with daemon metrics
    */
    if(m_ebpfManager != nullptr)
    {
        auto stats = m_ebpfManager->getStats();
        setCounter("pepctl_ebpf_packets_processed_total",
                   static_cast<double>(stats.packets_processed));

        /*
            Sync daemon metrics with eBPF statistics (eBPF is authoritative)
        */
        if(m_daemonMetrics != nullptr)
        {
            m_daemonMetrics->packetsProcessed.store(stats.packets_processed);
            m_daemonMetrics->packetsAllowed.store(stats.packets_allowed);
            m_daemonMetrics->packetsBlocked.store(stats.packets_blocked);
            m_daemonMetrics->packetsLogged.store(stats.packets_logged);
            m_daemonMetrics->packetsRateLimited.store(stats.packets_rate_limited);
        }
    }

    /*
        Update daemon metrics (now synced with eBPF)
    */
    if(m_daemonMetrics != nullptr)
    {
        setCounter("pepctl_daemon_packets_processed_total",
                   static_cast<double>(m_daemonMetrics->packetsProcessed.load()));
        setCounter("pepctl_daemon_packets_allowed_total",
                   static_cast<double>(m_daemonMetrics->packetsAllowed.load()));
        setCounter("pepctl_daemon_packets_blocked_total",
                   static_cast<double>(m_daemonMetrics->packetsBlocked.load()));
        setCounter("pepctl_daemon_packets_logged_total",
                   static_cast<double>(m_daemonMetrics->packetsLogged.load()));
        setCounter("pepctl_daemon_packets_rate_limited_total",
                   static_cast<double>(m_daemonMetrics->packetsRateLimited.load()));
        setCounter("pepctl_daemon_bytes_processed_total",
                   static_cast<double>(m_daemonMetrics->bytesProcessed.load()));
    }
}

void MetricsServer::startUpdateTimer()
{
    if(m_running.load() == false)
    {
        return;
    }

    m_updateRunning.store(true);
    m_updateTimer.expires_after(m_updateInterval);
    m_updateTimer.async_wait([this](boost::system::error_code ec) {
        if(ec.value() == 0 && m_updateRunning.load() == true)
        {
            updateSystemMetrics();
            startUpdateTimer();  // Schedule next update
        }
    });
}

std::string MetricsServer::formatMetricEntry(const MetricEntry& entry)
{
    std::ostringstream oss;

    /*
        Write help
    */
    if(entry.help.empty() == false)
    {
        oss << "# HELP " << entry.name << " " << entry.help << "\n";
    }

    /*
        Write type
    */
    oss << "# TYPE " << entry.name << " ";
    switch(entry.type)
    {
        case MetricType::COUNTER:
            oss << "counter";
            break;
        case MetricType::GAUGE:
            oss << "gauge";
            break;
        case MetricType::HISTOGRAM:
            oss << "histogram";
            break;
        case MetricType::SUMMARY:
            oss << "summary";
            break;
    }
    oss << "\n";

    /*
        Write value
    */
    oss << entry.name;
    if(entry.labels.empty() == false)
    {
        oss << "{";
        bool first = true;
        for(const auto& [key, value] : entry.labels)
        {
            if(first == false)
            {
                oss << ",";
            }
            oss << key << "=\"" << escapeLabelValue(value) << "\"";
            first = false;
        }
        oss << "}";
    }
    oss << " " << std::fixed << std::setprecision(6) << entry.value;

    return oss.str();
}

std::string MetricsServer::escapeLabelValue(const std::string& value)
{
    std::string escaped = value;
    /*
        Simple escaping - replace quotes and backslashes
    */
    size_t pos = 0;
    while((pos = escaped.find('"', pos)) != std::string::npos)
    {
        escaped.replace(pos, 1, "\\\"");
        pos += 2;
    }
    pos = 0;
    while((pos = escaped.find('\\', pos)) != std::string::npos)
    {
        escaped.replace(pos, 1, "\\\\");
        pos += 2;
    }
    return escaped;
}

double MetricsServer::getUptimeSeconds()
{
    static auto startTime = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime);
    return static_cast<double>(duration.count()) / 1000.0;
}

HttpResponse MetricsServer::handleInfo(const HttpRequestContext& /*unused*/)
{
    std::ostringstream oss;

    oss << "{\n";
    oss << "  \"service\": \"pepctl\",\n";
    oss << "  \"version\": \"1.0\",\n";
    oss << "  \"build_time\": \"" << __DATE__ << " " << __TIME__ << "\",\n";
    oss << "  \"uptime_seconds\": " << getUptimeSeconds() << ",\n";
    oss << "  \"metrics_endpoint\": \"/metrics\",\n";
    oss << "  \"health_endpoint\": \"/health\",\n";
    oss << "  \"policies_endpoint\": \"/policies\"\n";
    oss << "}\n";

    return HttpResponse(http::status::ok, "application/json", oss.str());
}

HttpResponse MetricsServer::handlePolicyAdd(const HttpRequestContext& ctx)
{
    if(ctx.method != "POST")
    {
        return HttpResponse(
            http::status::method_not_allowed,
            "application/json",
            R"({"error":"Method not allowed","message":"Use POST to add policies"})");
    }

    if(m_policyEngine == nullptr)
    {
        return HttpResponse(
            http::status::service_unavailable,
            "application/json",
            R"({"error":"Service unavailable","message":"Policy engine not available"})");
    }

    try
    {
        /*
            Parse JSON from request body
        */
        auto json = nlohmann::json::parse(ctx.body);

        /*
            Check if it's a single policy or array of policies
        */
        nlohmann::json policyArray;
        if(json.is_array() == true)
        {
            policyArray = json;
        }
        else
        {
            /*
                Single policy - wrap in array
            */
            policyArray = nlohmann::json::array();
            policyArray.push_back(json);
        }

        /*
            Use PolicyEngine's JSON loading method
        */
        if(PolicyEngine::loadPoliciesFromJson(policyArray.dump()))
        {
            /*
                Synchronize policies with eBPF map
            */
            if((m_ebpfManager != nullptr) && (m_policyEngine != nullptr))
            {
                auto policies = PolicyEngine::getAllPolicies();
                if(pepctl::EbpfManager::updatePolicyMap(policies) == false)
                {
                    if(gLogger != nullptr)
                    {
                        gLogger->warn(LogContext(LogCategory::POLICY),
                                      "Failed to synchronize policies with eBPF map");
                    }
                }
                else
                {
                    if(gLogger != nullptr)
                    {
                        gLogger->info(
                            LogContext(LogCategory::POLICY)
                                .withField("policy_count", std::to_string(policies.size())),
                            "Policies synchronized with eBPF map");
                    }
                }
            }

            return HttpResponse(
                http::status::created,
                "application/json",
                R"({"status":"success","message":"Policy(ies) added successfully"})");
        }

        return HttpResponse(http::status::bad_request,
                            "application/json",
                            R"({"error":"Bad request","message":"Failed to add policy"})");
    }
    catch(const std::exception& e)
    {
        return HttpResponse(http::status::bad_request,
                            "application/json",
                            "{\"error\":\"Invalid JSON\",\"message\":\"" + std::string(e.what())
                                + "\"}");
    }
}

HttpResponse MetricsServer::handlePolicyRemove(const HttpRequestContext& ctx)
{
    if(ctx.method != "DELETE")
    {
        return HttpResponse(
            http::status::method_not_allowed,
            "application/json",
            R"({"error":"Method not allowed","message":"Use DELETE to remove policies"})");
    }

    if(m_policyEngine == nullptr)
    {
        return HttpResponse(
            http::status::service_unavailable,
            "application/json",
            R"({"error":"Service unavailable","message":"Policy engine not available"})");
    }

    auto it = ctx.query_params.find("id");
    if(it == ctx.query_params.end())
    {
        return HttpResponse(http::status::bad_request,
                            "application/json",
                            R"({"error":"Bad request","message":"Policy ID required"})");
    }

    if(pepctl::PolicyEngine::removePolicy(it->second))
    {
        return HttpResponse(http::status::ok,
                            "application/json",
                            R"({"status":"success","message":"Policy removed successfully"})");
    }

    return HttpResponse(http::status::not_found,
                        "application/json",
                        R"({"error":"Not found","message":"Policy not found"})");
}

HttpResponse MetricsServer::handleDashboard(const HttpRequestContext& /*unused*/)
{
    return HttpResponse(http::status::ok, "text/html", getDashboardHtml());
}

HttpResponse MetricsServer::handleReset(const HttpRequestContext& ctx)
{
    if(ctx.method != "POST")
    {
        return HttpResponse(
            http::status::method_not_allowed,
            "application/json",
            R"({"error":"Method not allowed","message":"Use POST to reset statistics"})");
    }

    if(m_daemonMetrics == nullptr)
    {
        return HttpResponse(
            http::status::service_unavailable,
            "application/json",
            R"({"error":"Service unavailable","message":"Daemon metrics not available"})");
    }

    try
    {
        /*
            Reset all packet statistics
        */
        m_daemonMetrics->packetsProcessed.store(0);
        m_daemonMetrics->packetsAllowed.store(0);
        m_daemonMetrics->packetsBlocked.store(0);
        m_daemonMetrics->packetsLogged.store(0);
        m_daemonMetrics->packetsRateLimited.store(0);
        m_daemonMetrics->bytesProcessed.store(0);

        /*
            Reset start time to current time
        */
        m_daemonMetrics->startTime = std::chrono::system_clock::now();

        /*
            Reset eBPF statistics if available
        */
        if(m_ebpfManager != nullptr)
        {
            m_ebpfManager->resetStats();
        }

        /*
            Reset policy hit counts
        */
        if(m_policyEngine != nullptr)
        {
            /*
                Note: This would require a method in PolicyEngine to reset hit counts
            */
            // For now, we'll just log that policies weren't reset
        }

        if(gLogger != nullptr)
        {
            gLogger->info(LogContext(LogCategory::SYSTEM), "Packet statistics reset successfully");
        }

        return HttpResponse(
            http::status::ok,
            "application/json",
            R"({"status":"success","message":"Statistics reset successfully","timestamp":")"
                + getCurrentTimestampIso() + R"("})");
    }
    catch(const std::exception& e)
    {
        if(gLogger != nullptr)
        {
            gLogger->error(LogContext(LogCategory::SYSTEM).withField("error", e.what()),
                           "Error resetting statistics");
        }

        return HttpResponse(
            http::status::internal_server_error,
            "application/json",
            R"({"error":"Internal server error","message":"Failed to reset statistics"})");
    }
}

void MetricsServer::registerDefaultMetrics()
{
    registerMetric("pepctl_uptime_seconds", MetricType::GAUGE, "Uptime in seconds");
    registerMetric("pepctl_policies_total", MetricType::GAUGE, "Total number of policies");
    registerMetric(
        "pepctl_daemon_packets_processed_total", MetricType::COUNTER, "Total packets processed");
    registerMetric(
        "pepctl_daemon_packets_allowed_total", MetricType::COUNTER, "Total packets allowed");
    registerMetric(
        "pepctl_daemon_packets_blocked_total", MetricType::COUNTER, "Total packets blocked");
    registerMetric(
        "pepctl_daemon_packets_logged_total", MetricType::COUNTER, "Total packets logged only");
    registerMetric("pepctl_daemon_packets_rate_limited_total",
                   MetricType::COUNTER,
                   "Total packets rate limited");
    registerMetric(
        "pepctl_daemon_bytes_processed_total", MetricType::COUNTER, "Total bytes processed");
    registerMetric(
        "pepctl_ebpf_packets_processed_total", MetricType::COUNTER, "Total eBPF packets processed");
}

/*
    CORS (Cross-Origin Resource Sharing) is a web security mechanism that allows web
    pages from one domain to access resources from another domain safely.
    It is used to allow the dashboard to access the metrics server.
*/
void MetricsServer::addCorsHeaders(http::response<http::string_body>& res) const
{
    if(m_corsEnabled == true)
    {
        res.set("Access-Control-Allow-Origin", "*");
        res.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
        res.set("Access-Control-Max-Age", "86400");
    }
}

std::string MetricsServer::getDashboardHtml()
{
    return R"(<!DOCTYPE html>
<html>
<head>
    <title>PEPCTL Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { text-align: center; color: #333; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .metric { padding: 15px; background: #f8f9fa; border-radius: 4px; border-left: 4px solid #007bff; }
        .metric-name { font-weight: bold; color: #495057; }
        .metric-value { font-size: 1.5em; color: #007bff; margin: 5px 0; }
        .links { text-align: center; margin: 20px 0; }
        .links a { margin: 0 10px; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; }
        .links a:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1 class="header">PEPCTL Network Policy Enforcement Dashboard</h1>
            <p style="text-align: center; color: #666;">Real-time monitoring and management interface</p>
        </div>
        
        <div class="card">
            <h2>Quick Links</h2>
            <div class="links">
                <a href="/metrics">Prometheus Metrics</a>
                <a href="/health">Health Check</a>
                <a href="/stats">Statistics</a>
                <a href="/policies">Policies</a>
            </div>
        </div>
        
        <div class="card">
            <h2>System Status</h2>
            <div id="status">Loading...</div>
        </div>
    </div>
    
    <script>
        async function loadStatus() {
            try {
                const response = await fetch('/stats');
                const data = await response.json();
                
                let html = '<div class="metrics">';
                html += `<div class="metric"><div class="metric-name">Service</div><div class="metric-value">${data.service || 'N/A'}</div></div>`;
                html += `<div class="metric"><div class="metric-name">Version</div><div class="metric-value">${data.version || 'N/A'}</div></div>`;
                html += `<div class="metric"><div class="metric-name">Uptime (seconds)</div><div class="metric-value">${data.uptime_seconds || 0}</div></div>`;
                
                if(data.daemon) {
                    html += `<div class="metric"><div class="metric-name">Packets Processed</div><div class="metric-value">${data.daemon.packets_processed || 0}</div></div>`;
                    html += `<div class="metric"><div class="metric-name">Packets Allowed</div><div class="metric-value">${data.daemon.packets_allowed || 0}</div></div>`;
                    html += `<div class="metric"><div class="metric-name">Packets Blocked</div><div class="metric-value">${data.daemon.packets_blocked || 0}</div></div>`;
                }
                
                if(data.policies) {
                    html += `<div class="metric"><div class="metric-name">Total Policies</div><div class="metric-value">${data.policies.total_count || 0}</div></div>`;
                }
                
                html += '</div>';
                document.getElementById('status').innerHTML = html;
            } catch(e) {
                document.getElementById('status').innerHTML = '<p style="color: red;">Failed to load status</p>';
            }
        }
        
        loadStatus();
        setInterval(loadStatus, 5000); // Refresh every 5 seconds
    </script>
</body>
</html>)";
}

std::string MetricsServer::getCurrentTimestampIso()
{
    auto now = std::chrono::system_clock::now();
    auto timeT = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&timeT), "%Y-%m-%dT%H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';

    return oss.str();
}

void MetricsServer::updatePolicyMetrics()
{
    if(m_policyEngine != nullptr)
    {
        setGauge("pepctl_policies_total", static_cast<double>(PolicyEngine::getPolicyCount()));
    }
}

std::unordered_map<std::string, double> MetricsCollector::collectSystemMetrics()
{
    std::unordered_map<std::string, double> metrics;

    metrics["cpu_usage_percent"] = readProcStatValue("cpu_usage");

    metrics["memory_total_bytes"] = readProcMeminfoValue("MemTotal") * 1024;
    metrics["memory_available_bytes"] = readProcMeminfoValue("MemAvailable") * 1024;
    metrics["memory_free_bytes"] = readProcMeminfoValue("MemFree") * 1024;

    return metrics;
}

std::unordered_map<std::string, double> MetricsCollector::collectNetworkMetrics(
    const std::string& interface)
{
    std::unordered_map<std::string, double> metrics;

    metrics["rx_bytes"] = readSysClassNetValue(interface, "rx_bytes");
    metrics["tx_bytes"] = readSysClassNetValue(interface, "tx_bytes");
    metrics["rx_packets"] = readSysClassNetValue(interface, "rx_packets");
    metrics["tx_packets"] = readSysClassNetValue(interface, "tx_packets");
    metrics["rx_errors"] = readSysClassNetValue(interface, "rx_errors");
    metrics["tx_errors"] = readSysClassNetValue(interface, "tx_errors");

    return metrics;
}

std::unordered_map<std::string, double> MetricsCollector::collectProcessMetrics()
{
    std::unordered_map<std::string, double> metrics;

    metrics["process_cpu_seconds"] = readProcStatValue("process_cpu");
    metrics["process_memory_bytes"] = readProcStatValue("process_memory");
    metrics["process_threads"] = readProcStatValue("process_threads");

    return metrics;
}

double MetricsCollector::readProcStatValue(const std::string& field)
{
    try
    {
        if(field == "cpu_usage")
        {
            std::ifstream file("/proc/stat");
            std::string line;
            if(std::getline(file, line) && line.substr(0, 3) == "cpu")
            {
                std::istringstream iss(line);
                std::string cpu;
                long user;
                long nice;
                long system;
                long idle;
                iss >> cpu >> user >> nice >> system >> idle;

                static long prev_total = 0;
                static long prev_idle = 0;
                long total = user + nice + system + idle;
                long totalDiff = total - prev_total;
                long idleDiff = idle - prev_idle;

                double usage = totalDiff > 0 ? (100.0 * (totalDiff - idleDiff) / totalDiff) : 0.0;

                prev_total = total;
                prev_idle = idle;

                return usage;
            }
        }
        else if(field == "process_cpu")
        {
            std::ifstream file("/proc/self/stat");
            std::string line;
            if(std::getline(file, line))
            {
                std::istringstream iss(line);
                std::string token;
                for(int i = 0; i < 13; ++i)
                {
                    iss >> token;  // Skip to utime
                }
                long utime;
                long stime;
                iss >> utime >> stime;
                return static_cast<double>(utime + stime) / sysconf(_SC_CLK_TCK);
            }
        }
        else if(field == "process_memory")
        {
            std::ifstream file("/proc/self/status");
            std::string line;
            while(std::getline(file, line))
            {
                if(line.substr(0, 6) == "VmRSS:")
                {
                    std::istringstream iss(line);
                    std::string label;
                    std::string value;
                    std::string unit;
                    iss >> label >> value >> unit;
                    return std::stod(value) * 1024;  // Convert KB to bytes
                }
            }
        }
        else if(field == "process_threads")
        {
            std::ifstream file("/proc/self/status");
            std::string line;
            while(std::getline(file, line))
            {
                if(line.substr(0, 8) == "Threads:")
                {
                    std::istringstream iss(line);
                    std::string label;
                    std::string value;
                    iss >> label >> value;
                    return std::stod(value);
                }
            }
        }
    }
    catch(const std::exception&)
    {
        // Return 0 on any error
    }

    return 0.0;
}

double MetricsCollector::readProcMeminfoValue(const std::string& field)
{
    try
    {
        std::ifstream file("/proc/meminfo");
        std::string line;

        while(std::getline(file, line))
        {
            if(line.substr(0, field.length()) == field)
            {
                std::istringstream iss(line);
                std::string label;
                std::string value;
                std::string unit;
                iss >> label >> value >> unit;
                return std::stod(value);
            }
        }
    }
    catch(const std::exception&)
    {
        // Return 0 on any error
    }

    return 0.0;
}

double MetricsCollector::readSysClassNetValue(const std::string& interface,
                                              const std::string& field)
{
    try
    {
        std::string path = "/sys/class/net/" + interface + "/statistics/" + field;
        std::ifstream file(path);
        std::string value;

        if(std::getline(file, value))
        {
            return std::stod(value);
        }
    }
    catch(const std::exception&)
    {
        // Return 0 on any error
    }

    return 0.0;
}

}  // namespace pepctl