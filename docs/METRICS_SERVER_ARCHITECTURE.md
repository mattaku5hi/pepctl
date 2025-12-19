# PEPCTL Metrics Server Architecture & Boost.Beast Deep Dive

## 📊 **Overview**

The PEPCTL Metrics Server is a sophisticated HTTP server built on **Boost.Beast** that provides:
- **Prometheus-compatible metrics** endpoint
- **RESTful API** for policy management
- **Real-time dashboard** with live statistics
- **Health monitoring** and system diagnostics
- **Asynchronous I/O** for high performance

## 🏗️ **Architecture Components**

### **1. Core Classes Hierarchy**

```
MetricsServer (Main Server)
├── HttpSession (Per-connection handler)
├── Listener (Connection acceptor)
├── MetricsCollector (System metrics)
└── RequestHandler (Function objects)
```

### **2. Boost.Beast Integration**

```cpp
namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;
```

## 🔗 **Key Design Patterns**

### **1. Enable Shared From This Pattern**

```cpp
class HttpSession : public std::enable_shared_from_this<HttpSession>
{
    void run()
    {
        auto self = shared_from_this(); // Critical for async safety!
        // Pass 'self' to async operations to keep object alive
    }
};
```

**Why This Pattern?**
- **Problem**: Async operations might outlive the object
- **Solution**: `shared_from_this()` creates `std::shared_ptr<HttpSession>`
- **Benefit**: Object stays alive until all async operations complete
- **Safety**: Prevents crashes from accessing destroyed objects

### **2. RAII Resource Management**

```cpp
class HttpSession
{
    beast::tcp_stream m_stream;        // Auto-closes on destruction
    beast::flat_buffer m_buffer;       // Auto-deallocates memory
    http::request<http::string_body> m_req; // Auto-cleanup
};
```

### **3. Asynchronous Chain Pattern**

```cpp
void doRead() → onRead() → handleRequest() → onWrite() → doRead()
```

Each step in the chain:
1. **Initiates** the next async operation
2. **Passes control** to Boost.Asio event loop
3. **Continues** when operation completes
4. **Maintains state** through member variables

## 🚀 **Boost.Beast Deep Dive**

### **What is Boost.Beast?**

Boost.Beast is a **header-only C++ library** that provides:
- **HTTP/1.1 and WebSocket** protocol implementations
- **Built on Boost.Asio** for async I/O
- **Zero-copy parsing** for performance
- **Composable design** with other Boost libraries

### **Key Beast Components Used**

#### **1. `beast::tcp_stream`**
```cpp
beast::tcp_stream m_stream;
```
- **Purpose**: Manages TCP socket with timeouts
- **Features**: Automatic timeout handling, graceful shutdown
- **Benefit**: Prevents hanging connections

#### **2. `beast::flat_buffer`**
```cpp
beast::flat_buffer m_buffer;
```
- **Purpose**: Efficient buffer for HTTP parsing
- **Memory**: Single contiguous allocation
- **Performance**: Zero-copy operations where possible

#### **3. `http::request<http::string_body>`**
```cpp
http::request<http::string_body> m_req;
```
- **Purpose**: Parsed HTTP request representation
- **Body Type**: `string_body` stores body as `std::string`
- **Alternative**: `vector_body`, `file_body`, custom bodies

#### **4. `http::response<http::string_body>`**
```cpp
http::response<http::string_body> response;
```
- **Purpose**: HTTP response builder
- **Headers**: Automatic header management
- **Body**: String-based response content

### **Async Operation Flow**

#### **1. Connection Acceptance**
```cpp
m_acceptor.async_accept(
    boost::asio::make_strand(m_ioc),
    beast::bind_front_handler(&Listener::onAccept, shared_from_this())
);
```

**What happens:**
- **`async_accept`**: Non-blocking accept operation
- **`make_strand`**: Ensures thread safety for handlers
- **`bind_front_handler`**: Binds member function with `this` pointer
- **`shared_from_this()`**: Keeps Listener alive during async op

#### **2. HTTP Request Reading**
```cpp
http::async_read(m_stream, m_buffer, m_req,
    beast::bind_front_handler(&HttpSession::onRead, shared_from_this()));
```

**Process:**
1. **Reads HTTP headers** first
2. **Determines body size** from Content-Length
3. **Reads body** if present
4. **Parses into** `m_req` structure
5. **Calls handler** when complete

#### **3. Response Writing**
```cpp
http::async_write(m_stream, *response,
    beast::bind_front_handler(&HttpSession::onWrite, shared_from_this(), response));
```

**Features:**
- **Automatic chunking** for large responses
- **Header serialization** with proper formatting
- **Connection management** (keep-alive vs close)

## 📈 **Metrics System Architecture**

### **1. Metric Types (Prometheus Compatible)**

```cpp
enum class MetricType
{
    COUNTER,    // Monotonically increasing (packets_processed)
    GAUGE,      // Can go up/down (memory_usage)
    HISTOGRAM,  // Distribution of values (response_times)
    SUMMARY     // Quantiles and totals (request_duration)
};
```

### **2. Metric Storage**

```cpp
struct MetricEntry
{
    MetricType type;
    std::string name;
    std::string help;
    std::unordered_map<std::string, std::string> labels; // Key-value pairs
    double value;
    std::chrono::system_clock::time_point timestamp;
};
```

**Thread Safety:**
```cpp
mutable std::mutex m_metricsMutex;
std::unordered_map<std::string, MetricEntry> m_metrics;
```

### **3. Prometheus Format Output**

```
# HELP pepctl_packets_processed_total Total packets processed
# TYPE pepctl_packets_processed_total counter
pepctl_packets_processed_total{interface="eth0",policy="allow"} 12345.000000
```

**Format Rules:**
- **HELP**: Human-readable description
- **TYPE**: Metric type (counter, gauge, etc.)
- **Labels**: Key-value pairs in `{key="value"}` format
- **Value**: Floating-point number with 6 decimal places

## 🔧 **HTTP Endpoint System**

### **1. Endpoint Registration**

```cpp
using RequestHandler = std::function<HttpResponse(const HttpRequestContext&)>;

void registerEndpoint(const std::string& path,
                     const std::string& method,
                     const RequestHandler& handler);
```

**Lambda Handler Example:**
```cpp
registerEndpoint("/health", "GET", [this](const HttpRequestContext&) {
    return HttpResponse(http::status::ok, "application/json", 
                       R"({"status":"healthy"})");
});
```

### **2. Request Context Structure**

```cpp
struct HttpRequestContext
{
    std::string method;           // GET, POST, PUT, DELETE
    std::string target;           // /metrics?format=json
    std::string body;             // Request body content
    std::unordered_map<std::string, std::string> headers;      // HTTP headers
    std::unordered_map<std::string, std::string> query_params; // URL parameters
};
```

### **3. Response Building**

```cpp
struct HttpResponse
{
    http::status status;          // 200, 404, 500, etc.
    std::string contentType;      // "application/json", "text/html"
    std::string body;             // Response content
    std::unordered_map<std::string, std::string> headers; // Custom headers
};
```

## 🎯 **Built-in Endpoints**

### **1. `/metrics` - Prometheus Metrics**
- **Format**: Prometheus exposition format
- **Content-Type**: `text/plain; version=0.0.4; charset=utf-8`
- **Updates**: Real-time system metrics
- **Usage**: Scraped by Prometheus/Grafana

### **2. `/health` - Health Check**
```json
{
    "status": "healthy",
    "service": "pepctl",
    "version": "1.0"
}
```

### **3. `/stats` - Detailed Statistics**
```json
{
    "service": "pepctl",
    "uptime_seconds": 3600,
    "policies": {"total_count": 42},
    "daemon": {
        "packets_processed": 12345,
        "packets_allowed": 12000,
        "packets_blocked": 345
    }
}
```

### **4. `/policies` - Policy Management**
- **GET**: List all policies (JSON format)
- **POST**: Add new policy
- **DELETE**: Remove policy by ID

### **5. `/dashboard` - Web Dashboard**
- **HTML Interface**: Real-time monitoring
- **JavaScript**: Auto-refresh every 5 seconds
- **CSS Grid**: Responsive design
- **REST API**: Fetches data from `/stats`

## ⚡ **Performance Characteristics**

### **1. Memory Usage**

| Component | Memory per Connection |
|-----------|----------------------|
| **HttpSession** | ~2KB (buffers + state) |
| **TCP Stream** | ~1KB (socket buffers) |
| **Request/Response** | Variable (content size) |
| **Total Overhead** | ~3KB + content |

### **2. Concurrency Model**

```cpp
// Single-threaded event loop
m_serverThread = std::thread([this]() { 
    m_ioc.run(); // Boost.Asio event loop
});
```

**Benefits:**
- **No locking** needed for most operations
- **High throughput** with low CPU usage
- **Predictable latency** (no context switching)
- **Memory efficient** (shared event loop)

### **3. Async Timer System**

```cpp
net::steady_timer m_updateTimer;

void startUpdateTimer()
{
    m_updateTimer.expires_after(m_updateInterval);
    m_updateTimer.async_wait([this](boost::system::error_code ec) {
        if(!ec) {
            updateSystemMetrics();
            startUpdateTimer(); // Reschedule
        }
    });
}
```

## 🔍 **System Metrics Collection**

### **1. Process Metrics (`/proc/self/`)**

```cpp
// CPU time from /proc/self/stat
double process_cpu_seconds = readProcStatValue("process_cpu");

// Memory usage from /proc/self/status
double process_memory_bytes = readProcStatValue("process_memory");
```

### **2. System Metrics (`/proc/`)**

```cpp
// Overall CPU usage from /proc/stat
double cpu_usage_percent = readProcStatValue("cpu_usage");

// Memory info from /proc/meminfo
double memory_total = readProcMeminfoValue("MemTotal") * 1024;
```

### **3. Network Metrics (`/sys/class/net/`)**

```cpp
// Interface statistics
double rx_bytes = readSysClassNetValue("eth0", "rx_bytes");
double tx_packets = readSysClassNetValue("eth0", "tx_packets");
```

## 🛡️ **Error Handling & Safety**

### **1. Exception Safety**

```cpp
try {
    HttpRequestContext ctx = parseRequest(req);
    HttpResponse response = handler(ctx);
    buildResponse(response, res);
} catch(const std::exception& e) {
    createErrorResponse(http::status::internal_server_error, 
                       "Internal server error", res);
}
```

### **2. Timeout Management**

```cpp
m_stream.expires_after(std::chrono::seconds(30)); // Request timeout
```

### **3. Resource Cleanup**

```cpp
void doClose()
{
    beast::error_code ec;
    m_stream.socket().shutdown(tcp::socket::shutdown_send, ec);
    // Socket automatically closed by destructor
}
```

## 🎨 **Web Dashboard Features**

### **1. Modern CSS Grid Layout**
```css
.metrics { 
    display: grid; 
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
    gap: 20px; 
}
```

### **2. Real-time Updates**
```javascript
async function loadStatus() {
    const response = await fetch('/stats');
    const data = await response.json();
    updateMetricsDisplay(data);
}
setInterval(loadStatus, 5000); // Refresh every 5 seconds
```

### **3. Responsive Design**
- **Mobile-friendly**: Viewport meta tag
- **Flexible layout**: CSS Grid auto-fit
- **Accessible**: Semantic HTML structure

## 🔧 **Configuration & Customization**

### **1. Server Configuration**

```cpp
bool initialize(uint16_t port, const std::string& bind_address = "0.0.0.0");
void setUpdateInterval(std::chrono::seconds interval);
void enableCors(bool enable);
void setMetricsPrefix(const std::string& prefix);
```

### **2. Custom Endpoints**

```cpp
// Static content
registerStaticEndpoint("/favicon.ico", favicon_data, "image/x-icon");

// Dynamic handler
registerEndpoint("/api/custom", "POST", [](const HttpRequestContext& ctx) {
    // Custom logic here
    return HttpResponse(http::status::ok, "application/json", result);
});
```

### **3. CORS Support**

```cpp
void addCorsHeaders(http::response<http::string_body>& res)
{
    if(m_corsEnabled) {
        res.set("Access-Control-Allow-Origin", "*");
        res.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
    }
}
```

## 📚 **Integration with PEPCTL Components**

### **1. Policy Engine Integration**

```cpp
void setPolicyEngine(PolicyEngine* engine) { m_policyEngine = engine; }

// Usage in endpoints
if(m_policyEngine) {
    auto policies_json = PolicyEngine::exportPoliciesToJson();
    return HttpResponse(http::status::ok, "application/json", policies_json);
}
```

### **2. eBPF Manager Integration**

```cpp
void setEbpfManager(EbpfManager* manager) { m_ebpfManager = manager; }

// Collect eBPF statistics
auto ebpf_stats = m_ebpfManager->getStats();
setGauge("pepctl_ebpf_packets_processed", ebpf_stats.packets_processed);
```

### **3. Daemon Metrics Integration**

```cpp
void setDaemonMetrics(Metrics* metrics) { m_daemonMetrics = metrics; }

// Export atomic counters
setGauge("pepctl_packets_processed", 
         m_daemonMetrics->packetsProcessed.load());
```

## 🎯 **Best Practices & Patterns**

### **1. Thread Safety**
- **Single-threaded** event loop for HTTP operations
- **Atomic operations** for metrics counters
- **Mutex protection** for shared data structures

### **2. Memory Management**
- **RAII** for automatic resource cleanup
- **shared_ptr** for async operation safety
- **String views** where possible to avoid copies

### **3. Error Handling**
- **Exception safety** with try-catch blocks
- **Graceful degradation** when components unavailable
- **Proper HTTP status codes** for different error types

### **4. Performance Optimization**
- **Zero-copy** operations where possible
- **Efficient string formatting** with ostringstream
- **Minimal allocations** in hot paths
- **Connection reuse** with keep-alive

## 🔍 **Debugging & Monitoring**

### **1. Logging Integration**

```cpp
if(gLogger) {
    gLogger->debug(LogContext(LogCategory::NETWORK)
                      .withField("method", method)
                      .withField("path", target),
                   "HTTP request received");
}
```

### **2. Metrics for Monitoring**
- **Request count** by endpoint
- **Response time** histograms
- **Error rate** by status code
- **Active connections** gauge

### **3. Health Checks**
- **Component availability** checks
- **Resource usage** monitoring
- **Service dependencies** validation

This architecture provides a robust, scalable, and maintainable HTTP server that integrates seamlessly with the PEPCTL network policy enforcement system while following modern C++ best practices and design patterns. 