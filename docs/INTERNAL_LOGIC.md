# PEPCTL Internal Logic Documentation

## Table of Contents
- [Overview](#overview)
- [Component Interaction](#component-interaction)
- [Data Flow Pipeline](#data-flow-pipeline)
- [eBPF Processing Logic](#ebpf-processing-logic)
- [Policy Engine Logic](#policy-engine-logic)
- [Metrics Collection Logic](#metrics-collection-logic)
- [Admin API Logic](#admin-api-logic)
- [Error Handling Logic](#error-handling-logic)
- [Memory Management](#memory-management)
- [Threading Model](#threading-model)
- [Performance Optimizations](#performance-optimizations)

## Overview

PEPCTL implements a sophisticated multi-layered architecture that combines user-space control plane with kernel-space data plane processing. This document explains the internal logic and data flow throughout the system.

### High-Level Data Flow

```
Packet → XDP Hook → eBPF Filter → Policy Decision → Action → Statistics Update
   ↓         ↓           ↓             ↓           ↓           ↓
Network   Kernel     Policy Map    ALLOW/BLOCK   Forward/   Per-CPU
Interface  Space      Lookup        /RATE_LIMIT   Drop       Counters
   ↓         ↓           ↓             ↓           ↓           ↓
   └─────────┴───────────┴─────────────┴───────────┴───────────┘
                              │
                         Ring Buffer
                              │
                         User Space ← Event Processing
                              │
                    ┌─────────┴─────────┐
                    │                   │
            Metrics Server      Admin API Server
            (Port 9090)         (Port 8080)
                    │                   │
               Prometheus          Management
               Scraping            Interface
```

## Component Interaction

### 1. Daemon Startup Sequence

```cpp
int main(int argc, char* argv[]) {
    // 1. Parse command line arguments
    auto config = parseArguments(argc, argv);
    
    // 2. Initialize logging system
    Logger::initialize(config.log_level, config.log_file);
    
    // 3. Load configuration file
    auto config_data = ConfigManager::load(config.config_file);
    
    // 4. Initialize core components
    auto policy_engine = std::make_shared<PolicyEngine>(config_data.policy);
    auto ebpf_manager = std::make_shared<EbpfManager>(config_data.ebpf);
    auto metrics_server = std::make_shared<MetricsServer>(config_data.metrics);
    auto admin_server = std::make_shared<AdminServer>(config_data.server);
    
    // 5. Load eBPF program
    if (!ebpf_manager->loadProgram()) {
        spdlog::error("Failed to load eBPF program");
        return 1;
    }
    
    // 6. Attach to network interface
    if (!ebpf_manager->attachToInterface(config_data.network.interface)) {
        spdlog::error("Failed to attach to interface");
        return 1;
    }
    
    // 7. Start metrics server
    metrics_server->start();
    
    // 8. Start admin API server
    admin_server->start();
    
    // 9. Enter main event loop
    return runMainLoop(ebpf_manager, policy_engine, metrics_server, admin_server);
}
```

### 2. Main Event Loop Logic

```cpp
int runMainLoop(const std::shared_ptr<EbpfManager>& ebpf_manager,
                const std::shared_ptr<PolicyEngine>& policy_engine,
                const std::shared_ptr<MetricsServer>& metrics_server,
                const std::shared_ptr<AdminServer>& admin_server) {
    
    // Create event loop with multiple event sources
    EventLoop event_loop;
    
    // Register eBPF ring buffer events
    event_loop.addEventSource(
        ebpf_manager->getRingBufferFd(),
        [&ebpf_manager](int fd) {
            ebpf_manager->processRingBufferEvents();
        }
    );
    
    // Register policy update events
    event_loop.addEventSource(
        policy_engine->getUpdateFd(),
        [&policy_engine, &ebpf_manager](int fd) {
            auto updated_policies = policy_engine->getUpdatedPolicies();
            ebpf_manager->updatePolicyMaps(updated_policies);
        }
    );
    
    // Register metrics collection timer
    event_loop.addTimer(
        std::chrono::seconds(30),  // Every 30 seconds
        [&ebpf_manager, &metrics_server]() {
            auto stats = ebpf_manager->getStatistics();
            metrics_server->updateMetrics(stats);
        }
    );
    
    // Main event processing loop
    while (running_) {
        event_loop.processEvents(std::chrono::milliseconds(100));
    }
    
    return 0;
}
```

## Data Flow Pipeline

### 1. Packet Processing Pipeline

#### Step 1: Packet Arrival
```
Network Interface → Driver → XDP Hook (Earliest Processing Point)
```

When a network packet arrives at the interface, it travels through the network driver and hits the XDP hook before entering the full Linux network stack.

#### Step 2: eBPF Program Execution
```c
SEC("xdp")
int packet_filter(struct xdp_md *ctx)
{
    struct packet_info pkt = {0};
    
    // Parse Ethernet, IP, and transport headers
    if (parse_packet_headers(ctx, &pkt) != 0) {
        // Malformed packet - let kernel handle it
        increment_counter(STAT_PARSE_ERRORS);
        return XDP_PASS;
    }
    
    // Lookup policy in eBPF map
    struct policy_key key = create_policy_key(&pkt);
    struct policy_action *action = bpf_map_lookup_elem(&policy_map, &key);
    
    if (!action) {
        // No specific policy found - try wildcard matching
        action = lookup_wildcard_policy(&pkt);
    }
    
    if (!action) {
        // Use default policy
        increment_counter(STAT_DEFAULT_POLICY_USED);
        return XDP_PASS;  // Default: allow
    }
    
    // Execute policy action
    return execute_policy_action(action, &pkt);
}
```

#### Step 3: Policy Lookup Logic
```c
static struct policy_action* lookup_wildcard_policy(struct packet_info *pkt)
{
    // Try different levels of wildcard matching
    struct policy_key keys[] = {
        // Source IP + Destination Port
        {pkt->src_ip, 0, 0, pkt->dst_port, pkt->protocol},
        // Destination IP + Port
        {0, pkt->dst_ip, 0, pkt->dst_port, pkt->protocol}, 
        // Port only
        {0, 0, 0, pkt->dst_port, pkt->protocol},
        // Source IP only
        {pkt->src_ip, 0, 0, 0, 0},
        // Protocol only
        {0, 0, 0, 0, pkt->protocol}
    };
    
    for (int i = 0; i < ARRAY_SIZE(keys); i++) {
        struct policy_action *action = bpf_map_lookup_elem(&policy_map, &keys[i]);
        if (action) {
            return action;
        }
    }
    
    return NULL;
}
```

#### Step 4: Action Execution
```c
static int execute_policy_action(struct policy_action *action, struct packet_info *pkt)
{
    switch (action->action_type) {
        case ACTION_ALLOW:
            increment_counter(STAT_PACKETS_ALLOWED);
            add_counter(STAT_BYTES_ALLOWED, pkt->size);
            return XDP_PASS;
            
        case ACTION_BLOCK:
            increment_counter(STAT_PACKETS_BLOCKED);
            add_counter(STAT_BYTES_BLOCKED, pkt->size);
            
            // Send notification to userspace
            send_block_notification(pkt);
            return XDP_DROP;
            
        case ACTION_RATE_LIMIT:
            if (apply_rate_limiting(action, pkt)) {
                increment_counter(STAT_PACKETS_ALLOWED);
                return XDP_PASS;
            } else {
                increment_counter(STAT_PACKETS_RATE_LIMITED);
                send_rate_limit_notification(pkt);
                return XDP_DROP;
            }
            
        default:
            increment_counter(STAT_UNKNOWN_ACTION);
            return XDP_PASS;
    }
}
```

### 2. Rate Limiting Logic

The rate limiting implementation uses a token bucket algorithm:

```c
static bool apply_rate_limiting(struct policy_action *action, struct packet_info *pkt)
{
    __u64 now = bpf_ktime_get_ns();
    __u64 time_diff = now - action->last_update;
    
    // Calculate tokens to add based on elapsed time
    __u64 tokens_to_add = (time_diff * action->rate_limit) / 1000000000ULL;
    
    // Add tokens but don't exceed bucket capacity
    if (action->current_tokens + tokens_to_add > action->rate_limit) {
        action->current_tokens = action->rate_limit;
    } else {
        action->current_tokens += tokens_to_add;
    }
    
    action->last_update = now;
    
    // Check if we have enough tokens for this packet
    if (action->current_tokens >= pkt->size) {
        action->current_tokens -= pkt->size;
        return true;  // Allow packet
    }
    
    return false;  // Drop packet
}
```

## eBPF Processing Logic

### 1. Map Management

#### Policy Map Updates
```cpp
bool EbpfManager::updatePolicyMap(const std::vector<Policy>& policies) {
    // Begin atomic update transaction
    int temp_map_fd = createTempPolicyMap();
    
    // Populate temporary map with all policies
    for (const auto& policy : policies) {
        struct policy_key key = policyToKey(policy);
        struct policy_action action = policyToAction(policy);
        
        if (bpf_map_update_elem(temp_map_fd, &key, &action, BPF_ANY) != 0) {
            spdlog::error("Failed to update temp policy map");
            close(temp_map_fd);
            return false;
        }
    }
    
    // Atomically swap maps
    if (bpf_prog_replace_map(program_fd_, policy_map_fd_, temp_map_fd) != 0) {
        spdlog::error("Failed to replace policy map");
        close(temp_map_fd);
        return false;
    }
    
    // Clean up old map
    close(policy_map_fd_);
    policy_map_fd_ = temp_map_fd;
    
    spdlog::info("Policy map updated with {} policies", policies.size());
    return true;
}
```

#### Statistics Collection
```cpp
PacketStatistics EbpfManager::collectStatistics() {
    PacketStatistics total_stats = {0};
    
    // Collect per-CPU statistics
    for (int cpu = 0; cpu < num_cpus_; cpu++) {
        struct packet_stats cpu_stats;
        __u32 key = cpu;
        
        if (bpf_map_lookup_elem(stats_map_fd_, &key, &cpu_stats) == 0) {
            total_stats.packets_total += cpu_stats.packets_total;
            total_stats.packets_allowed += cpu_stats.packets_allowed;
            total_stats.packets_blocked += cpu_stats.packets_blocked;
            total_stats.bytes_total += cpu_stats.bytes_total;
            total_stats.policy_lookups += cpu_stats.policy_lookups;
        }
    }
    
    return total_stats;
}
```

### 2. Ring Buffer Event Processing

```cpp
void EbpfManager::processRingBufferEvents() {
    // Define callback for ring buffer events
    auto callback = [](void *ctx, void *data, size_t size) -> int {
        auto *manager = static_cast<EbpfManager*>(ctx);
        auto *event = static_cast<struct packet_event*>(data);
        
        switch (event->event_type) {
            case EVENT_PACKET_BLOCKED:
                manager->handlePacketBlocked(event);
                break;
                
            case EVENT_RATE_LIMITED:
                manager->handleRateLimited(event);
                break;
                
            case EVENT_POLICY_LOOKUP_FAILED:
                manager->handlePolicyLookupFailed(event);
                break;
                
            default:
                spdlog::warn("Unknown event type: {}", event->event_type);
        }
        
        return 0;
    };
    
    // Process all available events
    int ret = ring_buffer__consume(ring_buf_, callback, this);
    if (ret < 0) {
        spdlog::error("Ring buffer consume failed: {}", ret);
    }
}
```

## Policy Engine Logic

### 1. Policy Storage and Indexing

```cpp
class PolicyEngine {
private:
    // Primary policy storage - indexed by policy ID
    std::unordered_map<std::string, Policy> policies_;
    
    // Secondary indexes for fast lookup
    std::unordered_map<uint32_t, std::vector<std::string>> src_ip_index_;
    std::unordered_map<uint32_t, std::vector<std::string>> dst_ip_index_;
    std::unordered_map<uint16_t, std::vector<std::string>> port_index_;
    
    // Change tracking
    std::set<std::string> modified_policies_;
    std::chrono::steady_clock::time_point last_update_;
    
    // Concurrency control
    mutable std::shared_mutex policies_mutex_;

public:
    bool addPolicy(const Policy& policy) {
        std::unique_lock<std::shared_mutex> lock(policies_mutex_);
        
        // Validate policy
        if (!validatePolicy(policy)) {
            return false;
        }
        
        // Check for conflicts
        if (hasConflicts(policy)) {
            spdlog::warn("Policy {} conflicts with existing policies", policy.id);
        }
        
        // Add to primary storage
        policies_[policy.id] = policy;
        
        // Update indexes
        updateIndexes(policy);
        
        // Track modification
        modified_policies_.insert(policy.id);
        last_update_ = std::chrono::steady_clock::now();
        
        spdlog::info("Policy {} added", policy.id);
        return true;
    }
    
    std::vector<Policy> getModifiedPolicies() {
        std::shared_lock<std::shared_mutex> lock(policies_mutex_);
        
        std::vector<Policy> modified;
        for (const auto& policy_id : modified_policies_) {
            auto it = policies_.find(policy_id);
            if (it != policies_.end()) {
                modified.push_back(it->second);
            }
        }
        
        modified_policies_.clear();
        return modified;
    }
};
```

### 2. Policy Validation Logic

```cpp
bool PolicyEngine::validatePolicy(const Policy& policy) {
    // Check required fields
    if (policy.id.empty()) {
        spdlog::error("Policy ID cannot be empty");
        return false;
    }
    
    if (policy.action == Action::UNKNOWN) {
        spdlog::error("Policy action must be specified");
        return false;
    }
    
    // Validate IP addresses
    if (!policy.src_ip.empty() && !isValidIP(policy.src_ip)) {
        spdlog::error("Invalid source IP: {}", policy.src_ip);
        return false;
    }
    
    if (!policy.dst_ip.empty() && !isValidIP(policy.dst_ip)) {
        spdlog::error("Invalid destination IP: {}", policy.dst_ip);
        return false;
    }
    
    // Validate ports
    if (policy.src_port > 65535 || policy.dst_port > 65535) {
        spdlog::error("Invalid port number");
        return false;
    }
    
    // Validate rate limit
    if (policy.action == Action::RATE_LIMIT && policy.rate_limit == 0) {
        spdlog::error("Rate limit must be > 0 for RATE_LIMIT action");
        return false;
    }
    
    return true;
}
```

### 3. Conflict Detection

```cpp
bool PolicyEngine::hasConflicts(const Policy& new_policy) {
    for (const auto& [id, existing] : policies_) {
        if (policiesOverlap(new_policy, existing)) {
            // Check if actions are compatible
            if (new_policy.action != existing.action) {
                spdlog::warn("Policy {} conflicts with {} (different actions)", 
                           new_policy.id, existing.id);
                return true;
            }
        }
    }
    
    return false;
}

bool PolicyEngine::policiesOverlap(const Policy& p1, const Policy& p2) {
    // Check IP overlap
    if (!p1.src_ip.empty() && !p2.src_ip.empty() && p1.src_ip != p2.src_ip) {
        return false;  // Different source IPs
    }
    
    if (!p1.dst_ip.empty() && !p2.dst_ip.empty() && p1.dst_ip != p2.dst_ip) {
        return false;  // Different destination IPs
    }
    
    // Check port overlap
    if (p1.src_port != 0 && p2.src_port != 0 && p1.src_port != p2.src_port) {
        return false;  // Different source ports
    }
    
    if (p1.dst_port != 0 && p2.dst_port != 0 && p1.dst_port != p2.dst_port) {
        return false;  // Different destination ports
    }
    
    // Check protocol overlap
    if (p1.protocol != Protocol::ALL && p2.protocol != Protocol::ALL && 
        p1.protocol != p2.protocol) {
        return false;  // Different protocols
    }
    
    return true;  // Policies overlap
}
```

## Metrics Collection Logic

### 1. Metrics Server Architecture

```cpp
class MetricsServer {
private:
    // HTTP server for Prometheus scraping
    std::unique_ptr<httplib::Server> server_;
    
    // Metrics storage
    std::atomic<uint64_t> packets_total_{0};
    std::atomic<uint64_t> packets_allowed_{0};
    std::atomic<uint64_t> packets_blocked_{0};
    std::atomic<uint64_t> bytes_total_{0};
    
    // Historical data for rate calculations
    struct MetricsSample {
        std::chrono::steady_clock::time_point timestamp;
        uint64_t packets_total;
        uint64_t bytes_total;
    };
    
    std::deque<MetricsSample> samples_;
    mutable std::mutex samples_mutex_;

public:
    void start() {
        // Setup Prometheus metrics endpoint
        server_->Get("/metrics", [this](const httplib::Request&, httplib::Response& res) {
            res.set_content(generateMetrics(), "text/plain; charset=utf-8");
        });
        
        // Setup health check endpoint
        server_->Get("/health", [this](const httplib::Request&, httplib::Response& res) {
            res.set_content("{\"status\":\"healthy\"}", "application/json");
        });
        
        // Start server in background thread
        server_thread_ = std::thread([this]() {
            server_->listen("0.0.0.0", metrics_port_);
        });
        
        spdlog::info("Metrics server started on port {}", metrics_port_);
    }
    
    void updateMetrics(const PacketStatistics& stats) {
        // Update atomic counters
        packets_total_.store(stats.packets_total);
        packets_allowed_.store(stats.packets_allowed);
        packets_blocked_.store(stats.packets_blocked);
        bytes_total_.store(stats.bytes_total);
        
        // Store sample for rate calculations
        {
            std::lock_guard<std::mutex> lock(samples_mutex_);
            samples_.push_back({
                std::chrono::steady_clock::now(),
                stats.packets_total,
                stats.bytes_total
            });
            
            // Keep only last 100 samples
            if (samples_.size() > 100) {
                samples_.pop_front();
            }
        }
    }
};
```

### 2. Prometheus Metrics Generation

```cpp
std::string MetricsServer::generateMetrics() {
    std::ostringstream metrics;
    
    // Basic counters
    metrics << "# HELP pepctl_packets_processed_total Total packets processed\n";
    metrics << "# TYPE pepctl_packets_processed_total counter\n";
    metrics << "pepctl_packets_processed_total " << packets_total_.load() << "\n\n";
    
    metrics << "# HELP pepctl_packets_allowed_total Packets allowed\n";
    metrics << "# TYPE pepctl_packets_allowed_total counter\n";
    metrics << "pepctl_packets_allowed_total " << packets_allowed_.load() << "\n\n";
    
    metrics << "# HELP pepctl_packets_blocked_total Packets blocked\n";
    metrics << "# TYPE pepctl_packets_blocked_total counter\n";
    metrics << "pepctl_packets_blocked_total " << packets_blocked_.load() << "\n\n";
    
    // Rate calculations
    auto rates = calculateRates();
    metrics << "# HELP pepctl_packets_per_second Current packet processing rate\n";
    metrics << "# TYPE pepctl_packets_per_second gauge\n";
    metrics << "pepctl_packets_per_second " << rates.packets_per_second << "\n\n";
    
    // System metrics
    metrics << "# HELP pepctl_uptime_seconds Daemon uptime in seconds\n";
    metrics << "# TYPE pepctl_uptime_seconds counter\n";
    metrics << "pepctl_uptime_seconds " << getUptime() << "\n\n";
    
    metrics << "# HELP pepctl_policy_count Number of active policies\n";
    metrics << "# TYPE pepctl_policy_count gauge\n";
    metrics << "pepctl_policy_count " << getPolicyCount() << "\n\n";
    
    return metrics.str();
}
```

## Admin API Logic

### 1. Request Processing Pipeline

```cpp
class AdminServer {
private:
    std::unique_ptr<httplib::Server> server_;
    std::shared_ptr<PolicyEngine> policy_engine_;
    std::shared_ptr<EbpfManager> ebpf_manager_;

public:
    void setupRoutes() {
        // Policy management routes
        server_->Get("/api/v1/policies", [this](const httplib::Request& req, httplib::Response& res) {
            handleGetPolicies(req, res);
        });
        
        server_->Post("/api/v1/policies", [this](const httplib::Request& req, httplib::Response& res) {
            handleCreatePolicy(req, res);
        });
        
        server_->Put(R"(/api/v1/policies/(.*))", [this](const httplib::Request& req, httplib::Response& res) {
            std::string policy_id = req.matches[1];
            handleUpdatePolicy(policy_id, req, res);
        });
        
        server_->Delete(R"(/api/v1/policies/(.*))", [this](const httplib::Request& req, httplib::Response& res) {
            std::string policy_id = req.matches[1];
            handleDeletePolicy(policy_id, req, res);
        });
        
        // Status and monitoring routes
        server_->Get("/api/v1/status", [this](const httplib::Request& req, httplib::Response& res) {
            handleGetStatus(req, res);
        });
        
        server_->Get("/api/v1/stats", [this](const httplib::Request& req, httplib::Response& res) {
            handleGetStatistics(req, res);
        });
    }
};
```

### 2. Request Validation and Processing

```cpp
void AdminServer::handleCreatePolicy(const httplib::Request& req, httplib::Response& res) {
    try {
        // Parse JSON request
        nlohmann::json request_json = nlohmann::json::parse(req.body);
        
        // Validate required fields
        if (!request_json.contains("id") || !request_json.contains("action")) {
            sendErrorResponse(res, 400, "VALIDATION_ERROR", 
                            "Missing required fields: id, action");
            return;
        }
        
        // Convert JSON to Policy object
        Policy policy = jsonToPolicy(request_json);
        
        // Validate policy
        if (!policy_engine_->validatePolicy(policy)) {
            sendErrorResponse(res, 422, "VALIDATION_ERROR", 
                            "Policy validation failed");
            return;
        }
        
        // Check for existing policy
        if (policy_engine_->hasPolicy(policy.id)) {
            sendErrorResponse(res, 409, "POLICY_EXISTS", 
                            "Policy with this ID already exists");
            return;
        }
        
        // Add policy to engine
        if (!policy_engine_->addPolicy(policy)) {
            sendErrorResponse(res, 500, "INTERNAL_ERROR", 
                            "Failed to add policy");
            return;
        }
        
        // Update eBPF maps
        auto updated_policies = policy_engine_->getAllPolicies();
        if (!ebpf_manager_->updatePolicyMaps(updated_policies)) {
            // Rollback policy addition
            policy_engine_->removePolicy(policy.id);
            sendErrorResponse(res, 500, "EBPF_ERROR", 
                            "Failed to update eBPF maps");
            return;
        }
        
        // Send success response
        nlohmann::json response = {
            {"success", true},
            {"data", policyToJson(policy)},
            {"timestamp", getCurrentTimestamp()}
        };
        
        res.status = 201;
        res.set_content(response.dump(), "application/json");
        
    } catch (const std::exception& e) {
        sendErrorResponse(res, 400, "INVALID_REQUEST", e.what());
    }
}
```

## Error Handling Logic

### 1. Hierarchical Error Handling

```cpp
enum class ErrorLevel {
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

class ErrorHandler {
public:
    static void handleError(ErrorLevel level, const std::string& component, 
                          const std::string& message, const std::exception* e = nullptr) {
        // Log error
        switch (level) {
            case ErrorLevel::INFO:
                spdlog::info("[{}] {}", component, message);
                break;
            case ErrorLevel::WARNING:
                spdlog::warn("[{}] {}", component, message);
                break;
            case ErrorLevel::ERROR:
                spdlog::error("[{}] {}", component, message);
                if (e) spdlog::error("Exception details: {}", e->what());
                break;
            case ErrorLevel::CRITICAL:
                spdlog::critical("[{}] {}", component, message);
                if (e) spdlog::critical("Exception details: {}", e->what());
                // Trigger graceful shutdown
                triggerShutdown();
                break;
        }
        
        // Update error metrics
        error_counters_[component]++;
        
        // Send to monitoring system
        if (level >= ErrorLevel::ERROR) {
            sendAlertToMonitoring(level, component, message);
        }
    }
};
```

### 2. eBPF Error Recovery

```cpp
class EbpfErrorRecovery {
public:
    bool recoverFromError(const std::string& error_type) {
        if (error_type == "program_load_failed") {
            return reloadProgram();
        } else if (error_type == "map_update_failed") {
            return rebuildMaps();
        } else if (error_type == "attach_failed") {
            return reattachToInterface();
        }
        
        return false;
    }
    
private:
    bool reloadProgram() {
        // Attempt to reload eBPF program
        try {
            ebpf_manager_->unloadProgram();
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            if (ebpf_manager_->loadProgram()) {
                spdlog::info("eBPF program successfully reloaded");
                return true;
            }
        } catch (const std::exception& e) {
            spdlog::error("Failed to reload eBPF program: {}", e.what());
        }
        
        return false;
    }
};
```

## Threading Model

### 1. Thread Architecture

```cpp
class PepctlDaemon {
private:
    // Main event loop thread
    std::thread main_thread_;
    
    // eBPF event processing thread
    std::thread ebpf_event_thread_;
    
    // Metrics collection thread
    std::thread metrics_thread_;
    
    // Admin API server thread pool
    ThreadPool admin_thread_pool_;
    
    // Metrics server thread
    std::thread metrics_server_thread_;

public:
    void start() {
        // Start eBPF event processing
        ebpf_event_thread_ = std::thread([this]() {
            processEbpfEvents();
        });
        
        // Start metrics collection
        metrics_thread_ = std::thread([this]() {
            collectMetrics();
        });
        
        // Start admin API server
        admin_thread_pool_.start(4);  // 4 worker threads
        
        // Start metrics server
        metrics_server_thread_ = std::thread([this]() {
            metrics_server_->start();
        });
        
        // Run main event loop
        main_thread_ = std::thread([this]() {
            runMainEventLoop();
        });
    }
};
```

### 2. Lock-Free Communication

```cpp
// Ring buffer for inter-thread communication
template<typename T, size_t Size>
class LockFreeRingBuffer {
private:
    alignas(64) std::atomic<size_t> write_pos_{0};
    alignas(64) std::atomic<size_t> read_pos_{0};
    alignas(64) std::array<T, Size> buffer_;

public:
    bool push(const T& item) {
        size_t write_pos = write_pos_.load(std::memory_order_relaxed);
        size_t next_write_pos = (write_pos + 1) % Size;
        
        if (next_write_pos == read_pos_.load(std::memory_order_acquire)) {
            return false;  // Buffer full
        }
        
        buffer_[write_pos] = item;
        write_pos_.store(next_write_pos, std::memory_order_release);
        return true;
    }
    
    bool pop(T& item) {
        size_t read_pos = read_pos_.load(std::memory_order_relaxed);
        
        if (read_pos == write_pos_.load(std::memory_order_acquire)) {
            return false;  // Buffer empty
        }
        
        item = buffer_[read_pos];
        read_pos_.store((read_pos + 1) % Size, std::memory_order_release);
        return true;
    }
};
```

## Performance Optimizations

### 1. Memory Pool Allocation

```cpp
class MemoryPool {
private:
    struct Block {
        alignas(64) char data[BLOCK_SIZE];
        std::atomic<Block*> next{nullptr};
    };
    
    std::atomic<Block*> free_list_{nullptr};
    std::vector<std::unique_ptr<Block[]>> pools_;

public:
    void* allocate() {
        Block* block = free_list_.load();
        
        while (block && !free_list_.compare_exchange_weak(block, block->next.load())) {
            // Retry
        }
        
        if (block) {
            return block->data;
        }
        
        // Allocate new pool if needed
        return allocateNewBlock();
    }
    
    void deallocate(void* ptr) {
        Block* block = reinterpret_cast<Block*>(
            reinterpret_cast<char*>(ptr) - offsetof(Block, data));
        
        Block* head = free_list_.load();
        do {
            block->next.store(head);
        } while (!free_list_.compare_exchange_weak(head, block));
    }
};
```

### 2. CPU Affinity Optimization

```cpp
void optimizeCpuAffinity() {
    // Pin eBPF processing thread to specific CPU cores
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    
    // Use cores 0-3 for eBPF processing
    for (int i = 0; i < 4; i++) {
        CPU_SET(i, &cpuset);
    }
    
    pthread_setaffinity_np(ebpf_event_thread_.native_handle(), 
                          sizeof(cpuset), &cpuset);
    
    // Pin admin API threads to different cores
    CPU_ZERO(&cpuset);
    for (int i = 4; i < 8; i++) {
        CPU_SET(i, &cpuset);
    }
    
    admin_thread_pool_.setCpuAffinity(cpuset);
}
```

This comprehensive internal logic documentation provides deep insight into how PEPCTL processes packets, manages policies, handles errors, and optimizes performance across all its components. 