#pragma once

#include <chrono>
#include <filesystem>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <nlohmann/json.hpp>
#include <signal.h>
#include <unistd.h>

#include "pepctl/core.h"

namespace pepctl {
namespace test {

struct TestConfig
{
    std::string pid_file = "/tmp/pepctl_test.pid";
    std::string log_file = "/tmp/pepctl_test.log";
    std::string log_level = "debug";
    std::string ebpf_program_path = "./ebpf/packet_filter.o";
    std::string interface = "lo";
    bool metrics_enabled = true;
    uint16_t metrics_port = 18080;
    std::string metrics_bind_address = "127.0.0.1";
    std::string policies_file = "/tmp/test_policies.json";
    bool auto_reload_policies = false;
};

struct TestPolicy
{
    std::string id;
    std::string action;
    std::string src_ip;
    std::string dst_ip;
    std::string protocol;
    uint16_t dst_port;
    int priority = 100;
    bool enabled = true;
};

// Generate test policy JSON string
std::string generate_test_policy_json(const std::string& id,
                                      const std::string& action,
                                      const std::string& src_ip,
                                      const std::string& dst_ip,
                                      const std::string& protocol,
                                      uint16_t dst_port);

// Create test configuration file
bool create_test_config_file(const std::string& filename, const TestConfig& config);

// Create test policies file
bool create_test_policies_file(const std::string& filename,
                               const std::vector<TestPolicy>& policies);

// Generate test packet
PacketInfo generate_test_packet(const std::string& src_ip,
                                const std::string& dst_ip,
                                uint8_t protocol,
                                uint16_t src_port,
                                uint16_t dst_port);

// Generate test traffic
std::vector<PacketInfo> generate_test_traffic(size_t count,
                                              const std::string& src_network,
                                              const std::string& dst_network);

// Wait for condition with timeout
bool wait_for_condition(const std::function<bool()>& condition, std::chrono::milliseconds timeout);

// Check if process is running
bool check_process_running(pid_t pid);

// Make HTTP request
std::string make_http_request(const std::string& host,
                              uint16_t port,
                              const std::string& path,
                              const std::string& method = "GET",
                              const std::string& body = "");

// Cleanup test files
void cleanup_test_files(const std::vector<std::string>& files);

}  // namespace test
}  // namespace pepctl