#include "test_utils.h"

#include <chrono>
#include <csignal>
#include <fstream>
#include <random>
#include <sstream>

#include <arpa/inet.h>
#include <pepctl/core.h>
#include <sys/socket.h>
#include <unistd.h>

namespace pepctl::test {

auto generate_test_policy_json(const std::string& id,
                               const std::string& action,
                               const std::string& src_ip,
                               const std::string& dst_ip,
                               const std::string& protocol,
                               uint16_t dst_port) -> std::string
{
    nlohmann::json policy;
    policy["id"] = id;
    policy["action"] = action;
    policy["src_ip"] = src_ip;
    policy["dst_ip"] = dst_ip;
    policy["protocol"] = protocol;
    policy["dst_port"] = dst_port;
    policy["enabled"] = true;
    policy["priority"] = 100;

    return policy.dump();
}

auto create_test_config_file(const std::string& filename, const TestConfig& config) -> bool
{
    nlohmann::json jsonConfig;
    jsonConfig["pid_file"] = config.pid_file;
    jsonConfig["log_file"] = config.log_file;
    jsonConfig["log_level"] = config.log_level;
    jsonConfig["ebpf_program_path"] = config.ebpf_program_path;
    jsonConfig["interface"] = config.interface;
    jsonConfig["metrics_enabled"] = config.metrics_enabled;
    jsonConfig["metrics_port"] = config.metrics_port;
    jsonConfig["metrics_bind_address"] = config.metrics_bind_address;
    jsonConfig["policies_file"] = config.policies_file;
    jsonConfig["auto_reload_policies"] = config.auto_reload_policies;

    std::ofstream file(filename);
    if(!file.is_open())
    {
        return false;
    }

    file << jsonConfig.dump(4);
    return true;
}

auto create_test_policies_file(const std::string& filename,
                               const std::vector<TestPolicy>& policies) -> bool
{
    nlohmann::json jsonPolicies = nlohmann::json::array();

    for(const auto& policy : policies)
    {
        nlohmann::json p;
        p["id"] = policy.id;
        p["action"] = policy.action;
        p["src_ip"] = policy.src_ip;
        p["dst_ip"] = policy.dst_ip;
        p["protocol"] = policy.protocol;
        p["dst_port"] = policy.dst_port;
        p["priority"] = policy.priority;
        p["enabled"] = policy.enabled;
        jsonPolicies.push_back(p);
    }

    std::ofstream file(filename);
    if(!file.is_open())
    {
        return false;
    }

    file << jsonPolicies.dump(4);
    return true;
}

auto comparePolicies(const Policy& p1, const Policy& p2) -> bool
{
    return p1.id == p2.id && p1.action == p2.action && p1.src.ip == p2.src.ip
           && p1.src.port == p2.src.port && p1.src.protocol == p2.src.protocol
           && p1.dst.ip == p2.dst.ip && p1.dst.port == p2.dst.port
           && p1.dst.protocol == p2.dst.protocol;
}

auto isPortAvailable(uint16_t port) -> bool
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
    {
        return false;
    }

    struct sockaddr_in addr
    {};

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    int result = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);

    return result == 0;
}

auto findFreePort(uint16_t start_port, uint16_t end_port) -> uint16_t
{
    for(uint16_t port = start_port; port <= end_port; ++port)
    {
        if(isPortAvailable(port))
        {
            return port;
        }
    }
    return 0;  // No free port found
}

auto readFileContents(const std::string& filename) -> std::string
{
    std::ifstream file(filename);
    if(!file.is_open())
    {
        return "";
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return content;
}

auto wait_for_condition(const std::function<bool()>& condition,
                        std::chrono::milliseconds timeout) -> bool
{
    auto start = std::chrono::steady_clock::now();
    while(std::chrono::steady_clock::now() - start < timeout)
    {
        if(condition())
        {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

auto generateTestPolicy(const std::string& id,
                        PolicyAction action,
                        const std::string& src_ip,
                        const std::string& dst_ip,
                        uint16_t dst_port,
                        Protocol protocol) -> Policy
{
    Policy policy;
    policy.id = id;
    policy.action = action;

    // Convert IP strings to uint32_t
    policy.src.ip = inet_addr(src_ip.c_str());
    policy.dst.ip = inet_addr(dst_ip.c_str());
    policy.dst.port = dst_port;
    policy.src.protocol = protocol;
    policy.dst.protocol = protocol;

    // Set timestamps
    policy.createdAt = std::chrono::system_clock::now();
    policy.expiresAt = policy.createdAt + std::chrono::hours(1);

    return policy;
}

auto generate_test_packet(const std::string& src_ip,
                          const std::string& dst_ip,
                          uint8_t protocol,
                          uint16_t src_port,
                          uint16_t dst_port) -> PacketInfo
{
    PacketInfo packet;

    // Convert IP strings to uint32_t and set network addresses
    packet.src.ip = inet_addr(src_ip.c_str());
    packet.dst.ip = inet_addr(dst_ip.c_str());
    packet.src.protocol = static_cast<Protocol>(protocol);
    packet.dst.protocol = static_cast<Protocol>(protocol);
    packet.src.port = src_port;
    packet.dst.port = dst_port;
    packet.size = 64;  // Default packet size

    // Set timestamp
    auto timestamp = std::chrono::system_clock::now().time_since_epoch();
    packet.timestamp = std::chrono::system_clock::time_point(timestamp);

    return packet;
}

auto generate_test_traffic(size_t count,
                           const std::string& src_network,
                           const std::string& dst_network) -> std::vector<PacketInfo>
{
    std::vector<PacketInfo> packets;
    packets.reserve(count);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> portDist(1024, 65535);
    std::uniform_int_distribution<> protocolDist(1, 3);  // TCP, UDP, ICMP

    for(size_t i = 0; i < count; ++i)
    {
        std::string srcIp = src_network + std::to_string((i % 254) + 1);
        std::string dstIp = dst_network + std::to_string((i % 254) + 1);

        uint8_t protocol =
            protocolDist(gen) == 1 ? 6 : (protocolDist(gen) == 2 ? 17 : 1);  // TCP, UDP, ICMP
        uint16_t srcPort = portDist(gen);
        uint16_t dstPort = portDist(gen);

        packets.push_back(generate_test_packet(srcIp, dstIp, protocol, srcPort, dstPort));
    }

    return packets;
}

auto check_process_running(pid_t pid) -> bool
{
    return kill(pid, 0) == 0;
}

auto make_http_request(const std::string& host,
                       uint16_t port,
                       const std::string& path,
                       const std::string& method,
                       const std::string& body) -> std::string
{
    try
    {
        boost::asio::io_context ioc;
        boost::asio::ip::tcp::resolver resolver(ioc);
        boost::beast::tcp_stream stream(ioc);

        auto const results = resolver.resolve(host, std::to_string(port));
        stream.connect(results);

        boost::beast::http::verb verb = boost::beast::http::string_to_verb(method);
        boost::beast::http::request<boost::beast::http::string_body> req{verb, path, 11};
        req.set(boost::beast::http::field::host, host);
        req.set(boost::beast::http::field::user_agent, "pepctl-test-client");

        if(!body.empty())
        {
            req.body() = body;
            req.set(boost::beast::http::field::content_length, std::to_string(body.length()));
            req.set(boost::beast::http::field::content_type, "application/json");
        }

        boost::beast::http::write(stream, req);

        boost::beast::flat_buffer buffer;
        boost::beast::http::response<boost::beast::http::string_body> res;
        boost::beast::http::read(stream, buffer, res);

        boost::beast::error_code ec;
        stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);

        return res.body();
    }
    catch(const std::exception& e)
    {
        return "";
    }
}

void cleanup_test_files(const std::vector<std::string>& files)
{
    for(const auto& file : files)
    {
        std::filesystem::remove(file);
    }
}

}  // namespace pepctl::test
