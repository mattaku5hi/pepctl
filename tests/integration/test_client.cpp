#include <iostream>
#include <string>
#include <utility>

#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/program_options.hpp>
#include <nlohmann/json.hpp>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;
namespace po = boost::program_options;

class TestClient
{
  public:
    TestClient(std::string host, uint16_t port) : host_(std::move(host)), port_(port) {}

    auto makeRequest(const std::string& target,
                     const std::string& method = "GET",
                     const std::string& body = "") -> std::string
    {
        try
        {
            net::io_context ioc;
            tcp::resolver resolver(ioc);
            beast::tcp_stream stream(ioc);

            auto const results = resolver.resolve(host_, std::to_string(port_));
            stream.connect(results);

            http::verb verb = http::string_to_verb(method);
            http::request<http::string_body> req{verb, target, 11};
            req.set(http::field::host, host_);
            req.set(http::field::user_agent, "pepctl-test-client/1.0");

            if(!body.empty())
            {
                req.body() = body;
                req.set(http::field::content_length, std::to_string(body.length()));
                req.set(http::field::content_type, "application/json");
            }

            http::write(stream, req);

            beast::flat_buffer buffer;
            http::response<http::string_body> res;
            http::read(stream, buffer, res);

            beast::error_code ec;
            stream.socket().shutdown(tcp::socket::shutdown_both, ec);

            std::cout << "HTTP " << res.result_int() << " " << res.reason() << '\n';
            std::cout << "Response: " << res.body() << '\n';

            return res.body();
        }
        catch(const std::exception& e)
        {
            std::cerr << "Error: " << e.what() << '\n';
            return "";
        }
    }

    void testHealthEndpoint()
    {
        std::cout << "\n=== Testing /health endpoint ===" << '\n';
        makeRequest("/health");
    }

    void testMetricsEndpoint()
    {
        std::cout << "\n=== Testing /metrics endpoint ===" << '\n';
        makeRequest("/metrics");
    }

    void testPoliciesEndpoint()
    {
        std::cout << "\n=== Testing /policies endpoint ===" << '\n';
        makeRequest("/policies");
    }

    void testApiPoliciesList()
    {
        std::cout << "\n=== Testing GET /api/policies ===" << '\n';
        makeRequest("/api/policies");
    }

    void testApiPoliciesAdd()
    {
        std::cout << "\n=== Testing POST /api/policies ===" << '\n';

        nlohmann::json policy = {
            {      "id", "test_client_policy"},
            {  "action",              "allow"},
            {  "src_ip",   "192.168.100.0/24"},
            {  "dst_ip",         "10.0.0.0/8"},
            {"protocol",                "tcp"},
            {"dst_port",                 8080},
            {"priority",                  100},
            { "enabled",                 true}
        };

        makeRequest("/api/policies", "POST", policy.dump());
    }

    void testApiPoliciesGet()
    {
        std::cout << "\n=== Testing GET /api/policies/test_client_policy ===" << '\n';
        makeRequest("/api/policies/test_client_policy");
    }

    void testApiPoliciesDelete()
    {
        std::cout << "\n=== Testing DELETE /api/policies/test_client_policy ===" << '\n';
        makeRequest("/api/policies/test_client_policy", "DELETE");
    }

    void testApiStats()
    {
        std::cout << "\n=== Testing /api/stats endpoint ===" << '\n';
        makeRequest("/api/stats");
    }

    void runAllTests()
    {
        std::cout << "Running all API tests against " << host_ << ":" << port_ << '\n';

        testHealthEndpoint();
        testMetricsEndpoint();
        testPoliciesEndpoint();
        testApiPoliciesList();
        testApiPoliciesAdd();
        testApiPoliciesGet();
        testApiStats();
        testApiPoliciesDelete();

        std::cout << "\n=== All tests completed ===" << '\n';
    }

  private:
    std::string host_;
    uint16_t port_;
};

auto main(int argc, char* argv[]) -> int
{
    try
    {
        po::options_description desc("Allowed options");
        desc.add_options()("help,h", "produce help message")(
            "host", po::value<std::string>()->default_value("127.0.0.1"), "server host")(
            "port,p", po::value<uint16_t>()->default_value(8080), "server port")(
            "endpoint,e", po::value<std::string>(), "specific endpoint to test")(
            "method,m", po::value<std::string>()->default_value("GET"), "HTTP method")(
            "body,b", po::value<std::string>()->default_value(""), "request body")("all",
                                                                                   "run all tests");

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if(vm.count("help") != 0U)
        {
            std::cout << desc << '\n';
            return 0;
        }

        std::string host = vm["host"].as<std::string>();
        uint16_t port = vm["port"].as<uint16_t>();

        TestClient client(host, port);

        if(vm.count("all") != 0U)
        {
            client.runAllTests();
        }
        else if(vm.count("endpoint") != 0U)
        {
            std::string endpoint = vm["endpoint"].as<std::string>();
            std::string method = vm["method"].as<std::string>();
            std::string body = vm["body"].as<std::string>();

            std::cout << "Testing " << method << " " << endpoint << '\n';
            client.makeRequest(endpoint, method, body);
        }
        else
        {
            std::cout << "Use --all to run all tests or --endpoint to test specific endpoint"
                      << '\n';
            std::cout << "Use --help for more options" << '\n';
            return 1;
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}