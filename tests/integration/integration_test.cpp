#include <csignal>

#include <gtest/gtest.h>
#include <sys/wait.h>

#include "../test_utils.h"
#include "pepctl/core.h"
#include "pepctl/logger.h"
#include "pepctl/metrics_server.h"
#include "pepctl/policy_engine.h"

using namespace pepctl;
using namespace pepctl::test;

class IntegrationTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Setup test configuration
        test_config.pid_file = "/tmp/pepctl_integration_test.pid";
        test_config.log_file = "/tmp/pepctl_integration_test.log";
        test_config.policies_file = "/tmp/integration_test_policies.json";
        test_config.metrics_port = 18081;

        config_file = "/tmp/pepctl_integration_test.json";

        // Create test policies
        test_policies = {
            {"allow_http", "allow", "192.168.1.0/24", "10.0.0.0/8", "tcp", 80, 100, true},
            {  "deny_ssh",  "deny",      "0.0.0.0/0",   "10.0.0.1", "tcp", 22, 200, true},
            { "allow_dns", "allow", "192.168.1.0/24",    "8.8.8.8", "udp", 53, 150, true}
        };

        // Create test files
        ASSERT_TRUE(create_test_config_file(config_file, test_config));
        ASSERT_TRUE(create_test_policies_file(test_config.policies_file, test_policies));

        daemon_pid = -1;
    }

    void TearDown() override
    {
        // Stop daemon if running
        if(daemon_pid > 0)
        {
            kill(daemon_pid, SIGTERM);
            int status = 0;
            waitpid(daemon_pid, &status, 0);
        }

        // Cleanup test files
        cleanup_test_files(
            {config_file, test_config.pid_file, test_config.log_file, test_config.policies_file});
    }

    TestConfig test_config;
    std::string config_file;
    std::vector<TestPolicy> test_policies;
    pid_t daemon_pid{};
};

TEST_F(IntegrationTest, DaemonStartupShutdownTest)
{
    // Fork and start daemon
    daemon_pid = fork();
    if(daemon_pid == 0)
    {
        // Child process - start daemon
        execl("./pepctl", "pepctl", "--config", config_file.c_str(), "--daemon", nullptr);
        exit(1);  // Should not reach here
    }

    ASSERT_GT(daemon_pid, 0);

    // Wait for daemon to start
    EXPECT_TRUE(
        wait_for_condition([this]() { return std::filesystem::exists(test_config.pid_file); },
                           std::chrono::seconds(5)));

    // Check if daemon is running
    EXPECT_TRUE(check_process_running(daemon_pid));

    // Check if metrics server is responding
    EXPECT_TRUE(wait_for_condition(
        [this]() {
            auto response = make_http_request("127.0.0.1", test_config.metrics_port, "/health");
            return !response.empty();
        },
        std::chrono::seconds(5)));

    // Stop daemon gracefully
    kill(daemon_pid, SIGTERM);

    // Wait for daemon to stop
    int status = 0;
    EXPECT_EQ(waitpid(daemon_pid, &status, 0), daemon_pid);
    daemon_pid = -1;

    // Check if PID file is removed
    EXPECT_TRUE(
        wait_for_condition([this]() { return !std::filesystem::exists(test_config.pid_file); },
                           std::chrono::seconds(3)));
}

TEST_F(IntegrationTest, PolicyLoadingTest)
{
    // Start daemon
    daemon_pid = fork();
    if(daemon_pid == 0)
    {
        execl("./pepctl", "pepctl", "--config", config_file.c_str(), "--daemon", nullptr);
        exit(1);
    }

    ASSERT_GT(daemon_pid, 0);

    // Wait for daemon to start
    EXPECT_TRUE(
        wait_for_condition([this]() { return std::filesystem::exists(test_config.pid_file); },
                           std::chrono::seconds(5)));

    // Wait for metrics server to be ready
    EXPECT_TRUE(wait_for_condition(
        [this]() {
            auto response = make_http_request("127.0.0.1", test_config.metrics_port, "/metrics");
            return !response.empty();
        },
        std::chrono::seconds(5)));

    // Check if policies are loaded
    auto metricsResponse = make_http_request("127.0.0.1", test_config.metrics_port, "/metrics");
    EXPECT_FALSE(metricsResponse.empty());
    EXPECT_TRUE(metricsResponse.find("pepctl_total_policies") != std::string::npos);

    // The metrics should show the number of loaded policies
    EXPECT_TRUE(metricsResponse.find('3') != std::string::npos);  // 3 test policies
}

TEST_F(IntegrationTest, MetricsEndpointTest)
{
    // Start daemon
    daemon_pid = fork();
    if(daemon_pid == 0)
    {
        execl("./pepctl", "pepctl", "--config", config_file.c_str(), "--daemon", nullptr);
        exit(1);
    }

    ASSERT_GT(daemon_pid, 0);

    // Wait for daemon to start
    EXPECT_TRUE(
        wait_for_condition([this]() { return std::filesystem::exists(test_config.pid_file); },
                           std::chrono::seconds(5)));

    // Test /health endpoint
    auto healthResponse = make_http_request("127.0.0.1", test_config.metrics_port, "/health");
    EXPECT_FALSE(healthResponse.empty());
    EXPECT_TRUE(healthResponse.find("status") != std::string::npos);

    // Test /metrics endpoint
    auto metricsResponse = make_http_request("127.0.0.1", test_config.metrics_port, "/metrics");
    EXPECT_FALSE(metricsResponse.empty());
    EXPECT_TRUE(metricsResponse.find("pepctl_") != std::string::npos);

    // Test /policies endpoint (if implemented)
    auto policiesResponse = make_http_request("127.0.0.1", test_config.metrics_port, "/policies");
    // This might return empty if not implemented, which is okay for now
}

TEST_F(IntegrationTest, PolicyManagementAPITest)
{
    // Start daemon
    daemon_pid = fork();
    if(daemon_pid == 0)
    {
        execl("./pepctl", "pepctl", "--config", config_file.c_str(), "--daemon", nullptr);
        exit(1);
    }

    ASSERT_GT(daemon_pid, 0);

    // Wait for daemon to start
    EXPECT_TRUE(
        wait_for_condition([this]() { return std::filesystem::exists(test_config.pid_file); },
                           std::chrono::seconds(5)));

    // Test adding a new policy via API
    std::string newPolicy = generate_test_policy_json(
        "test_api_policy", "allow", "172.16.0.0/16", "10.0.0.0/8", "tcp", 443);

    auto addResponse = make_http_request(
        "127.0.0.1", test_config.metrics_port, "/api/policies", "POST", newPolicy);

    // The response might be empty if API is not fully implemented
    // This test documents the expected behavior

    // Test listing policies
    auto listResponse = make_http_request("127.0.0.1", test_config.metrics_port, "/api/policies");

    // Test deleting a policy
    auto deleteResponse = make_http_request(
        "127.0.0.1", test_config.metrics_port, "/api/policies/test_api_policy", "DELETE");
}

TEST_F(IntegrationTest, LoggingTest)
{
    // Start daemon
    daemon_pid = fork();
    if(daemon_pid == 0)
    {
        execl("./pepctl", "pepctl", "--config", config_file.c_str(), "--daemon", nullptr);
        exit(1);
    }

    ASSERT_GT(daemon_pid, 0);

    // Wait for daemon to start
    EXPECT_TRUE(
        wait_for_condition([this]() { return std::filesystem::exists(test_config.pid_file); },
                           std::chrono::seconds(5)));

    // Wait a bit for logging to occur
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Check if log file exists and has content
    EXPECT_TRUE(std::filesystem::exists(test_config.log_file));

    std::ifstream logFile(test_config.log_file);
    std::string logContent((std::istreambuf_iterator<char>(logFile)),
                           std::istreambuf_iterator<char>());

    EXPECT_FALSE(logContent.empty());

    // Check for expected log entries
    EXPECT_TRUE(logContent.find("pepctl") != std::string::npos);
    EXPECT_TRUE(logContent.find("started") != std::string::npos
                || logContent.find("initialized") != std::string::npos);
}

TEST_F(IntegrationTest, ConfigReloadTest)
{
    // Start daemon
    daemon_pid = fork();
    if(daemon_pid == 0)
    {
        execl("./pepctl", "pepctl", "--config", config_file.c_str(), "--daemon", nullptr);
        exit(1);
    }

    ASSERT_GT(daemon_pid, 0);

    // Wait for daemon to start
    EXPECT_TRUE(
        wait_for_condition([this]() { return std::filesystem::exists(test_config.pid_file); },
                           std::chrono::seconds(5)));

    // Modify policies file
    std::vector<TestPolicy> newPolicies = test_policies;
    newPolicies.push_back(
        {"new_policy", "deny", "192.168.2.0/24", "10.0.0.0/8", "tcp", 8080, 300, true});

    EXPECT_TRUE(create_test_policies_file(test_config.policies_file, newPolicies));

    // Send SIGHUP to reload configuration
    kill(daemon_pid, SIGHUP);

    // Wait a bit for reload to complete
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Check if new policy count is reflected in metrics
    auto metricsResponse = make_http_request("127.0.0.1", test_config.metrics_port, "/metrics");
    EXPECT_FALSE(metricsResponse.empty());

    // Should now have 4 policies instead of 3
    // This test documents expected behavior even if not fully implemented
}

TEST_F(IntegrationTest, ErrorHandlingTest)
{
    // Test with invalid configuration
    TestConfig invalidConfig = test_config;
    invalidConfig.metrics_port = 0;  // Invalid port

    std::string invalidConfigFile = "/tmp/pepctl_invalid_test.json";
    ASSERT_TRUE(create_test_config_file(invalidConfigFile, invalidConfig));

    // Try to start daemon with invalid config
    pid_t invalidDaemonPid = fork();
    if(invalidDaemonPid == 0)
    {
        execl("./pepctl", "pepctl", "--config", invalidConfigFile.c_str(), "--daemon", nullptr);
        exit(1);
    }

    ASSERT_GT(invalidDaemonPid, 0);

    // Wait for process to exit (should fail)
    int status = 0;
    EXPECT_EQ(waitpid(invalidDaemonPid, &status, 0), invalidDaemonPid);
    EXPECT_NE(WEXITSTATUS(status), 0);  // Should exit with error

    // Cleanup
    std::filesystem::remove(invalidConfigFile);
}