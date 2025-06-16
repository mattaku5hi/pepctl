#include <gtest/gtest.h>
#include <pepctl/core.h>

class CoreTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Setup test environment
    }

    void TearDown() override
    {
        // Cleanup test environment
    }
};

// Test utility functions
TEST_F(CoreTest, IPStringConversion)
{
    // Test IP string to uint32 conversion
    uint32_t ip = pepctl::ipStringToUint32("192.168.1.1");
    EXPECT_NE(ip, 0);

    // Test uint32 to IP string conversion
    std::string ipStr = pepctl::uint32ToIpString(ip);
    EXPECT_EQ(ipStr, "192.168.1.1");
}

TEST_F(CoreTest, PolicyActionConversion)
{
    // Test policy action to string conversion
    std::string actionStr = pepctl::policyActionToString(pepctl::PolicyAction::ALLOW);
    EXPECT_EQ(actionStr, "ALLOW");

    actionStr = pepctl::policyActionToString(pepctl::PolicyAction::BLOCK);
    EXPECT_EQ(actionStr, "BLOCK");

    // Test string to policy action conversion
    pepctl::PolicyAction action = pepctl::stringToPolicyAction("ALLOW");
    EXPECT_EQ(action, pepctl::PolicyAction::ALLOW);

    action = pepctl::stringToPolicyAction("BLOCK");
    EXPECT_EQ(action, pepctl::PolicyAction::BLOCK);
}

TEST_F(CoreTest, ProtocolConversion)
{
    // Test protocol to string conversion
    std::string protoStr = pepctl::protocolToString(pepctl::Protocol::TCP);
    EXPECT_EQ(protoStr, "TCP");

    protoStr = pepctl::protocolToString(pepctl::Protocol::UDP);
    EXPECT_EQ(protoStr, "UDP");

    // Test string to protocol conversion
    pepctl::Protocol proto = pepctl::stringToProtocol("TCP");
    EXPECT_EQ(proto, pepctl::Protocol::TCP);

    proto = pepctl::stringToProtocol("UDP");
    EXPECT_EQ(proto, pepctl::Protocol::UDP);
}

TEST_F(CoreTest, NetworkAddressCreation)
{
    pepctl::NetworkAddress addr(0x0101A8C0, 80, pepctl::Protocol::TCP);  // 192.168.1.1:80

    EXPECT_EQ(addr.ip, 0x0101A8C0);
    EXPECT_EQ(addr.port, 80);
    EXPECT_EQ(addr.protocol, pepctl::Protocol::TCP);
}

TEST_F(CoreTest, PolicyCreation)
{
    pepctl::Policy policy;
    policy.id = "test_policy";
    policy.action = pepctl::PolicyAction::BLOCK;
    policy.src = pepctl::NetworkAddress(0x0101A8C0, 0, pepctl::Protocol::ANY);
    policy.dst = pepctl::NetworkAddress(0, 80, pepctl::Protocol::TCP);

    EXPECT_EQ(policy.id, "test_policy");
    EXPECT_EQ(policy.action, pepctl::PolicyAction::BLOCK);
    EXPECT_EQ(policy.hitCount.load(), 0);
    EXPECT_EQ(policy.bytesProcessed.load(), 0);
}

TEST_F(CoreTest, MetricsInitialization)
{
    pepctl::Metrics metrics;

    EXPECT_EQ(metrics.packetsProcessed.load(), 0);
    EXPECT_EQ(metrics.packetsAllowed.load(), 0);
    EXPECT_EQ(metrics.packetsBlocked.load(), 0);
    EXPECT_EQ(metrics.policiesLoaded.load(), 0);
    EXPECT_EQ(metrics.bytesProcessed.load(), 0);
}

TEST_F(CoreTest, ConfigDefaults)
{
    pepctl::Config config;

    EXPECT_EQ(config.logLevel, "info");
    EXPECT_EQ(config.adminPort, pepctl::defaultAdminPort);
    EXPECT_EQ(config.metricsPort, pepctl::defaultMetricsPort);
    EXPECT_EQ(config.interfaceName, "eth0");
    EXPECT_FALSE(config.daemonMode);
    EXPECT_TRUE(config.enableMetrics);
    EXPECT_EQ(config.policyCapacity, pepctl::defaultPolicyCapacity);
}

// Performance test for atomic operations
TEST_F(CoreTest, AtomicPerformance)
{
    pepctl::Metrics metrics;
    const int numOperations = 1000000;

    auto start = std::chrono::high_resolution_clock::now();

    for(int i = 0; i < numOperations; ++i)
    {
        metrics.packetsProcessed.fetch_add(1);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    EXPECT_EQ(metrics.packetsProcessed.load(), numOperations);

    // Performance should be reasonable (less than 1ms per 1000 operations)
    EXPECT_LT(duration.count(), 1000 * (numOperations / 1000));
}

auto main(int argc, char** argv) -> int
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}