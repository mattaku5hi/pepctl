#include <chrono>
#include <thread>

#include <gtest/gtest.h>
#include <pepctl/core.h>
#include <pepctl/policy_engine.h>

using namespace pepctl;

class PolicyEngineTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        engine = std::make_unique<PolicyEngine>();
        ASSERT_TRUE(engine->initialize());
    }

    void TearDown() override
    {
        if(engine != nullptr)
        {
            engine->shutdown();
        }
    }

    std::unique_ptr<PolicyEngine> engine;
};

TEST_F(PolicyEngineTest, InitializationTest)
{
    EXPECT_TRUE(engine != nullptr);
    EXPECT_EQ(engine->getPolicyCount(), 0);
}

TEST_F(PolicyEngineTest, LoadPolicyTest)
{
    Policy policy;
    policy.id = "test_policy_1";
    policy.action = PolicyAction::BLOCK;
    policy.src.ip = 0xC0A80164;  // 192.168.1.100
    policy.dst.ip = 0x0A000001;  // 10.0.0.1
    policy.dst.port = 443;
    policy.dst.protocol = Protocol::TCP;
    policy.createdAt = std::chrono::system_clock::now();
    policy.expiresAt = std::chrono::system_clock::now() + std::chrono::hours(1);

    EXPECT_TRUE(engine->addPolicy(policy));
    EXPECT_EQ(engine->getPolicyCount(), 1);

    auto loadedPolicy = engine->getPolicy("test_policy_1");
    EXPECT_TRUE(loadedPolicy != nullptr);
    EXPECT_EQ(loadedPolicy->id, "test_policy_1");
}

TEST_F(PolicyEngineTest, PolicyLookupTest)
{
    Policy policy;
    policy.id = "lookup_test_policy";
    policy.action = PolicyAction::BLOCK;
    policy.src.ip = 0xC0A80164;  // 192.168.1.100
    policy.dst.ip = 0x0A000001;  // 10.0.0.1
    policy.dst.port = 443;
    policy.dst.protocol = Protocol::TCP;
    policy.createdAt = std::chrono::system_clock::now();
    policy.expiresAt = std::chrono::system_clock::now() + std::chrono::hours(1);

    EXPECT_TRUE(engine->addPolicy(policy));

    PacketInfo packet;
    packet.src.ip = 0xC0A80164;  // 192.168.1.100
    packet.dst.ip = 0x0A000001;  // 10.0.0.1
    packet.dst.protocol = Protocol::TCP;
    packet.dst.port = 443;
    packet.size = 1024;
    packet.timestamp = std::chrono::system_clock::now();

    auto result = engine->evaluatePacket(packet);
    EXPECT_EQ(result.action, PolicyAction::BLOCK);
    EXPECT_EQ(result.policy_id, "lookup_test_policy");
}

TEST_F(PolicyEngineTest, PolicyRemovalTest)
{
    Policy policy;
    policy.id = "removal_test_policy";
    policy.action = PolicyAction::ALLOW;
    policy.src.ip = 0x00000000;  // Any source
    policy.dst.ip = 0x0A000001;  // 10.0.0.1
    policy.createdAt = std::chrono::system_clock::now();
    policy.expiresAt = std::chrono::system_clock::now() + std::chrono::hours(1);

    EXPECT_TRUE(engine->addPolicy(policy));
    EXPECT_EQ(engine->getPolicyCount(), 1);

    EXPECT_TRUE(engine->removePolicy("removal_test_policy"));
    EXPECT_EQ(engine->getPolicyCount(), 0);
}

TEST_F(PolicyEngineTest, InvalidPolicyTest)
{
    Policy invalidPolicy;
    // Leave required fields empty/invalid
    invalidPolicy.id = "";  // Empty ID should be invalid
    EXPECT_FALSE(engine->addPolicy(invalidPolicy));
}

TEST_F(PolicyEngineTest, PolicyStatsTest)
{
    EXPECT_EQ(engine->getPolicyCount(), 0);

    // Add some policies and verify count
    for(int i = 0; i < 5; ++i)
    {
        Policy policy;
        policy.id = "policy_" + std::to_string(i);
        policy.action = PolicyAction::ALLOW;
        policy.createdAt = std::chrono::system_clock::now();
        policy.expiresAt = std::chrono::system_clock::now() + std::chrono::hours(1);
        engine->addPolicy(policy);
    }

    EXPECT_EQ(engine->getPolicyCount(), 5);
}

TEST_F(PolicyEngineTest, ConcurrentAccessTest)
{
    const int numThreads = 4;
    const int policiesPerThread = 25;
    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};

    threads.reserve(numThreads);
    for(int t = 0; t < numThreads; ++t)
    {
        threads.emplace_back([this, t, &successCount]() {
            for(int i = 0; i < policiesPerThread; ++i)
            {
                Policy policy;
                policy.id = "thread_" + std::to_string(t) + "_policy_" + std::to_string(i);
                policy.action = PolicyAction::ALLOW;
                policy.createdAt = std::chrono::system_clock::now();
                policy.expiresAt = std::chrono::system_clock::now() + std::chrono::hours(1);

                if(engine->addPolicy(policy))
                {
                    successCount++;
                }
            }
        });
    }

    for(auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(successCount.load(), numThreads * policiesPerThread);
    EXPECT_EQ(engine->getPolicyCount(), numThreads * policiesPerThread);
}