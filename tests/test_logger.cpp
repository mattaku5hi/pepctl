#include <filesystem>
#include <fstream>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <pepctl/logger.h>

using namespace pepctl;

class LoggerTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        test_log_file = "/tmp/pepctl_test_" + std::to_string(std::time(nullptr)) + ".log";
    }

    void TearDown() override
    {
        if(std::filesystem::exists(test_log_file))
        {
            std::filesystem::remove(test_log_file);
        }
    }

    std::string test_log_file;
};

TEST_F(LoggerTest, InitializationTest)
{
    Logger logger;
    LoggerConfig config;
    config.level = LogLevel::INFO;
    config.fileOutput = true;
    config.logFilePath = test_log_file;

    EXPECT_TRUE(logger.initialize(config));
}

TEST_F(LoggerTest, LogLevelsTest)
{
    Logger logger;
    LoggerConfig config;
    config.level = LogLevel::DBG;
    config.fileOutput = true;
    config.logFilePath = test_log_file;

    logger.initialize(config);

    LogContext ctx(LogCategory::SYSTEM);
    logger.trace(ctx, "Trace message");
    logger.debug(ctx, "Debug message");
    logger.info(ctx, "Info message");
    logger.warn(ctx, "Warning message");
    logger.error(ctx, "Error message");
    logger.critical(ctx, "Critical message");

    logger.flush();

    // Verify file exists and has content
    EXPECT_TRUE(std::filesystem::exists(test_log_file));
    std::ifstream file(test_log_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    EXPECT_FALSE(content.empty());
}

TEST_F(LoggerTest, StructuredLoggingTest)
{
    Logger logger;
    LoggerConfig config;
    config.level = LogLevel::INFO;
    config.fileOutput = true;
    config.logFilePath = test_log_file;

    logger.initialize(config);

    LogContext ctx(LogCategory::POLICY);
    ctx.withPolicy("policy_123").withClientIp("192.168.1.100");

    logger.logPolicyEvent("policy_123", "loaded", "192.168.1.100", "Policy successfully loaded");
    logger.info("System event: eBPF program loaded successfully");

    logger.flush();

    // Verify structured data was logged
    std::ifstream file(test_log_file);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("policy_123"), std::string::npos);
}

TEST_F(LoggerTest, LogRotationTest)
{
    Logger logger;
    LoggerConfig config;
    config.level = LogLevel::INFO;
    config.fileOutput = true;
    config.logFilePath = test_log_file;
    config.maxFileSize = 1024;  // 1KB max size

    logger.initialize(config);

    // Write many log messages to trigger rotation
    for(int i = 0; i < 100; ++i)
    {
        logger.info("This is a test log message number " + std::to_string(i));
    }

    logger.flush();
    EXPECT_TRUE(std::filesystem::exists(test_log_file));
}

TEST_F(LoggerTest, PerformanceTest)
{
    Logger logger;
    LoggerConfig config;
    config.level = LogLevel::INFO;
    config.fileOutput = true;
    config.logFilePath = test_log_file;

    logger.initialize(config);

    auto start = std::chrono::high_resolution_clock::now();
    for(int i = 0; i < 10000; ++i)
    {
        logger.info("Performance test message " + std::to_string(i));
    }
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    EXPECT_LT(duration.count(), 5000);  // Should complete in less than 5 seconds
}

TEST_F(LoggerTest, ThreadSafetyTest)
{
    Logger logger;
    LoggerConfig config;
    config.level = LogLevel::INFO;
    config.fileOutput = true;
    config.logFilePath = test_log_file;

    logger.initialize(config);

    const int numThreads = 4;
    const int messagesPerThread = 100;
    std::vector<std::thread> threads;

    threads.reserve(numThreads);
    for(int t = 0; t < numThreads; ++t)
    {
        threads.emplace_back([&logger, t]() {
            for(int i = 0; i < messagesPerThread; ++i)
            {
                logger.info("Thread " + std::to_string(t) + " message " + std::to_string(i));
            }
        });
    }

    for(auto& thread : threads)
    {
        thread.join();
    }

    logger.flush();
    EXPECT_TRUE(std::filesystem::exists(test_log_file));
}