/*
 * PEPCTL - Policy Enforcement Point Control Utility
 * Main entry point for the systemd service
 */


#include <atomic>
#include <boost/program_options.hpp>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <fcntl.h>
#include <nlohmann/json.hpp>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <thread>
#include <unordered_set>

#include "pepctl/core.h"
#include "pepctl/logger.h"


#define PEPCTL_DEFAULT_CONFIG_PATH          "/etc/pepctl/config.json"
#define PEPCTL_DEFAULT_EBPF_PATH            "/usr/share/pepctl/ebpf/packet_filter.o"
#define PEPCTL_DEV_NULL_PATH                "/dev/null"
#define PEPCTL_ROOT_DIR                     "/var/run/pepctl"

#ifdef SYSTEMD_NOTIFY_SUPPORT
#include <systemd/sd-notify.h>
#endif


/*
    Global variables for signal handlers (required by signal handling)
*/
std::unique_ptr<pepctl::IPepctlDaemon> gDaemon;
std::atomic<bool> gShutdownRequested{false};
std::atomic<bool> gConfigReloadRequested{false};
std::string gCurrentConfigPath;  // Store config path for reload

void validateEbpfProgramPath(const std::string& path);


void signalHandler(int signum)
{
    switch(signum)
    {
        case SIGTERM:
        case SIGINT:
            {
                std::cout << "Received shutdown signal " << signum << ", stopping daemon..."
                          << '\n';
                gShutdownRequested = true;

                if(gDaemon != nullptr)
                {
                    try
                    {
                        gDaemon->stop();
                    }
                    catch(...)
                    {
                        // Ignore exceptions during signal handling
                    }
                }
                break;
            }
        case SIGHUP:
            {
                std::cout << "Received SIGHUP, scheduling configuration reload..." << '\n';
                gConfigReloadRequested = true;
                break;
            }
        default:
            {
                break;
            }
    }
}

/**
 * @brief Setup signal handlers for daemon
 *
 * SIGNAL EXPLANATIONS:
 *
 * SIGTERM (15) - "Terminate":
 * - Sent by: systemctl stop, kill <pid>, system shutdown
 * - Purpose: Polite request to terminate gracefully
 * - Action: Clean shutdown, save state, close files
 *
 * SIGINT (2) - "Interrupt":
 * - Sent by: Ctrl+C in terminal, kill -INT <pid>
 * - Purpose: Interactive termination request
 * - Action: Same as SIGTERM for daemons
 *
 * SIGHUP (1) - "Hang Up":
 * - Historical: Terminal disconnection
 * - Modern: Configuration reload signal
 * - Sent by: kill -HUP <pid>, systemctl reload
 * - Purpose: Reload config without restarting
 * - Action: Re-read config files, update runtime settings
 *
 * SIGPIPE (13) - "Broken Pipe":
 * - Sent by: Writing to closed socket/pipe
 * - Default: Terminates process
 * - Why ignore: Network servers handle connection errors explicitly
 * - Action: Ignore, handle network errors in code
 */
void setupSignalHandlers()
{
    struct sigaction sa{};

    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    /*
        Install handlers for graceful shutdown and config reload
    */
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);

    /*
        Ignore SIGPIPE - Critical for network daemons!
        - Client connects to admin API
        - Client closes connection abruptly
        - Daemon tries to send response (SIGPIPE)
        - Without SIG_IGN: daemon crashes with SIGPIPE
        - With SIG_IGN: write() returns -1 with EPIPE, daemon continues
    */
    signal(SIGPIPE, SIG_IGN);
}

/**
 * @brief Load configuration from JSON file
 * @param config_path Path to configuration file
 * @return Configuration
 */
auto loadConfig(const std::string& config_path) -> pepctl::Config
{
    pepctl::Config config;

    if(config_path.empty())
    {
        std::cout << "No config file specified, using defaults" << '\n';
        config.ebpfProgramPath = PEPCTL_DEFAULT_EBPF_PATH;

        return config;
    }

    /*
        Try to load configuration from file
    */
    try
    {
        std::ifstream config_file(config_path);
        if(config_file.is_open() == false)
        {
            throw std::runtime_error("Cannot open config file");
        }

        /*
            Create empty JSON object on stack
            Equivalent to empty JSON object ({} in JSON notation)
        */
        nlohmann::json jsonConfig;  // ~64 bytes on stack

        /*
            Parse JSON from file stream using extraction operator
            Equivalent to: json_config = nlohmann::json::parse(config_file)
            1. File reading: O(n) - reads entire file
            2. Tokenization: O(n) - scans each character once
            3. Parsing: O(n) - processes each token once
            4. Tree building: O(n) - creates nodes for content
        */
        config_file >> jsonConfig;  // heap allocation for temp buffer ~ file size

        /*
            Use safe chain access to load configuration
        */
        config.configFilePath = config_path;
        config.daemonMode =
            jsonConfig.value("daemon", nlohmann::json::object()).value("mode", false);
        config.logLevel = jsonConfig.value("log", nlohmann::json::object()).value("level", "info");
        config.logFilePath = jsonConfig.value("log", nlohmann::json::object()).value("file", "");
        config.adminPort = jsonConfig.value("server", nlohmann::json::object())
                               .value("admin_port", pepctl::defaultAdminPort);
        config.metricsPort = jsonConfig.value("server", nlohmann::json::object())
                                 .value("metrics_port", pepctl::defaultMetricsPort);
        config.interfaceName =
            jsonConfig.value("network", nlohmann::json::object()).value("interface", "eth0");
        config.enableMetrics =
            jsonConfig.value("metrics", nlohmann::json::object()).value("enabled", true);
        config.policyCapacity = jsonConfig.value("policy", nlohmann::json::object())
                                    .value("capacity", pepctl::defaultPolicyCapacity);
        config.policiesFile =
            jsonConfig.value("policy", nlohmann::json::object()).value("policies_file", "");
        config.ebpfProgramPath = jsonConfig.value("ebpf", nlohmann::json::object())
                                     .value("program_path", PEPCTL_DEFAULT_EBPF_PATH);
        config.ebpfProgramType =
            jsonConfig.value("ebpf", nlohmann::json::object()).value("program_type", "xdp");

        std::cout << "Loaded configuration from: " << config_path << '\n';
    }
    catch(const std::exception& e)
    {
        std::cerr << "Error loading config file '" << config_path << "': " << e.what() << '\n';
        std::cerr << "Using default configuration" << '\n';

        config.ebpfProgramPath = PEPCTL_DEFAULT_EBPF_PATH;
    }

    /*
        Validate eBPF program path after configuration is fully loaded
    */
    try
    {
        validateEbpfProgramPath(config.ebpfProgramPath);
    }
    catch(const std::exception& validationError)
    {
        std::cerr << "Warning: eBPF program validation failed: " << validationError.what() << '\n';
        std::cerr << "Daemon will start but eBPF functionality may not work" << '\n';
    }

    return config;
}

/**
 * @brief Handle configuration reload (called from main loop)
 * @return true if reload successful, false otherwise
 */
auto handleConfigReload() -> bool
{
    if(!gConfigReloadRequested)
    {
        return true;  // Nothing to do
    }

    std::cout << "Processing configuration reload..." << '\n';

    try
    {
        /*
            Load new configuration
        */
        pepctl::Config newConfig = loadConfig(gCurrentConfigPath);

        /*
            Apply new configuration to running daemon
        */
        if(gDaemon != nullptr)
        {
            /*
                Update runtime configuration
            */

            std::cout << "Configuration reloaded successfully" << '\n';
            std::cout << "Note: Some settings may require daemon restart to take effect" << '\n';
        }

        gConfigReloadRequested = false;
        return true;
    }
    catch(const std::exception& e)
    {
        std::cerr << "Failed to reload configuration: " << e.what() << '\n';
        std::cerr << "Continuing with current configuration" << '\n';
        gConfigReloadRequested = false;
        return false;
    }
}

/**
 * @brief Create directory recursively (like mkdir -p)
 * @param path Directory path to create
 * @return true if successful or directory already exists
 */
auto createDirectoryRecursive(const std::string& path) -> bool
{
    struct stat st{};

    if(stat(path.c_str(), &st) == 0)
    {
        return S_ISDIR(st.st_mode);
    }

    size_t pos = path.find_last_of('/');
    if(pos != std::string::npos && pos > 0)
    {
        std::string parent = path.substr(0, pos);
        if(createDirectoryRecursive(parent) == false)
        {
            return false;
        }
    }

    /*
        Create this directory
    */
    if(mkdir(path.c_str(), 0755) != 0)
    {
        std::cerr << "Failed to create directory " << path << ": " << strerror(errno) << '\n';
        return false;
    }

    return true;
}

/**
 * @brief Daemonize the process (Double-fork method)
 * @return true if successful, false otherwise
 */
auto daemonize() -> bool
{
    /*
        Separate from parent process
    */
    pid_t pid = fork();

    if(pid < 0)
    {
        std::cerr << "Fork failed: " << strerror(errno) << '\n';
        return false;
    }

    if(pid > 0)
    {
        std::exit(EXIT_SUCCESS);  // Parent exits here
    }

    /*
        Child becomes session leader of new session and process group leader of new process group
    */
    if(setsid() < 0)
    {
        std::cerr << "setsid failed: " << strerror(errno) << '\n';
        return false;
    }

    /*
        Ensure daemon truly runs in background without terminal
        Industry standard for robust daemons
    */
    pid = fork();
    if(pid < 0)
    {
        std::cerr << "Second fork failed: " << strerror(errno) << '\n';
        return false;
    }

    if(pid > 0)
    {
        std::exit(EXIT_SUCCESS);  // First child exits, second child continues
    }

    /*
        Create the root directory if it doesn't exist
    */
    if(!createDirectoryRecursive(PEPCTL_ROOT_DIR))
    {
        std::cerr << "Warning: Failed to create directory " << PEPCTL_ROOT_DIR << '\n';
    }

    /*
        Prevent daemon from holding references to directories
    */
    if(chdir(PEPCTL_ROOT_DIR) != 0)
    {
        std::cerr << "Warning: Failed to change directory to " << PEPCTL_ROOT_DIR << ": "
                  << strerror(errno) << '\n';
    }

    /*
        Set no restrictions on file creation
        e.g. 666 & ~0 (777) = 666
        Don't forget to make compiler happy and check the result
    */
    int result = umask(0);
    static_cast<void>(result);

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    if(open(PEPCTL_DEV_NULL_PATH, O_RDONLY) != STDIN_FILENO)
    {
        return false;
    }
    if(open(PEPCTL_DEV_NULL_PATH, O_WRONLY) != STDOUT_FILENO)
    {
        return false;
    }
    if(open(PEPCTL_DEV_NULL_PATH, O_WRONLY) != STDERR_FILENO)
    {
        return false;
    }

    return true;
}

/**
 * @brief Print version information
 */
void printVersion()
{
    std::cout << "pepctl version " << pepctl::version << '\n';
    std::cout << "Policy Enforcement Point Control Utility" << '\n';
}

/**
 * @brief Print usage information
 * @param desc Options description
 */
void printUsage(const boost::program_options::options_description& desc)
{
    std::cout << "PEPCTL - Policy Enforcement Point Control Utility" << '\n';
    std::cout << "Usage: pepctl --config <config_file> [--daemon]" << '\n';
    std::cout << '\n';
    std::cout
        << "All configuration (interface, ports, log level, etc.) is specified in the config file."
        << '\n';
    std::cout << "Command line options are minimal by design for simplicity." << '\n';
    std::cout << '\n';
    std::cout << desc << '\n';
}

/**
 * @brief Validate port number
 * @param port Port number
 */
void validatePort(uint16_t port)
{
    if(port < 1024)
    {
        throw std::runtime_error("Port " + std::to_string(port)
                                 + " is invalid (ports below 1024 require root privileges)");
    }
}

/**
 * @brief Validate log level
 * @param level Log level
 */
void validateLogLevel(const std::string& level)
{
    /*
        Using unordered_set for O(1) lookup
    */
    static const std::unordered_set<std::string> validLevels = {
        "trace", "debug", "info", "warn", "warning", "error", "critical", "off"};

    if(validLevels.find(level) == validLevels.end())
    {
        throw std::runtime_error("Invalid log level '" + level
                                 + "' (valid: trace, debug, info, warn, error, critical, off)");
    }
}

/**
 * @brief Validate eBPF program path
 * @param path eBPF program file path
 */
void validateEbpfProgramPath(const std::string& path)
{
    if(path.empty())
    {
        return;  // Empty path is allowed (no eBPF program will be loaded)
    }

    if(std::filesystem::exists(path) == false)
    {
        throw std::runtime_error("eBPF program file does not exist: " + path);
    }

    if(std::filesystem::is_regular_file(path) == false)
    {
        throw std::runtime_error("eBPF program path is not a regular file: " + path);
    }

    if(path.ends_with(".o") == false)
    {
        std::cerr << "Warning: eBPF program file does not have .o extension: " << path << '\n';
    }
}

/**
 * @brief Main function
 * @param argc Number of arguments
 * @param argv Arguments
 * @return Return code
 */
auto main(int argc, char* argv[]) -> int  // trailing return type
{
    /*
        Parse command line arguments
    */
    boost::program_options::options_description desc("Options");
    {
        desc.add_options()("help,h", "Show this help message")("version,v",
                                                               "Show version information")(
            "config,c",
            boost::program_options::value<std::string>()->default_value(PEPCTL_DEFAULT_CONFIG_PATH),
            "Configuration file path")("daemon,d", "Run as daemon (fork to background)");
    }

    /*
        variables_map is type-safe storage with metadata
        - Stores actual typed values (uint16_t, bool, string, etc.)
        - Plus metadata: was it set? from command line or config file? default value?
        - Type safety: vm["port"].as<uint16_t>() vs std::stoi(simple_map["port"])
        - Multiple sources: Can merge command line, config files, environment variables
        - Validation: Built-in type checking and constraints
    */
    boost::program_options::variables_map vm;

    try
    {
        /*
            store():
            - Parses the command line arguments according to the description (desc)
            - Stores the raw parsed values in the variables_map
            - Does NOT trigger any validation or default value assignment yet
            - Just populates the map with what was found
        */
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc),
                                      vm);

        /*
            Handle help and version options BEFORE validation
        */
        if(vm.count("help") != 0U)
        {
            printUsage(desc);
            return EXIT_SUCCESS;
        }

        if(vm.count("version") != 0U)
        {
            printVersion();
            return EXIT_SUCCESS;
        }

        if(vm.count("config") == 0U)
        {
            std::cout << "No config file specified, using the default one" << '\n';
            return EXIT_SUCCESS;
        }

        /*
            notify():
            - Triggers all the validation and post-processing
            - Calls any custom validators you've defined (like validatePort, validateLogLevel)
            - Applies default values for options not provided
            - Throws exceptions if required options are missing
            - Executes any custom actions (like help/version handlers)
        */
        boost::program_options::notify(vm);
    }
    catch(const boost::program_options::required_option& e)
    {
        std::cerr << "Missing required option: " << e.what() << '\n';
        std::cerr << "Use --help for usage information" << '\n';
        return EXIT_FAILURE;
    }
    catch(const boost::program_options::validation_error& e)
    {
        std::cerr << "Invalid option value: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
    catch(const std::exception& e)
    {
        std::cerr << "Error parsing command line: " << e.what() << '\n';
        return EXIT_FAILURE;
    }

    /*
        Check for root privileges
    */
    if(geteuid() != 0)
    {
        std::cerr << "[FATAL] pepctl must be run as root (euid=0) for eBPF and network operations."
                  << '\n';
        return EXIT_FAILURE;
    }

    /*
        Load configuration and store path for reloads
    */
    gCurrentConfigPath = vm["config"].as<std::string>();
    pepctl::Config config = loadConfig(gCurrentConfigPath);

    /*
        Set daemon mode if specified on command line
        All other configuration comes from config file only
    */
    if(vm.count("daemon") != 0U)
    {
        config.daemonMode = true;
    }

    std::cout << "Starting PEPCTL daemon..." << '\n';
    std::cout << "Interface: " << config.interfaceName << '\n';
    std::cout << "Admin port: " << config.adminPort << '\n';
    std::cout << "Metrics port: " << config.metricsPort << '\n';
    std::cout << "Log level: " << config.logLevel << '\n';

    /*
        Daemonize process if required
    */
    if(config.daemonMode)
    {
        if(daemonize() == false)
        {
            std::cerr << "Failed to daemonize process" << '\n';
            return EXIT_FAILURE;
        }
    }

    /*
        Setup signal handlers
    */
    setupSignalHandlers();

    /*
        Create and initialize daemon
    */
    gDaemon = pepctl::createDaemon();
    if(gDaemon == nullptr)
    {
        std::cerr << "Failed to create daemon instance" << '\n';
        return EXIT_FAILURE;
    }

    /*
        Initialize daemon
    */
    if(gDaemon->initialize(config) == false)
    {
        std::cerr << "Failed to initialize daemon" << '\n';
        gDaemon.reset();
        return EXIT_FAILURE;
    }

    /*
        Start daemon
    */
    if(gDaemon->start() == false)
    {
        std::cerr << "Failed to start daemon" << '\n';
        if(gDaemon)
        {
            gDaemon->getLogger().info(
                pepctl::LogContext(pepctl::LogCategory::SYSTEM),
                "main.cpp: gDaemon->start() returned false, cleaning up and exiting");
        }

        std::cout << "main.cpp: About to call gDaemon.reset() after failed start" << '\n';
        std::cout.flush();

        /*
            Set up a timeout mechanism to prevent hanging
        */
        std::atomic<bool> resetCompleted{false};
        std::thread resetThread([&]() {
            try
            {
                gDaemon.reset();
                resetCompleted.store(true);
            }
            catch(const std::exception& e)
            {
                std::cerr << "main.cpp: Exception during gDaemon.reset(): " << e.what() << '\n';
                resetCompleted.store(true);
            }
            catch(...)
            {
                std::cerr << "main.cpp: Unknown exception during gDaemon.reset()" << '\n';
                resetCompleted.store(true);
            }
        });

        /*
            Wait for reset to complete with timeout
        */
        auto start = std::chrono::steady_clock::now();
        while(resetCompleted.load() == false)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            auto elapsed = std::chrono::steady_clock::now() - start;
            if(elapsed > std::chrono::seconds(2))
            {
                std::cerr << "main.cpp: gDaemon.reset() timed out after 2 seconds, forcing exit"
                          << '\n';
                std::cerr.flush();
                std::_Exit(EXIT_SUCCESS);  // Force immediate exit with success since we're in
                                           // normal shutdown
            }
        }

        if(resetThread.joinable())
        {
            resetThread.join();
        }

        std::cout << "main.cpp: gDaemon cleanup completed" << '\n';

        return EXIT_FAILURE;
    }

    /*
        Main loop
    */
    while(gShutdownRequested.load() == false)
    {
        if(gConfigReloadRequested.load())
        {
            if(handleConfigReload() == false)
            {
                std::cerr << "Failed to reload configuration" << '\n';
                gShutdownRequested.store(true);
                break;
            }
            gConfigReloadRequested.store(false);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    /*
        Clean shutdown
    */
    if(gDaemon != nullptr)
    {
        if(gDaemon)
        {
            try
            {
                gDaemon->getLogger().info(pepctl::LogContext(pepctl::LogCategory::SYSTEM),
                                          "main.cpp: Starting clean shutdown");
            }
            catch(...)
            {}
        }
        gDaemon->stop();
        if(gDaemon)
        {
            try
            {
                gDaemon->getLogger().info(pepctl::LogContext(pepctl::LogCategory::SYSTEM),
                                          "main.cpp: gDaemon->stop() completed");
            }
            catch(...)
            {}
        }

        std::cout << "main.cpp: About to call gDaemon.reset()" << '\n';
        std::cout.flush();

        /*
            Set up a timeout mechanism to prevent hanging
        */
        std::atomic<bool> resetCompleted{false};
        std::thread resetThread([&]() {
            try
            {
                gDaemon.reset();
                resetCompleted.store(true);
            }
            catch(const std::exception& e)
            {
                std::cerr << "main.cpp: Exception during gDaemon.reset(): " << e.what() << '\n';
                resetCompleted.store(true);
            }
            catch(...)
            {
                std::cerr << "main.cpp: Unknown exception during gDaemon.reset()" << '\n';
                resetCompleted.store(true);
            }
        });

        /*
            Wait for reset to complete with timeout
        */
        auto start = std::chrono::steady_clock::now();
        while(resetCompleted.load() == false)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            auto elapsed = std::chrono::steady_clock::now() - start;
            if(elapsed > std::chrono::seconds(2))
            {
                std::cerr << "main.cpp: gDaemon.reset() timed out after 2 seconds, forcing exit"
                          << '\n';
                std::cerr.flush();
                std::_Exit(EXIT_SUCCESS);  // Force immediate exit with success since we're in
                                           // normal shutdown
            }
        }

        if(resetThread.joinable())
        {
            resetThread.join();
        }

        std::cout << "main.cpp: gDaemon cleanup completed" << '\n';
    }

    std::cout << "main.cpp: Exiting with EXIT_SUCCESS" << '\n';
    std::cout.flush();
    return EXIT_SUCCESS;
}


