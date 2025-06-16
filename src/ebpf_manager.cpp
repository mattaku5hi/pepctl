#include <arpa/inet.h>
#include <boost/core/ignore_unused.hpp>
#include <cstring>
#include <fstream>
#include <iostream>
#include <linux/if_link.h>
#include <net/if.h>
#include <sstream>
#include <sys/resource.h>
#include <unistd.h>
#include <utility>

#include "pepctl/ebpf_manager.h"
#include "pepctl/logger.h"


namespace pepctl
{

/*
  Global variables for static methods
*/
static struct bpf_object* sBpfObj = nullptr;
static struct bpf_program* sBpfProg = nullptr;
static struct bpf_link* sBpfLink = nullptr;
static int sPolicyMapFd = -1;
static int sStatsMapFd = -1;
static std::string sInterfaceName;
static EbpfProgramType sProgramType = EbpfProgramType::XDP;


EbpfManager::EbpfManager() :
    m_bpfObj(nullptr),
    m_bpf_prog(nullptr),
    m_bpf_link(nullptr),
    m_policy_map_fd(-1),
    m_stats_map_fd(-1),
    m_ring_buffer(nullptr),
    m_interface_index(-1),
    m_programType(EbpfProgramType::XDP),
    m_program_loaded(false),
    m_program_attached(false),
    m_processing_active(false),
    m_processing_running(false),
    m_stats{}
{
    /*
      Set memory limit for eBPF
    */
    [[maybe_unused]] bool result = setRlimitMemlock();
}

EbpfManager::~EbpfManager()
{
    shutdown();
}

auto EbpfManager::initialize(const std::string& interface_name,
                             EbpfProgramType program_type) -> bool
{
    m_interfaceName = interface_name;
    m_programType = program_type;
    sInterfaceName = interface_name;
    sProgramType = program_type;

    /*
      Get interface index
    */
    m_interface_index = getInterfaceIndex(interface_name);
    if(m_interface_index < 0)
    {
        if(gLogger != nullptr)
        {
            gLogger->error(LogContext(LogCategory::EBPF),
                           "Failed to get interface index for " + interface_name);
        }
        return false;
    }

    if(gLogger != nullptr)
    {
        gLogger->info(LogContext(LogCategory::EBPF)
                          .withField("interface", interface_name)
                          .withField("index", std::to_string(m_interface_index)),
                      "eBPF manager initialized successfully");
    }

    return true;
}

auto EbpfManager::loadProgram(const std::string& program_path) -> bool
{
    if(m_program_loaded.load())
    {
        if(gLogger != nullptr)
        {
            gLogger->warn(LogContext(LogCategory::EBPF), "Program already loaded");
        }
        return true;
    }

    m_program_path = program_path;

    /*
      Load eBPF object
    */
    m_bpfObj = bpf_object__open(program_path.c_str());
    if(m_bpfObj == nullptr)
    {
        logLibbpfError("bpf_object__open");
        return false;
    }

    sBpfObj = m_bpfObj;

    /*
      Load the eBPF program
    */
    if(bpf_object__load(m_bpfObj) != 0)
    {
        logLibbpfError("bpf_object__load");
        bpf_object__close(m_bpfObj);
        m_bpfObj = nullptr;
        sBpfObj = nullptr;
        return false;
    }

    /*
      Find the main program based on program type
    */
    const char* programName = nullptr;
    switch(m_programType)
    {
        case EbpfProgramType::XDP:
            programName = "packet_filter_modern";
            break;
        case EbpfProgramType::TC_INGRESS:
        case EbpfProgramType::TC_EGRESS:
            programName = "packet_filter_tc";
            break;
        default:
            programName = "packet_filter_modern";
            break;
    }

    m_bpf_prog = bpf_object__find_program_by_name(m_bpfObj, programName);
    if(m_bpf_prog == nullptr)
    {
        if(gLogger != nullptr)
        {
            gLogger->error(
                LogContext(LogCategory::EBPF)
                    .withField("program_name", programName)
                    .withField("program_type", std::to_string(static_cast<int>(m_programType))),
                "Failed to find eBPF program in " + program_path);
        }
        bpf_object__close(m_bpfObj);
        m_bpfObj = nullptr;
        sBpfObj = nullptr;
        return false;
    }

    sBpfProg = m_bpf_prog;

    /*
      Load maps
    */
    if(loadMaps() == false)
    {
        bpf_object__close(m_bpfObj);
        m_bpfObj = nullptr;
        sBpfObj = nullptr;
        return false;
    }

    /*
      Verify program
    */
    if(verifyProgram() == false)
    {
        bpf_object__close(m_bpfObj);
        m_bpfObj = nullptr;
        sBpfObj = nullptr;
        return false;
    }

    m_program_loaded.store(true);

    if(gLogger != nullptr)
    {
        gLogger->info(LogContext(LogCategory::EBPF).withField("path", program_path),
                      "eBPF program loaded successfully");
    }

    return true;
}

auto EbpfManager::attachProgram() -> bool
{
    if(sBpfProg == nullptr)
    {
        if(gLogger != nullptr)
        {
            gLogger->error(LogContext(LogCategory::EBPF), "No program loaded to attach");
        }
        return false;
    }

    if(sBpfLink != nullptr)
    {
        if(gLogger != nullptr)
        {
            gLogger->warn(LogContext(LogCategory::EBPF), "Program already attached");
        }
        return true;
    }

    /*
      Get interface index
    */
    int ifIndex = if_nametoindex(sInterfaceName.c_str());
    if(ifIndex == 0)
    {
        if(gLogger != nullptr)
        {
            gLogger->error(LogContext(LogCategory::EBPF),
                           "Failed to get interface index for " + sInterfaceName);
        }
        return false;
    }

    /*
      Check if TC programs are actually attached - if so, skip XDP attachment
    */
    std::string checkCmd =
        "bpftool net show dev " + sInterfaceName + " | grep -A 10 'tc:' | grep -q 'id [0-9]'";
    int tcCheck = std::system(checkCmd.c_str());
    if(tcCheck == 0 && sProgramType == EbpfProgramType::XDP)
    {
        if(gLogger != nullptr)
        {
            gLogger->info(LogContext(LogCategory::EBPF).withField("interface", sInterfaceName),
                          "TC program already attached, skipping XDP attachment");
        }
        // Create a dummy link to indicate "attached" state
        sBpfLink = reinterpret_cast<struct bpf_link*>(0x1);  // Non-null dummy value
        return true;
    }

    /*
      Attach based on program type
    */
    switch(sProgramType)
    {
        case EbpfProgramType::XDP:
        {
            /*
                Try native mode first, fallback to generic if needed
            */
            struct bpf_xdp_attach_opts opts = {};
            opts.sz = sizeof(opts);

            /*
                Try native mode first
            */
            opts.old_prog_fd = 0;
            int progFd = bpf_program__fd(sBpfProg);
            int ret = bpf_xdp_attach(ifIndex, progFd, XDP_FLAGS_DRV_MODE, &opts);

            if(ret != 0)
            {
                if(gLogger != nullptr)
                {
                    gLogger->warn(
                        LogContext(LogCategory::EBPF).withField("error", std::to_string(ret)),
                        "Failed to attach XDP in native mode, trying generic mode");
                }

                /*
                    Fallback to generic mode
                */
                ret = bpf_xdp_attach(ifIndex, progFd, XDP_FLAGS_SKB_MODE, &opts);
                if(ret != 0)
                {
                    if(gLogger != nullptr)
                    {
                        gLogger->error(LogContext(LogCategory::EBPF)
                                            .withField("error", std::to_string(ret)),
                                        "Failed to attach XDP in both native and generic modes");
                    }
                    return false;
                }

                if(gLogger != nullptr)
                {
                    gLogger->info(LogContext(LogCategory::EBPF),
                                    "XDP attached in generic mode");
                }
            }
            else
            {
                if(gLogger != nullptr)
                {
                    gLogger->info(LogContext(LogCategory::EBPF), "XDP attached in native mode");
                }
            }

            /*
                Create a dummy link to indicate successful attachment
            */
            sBpfLink = reinterpret_cast<struct bpf_link*>(0x3);  // XDP marker
            break;
        }
        case EbpfProgramType::TC_INGRESS:
        case EbpfProgramType::TC_EGRESS:
        {
            /*
                Use modern libbpf TC API
            */
            struct bpf_tc_hook hook = {};
            hook.sz = sizeof(hook);
            hook.ifindex = ifIndex;
            hook.attach_point =
                (sProgramType == EbpfProgramType::TC_INGRESS) ? BPF_TC_INGRESS : BPF_TC_EGRESS;

            /*
                Create TC hook
            */
            int ret = bpf_tc_hook_create(&hook);
            if(ret != 0 && ret != -EEXIST)
            {
                if(gLogger != nullptr)
                {
                    gLogger->error(
                        LogContext(LogCategory::EBPF).withField("error", std::to_string(ret)),
                        "Failed to create TC hook");
                }
                return false;
            }

            /*
                Attach program
            */
            struct bpf_tc_opts opts = {};
            opts.sz = sizeof(opts);
            opts.prog_fd = bpf_program__fd(sBpfProg);

            ret = bpf_tc_attach(&hook, &opts);
            if(ret != 0)
            {
                if(gLogger != nullptr)
                {
                    gLogger->error(
                        LogContext(LogCategory::EBPF).withField("error", std::to_string(ret)),
                        "Failed to attach TC program");
                }
                return false;
            }

            /*
                Store hook info for later detachment (use a dummy link)
            */
            sBpfLink = reinterpret_cast<struct bpf_link*>(0x2);  // TC marker
            break;
        }
        case EbpfProgramType::SOCKET_FILTER:
        {
            if(gLogger != nullptr)
            {
                gLogger->error(LogContext(LogCategory::EBPF),
                               "Socket filter attachment not yet implemented");
            }
            return false;
        }
    }

    if(sBpfLink == nullptr)
    {
        if(gLogger != nullptr)
        {
            gLogger->error(LogContext(LogCategory::EBPF), "Failed to attach eBPF program");
        }
        return false;
    }

    if(gLogger != nullptr)
    {
        gLogger->info(LogContext(LogCategory::EBPF)
                          .withField("interface", sInterfaceName)
                          .withField("type", std::to_string(static_cast<int>(sProgramType))),
                      "eBPF program attached successfully");
    }

    return true;
}

void EbpfManager::notifyProgramAttached()
{
    m_program_attached.store(true);
    if(gLogger != nullptr)
    {
        gLogger->debug(LogContext(LogCategory::EBPF),
                       "Instance notified of successful program attachment");
    }
}

void EbpfManager::notifyProgramDetached()
{
    m_program_attached.store(false);
    if(gLogger != nullptr)
    {
        gLogger->debug(LogContext(LogCategory::EBPF),
                       "Instance notified of successful program detachment");
    }
}

auto EbpfManager::detachProgram() -> bool
{
    if(sBpfLink == nullptr)
    {
        return true;  // Already detached
    }

    /*
      Check if this is our dummy link (TC case)
    */
    if(sBpfLink == reinterpret_cast<struct bpf_link*>(0x1))
    {
        sBpfLink = nullptr;
        if(gLogger != nullptr)
        {
            gLogger->info(LogContext(LogCategory::EBPF), "Skipped detaching (manual TC mode)");
        }
        return true;
    }

    /*
      Check if this is our XDP link
    */
    if(sBpfLink == reinterpret_cast<struct bpf_link*>(0x3))
    {
        /*
          Detach XDP program
        */
        int ifIndex = if_nametoindex(sInterfaceName.c_str());
        if(ifIndex > 0)
        {
            bpf_xdp_detach(ifIndex, 0, nullptr);
        }

        sBpfLink = nullptr;
        if(gLogger != nullptr)
        {
            gLogger->info(LogContext(LogCategory::EBPF), "XDP program detached");
        }
        return true;
    }

    /*
      Check if this is our TC link
    */
    if(sBpfLink == reinterpret_cast<struct bpf_link*>(0x2))
    {
        /*
          Detach TC program using modern API
        */
        int ifIndex = if_nametoindex(sInterfaceName.c_str());
        if(ifIndex > 0)
        {
            struct bpf_tc_hook hook = {};
            hook.sz = sizeof(hook);
            hook.ifindex = ifIndex;
            hook.attach_point =
                (sProgramType == EbpfProgramType::TC_INGRESS) ? BPF_TC_INGRESS : BPF_TC_EGRESS;

            struct bpf_tc_opts opts = {};
            opts.sz = sizeof(opts);
            opts.prog_fd = bpf_program__fd(sBpfProg);

            bpf_tc_detach(&hook, &opts);
            bpf_tc_hook_destroy(&hook);
        }

        sBpfLink = nullptr;
        if(gLogger != nullptr)
        {
            gLogger->info(LogContext(LogCategory::EBPF), "TC program detached");
        }
        return true;
    }

    [[maybe_unused]] int result = bpf_link__destroy(sBpfLink);
    sBpfLink = nullptr;

    if(gLogger != nullptr)
    {
        gLogger->info(LogContext(LogCategory::EBPF), "eBPF program detached successfully");
    }

    return true;
}

void EbpfManager::shutdown()
{
    /*
      Stop packet processing if running
    */
    stopPacketProcessing();

    /*
      Only close/free resources if they were initialized
    */
    if(m_bpfObj != nullptr)
    {
        bpf_object__close(m_bpfObj);
        m_bpfObj = nullptr;
    }
    m_bpf_prog = nullptr;
    m_bpf_link = nullptr;
    m_policy_map_fd = -1;
    m_stats_map_fd = -1;
    if(m_ring_buffer != nullptr)
    {
        ring_buffer__free(m_ring_buffer);
        m_ring_buffer = nullptr;
    }
    m_interface_index = -1;
    m_program_loaded.store(false);
    m_program_attached.store(false);
    m_processing_active.store(false);
    m_processing_running.store(false);
    m_stats = {};
    if(gLogger != nullptr)
    {
        gLogger->info(LogContext(LogCategory::EBPF), "EbpfManager shutdown complete");
    }
}

auto EbpfManager::updatePolicyMap(const std::vector<std::shared_ptr<Policy>>& policies) -> bool
{
    if(sPolicyMapFd < 0)
    {
        if(gLogger != nullptr)
        {
            gLogger->error(LogContext(LogCategory::EBPF), "Policy map not loaded");
        }
        return false;
    }

    /*
      Clear existing policies
    */
    if(clearPolicyMap() == false)
    {
        return false;
    }

    /*
      Add new policies
    */
    int successCount = 0;
    for(const auto& policy : policies)
    {
        if(policy && addPolicyToMap(*policy))
        {
            successCount++;
        }
    }

    if(gLogger != nullptr)
    {
        gLogger->info(LogContext(LogCategory::EBPF)
                          .withField("total", std::to_string(policies.size()))
                          .withField("success", std::to_string(successCount)),
                      "Policy map updated");
    }

    return successCount > 0;
}

auto EbpfManager::addPolicyToMap(const Policy& policy) -> bool
{
    if(sPolicyMapFd < 0)
    {
        return false;
    }

    /*
      Create eBPF-compatible policy key (must match eBPF program structure exactly)
    */
    struct EbpfPolicyKey
    {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t protocol;
        uint8_t pad[3];  // Padding for alignment
    } __attribute__((packed));

    struct EbpfPolicyEntry
    {
        uint32_t action;
        uint64_t rate_limit;
    } __attribute__((packed));

    EbpfPolicyKey key = {};
    key.src_ip = policy.src.ip;             // Already in network byte order from inet_aton()
    key.dst_ip = policy.dst.ip;             // Already in network byte order from inet_aton()
    key.src_port = htons(policy.src.port);  // Convert to network byte order to match packet headers
    key.dst_port = htons(policy.dst.port);  // Convert to network byte order to match packet headers
    key.protocol = static_cast<uint8_t>(policy.src.protocol);
    // pad is automatically zero-initialized

    EbpfPolicyEntry entry = {};
    entry.action = static_cast<uint32_t>(policy.action);
    entry.rate_limit = policy.rateLimitBps;

    /*
      Update map
    */
    int ret = bpf_map_update_elem(sPolicyMapFd, &key, &entry, BPF_ANY);
    if(ret != 0)
    {
        if(gLogger != nullptr)
        {
            gLogger->error(LogContext(LogCategory::EBPF)
                               .withField("policy_id", policy.id)
                               .withField("error", std::to_string(ret)),
                           "Failed to add policy to map");
        }
        return false;
    }

    if(gLogger != nullptr)
    {
        gLogger->debug(LogContext(LogCategory::EBPF)
                           .withField("policy_id", policy.id)
                           .withField("src_ip", std::to_string(key.src_ip))
                           .withField("dst_ip", std::to_string(key.dst_ip))
                           .withField("src_port", std::to_string(ntohs(key.src_port)))
                           .withField("dst_port", std::to_string(ntohs(key.dst_port)))
                           .withField("protocol", std::to_string(key.protocol))
                           .withField("action", std::to_string(entry.action)),
                       "Policy added to eBPF map");
    }

    return true;
}

auto EbpfManager::removePolicyFromMap(const std::string& policy_id) -> bool
{
    boost::ignore_unused(policy_id);

    /*
      This is a simplified implementation
      In a real system, you'd need to maintain a mapping of policy_id to PolicyKey
    */
    if(gLogger != nullptr)
    {
        gLogger->warn(LogContext(LogCategory::EBPF), "Policy removal by ID not fully implemented");
    }
    return false;
}

auto EbpfManager::clearPolicyMap() -> bool
{
    if(sPolicyMapFd < 0)
    {
        return false;
    }

    /*
      Use eBPF-compatible key structure
    */
    struct EbpfPolicyKey
    {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t protocol;
        uint8_t pad[3];
    } __attribute__((packed));

    EbpfPolicyKey key = {};
    EbpfPolicyKey nextKey{};

    /*
      Iterate through all entries and delete them
    */
    while(bpf_map_get_next_key(sPolicyMapFd, &key, &nextKey) == 0)
    {
        [[maybe_unused]] int result = bpf_map_delete_elem(sPolicyMapFd, &nextKey);
        key = nextKey;
    }

    return true;
}

void EbpfManager::setPacketCallback(PacketCallback callback)
{
    m_packet_callback = std::move(callback);
}

void EbpfManager::setEbpfPacketCallback(EbpfPacketCallback callback)
{
    m_ebpf_packet_callback = std::move(callback);
}

auto EbpfManager::startPacketProcessing() -> bool
{
    if(gLogger != nullptr)
    {
        gLogger->debug(
            LogContext(LogCategory::EBPF)
                .withField("m_program_loaded", m_program_loaded.load() ? "true" : "false")
                .withField("m_program_attached", m_program_attached.load() ? "true" : "false")
                .withField("m_processing_active", m_processing_active.load() ? "true" : "false")
                .withField("interface", m_interfaceName)
                .withField("program_path", m_program_path),
            "Attempting to start packet processing");
    }
    if(m_processing_active.load())
    {
        if(gLogger != nullptr)
        {
            gLogger->warn(LogContext(LogCategory::EBPF), "Packet processing already active");
        }
        return true;
    }

    if(!m_program_loaded.load() || !m_program_attached.load())
    {
        if(gLogger != nullptr)
        {
            gLogger->error(
                LogContext(LogCategory::EBPF)
                    .withField("m_program_loaded", m_program_loaded.load() ? "true" : "false")
                    .withField("m_program_attached", m_program_attached.load() ? "true" : "false")
                    .withField("interface", m_interfaceName)
                    .withField("program_path", m_program_path),
                "Cannot start processing: program not loaded or attached");
        }
        return false;
    }

    m_processing_running.store(true);
    m_processing_active.store(true);
    m_processing_thread = std::thread(&EbpfManager::packetProcessingLoop, this);

    if(gLogger != nullptr)
    {
        gLogger->info(LogContext(LogCategory::EBPF), "Packet processing started");
    }

    return true;
}

void EbpfManager::stopPacketProcessing()
{
    if(!m_processing_active.load())
    {
        return;
    }

    m_processing_running.store(false);
    if(m_processing_thread.joinable())
    {
        m_processing_thread.join();
    }
    m_processing_active.store(false);

    if(gLogger != nullptr)
    {
        gLogger->info(LogContext(LogCategory::EBPF), "Packet processing stopped");
    }
}

auto EbpfManager::getStats() const -> EbpfManager::EbpfStats
{
    /*
      Update stats from kernel before returning
    */
    const_cast<EbpfManager*>(this)->updateKernelStats();

    std::lock_guard<std::mutex> lock(m_statsMutex);
    return m_stats;
}

void EbpfManager::resetStats()
{
    std::lock_guard<std::mutex> lock(m_statsMutex);
    m_stats = {};
}

auto EbpfManager::readPolicyMap(std::vector<EbpfPolicyEntry>& policies) -> bool
{
    if(sPolicyMapFd < 0)
    {
        return false;
    }

    policies.clear();
    PolicyKey key = {};
    PolicyKey nextKey{};
    EbpfPolicyEntry entry{};

    /*
      Iterate through all entries
    */
    while(bpf_map_get_next_key(sPolicyMapFd, &key, &nextKey) == 0)
    {
        if(bpf_map_lookup_elem(sPolicyMapFd, &nextKey, &entry) == 0)
        {
            policies.push_back(entry);
        }
        key = nextKey;
    }

    return true;
}

auto EbpfManager::getMapInfo(const std::string& map_name, EbpfMapInfo& info) -> bool
{
    if(sBpfObj == nullptr)
    {
        return false;
    }

    struct bpf_map* map = bpf_object__find_map_by_name(sBpfObj, map_name.c_str());
    if(map == nullptr)
    {
        return false;
    }

    info.fd = bpf_map__fd(map);
    info.name = map_name;
    info.key_size = bpf_map__key_size(map);
    info.value_size = bpf_map__value_size(map);
    info.max_entries = bpf_map__max_entries(map);

    return true;
}

auto EbpfManager::setInterface(const std::string& interface_name) -> bool
{
    m_interfaceName = interface_name;
    sInterfaceName = interface_name;
    m_interface_index = getInterfaceIndex(interface_name);
    return m_interface_index >= 0;
}

auto EbpfManager::loadMaps() -> bool
{
    if(m_bpfObj == nullptr)
    {
        return false;
    }

    /*
      Load policy map
    */
    struct bpf_map* policyMap = bpf_object__find_map_by_name(m_bpfObj, "policy_map");
    if(policyMap != nullptr)
    {
        m_policy_map_fd = bpf_map__fd(policyMap);
        sPolicyMapFd = m_policy_map_fd;
    }

    /*
      Load stats map
    */
    struct bpf_map* statsMap = bpf_object__find_map_by_name(m_bpfObj, "stats_map");
    if(statsMap != nullptr)
    {
        m_stats_map_fd = bpf_map__fd(statsMap);
        sStatsMapFd = m_stats_map_fd;
    }

    /*
      Set up ring buffer for packet events
    */
    struct bpf_map* packetEventsMap = bpf_object__find_map_by_name(m_bpfObj, "packet_events");
    if(packetEventsMap != nullptr)
    {
        int ringFd = bpf_map__fd(packetEventsMap);
        m_ring_buffer = ring_buffer__new(ringFd, handleRingBufferEvent, this, nullptr);
        if(m_ring_buffer == nullptr)
        {
            if(gLogger != nullptr)
            {
                gLogger->error(LogContext(LogCategory::EBPF), "Failed to create ring buffer");
            }
            return false;
        }
    }

    if(gLogger != nullptr)
    {
        gLogger->info(
            LogContext(LogCategory::EBPF)
                .withField("policy_fd", std::to_string(m_policy_map_fd))
                .withField("stats_fd", std::to_string(m_stats_map_fd))
                .withField("ring_buffer", (m_ring_buffer != nullptr) ? "initialized" : "null"),
            "eBPF maps loaded");
    }

    return m_policy_map_fd >= 0;  // At least policy map should be available
}

auto EbpfManager::verifyProgram() -> bool
{
    if(m_bpf_prog == nullptr)
    {
        return false;
    }

    /*
      Basic verification - check if program loaded successfully
    */
    int progFd = bpf_program__fd(m_bpf_prog);
    if(progFd < 0)
    {
        if(gLogger != nullptr)
        {
            gLogger->error(LogContext(LogCategory::EBPF), "Invalid program file descriptor");
        }
        return false;
    }

    return true;
}

void EbpfManager::packetProcessingLoop()
{
    if(m_ring_buffer == nullptr)
    {
        if(gLogger != nullptr)
        {
            gLogger->error(LogContext(LogCategory::EBPF), "Ring buffer not initialized");
        }
        return;
    }

    while(m_processing_running.load())
    {
        /*
          Poll ring buffer for events (timeout: 100ms)
        */
        int ret = ring_buffer__poll(m_ring_buffer, 100);
        if(ret < 0 && ret != -EINTR)
        {
            if(gLogger != nullptr)
            {
                gLogger->error(
                    LogContext(LogCategory::EBPF).withField("error", std::to_string(ret)),
                    "Ring buffer poll failed");
            }
            break;
        }
    }
}

int EbpfManager::handleRingBufferEvent(void* ctx, void* data, size_t data_sz)
{
    auto* manager = static_cast<EbpfManager*>(ctx);

    /*
      Define kernel packet metadata structure (must match eBPF program)
    */
    struct PacketMetadata
    {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t protocol;
        uint32_t packet_size;
        uint64_t timestamp;
        uint32_t action;
    } __attribute__((packed));

    if((manager == nullptr) || (data == nullptr) || data_sz < sizeof(PacketMetadata))
    {
        return 0;
    }

    /*
      Cast the data to our packet metadata structure
    */
    auto* meta = static_cast<PacketMetadata*>(data);

    /*
      Convert to PacketInfo
    */
    PacketInfo packet;
    packet.src.ip = meta->src_ip;
    packet.src.port = meta->src_port;
    packet.src.protocol = static_cast<Protocol>(meta->protocol);
    packet.dst.ip = meta->dst_ip;
    packet.dst.port = meta->dst_port;
    packet.dst.protocol = static_cast<Protocol>(meta->protocol);
    packet.size = meta->packet_size;
    packet.timestamp = std::chrono::system_clock::from_time_t(meta->timestamp / 1000000000);
    packet.interfaceName = manager->m_interfaceName;

    /*
      Use enhanced callback if available, otherwise fall back to regular callback
    */
    if(manager->m_ebpf_packet_callback)
    {
        manager->m_ebpf_packet_callback(packet, meta->action);
    }
    else if(manager->m_packet_callback)
    {
        manager->m_packet_callback(packet);
    }

    /*
      Update statistics
    */
    {
        std::lock_guard<std::mutex> lock(manager->m_statsMutex);
        manager->m_stats.packets_processed++;
    }

    return 0;
}

auto EbpfManager::updateKernelStats() -> bool
{
    if(m_stats_map_fd < 0)
    {
        return false;
    }

    /*
      Define the eBPF stats structure (must match kernel definition)
    */
    struct EbpfStats
    {
        uint64_t packets_processed;
        uint64_t packets_allowed;
        uint64_t packets_blocked;
        uint64_t packets_logged;
        uint64_t packets_rate_limited;
        uint64_t map_lookup_errors;
    };

    uint32_t key = 0;  // Single entry in the array map

    /*
      Get number of CPUs to allocate per-CPU values array
    */
    int numCpus = libbpf_num_possible_cpus();
    if(numCpus <= 0)
    {
        if(gLogger != nullptr)
        {
            gLogger->error(LogContext(LogCategory::EBPF), "Failed to get number of CPUs");
        }
        return false;
    }

    /*
      Allocate array for per-CPU values
    */
    std::vector<EbpfStats> cpuStats(numCpus);

    /*
      Read per-CPU statistics from the map
    */
    int ret = bpf_map_lookup_elem(m_stats_map_fd, &key, cpuStats.data());
    if(ret != 0)
    {
        if(gLogger != nullptr)
        {
            gLogger->debug(LogContext(LogCategory::EBPF)
                               .withField("error", std::to_string(ret))
                               .withField("errno", std::to_string(errno)),
                           "Failed to read stats from eBPF map");
        }
        return false;
    }

    /*
      Aggregate statistics across all CPUs
    */
    EbpfStats totalStats = {};
    for(int cpu = 0; cpu < numCpus; cpu++)
    {
        totalStats.packets_processed += cpuStats[cpu].packets_processed;
        totalStats.packets_allowed += cpuStats[cpu].packets_allowed;
        totalStats.packets_blocked += cpuStats[cpu].packets_blocked;
        totalStats.packets_logged += cpuStats[cpu].packets_logged;
        totalStats.packets_rate_limited += cpuStats[cpu].packets_rate_limited;
        totalStats.map_lookup_errors += cpuStats[cpu].map_lookup_errors;
    }

    /*
      Update userspace statistics
    */
    {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        m_stats.packets_processed = totalStats.packets_processed;
        m_stats.packets_allowed = totalStats.packets_allowed;
        m_stats.packets_blocked = totalStats.packets_blocked;
        m_stats.packets_logged = totalStats.packets_logged;
        m_stats.packets_rate_limited = totalStats.packets_rate_limited;
        m_stats.map_lookup_errors = totalStats.map_lookup_errors;
        /*
          Keep existing map_updates value as it's userspace-only
        */
    }

    if(gLogger != nullptr)
    {
        gLogger->debug(
            LogContext(LogCategory::EBPF)
                .withField("cpus", std::to_string(numCpus))
                .withField("packets_processed", std::to_string(totalStats.packets_processed))
                .withField("packets_allowed", std::to_string(totalStats.packets_allowed))
                .withField("packets_blocked", std::to_string(totalStats.packets_blocked))
                .withField("packets_logged", std::to_string(totalStats.packets_logged))
                .withField("packets_rate_limited", std::to_string(totalStats.packets_rate_limited))
                .withField("map_lookup_errors", std::to_string(totalStats.map_lookup_errors)),
            "Updated eBPF statistics from kernel");
    }

    return true;
}

auto EbpfManager::getInterfaceIndex(const std::string& interface_name) -> int
{
    return if_nametoindex(interface_name.c_str());
}

void EbpfManager::logLibbpfError(const std::string& operation)
{
    if(gLogger != nullptr)
    {
        gLogger->error(LogContext(LogCategory::EBPF)
                           .withField("operation", operation)
                           .withField("errno", std::to_string(errno)),
                       "libbpf operation failed");
    }
}

auto EbpfManager::setRlimitMemlock() -> bool
{
    struct rlimit rlimNew = 
    {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if(setrlimit(RLIMIT_MEMLOCK, &rlimNew) != 0)
    {
        if(gLogger != nullptr)
        {
            gLogger->warn(LogContext(LogCategory::EBPF), "Failed to increase RLIMIT_MEMLOCK");
        }
        return false;
    }

    return true;
}

auto EbpfProgramLoader::compileProgram(const std::string& source_path,
                                       const std::string& output_path,
                                       const std::vector<std::string>& include_paths) -> bool
{
    std::vector<std::string> args = {
        "clang", "-O2", "-target", "bpf", "-c", source_path, "-o", output_path};

    for(const auto& includePath : include_paths)
    {
        args.push_back("-I" + includePath);
    }

    return runClangCommand(args);
}

auto EbpfProgramLoader::validateProgram(const std::string& program_path) -> bool
{
    /*
      Try to open and load the program
    */
    struct bpf_object* obj = bpf_object__open(program_path.c_str());
    if(obj == nullptr)
    {
        return false;
    }

    int ret = bpf_object__load(obj);
    bpf_object__close(obj);

    return ret == 0;
}

auto EbpfProgramLoader::getRequiredMaps(const std::string& program_path) -> std::vector<std::string>
{
    std::vector<std::string> maps;

    struct bpf_object* obj = bpf_object__open(program_path.c_str());
    if(obj == nullptr)
    {
        return maps;
    }

    struct bpf_map* map = nullptr;
    bpf_object__for_each_map(map, obj)
    {
        maps.push_back(bpf_map__name(map));
    }

    bpf_object__close(obj);
    return maps;
}

auto EbpfProgramLoader::getDefaultProgramPath(EbpfProgramType type) -> std::string
{
    switch(type)
    {
        case EbpfProgramType::XDP:
            return "ebpf/packet_filter.o";
        case EbpfProgramType::TC_INGRESS:
            return "ebpf/tc_ingress_filter.o";
        case EbpfProgramType::TC_EGRESS:
            return "ebpf/tc_egress_filter.o";
        case EbpfProgramType::SOCKET_FILTER:
            return "ebpf/socket_filter.o";
        default:
            return "";
    }
}

auto EbpfProgramLoader::runClangCommand(const std::vector<std::string>& args) -> bool
{
    std::ostringstream cmd;
    for(size_t i = 0; i < args.size(); ++i)
    {
        if(i > 0)
        {
            cmd << " ";
        }
        cmd << args[i];
    }

    int ret = std::system(cmd.str().c_str());
    return ret == 0;
}


}  // namespace pepctl