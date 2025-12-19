#pragma once

#include <atomic>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include "core.h"
#include "policy_engine.h"


namespace pepctl
{

class Logger;

//
//   eBPF program types
enum class EbpfProgramType
{
    XDP,           // eXpress Data Path - highest performance
    TC_INGRESS,    // Traffic Control ingress
    TC_EGRESS,     // Traffic Control egress
    SOCKET_FILTER  // Socket filter
};

//
//   eBPF verdict (must match kernel definitions)
enum class EbpfVerdict : uint32_t
{
    PASS = 0,      // Allow packet to continue
    DROP = 1,      // Drop the packet
    REDIRECT = 2,  // Redirect to another interface
    TX = 3         // Retransmit packet
};

//
//   eBPF packet metadata (shared with kernel)
struct __attribute__((packed)) EbpfPacketMeta
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint32_t packet_size;
    uint64_t timestamp;
    uint32_t action;  // PolicyAction value
};

//
//   eBPF policy entry (shared with kernel)
struct __attribute__((packed)) EbpfPolicyEntry
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint32_t action;      // PolicyAction value
    uint64_t rate_limit;  // bytes per second
};

//
//   eBPF map information
struct EbpfMapInfo
{
    int fd;
    std::string name;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
};

//
//   Packet callback for userspace processing
using PacketCallback = std::function<void(const PacketInfo&)>;

//
//   Enhanced packet callback that includes eBPF action
using EbpfPacketCallback = std::function<void(const PacketInfo&, uint32_t ebpf_action)>;

//
//   Main eBPF manager class
class EbpfManager
{
  public:
    explicit EbpfManager(std::shared_ptr<Logger> logger);
    virtual ~EbpfManager();

    //
    //       Initialization and lifecycle
    //
    bool initialize(const std::string& interface_name,
                    EbpfProgramType program_type = EbpfProgramType::XDP);
    bool loadProgram(const std::string& program_path);
    bool attachProgram();
    bool detachProgram();
    void notifyProgramAttached();  // Notify instance that static attach succeeded
    void notifyProgramDetached();  // Notify instance that static detach succeeded
    void shutdown();

    //
    //       Policy synchronization with kernel
    //
    bool updatePolicyMap(const std::vector<std::shared_ptr<Policy>>& policies);
    bool addPolicyToMap(const Policy& policy);
    bool removePolicyFromMap(const std::string& policy_id);
    bool clearPolicyMap();

    //
    //       Packet processing
    //
    void setPacketCallback(PacketCallback callback);
    void setEbpfPacketCallback(EbpfPacketCallback callback);
    bool startPacketProcessing();
    void stopPacketProcessing();

    //
    //       Statistics and monitoring
    //
    struct EbpfStats
    {
        uint64_t packets_processed;
        uint64_t packets_allowed;
        uint64_t packets_blocked;
        uint64_t packets_logged;
        uint64_t packets_rate_limited;
        uint64_t map_updates;
        uint64_t map_lookup_errors;
    };

    EbpfStats getStats() const;
    void resetStats();

    //
    //       Map access
    //
    bool readPolicyMap(std::vector<EbpfPolicyEntry>& policies);
    bool getMapInfo(const std::string& map_name, EbpfMapInfo& info);

    //
    //       Interface management
    //
    bool setInterface(const std::string& interface_name);

    std::string getInterface() const 
    { 
        return m_interfaceName; 
    }

    int getInterfaceIndex() const 
    { 
      return m_interface_index;
    }

    //
    //       Program information
    //
    bool isLoaded() const 
    { 
        return m_program_loaded; 
    }

    bool isAttached() const 
    { 
        return m_program_attached; 
    }

    EbpfProgramType getProgramType() const 
    { 
        return m_programType; 
    }

  private:
    std::shared_ptr<Logger> m_logger;

    //
    //       eBPF objects
    //
    struct bpf_object* m_bpfObj{nullptr};
    struct bpf_program* m_bpf_prog{nullptr};
    struct bpf_link* m_bpf_link{nullptr};

    //
    //       Map file descriptors
    //
    int m_policy_map_fd{};
    int m_stats_map_fd{};
    struct ring_buffer* m_ring_buffer{};

    //
    //       Configuration
    //
    std::string m_interfaceName;
    int m_interface_index{};
    EbpfProgramType m_programType{EbpfProgramType::XDP};
    std::string m_program_path;

    //
    //       State
    //
    std::atomic<bool> m_program_loaded;
    std::atomic<bool> m_program_attached;
    std::atomic<bool> m_processing_active;

    //
    //       Packet processing
    //
    PacketCallback m_packet_callback;
    EbpfPacketCallback m_ebpf_packet_callback;
    std::thread m_processing_thread;
    std::atomic<bool> m_processing_running;

    //
    //       Statistics
    //
    mutable std::mutex m_statsMutex;
    EbpfStats m_stats{};

    //
    //       Private methods
    //
    bool loadMaps();
    bool verifyProgram();
    void packetProcessingLoop();
    static int handleRingBufferEvent(void* ctx, void* data, size_t data_sz);
    bool updateKernelStats();
    static int getInterfaceIndex(const std::string& interface_name);

    //
    //       Map operations
    //
    bool mapUpdatePolicy(const PolicyKey& key, const EbpfPolicyEntry& entry);
    bool mapDeletePolicy(const PolicyKey& key);
    bool mapLookupPolicy(const PolicyKey& key, EbpfPolicyEntry& entry) const;

    //
    //       Policy conversion
    //
    EbpfPolicyEntry policyToEbpfEntry(const Policy& policy) const;
    PolicyKey ebpfEntryToPolicyKey(const EbpfPolicyEntry& entry) const;

    //
    //       Utilities
    //
    void logLibbpfError(const std::string& operation);
    bool setRlimitMemlock();
};

//
//   eBPF program loader utility
class EbpfProgramLoader
{
  public:
    static bool compileProgram(const std::string& source_path,
                               const std::string& output_path,
                               const std::vector<std::string>& include_paths = {});

    static bool validateProgram(const std::string& program_path);

    static std::vector<std::string> getRequiredMaps(const std::string& program_path);

    static std::string getDefaultProgramPath(EbpfProgramType type);

  private:
    static bool runClangCommand(const std::vector<std::string>& args);
};


}  // namespace pepctl