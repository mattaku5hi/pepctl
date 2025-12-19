# PEPCTL eBPF Internals Documentation

## Table of Contents
- [Overview](#overview)
- [eBPF Architecture](#ebpf-architecture)
- [XDP Processing Pipeline](#xdp-processing-pipeline)
- [eBPF Maps Deep Dive](#ebpf-maps-deep-dive)
- [Packet Processing Logic](#packet-processing-logic)
- [Kernel-Userspace Communication](#kernel-userspace-communication)
- [Performance Optimizations](#performance-optimizations)
- [Debugging and Monitoring](#debugging-and-monitoring)

## Overview

PEPCTL leverages eBPF (extended Berkeley Packet Filter) technology to provide high-performance packet filtering directly in the Linux kernel. This document explains the internal workings of the eBPF components.

### Why eBPF?

eBPF provides several advantages over traditional userspace packet processing:

- **Zero-copy packet processing**: No memory copies between kernel and userspace
- **Bypass network stack**: XDP hooks process packets before the full network stack
- **CPU efficiency**: Direct execution in kernel space
- **Atomic operations**: Lock-free data structures with per-CPU maps
- **Safety**: eBPF verifier ensures memory safety and bounded execution

## eBPF Architecture

### Component Overview

```
┌─────────────── Userspace ───────────────┐
│                                         │
│  ┌─────────────┐    ┌─────────────┐     │
│  │ PEPCTL      │    │ BPF Tools   │     │
│  │ Daemon      │    │ (bpftool)   │     │
│  └─────────────┘    └─────────────┘     │
│         │                   │           │
│         │ libbpf API       │ syscalls  │
│         │                   │           │
└─────────│───────────────────│───────────┘
          │                   │
┌─────────│───────────────────│───────────┐
│         │                   │           │
│  ┌──────▼──────┐     ┌──────▼──────┐    │
│  │ eBPF Maps   │     │ eBPF Progs  │    │
│  │ - policy_map│     │ - packet_   │    │
│  │ - stats_map │     │   filter.o  │    │
│  │ - ring_buf  │     │             │    │
│  └─────────────┘     └─────────────┘    │
│                                         │
│                Kernel Space             │
└─────────────────────────────────────────┘
```

### File Structure

```
ebpf/
├── packet_filter.c     # Main XDP program
├── common.h           # Shared structs and constants
└── CMakeLists.txt     # Build configuration
```

## XDP Processing Pipeline

### Hook Points

XDP (eXpress Data Path) provides the earliest hook point for packet processing:

```
Network Interface → Driver → XDP Hook → Network Stack
                              │
                         packet_filter.c
                         (eBPF Program)
                              │
                         [XDP_PASS|XDP_DROP|XDP_TX|XDP_REDIRECT]
```

### XDP Return Codes

| Return Code | Action | Use Case |
|-------------|--------|----------|
| `XDP_PASS` | Continue to network stack | Allowed packets |
| `XDP_DROP` | Drop packet immediately | Blocked packets |
| `XDP_TX` | Transmit back on same interface | Traffic reflection |
| `XDP_REDIRECT` | Redirect to another interface | Load balancing |

### Processing Modes

1. **Native XDP**: Best performance, requires driver support
2. **Generic XDP**: Fallback mode, works with any driver
3. **Offloaded XDP**: Hardware acceleration (SmartNICs)

PEPCTL attempts native mode first, falls back to generic if needed.

## eBPF Maps Deep Dive

### Map Types and Usage

#### 1. Policy Map (BPF_MAP_TYPE_HASH)

**Purpose**: Store packet filtering policies for O(1) lookup

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct policy_key);
    __type(value, struct policy_action);
} policy_map SEC(".maps");
```

**Key Structure**:
```c
struct policy_key {
    __u32 src_ip;      // Source IP (0 = any)
    __u32 dst_ip;      // Destination IP (0 = any)
    __u16 src_port;    // Source port (0 = any)
    __u16 dst_port;    // Destination port (0 = any)
    __u8  protocol;    // TCP/UDP/ICMP (0 = any)
};
```

**Value Structure**:
```c
struct policy_action {
    __u32 action;          // ALLOW/BLOCK/RATE_LIMIT
    __u32 rate_limit;      // Bytes per second (for rate limiting)
    __u64 last_update;     // Timestamp for rate limiting
    __u64 byte_count;      // Accumulated bytes
};
```

#### 2. Statistics Map (BPF_MAP_TYPE_PERCPU_ARRAY)

**Purpose**: Collect per-CPU statistics for lock-free performance

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct packet_stats);
} stats_map SEC(".maps");
```

**Statistics Structure**:
```c
struct packet_stats {
    __u64 packets_total;     // Total packets processed
    __u64 packets_allowed;   // Packets allowed
    __u64 packets_blocked;   // Packets blocked
    __u64 bytes_total;       // Total bytes processed
    __u64 policy_lookups;    // Policy map lookups
    __u64 parse_errors;      // Packet parsing errors
};
```

#### 3. Ring Buffer (BPF_MAP_TYPE_RINGBUF)

**Purpose**: Asynchronous communication from kernel to userspace

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024); // 64KB buffer
} ring_buffer SEC(".maps");
```

**Event Structure**:
```c
struct packet_event {
    __u32 timestamp;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  action_taken;    // What action was applied
    __u16 packet_size;
};
```

### Map Access From Userspace

The userspace daemon interacts with maps through file descriptors:

```cpp
// Policy map operations
int policy_fd = bpf_object__find_map_fd_by_name(obj, "policy_map");

// Add policy
struct policy_key key = {.src_ip = src_ip, .dst_port = dst_port};
struct policy_action action = {.action = BLOCK};
bpf_map_update_elem(policy_fd, &key, &action, BPF_ANY);

// Statistics collection
int stats_fd = bpf_object__find_map_fd_by_name(obj, "stats_map");
struct packet_stats stats[num_cpus];
bpf_map_lookup_elem(stats_fd, &key, stats);
```

## Packet Processing Logic

### Main Processing Function

```c
SEC("xdp")
int packet_filter(struct xdp_md *ctx)
{
    // 1. Parse packet headers
    struct packet_info pkt;
    if (parse_packet(ctx, &pkt) != 0) {
        update_stats(STAT_PARSE_ERRORS);
        return XDP_PASS; // Let kernel handle malformed packets
    }
    
    // 2. Policy lookup
    struct policy_key key = {
        .src_ip = pkt.src_ip,
        .dst_ip = pkt.dst_ip,
        .src_port = pkt.src_port,
        .dst_port = pkt.dst_port,
        .protocol = pkt.protocol
    };
    
    struct policy_action *action = bpf_map_lookup_elem(&policy_map, &key);
    
    // 3. Apply default policy if no match
    if (!action) {
        action = get_default_policy();
    }
    
    // 4. Execute action
    int result = execute_action(action, &pkt);
    
    // 5. Update statistics
    update_stats_for_action(result, pkt.size);
    
    // 6. Optional: Send event to userspace
    if (result == XDP_DROP) {
        send_block_event(&pkt);
    }
    
    return result;
}
```

### Header Parsing

The packet parser extracts relevant information from network headers:

```c
static int parse_packet(struct xdp_md *ctx, struct packet_info *pkt)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return -1;
    
    // Skip non-IP packets
    if (eth->h_proto != htons(ETH_P_IP))
        return 0;
    
    // IP header
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return -1;
    
    pkt->src_ip = ip->saddr;
    pkt->dst_ip = ip->daddr;
    pkt->protocol = ip->protocol;
    pkt->size = ntohs(ip->tot_len);
    
    // Parse transport layer headers
    if (ip->protocol == IPPROTO_TCP) {
        return parse_tcp(ip, data_end, pkt);
    } else if (ip->protocol == IPPROTO_UDP) {
        return parse_udp(ip, data_end, pkt);
    }
    
    return 0;
}
```

### Policy Matching Algorithm

PEPCTL uses a hierarchical policy matching system:

1. **Exact Match**: All fields match exactly
2. **Wildcard Match**: Some fields are wildcards (0)
3. **Default Policy**: Fallback when no policies match

```c
static struct policy_action* lookup_policy(struct packet_info *pkt)
{
    struct policy_key keys[] = {
        // Exact match
        {pkt->src_ip, pkt->dst_ip, pkt->src_port, pkt->dst_port, pkt->protocol},
        // Source IP + destination port
        {pkt->src_ip, 0, 0, pkt->dst_port, pkt->protocol},
        // Destination IP + port
        {0, pkt->dst_ip, 0, pkt->dst_port, pkt->protocol},
        // Port only
        {0, 0, 0, pkt->dst_port, pkt->protocol},
        // IP only
        {pkt->src_ip, 0, 0, 0, 0},
        // Protocol only
        {0, 0, 0, 0, pkt->protocol}
    };
    
    for (int i = 0; i < ARRAY_SIZE(keys); i++) {
        struct policy_action *action = bpf_map_lookup_elem(&policy_map, &keys[i]);
        if (action) {
            return action;
        }
    }
    
    return NULL; // Use default policy
}
```

### Rate Limiting Implementation

Rate limiting uses a token bucket algorithm implemented in eBPF:

```c
static int apply_rate_limit(struct policy_action *action, struct packet_info *pkt)
{
    __u64 now = bpf_ktime_get_ns();
    __u64 time_diff = now - action->last_update;
    
    // Add tokens based on time elapsed
    __u64 tokens_to_add = (time_diff * action->rate_limit) / 1000000000ULL;
    action->byte_count = max(0, action->byte_count - tokens_to_add);
    
    // Check if packet can pass
    if (action->byte_count + pkt->size <= action->rate_limit) {
        action->byte_count += pkt->size;
        action->last_update = now;
        return XDP_PASS;
    }
    
    return XDP_DROP; // Exceed rate limit
}
```

## Kernel-Userspace Communication

### Ring Buffer Events

The eBPF program sends events to userspace via ring buffer:

```c
static void send_block_event(struct packet_info *pkt)
{
    struct packet_event *event = bpf_ringbuf_reserve(&ring_buffer, 
                                                    sizeof(*event), 0);
    if (!event)
        return;
    
    event->timestamp = bpf_ktime_get_ns() / 1000000; // Convert to milliseconds
    event->src_ip = pkt->src_ip;
    event->dst_ip = pkt->dst_ip;
    event->src_port = pkt->src_port;
    event->dst_port = pkt->dst_port;
    event->protocol = pkt->protocol;
    event->action_taken = ACTION_BLOCK;
    event->packet_size = pkt->size;
    
    bpf_ringbuf_submit(event, 0);
}
```

### Userspace Event Processing

The daemon processes ring buffer events asynchronously:

```cpp
void EbpfManager::processRingBufferEvents() {
    auto callback = [](void *ctx, void *data, size_t size) -> int {
        auto *event = static_cast<packet_event*>(data);
        auto *manager = static_cast<EbpfManager*>(ctx);
        
        // Log blocked packet
        spdlog::warn("Blocked packet: {}:{} -> {}:{} ({})", 
                    inet_ntoa({event->src_ip}), event->src_port,
                    inet_ntoa({event->dst_ip}), event->dst_port,
                    protocol_to_string(event->protocol));
        
        // Update metrics
        manager->updateMetrics(event);
        
        return 0;
    };
    
    ring_buffer__consume(ring_buf_, callback, this);
}
```

### Map Updates from Userspace

Policy updates are synchronized from userspace to eBPF maps:

```cpp
bool EbpfManager::addPolicy(const Policy& policy) {
    struct policy_key key = {
        .src_ip = policy.src_ip,
        .dst_ip = policy.dst_ip,
        .src_port = policy.src_port,
        .dst_port = policy.dst_port,
        .protocol = policy.protocol
    };
    
    struct policy_action action = {
        .action = static_cast<uint32_t>(policy.action),
        .rate_limit = policy.rate_limit,
        .last_update = 0,
        .byte_count = 0
    };
    
    int ret = bpf_map_update_elem(policy_fd_, &key, &action, BPF_ANY);
    if (ret != 0) {
        spdlog::error("Failed to add policy to eBPF map: {}", strerror(errno));
        return false;
    }
    
    spdlog::info("Added policy to eBPF map: {}", policy.id);
    return true;
}
```

## Performance Optimizations

### Per-CPU Maps

Statistics use per-CPU maps to avoid lock contention:

```c
// Each CPU has its own stats counter
struct packet_stats *stats = bpf_map_lookup_elem(&stats_map, &cpu_key);
if (stats) {
    __sync_fetch_and_add(&stats->packets_total, 1);
    __sync_fetch_and_add(&stats->bytes_total, pkt_size);
}
```

Userspace aggregates per-CPU values:

```cpp
uint64_t EbpfManager::getTotalPackets() {
    uint64_t total = 0;
    uint32_t key = STAT_PACKETS_TOTAL;
    
    struct packet_stats stats[num_cpus_];
    if (bpf_map_lookup_elem(stats_fd_, &key, stats) == 0) {
        for (int i = 0; i < num_cpus_; i++) {
            total += stats[i].packets_total;
        }
    }
    
    return total;
}
```

### Memory Access Patterns

eBPF programs optimize memory access:

```c
// Bounds checking required by eBPF verifier
static inline int safe_memcpy(void *dst, void *src, size_t size, void *data_end) {
    if (src + size > data_end)
        return -1;
    
    __builtin_memcpy(dst, src, size);
    return 0;
}
```

### Compiler Optimizations

The eBPF build uses aggressive optimization:

```cmake
set(BPF_CFLAGS
    -O2                    # Optimization level
    -target bpf           # eBPF target
    -g                    # Debug info for BTF
    -Wall -Wextra         # Warnings
    -fno-stack-protector  # No stack protection
)
```

## Debugging and Monitoring

### BPF Tool Commands

```bash
# Show loaded programs
sudo bpftool prog show

# Show program details
sudo bpftool prog show id <prog_id> --pretty

# Show maps
sudo bpftool map show

# Dump map contents
sudo bpftool map dump id <map_id>

# Show network attachments
sudo bpftool net show

# Generate program CFG
sudo bpftool prog dump xlated id <prog_id> visual &> cfg.dot
dot -Tpng cfg.dot -o cfg.png
```

### Verifier Logs

Enable eBPF verifier logs for debugging:

```cpp
// Load program with verifier logs
struct bpf_object_open_opts opts = {
    .sz = sizeof(opts),
    .kernel_log_level = 1,
    .kernel_log_buf = log_buf,
    .kernel_log_size = sizeof(log_buf),
};

struct bpf_object *obj = bpf_object__open_file("packet_filter.o", &opts);
```

### Performance Profiling

Use `perf` to profile eBPF programs:

```bash
# Sample eBPF program execution
sudo perf record -e cycles -g --call-graph=dwarf -a sleep 10

# Analyze results
sudo perf report
```

### Statistics Monitoring

Monitor eBPF performance through statistics:

```cpp
void EbpfManager::printStatistics() {
    auto stats = getStatistics();
    
    spdlog::info("eBPF Statistics:");
    spdlog::info("  Packets processed: {}", stats.packets_total);
    spdlog::info("  Packets allowed: {}", stats.packets_allowed);
    spdlog::info("  Packets blocked: {}", stats.packets_blocked);
    spdlog::info("  Policy lookups: {}", stats.policy_lookups);
    spdlog::info("  Parse errors: {}", stats.parse_errors);
    
    double block_rate = (double)stats.packets_blocked / stats.packets_total * 100;
    spdlog::info("  Block rate: {:.2f}%", block_rate);
}
```

## Troubleshooting

### Common Issues

1. **XDP Attachment Failure**
   - Check interface supports XDP
   - Try generic mode if native fails
   - Verify privileges (CAP_BPF, CAP_NET_ADMIN)

2. **Map Update Failures**
   - Check map size limits
   - Verify key/value structure alignment
   - Monitor memory usage

3. **Performance Issues**
   - Use per-CPU maps for statistics
   - Minimize map lookups in fast path
   - Optimize packet parsing logic

4. **Verifier Rejection**
   - Ensure all memory accesses are bounds-checked
   - Limit loop iterations
   - Use proper return codes

### Debug Workflow

1. Check eBPF program load: `bpftool prog show`
2. Verify map creation: `bpftool map show`
3. Monitor statistics: Check userspace metrics
4. Analyze verifier logs: Enable kernel log level
5. Use tracing: Add bpf_trace_printk() calls
6. Performance profiling: Use perf tools 