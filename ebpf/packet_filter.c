/*
 * Modern eBPF XDP packet filter using proper kernel headers
 * Uses vmlinux.h (BTF-generated) + libbpf helpers
 */

/*
    It must go first
*/
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Only define constants that are missing from vmlinux.h
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800  // IPv4 Ethernet frame type
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#ifndef ETH_HLEN
#define ETH_HLEN 14  // Ethernet header length
#endif

#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6 41
#endif

// TC action definitions (if not in vmlinux.h)
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

// Policy actions (application-specific)
#define POLICY_ALLOW 0
#define POLICY_BLOCK 1
#define POLICY_LOG_ONLY 2
#define POLICY_RATE_LIMIT 3

// Policy key structure for our application
struct policy_key
{
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 pad[3];  // Padding for alignment
};

// Policy entry structure
struct policy_entry
{
    __u32 action;
    __u64 rate_limit;
};

// Statistics structure
struct ebpf_stats
{
    __u64 packets_processed;
    __u64 packets_allowed;
    __u64 packets_blocked;
    __u64 packets_logged;
    __u64 packets_rate_limited;
    __u64 map_lookup_errors;
};

// Packet metadata structure for userspace
struct packet_metadata
{
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u32 packet_size;
    __u64 timestamp;
    __u32 action;
};

// BPF maps using standard libbpf syntax
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct policy_key);
    __type(value, struct policy_entry);
    __uint(max_entries, 10000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct ebpf_stats);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stats_map SEC(".maps");

// Ring buffer for sending packet metadata to userspace
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB ring buffer
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} packet_events SEC(".maps");

// Packet parsing function for XDP using standard kernel structures
static __always_inline int parse_packet_xdp(struct xdp_md* ctx, struct policy_key* key)
{
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    // Parse Ethernet header using standard struct ethhdr
    struct ethhdr* eth = data;
    if((void*)(eth + 1) > data_end)
        return -1;

    // Only handle IPv4 packets
    __u16 h_proto = bpf_ntohs(eth->h_proto);
    __u64 l3_offset = sizeof(*eth);
    if(h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD)
    {
        void* vlan = (void*)((char*)data + l3_offset);
        if((void*)((char*)vlan + 4) > data_end)
        {
            return -1;
        }
        h_proto = bpf_ntohs(*(__be16*)((char*)vlan + 2));
        l3_offset += 4;
    }
    if(h_proto == ETH_P_IPV6)
    {
        key->src_ip = 0;
        key->dst_ip = 0;
        key->protocol = IPPROTO_IPV6;
        key->src_port = 0;
        key->dst_port = 0;

        // Explicitly zero padding for consistent hash lookup
        key->pad[0] = 0;
        key->pad[1] = 0;
        key->pad[2] = 0;

        return 0;
    }
    if(h_proto != ETH_P_IP)
        return -1;

    // Parse IP header using standard struct iphdr
    struct iphdr* ip = (void*)((char*)data + l3_offset);
    if((void*)(ip + 1) > data_end)
    {
        return -1;
    }
    if(ip->ihl < 5)
    {
        return -1;
    }

    // Extract IP information
    key->src_ip = ip->saddr;
    key->dst_ip = ip->daddr;
    key->protocol = ip->protocol;
    key->src_port = 0;
    key->dst_port = 0;

    // Explicitly zero padding for consistent hash lookup
    key->pad[0] = 0;
    key->pad[1] = 0;
    key->pad[2] = 0;

    // Extract port information for TCP/UDP using standard headers
    __u16 frag_off = bpf_ntohs(ip->frag_off);
    if((frag_off & 0x1FFF) != 0 || (frag_off & 0x2000) != 0)
        return 0;

    void* l4_hdr = (void*)((char*)ip + (ip->ihl * 4));
    if(l4_hdr > data_end)
        return 0;

    if(ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr* tcp = l4_hdr;
        if((void*)(tcp + 1) > data_end)
            return 0;  // Continue without ports
        key->src_port = tcp->source;
        key->dst_port = tcp->dest;
    }
    else if(ip->protocol == IPPROTO_UDP)
    {
        struct udphdr* udp = l4_hdr;
        if((void*)(udp + 1) > data_end)
            return 0;  // Continue without ports
        key->src_port = udp->source;
        key->dst_port = udp->dest;
    }

    return 0;
}

// Update statistics helper
static __always_inline void update_stat(__u32 stat_type)
{
    __u32 key = 0;
    struct ebpf_stats* stats = bpf_map_lookup_elem(&stats_map, &key);
    if(stats != NULL)
    {
        switch(stat_type)
        {
            case 0:
                __sync_fetch_and_add(&stats->packets_processed, 1);
                break;
            case 1:
                __sync_fetch_and_add(&stats->packets_allowed, 1);
                break;
            case 2:
                __sync_fetch_and_add(&stats->packets_blocked, 1);
                break;
            case 3:
                __sync_fetch_and_add(&stats->packets_logged, 1);
                break;
            case 4:
                __sync_fetch_and_add(&stats->packets_rate_limited, 1);
                break;
            case 5:
                __sync_fetch_and_add(&stats->map_lookup_errors, 1);
                break;
        }
    }
}

// Main XDP program
SEC("xdp")

int packet_filter_modern(struct xdp_md* ctx)
{
    struct policy_key key = {};

    // Update processed packets counter
    update_stat(0);

    // Parse packet using standard kernel structures
    if(parse_packet_xdp(ctx, &key) < 0)
    {
        // Failed to parse packet, allow it to pass
        update_stat(1);  // packets_allowed
        return XDP_PASS;
    }

    // Look up policy for this packet - try multiple keys for wildcard matching
    struct policy_entry* policy = NULL;
    __u32 action = POLICY_ALLOW;  // Default action

    // Try exact match first
    policy = bpf_map_lookup_elem(&policy_map, &key);

    if(policy == NULL)
    {
        // Try wildcard source IP (0.0.0.0)
        struct policy_key wildcard_src_key = key;
        wildcard_src_key.src_ip = 0;
        policy = bpf_map_lookup_elem(&policy_map, &wildcard_src_key);
    }

    if(policy == NULL)
    {
        // Try wildcard destination IP (0.0.0.0)
        struct policy_key wildcard_dst_key = key;
        wildcard_dst_key.dst_ip = 0;
        policy = bpf_map_lookup_elem(&policy_map, &wildcard_dst_key);
    }

    if(policy == NULL)
    {
        // Try wildcard both IPs
        struct policy_key wildcard_both_key = key;
        wildcard_both_key.src_ip = 0;
        wildcard_both_key.dst_ip = 0;
        policy = bpf_map_lookup_elem(&policy_map, &wildcard_both_key);
    }

    if(policy == NULL)
    {
        // Try wildcard source port (0)
        struct policy_key wildcard_src_port_key = key;
        wildcard_src_port_key.src_port = 0;
        policy = bpf_map_lookup_elem(&policy_map, &wildcard_src_port_key);
    }

    if(policy == NULL)
    {
        // Try wildcard destination port (0)
        struct policy_key wildcard_dst_port_key = key;
        wildcard_dst_port_key.dst_port = 0;
        policy = bpf_map_lookup_elem(&policy_map, &wildcard_dst_port_key);
    }

    if(policy == NULL)
    {
        // Try wildcard both ports
        struct policy_key wildcard_ports_key = key;
        wildcard_ports_key.src_port = 0;
        wildcard_ports_key.dst_port = 0;
        policy = bpf_map_lookup_elem(&policy_map, &wildcard_ports_key);
    }

    if(policy == NULL)
    {
        // Try full wildcard (0.0.0.0:0 -> 0.0.0.0:0)
        struct policy_key wildcard_all_key = {};
        wildcard_all_key.protocol = key.protocol;  // Keep protocol matching
        policy = bpf_map_lookup_elem(&policy_map, &wildcard_all_key);
    }

    if(policy != NULL)
    {
        action = policy->action;
    }

    // Send packet metadata to userspace for processing
    struct packet_metadata* event = bpf_ringbuf_reserve(&packet_events, sizeof(*event), 0);
    if(event != NULL)
    {
        event->src_ip = key.src_ip;
        event->dst_ip = key.dst_ip;
        event->src_port = key.src_port;
        event->dst_port = key.dst_port;
        event->protocol = key.protocol;
        event->packet_size = ctx->data_end - ctx->data;
        event->timestamp = bpf_ktime_get_ns();
        event->action = action;

        bpf_ringbuf_submit(event, 0);
    }

    // Execute action
    switch(action)
    {
        case POLICY_ALLOW:
            update_stat(1);  // packets_allowed
            return XDP_PASS;

        case POLICY_LOG_ONLY:
            update_stat(3);  // packets_logged
            return XDP_PASS;

        case POLICY_RATE_LIMIT:
            update_stat(4);   // packets_rate_limited
            return XDP_PASS;  // Let userspace handle rate limiting

        case POLICY_BLOCK:
            update_stat(2);  // packets_blocked
            return XDP_DROP;

        default:
            update_stat(5);  // map_lookup_errors
            update_stat(1);  // packets_allowed (default to allow)
            return XDP_PASS;
    }
}

// Packet parsing function for TC using standard kernel structures
static __always_inline int parse_packet_tc(struct __sk_buff* skb, struct policy_key* key)
{
    void* data_end = (void*)(long)skb->data_end;
    void* data = (void*)(long)skb->data;

    // Parse Ethernet header using standard struct ethhdr
    struct ethhdr* eth = data;
    if((void*)(eth + 1) > data_end)
        return -1;

    // Only handle IPv4 packets
    __u16 h_proto = bpf_ntohs(eth->h_proto);
    __u64 l3_offset = sizeof(*eth);
    if(h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD)
    {
        void* vlan = (void*)((char*)data + l3_offset);
        if((void*)((char*)vlan + 4) > data_end)
            return -1;
        h_proto = bpf_ntohs(*(__be16*)((char*)vlan + 2));
        l3_offset += 4;
    }
    if(h_proto == ETH_P_IPV6)
    {
        key->src_ip = 0;
        key->dst_ip = 0;
        key->protocol = IPPROTO_IPV6;
        key->src_port = 0;
        key->dst_port = 0;

        // Explicitly zero padding for consistent hash lookup
        key->pad[0] = 0;
        key->pad[1] = 0;
        key->pad[2] = 0;

        return 0;
    }
    if(h_proto != ETH_P_IP)
        return -1;

    // Parse IP header using standard struct iphdr
    struct iphdr* ip = (void*)((char*)data + l3_offset);
    if((void*)(ip + 1) > data_end)
    {
        return -1;
    }
    if(ip->ihl < 5)
    {
        return -1;
    }

    // Extract IP information
    key->src_ip = ip->saddr;
    key->dst_ip = ip->daddr;
    key->protocol = ip->protocol;
    key->src_port = 0;
    key->dst_port = 0;

    // Explicitly zero padding for consistent hash lookup
    key->pad[0] = 0;
    key->pad[1] = 0;
    key->pad[2] = 0;

    // Extract port information for TCP/UDP using standard headers
    void* l4_hdr = (void*)ip + (ip->ihl * 4);

    if(ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr* tcp = l4_hdr;
        if((void*)(tcp + 1) > data_end)
        {
            return 0; // Continue without ports
        }
        key->src_port = tcp->source;
        key->dst_port = tcp->dest;
    }
    else if(ip->protocol == IPPROTO_UDP)
    {
        struct udphdr* udp = l4_hdr;
        if((void*)(udp + 1) > data_end)
        {
            return 0;  // Continue without ports
        }
        key->src_port = udp->source;
        key->dst_port = udp->dest;
    }

    return 0;
}

// Main TC program
SEC("tc")

int packet_filter_tc(struct __sk_buff* skb)
{
    struct policy_key key = {};

    // Update processed packets counter
    update_stat(0);

    // Parse packet using standard kernel structures
    if(parse_packet_tc(skb, &key) < 0)
    {
        // Failed to parse packet, allow it to pass
        update_stat(1);  // packets_allowed
        return TC_ACT_OK;
    }

    // Look up policy for this packet - try multiple keys for wildcard matching
    struct policy_entry* policy = NULL;
    __u32 action = POLICY_ALLOW;  // Default action

    // Try exact match first
    policy = bpf_map_lookup_elem(&policy_map, &key);

    if(policy == NULL)
    {
        // Try wildcard source IP (0.0.0.0)
        struct policy_key wildcard_src_key = key;
        wildcard_src_key.src_ip = 0;
        policy = bpf_map_lookup_elem(&policy_map, &wildcard_src_key);
    }

    if(policy == NULL)
    {
        // Try wildcard destination IP (0.0.0.0)
        struct policy_key wildcard_dst_key = key;
        wildcard_dst_key.dst_ip = 0;
        policy = bpf_map_lookup_elem(&policy_map, &wildcard_dst_key);
    }

    if(policy == NULL)
    {
        // Try wildcard both IPs
        struct policy_key wildcard_both_key = key;
        wildcard_both_key.src_ip = 0;
        wildcard_both_key.dst_ip = 0;
        policy = bpf_map_lookup_elem(&policy_map, &wildcard_both_key);
    }

    if(policy == NULL)
    {
        // Try wildcard source port (0)
        struct policy_key wildcard_src_port_key = key;
        wildcard_src_port_key.src_port = 0;
        policy = bpf_map_lookup_elem(&policy_map, &wildcard_src_port_key);
    }

    if(policy == NULL)
    {
        // Try wildcard destination port (0)
        struct policy_key wildcard_dst_port_key = key;
        wildcard_dst_port_key.dst_port = 0;
        policy = bpf_map_lookup_elem(&policy_map, &wildcard_dst_port_key);
    }

    if(policy == NULL)
    {
        // Try wildcard both ports
        struct policy_key wildcard_ports_key = key;
        wildcard_ports_key.src_port = 0;
        wildcard_ports_key.dst_port = 0;
        policy = bpf_map_lookup_elem(&policy_map, &wildcard_ports_key);
    }

    if(policy == NULL)
    {
        // Try full wildcard (0.0.0.0:0 -> 0.0.0.0:0)
        struct policy_key wildcard_all_key = {};
        wildcard_all_key.protocol = key.protocol;  // Keep protocol matching
        policy = bpf_map_lookup_elem(&policy_map, &wildcard_all_key);
    }

    if(policy != NULL)
    {
        action = policy->action;
    }

    // Send packet metadata to userspace for processing
    struct packet_metadata* event = bpf_ringbuf_reserve(&packet_events, sizeof(*event), 0);
    if(event != NULL)
    {
        event->src_ip = key.src_ip;
        event->dst_ip = key.dst_ip;
        event->src_port = key.src_port;
        event->dst_port = key.dst_port;
        event->protocol = key.protocol;
        event->packet_size = skb->data_end - skb->data;
        event->timestamp = bpf_ktime_get_ns();
        event->action = action;

        bpf_ringbuf_submit(event, 0);
    }

    // Execute action
    switch(action)
    {
        case POLICY_ALLOW:
            update_stat(1);  // packets_allowed
            return TC_ACT_OK;

        case POLICY_LOG_ONLY:
            update_stat(3);  // packets_logged
            return TC_ACT_OK;

        case POLICY_RATE_LIMIT:
            update_stat(4);    // packets_rate_limited
            return TC_ACT_OK;  // Let userspace handle rate limiting

        case POLICY_BLOCK:
            update_stat(2);      // packets_blocked
            return TC_ACT_SHOT;  // Drop the packet

        default:
            update_stat(5);  // map_lookup_errors
            update_stat(1);  // packets_allowed (default to allow)
            return TC_ACT_OK;
    }
}

char _license[] SEC("license") = "GPL";