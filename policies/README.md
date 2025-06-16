# PEPCTL Policy Files

This directory contains all PEPCTL policy files organized by environment.

## Available Policy Sets

### `production.json`
Production-ready policies for real-world deployment:
- **ALLOW**: SSH (22), HTTP (80), HTTPS (443), PEPCTL admin/metrics
- **LOG_ONLY**: DNS queries (53)
- **BLOCK**: Telnet (23)
-️ **RATE_LIMIT**: FTP (21)

### `development.json`
Development policies with enhanced logging:
- **ALLOW**: SSH (22), PEPCTL admin/metrics
- **LOG_ONLY**: HTTP (80), HTTPS (443), ICMP
- Focus on observability and debugging

### `testing.json`
Testing policies to demonstrate all packet categories:
- **ALLOW**: SSH (22), PEPCTL admin/metrics
- **BLOCK**: Telnet (23)
- **LOG_ONLY**: HTTP (80)
-️ **RATE_LIMIT**: HTTPS (443)
- Uses wildcard IPs (0.0.0.0) for broader matching

### `loopback.json`
Loopback-specific policies for local testing:
- **ALLOW**: SSH (22), ICMP ping, PEPCTL admin/metrics
- **LOG_ONLY**: HTTP (80)
- All policies use 127.0.0.1 for loopback traffic

## Policy Structure

Each policy follows this structure:

```json
{
"id": "unique_policy_identifier",
"action": "ALLOW|BLOCK|LOG_ONLY|RATE_LIMIT",
"src": {
"ip": "source_ip_or_0.0.0.0_for_wildcard",
"port": "source_port_or_0_for_any",
"protocol": "TCP|UDP|ICMP"
},
"dst": {
"ip": "destination_ip_or_0.0.0.0_for_wildcard",
"port": "destination_port",
"protocol": "TCP|UDP|ICMP"
}
}
```

## Packet Categories

### ALLOW
- Packets are allowed to pass through
- Counted in `packets_allowed` metric
- Default action for unmatched packets

### BLOCK
- Packets are dropped by eBPF program
- Counted in `packets_blocked` metric
- Returns `XDP_DROP` or `TC_ACT_SHOT`

### LOG_ONLY
- Packets are allowed to pass but logged
- Counted in `packets_logged` metric
- Useful for monitoring and analysis

###️ RATE_LIMIT
- Packets are rate limited (implementation dependent)
- Counted in `packets_rate_limited` metric
- Can be combined with userspace rate limiting

## Usage Examples

```bash
# Test all categories
./scripts/test_categories.sh

# View current policies via API
curl http://localhost:8080/policies

# Monitor metrics
curl http://localhost:9090/metrics | grep packets_
```

## Wildcard Matching

The eBPF program supports wildcard matching:
- **IP**: Use `0.0.0.0` to match any IP
- **Port**: Use `0` to match any port
- **Protocol**: Must be specified (TCP=6, UDP=17, ICMP=1)

## Best Practices

1. **Specific to General**: Order policies from most specific to most general
2. **Always Allow Admin**: Ensure PEPCTL admin/metrics ports are always allowed
3. **Test First**: Use testing environment before production deployment
4. **Monitor Logs**: Check logs for policy match information 