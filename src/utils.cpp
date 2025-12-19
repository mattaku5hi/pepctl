#include <iostream>
#include <sstream>
#include <stdexcept>

#include <arpa/inet.h>
#include <pepctl/core.h>

namespace pepctl {

//
//   Utility function implementations
auto policyActionToString(PolicyAction action) -> std::string
{
    switch(action)
    {
        case PolicyAction::ALLOW:
            return "ALLOW";
        case PolicyAction::BLOCK:
            return "BLOCK";
        case PolicyAction::LOG_ONLY:
            return "LOG_ONLY";
        case PolicyAction::RATE_LIMIT:
            return "RATE_LIMIT";
        default:
            return "UNKNOWN";
    }
}

auto stringToPolicyAction(const std::string& str) -> PolicyAction
{
    if(str == "ALLOW")
    {
        return PolicyAction::ALLOW;
    }
    if(str == "BLOCK")
    {
        return PolicyAction::BLOCK;
    }
    if(str == "LOG_ONLY")
    {
        return PolicyAction::LOG_ONLY;
    }
    if(str == "RATE_LIMIT")
    {
        return PolicyAction::RATE_LIMIT;
    }
    throw std::invalid_argument("Unknown policy action: " + str);
}

auto protocolToString(Protocol proto) -> std::string
{
    switch(proto)
    {
        case Protocol::TCP:
            return "TCP";
        case Protocol::UDP:
            return "UDP";
        case Protocol::ICMP:
            return "ICMP";
        case Protocol::ANY:
            return "ANY";
        default:
            return "UNKNOWN";
    }
}

auto stringToProtocol(const std::string& str) -> Protocol
{
    if(str == "TCP")
    {
        return Protocol::TCP;
    }
    if(str == "UDP")
    {
        return Protocol::UDP;
    }
    if(str == "ICMP")
    {
        return Protocol::ICMP;
    }
    if(str == "ANY")
    {
        return Protocol::ANY;
    }
    throw std::invalid_argument("Unknown protocol: " + str);
}

auto ipStringToUint32(const std::string& ip_str) -> uint32_t
{
    struct in_addr addr
    {};

    if(inet_aton(ip_str.c_str(), &addr) == 0)
    {
        throw std::invalid_argument("Invalid IP address: " + ip_str);
    }
    return addr.s_addr;
}

auto uint32ToIpString(uint32_t ip) -> std::string
{
    struct in_addr addr
    {};

    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

//
//   NetworkAddress member functions
auto NetworkAddress::toString() const -> std::string
{
    return uint32ToIpString(ip) + ":" + std::to_string(port);
}


}  // namespace pepctl