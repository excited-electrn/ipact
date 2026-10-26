#include <algorithm>
#include <optional>
#include <vector>
#include "net/ipv4.hpp"

// Returns a complete IP packet to send back, or nullopt if we have nothing to say.
std::optional<std::vector<uint8_t>> handle_icmp(const Ipv4View& ip, uint16_t& ip_id_counter) {
    auto msg = ip.payload;
    if (msg.size() < 8) return std::nullopt;
    if (internet_checksum(msg) != 0) return std::nullopt;   // corrupted: drop
    if (msg[0] != 8 || msg[1] != 0) return std::nullopt;    // only Echo Request for now

    std::vector<uint8_t> reply(msg.begin(), msg.end());     // identifier, seq, data copied as-is
    reply[0] = 0;                                           // type: echo reply
    write_be16(reply, 2, 0);                                // zero checksum before computing
    write_be16(reply, 2, internet_checksum(reply));

    // Swap addresses: reply goes from their destination (us) to their source.
    return build_ipv4(ip.h.dst, ip.h.src, IpProto::ICMP, reply, ip_id_counter++);
}
