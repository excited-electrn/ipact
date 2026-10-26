#include <cstdio>
#include "io/tun_device.hpp"
#include "net/ipv4.hpp"

std::optional<std::vector<uint8_t>> handle_icmp(const Ipv4View&, uint16_t&);

constexpr uint32_t OUR_IP = (10u << 24) | 2;    // 10.0.0.2

int main() {
    TunDevice tun("tun0");
    std::vector<uint8_t> buf(65535);
    uint16_t ip_id = 1;

    for (;;) {
        ssize_t n = tun.read_packet(buf);
        if (n <= 0) break;
        auto ip = parse_ipv4(std::span<const uint8_t>(buf.data(), size_t(n)));
        if (!ip) continue;                                   // malformed: silently drop
        if (ip->h.dst != OUR_IP) continue;                   // not for us

        switch (ip->h.protocol) {
            case uint8_t(IpProto::ICMP):
                if (auto out = handle_icmp(*ip, ip_id)) tun.write_packet(*out);
                break;
            case uint8_t(IpProto::TCP):
                std::printf("TCP segment, %zu bytes (not implemented yet)\n", ip->payload.size());
                break;
            default: break;
        }
    }
}
