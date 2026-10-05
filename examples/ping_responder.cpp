#include <cstdio>

#include "io/tun_device.hpp"
#include "net/ipv4.hpp"
#include "net/icmp.hpp"
#include "tcp/header.hpp"

constexpr uint32_t OUR_IP = (10u << 24) | 2; //10.0.0.2

int main() {
	TunDevice tun("tun0");
	std::vector<uint8_t> buf(65535);
	uint16_t ip_id = 1;

	for (;;) {
		ssize_t n = tun.read_packet(buf);
		if (n <= 0) break;

		auto ip = parse_ipv4(std::span<const uint8_t>(buf.data(), size_t(n)));
		if (!ip) continue;
		if (ip->header.dst != OUR_IP) continue;

		switch(ip->header.protocol) {
			case uint8_t(IpProto::ICMP):
				if (auto out = handle_icmp(*ip, ip_id)) tun.write_packet(*out);
				break;
			case uint8_t(IpProto::TCP): {
				auto t = parse_tcp(ip->header.src, ip->header.dst, ip->payload);
				if (!t) { std::printf("TCP: parse failed (%zu bytes)\n", ip->payload.size()); break; }
				const auto& h = t->header;
				std::printf("TCP %u -> %u seq=%u ack=%u hdr=%u win=%u flags=%s%s%s%s%s opts=%zu payload=%zu\n",
					h.src_port, h.dst_port, h.seq, h.ack, h.hdr_len, h.window,
					h.has(flag::SYN) ? "S" : "", h.has(flag::ACK) ? "A" : "",
					h.has(flag::FIN) ? "F" : "", h.has(flag::RST) ? "R" : "",
					h.has(flag::PSH) ? "P" : "",
					t->options.size(), t->payload.size());
				break;
			}
			default:
				break;
		}
	}
}
