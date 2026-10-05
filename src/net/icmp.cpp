#include "icmp.hpp"

std::optional<std::vector<uint8_t>> handle_icmp(const Ipv4View& ip, uint16_t& ip_id_counter) {
	auto msg = ip.payload;
	if (msg.size() < 8) return std::nullopt;
	if (internet_checksum(msg) != 0) return std::nullopt;
	if (msg[0] != 8 || msg[1] != 0) return std::nullopt;

	std::vector<uint8_t> reply(msg.begin(), msg.end());
	reply[0] = 0;
	write_big_endian_16(reply, 2, 0);
	write_big_endian_16(reply, 2, internet_checksum(reply));

	return build_ipv4(ip.header.dst, ip.header.src, IpProto::ICMP, reply, ip_id_counter++);
}