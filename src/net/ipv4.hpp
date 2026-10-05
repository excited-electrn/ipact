#pragma once
#include <cstdint>
#include <optional>
#include <algorithm>
#include <span>
#include <vector>

#include "util/bytes.hpp"
#include "util/checksum.hpp"

enum class IpProto : uint8_t {
	ICMP = 1,
	TCP = 6,
	UDP = 17,
};

struct Ipv4Header {
	uint8_t  ihl_bytes;
	uint8_t  dscp_ecn;
	uint16_t total_len;
	uint16_t id;
	bool	 dont_fragment;
	bool	 more_fragments;
	uint16_t frag_offset;
	uint8_t  ttl;
	uint8_t  protocol;
	uint32_t src;
	uint32_t dst;
};

struct Ipv4View {
	Ipv4Header header;
	std::span<const uint8_t> payload;
};


inline std::optional<Ipv4View> parse_ipv4(std::span<const uint8_t> pkt) {
	if (pkt.size() < 20) return std::nullopt;
	uint8_t ver = pkt[0] >> 4;
	uint8_t ihl = pkt[0] & 0x0F;

	// std::printf("IP Version : %u \n", ver);

	if (ver != 4 || ihl < 5) return std::nullopt;
	size_t hlen = ihl * 4;
	if (pkt.size() < hlen) return std::nullopt;

	Ipv4Header h;
	h.ihl_bytes	 	 = (uint8_t)hlen;
	h.dscp_ecn  	 = pkt[1];
	h.total_len 	 = read_big_endian_16(pkt, 2);
	h.id 			 = read_big_endian_16(pkt, 4);
	uint16_t ff 	 = read_big_endian_16(pkt, 6);
	h.dont_fragment	 = ff & 0x4000;
	h.more_fragments = ff & 0x2000;
	h.frag_offset 	 = ff & 0x1FFF;
	h.ttl 			 = pkt[8];
	h.protocol 		 = pkt[9];
	h.src 			 = read_big_endian_32(pkt, 12);
	h.dst 			 = read_big_endian_32(pkt, 16);

	if (h.total_len < hlen || h.total_len > pkt.size()) {
		// std::printf("IPv4 parse: length missmatch : %u, %u\n", (h.total_len < hlen), (h.total_len > pkt.size()));
		// std::printf("IPv4 parse: length total %hu, hlen %zu, pkt %zu \n", h.total_len, hlen, pkt.size());
		return std::nullopt;
	}

	if (internet_checksum(pkt.first(hlen)) != 0) {
		// std::printf("IPv4 parse: checksum mismatch\n");
		return std::nullopt;
	}

	if (h.more_fragments || h.frag_offset != 0) {
		// std::printf("IPv4 parse: frag mismatch\n");
		return std::nullopt;
	}

	return Ipv4View{h, pkt.subspan(hlen, h.total_len - hlen)};
}

inline std::vector<uint8_t> build_ipv4(uint32_t src, uint32_t dst, IpProto proto,
										std::span<const uint8_t> payload, uint16_t id) {
	std::vector<uint8_t> p(20 + payload.size());
	p[0] = 0x45;
	p[1] = 0;
	write_big_endian_16(p, 2, uint16_t(p.size()));
	write_big_endian_16(p, 4, id);
	write_big_endian_16(p, 6, 0x4000);
	p[8] = 64;
	p[9] = uint8_t(proto);
	write_big_endian_16(p, 10, 0);
	write_big_endian_32(p, 12, src);
	write_big_endian_32(p, 16, dst);
	write_big_endian_16(p, 10, internet_checksum(std::span<const uint8_t>(p).first(20)));
	std::copy(payload.begin(), payload.end(), p.begin() + 20);
	return p;
}
