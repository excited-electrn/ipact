#pragma once
#include <cstdint>
#include <optional>
#include <algorithm>
#include <span>
#include <vector>
#include "util/bytes.hpp"
#include "util/checksum.hpp"

enum class IpProto : uint8_t { ICMP = 1, TCP = 6, UDP = 17 };

struct Ipv4Header {
    uint8_t  ihl_bytes;        // header length in BYTES (already multiplied by 4)
    uint8_t  dscp_ecn;
    uint16_t total_len;
    uint16_t id;
    bool     dont_fragment;
    bool     more_fragments;
    uint16_t frag_offset;      // in 8-byte units
    uint8_t  ttl;
    uint8_t  protocol;
    uint32_t src;              // host byte order, e.g. 10.0.0.2 = 0x0A000002
    uint32_t dst;
};

struct Ipv4View {
    Ipv4Header h;
    std::span<const uint8_t> payload;   // bytes after the IP header, trimmed to total_len
};

inline std::optional<Ipv4View> parse_ipv4(std::span<const uint8_t> pkt) {
    if (pkt.size() < 20) return std::nullopt;                  // too short for a header
    uint8_t ver = pkt[0] >> 4;
    uint8_t ihl = pkt[0] & 0x0F;
    if (ver != 4 || ihl < 5) return std::nullopt;
    size_t hlen = size_t(ihl) * 4;
    if (pkt.size() < hlen) return std::nullopt;

    Ipv4Header h{};
    h.ihl_bytes      = uint8_t(hlen);
    h.dscp_ecn       = pkt[1];
    h.total_len      = read_be16(pkt, 2);
    h.id             = read_be16(pkt, 4);
    uint16_t ff      = read_be16(pkt, 6);
    h.dont_fragment  = ff & 0x4000;
    h.more_fragments = ff & 0x2000;
    h.frag_offset    = ff & 0x1FFF;
    h.ttl            = pkt[8];
    h.protocol       = pkt[9];
    h.src            = read_be32(pkt, 12);
    h.dst            = read_be32(pkt, 16);

    if (h.total_len < hlen || h.total_len > pkt.size()) return std::nullopt;   // lying length
    if (internet_checksum(pkt.first(hlen)) != 0) return std::nullopt;          // corrupted header
    if (h.more_fragments || h.frag_offset != 0) return std::nullopt;           // no fragments (for now)

    return Ipv4View{h, pkt.subspan(hlen, h.total_len - hlen)};
}

// Build a packet: 20-byte header (no options) + payload.
inline std::vector<uint8_t> build_ipv4(uint32_t src, uint32_t dst, IpProto proto,
                                       std::span<const uint8_t> payload, uint16_t id) {
    std::vector<uint8_t> p(20 + payload.size());
    p[0] = 0x45;                                   // version 4, IHL 5
    p[1] = 0;
    write_be16(p, 2, uint16_t(p.size()));          // total length
    write_be16(p, 4, id);
    write_be16(p, 6, 0x4000);                      // DF set, no fragmentation
    p[8] = 64;                                     // TTL
    p[9] = uint8_t(proto);
    write_be16(p, 10, 0);                          // checksum placeholder = 0
    write_be32(p, 12, src);
    write_be32(p, 16, dst);
    write_be16(p, 10, internet_checksum(std::span<const uint8_t>(p).first(20)));
    std::copy(payload.begin(), payload.end(), p.begin() + 20);
    return p;
}
