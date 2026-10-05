#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "util/bytes.hpp"
#include "util/checksum.hpp"

namespace flag {
    constexpr uint8_t FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08,
                      ACK = 0x10, URG = 0x20, ECE = 0x40, CWR = 0x80;
}

struct TcpHeader
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  hdr_len;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
    bool has(uint8_t f) const { return (flags & f) != 0; }
};


struct TcpView
{
    TcpHeader header;
    std::span<const uint8_t> options;
    std::span<const uint8_t> payload;
};

inline uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip, std::span<const uint8_t> segment) {
    uint8_t ph[12];
    write_big_endian_32(ph, 0, src_ip);
    write_big_endian_32(ph, 4, dst_ip);
    ph[8] = 0;
    ph[9] = 6;
    write_big_endian_16(ph, 10, uint16_t(segment.size()));
    uint32_t sum = csum_add(0, ph);
    sum = csum_add(sum, segment);
    return csum_finish(sum);
}

inline std::optional<TcpView> parse_tcp(uint32_t src_ip, uint32_t dst_ip, std::span<const uint8_t> seg) {
    if (seg.size() < 20) return std::nullopt;
    TcpHeader h{};
    h.src_port = read_big_endian_16(seg, 0);
    h.dst_port = read_big_endian_16(seg, 2);
    h.seq      = read_big_endian_32(seg, 4);
    h.ack      = read_big_endian_32(seg, 8);
    h.hdr_len  = (seg[12] >> 4) * 4;
    h.flags    = seg[13];
    h.window   = read_big_endian_16(seg, 14);
    h.checksum = read_big_endian_16(seg, 16);
    h.urgent   = read_big_endian_16(seg, 18);

    if (h.hdr_len < 20 || h.hdr_len > seg.size()) return std::nullopt;
    if (tcp_checksum(src_ip, dst_ip, seg) != 0) return std::nullopt;

    return TcpView { h, seg.subspan(20, h.hdr_len - 20), seg.subspan(h.hdr_len) };
}

inline std::vector<uint8_t> build_tcp(uint32_t src_ip, uint32_t dst_ip, const TcpHeader& h,
                                      std::span<const uint8_t> payload) {
    std::vector<uint8_t> s(20 + payload.size());
    write_big_endian_16(s, 0, h.src_port);
    write_big_endian_16(s, 2, h.dst_port);
    write_big_endian_32(s, 4, h.seq);
    write_big_endian_32(s, 8, h.ack);
    s[12] = 5 << 4;
    s[13] = h.flags;
    write_big_endian_16(s, 14, h.window);
    write_big_endian_16(s, 16, 0);
    write_big_endian_16(s, 18, 0);

    std::copy(payload.begin(), payload.end(), s.begin() + 20);
    write_big_endian_16(s, 16, tcp_checksum(src_ip, dst_ip, s));
    return s;
}