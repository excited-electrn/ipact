#pragma once
#include <cstdint>
#include <span>
#include <arpa/inet.h>   // htons, ntohs, htonl, ntohl

// Way 1: C library helpers (fine for single fields)
//   uint16_t wire_port = htons(80);      // host -> network
//   uint16_t host_port = ntohs(wire);    // network -> host

// Way 2 (preferred): read/write big-endian values directly from a byte buffer.
// No alignment problems, no struct-padding surprises, works on any CPU.
inline uint16_t read_be16(std::span<const uint8_t> b, size_t off) {
    return static_cast<uint16_t>((b[off] << 8) | b[off + 1]);
}
inline uint32_t read_be32(std::span<const uint8_t> b, size_t off) {
    return (uint32_t(b[off]) << 24) | (uint32_t(b[off + 1]) << 16) |
           (uint32_t(b[off + 2]) << 8) | uint32_t(b[off + 3]);
}
inline void write_be16(std::span<uint8_t> b, size_t off, uint16_t v) {
    b[off] = uint8_t(v >> 8);
    b[off + 1] = uint8_t(v);
}
inline void write_be32(std::span<uint8_t> b, size_t off, uint32_t v) {
    b[off]     = uint8_t(v >> 24);
    b[off + 1] = uint8_t(v >> 16);
    b[off + 2] = uint8_t(v >> 8);
    b[off + 3] = uint8_t(v);
}
