#pragma once
#include <cstdint>
#include <span>

// Running (not yet complemented) ones'-complement sum. Splitting this from the final
// step lets you checksum several buffers in a row, e.g. TCP pseudo-header + segment.
inline uint32_t csum_add(uint32_t sum, std::span<const uint8_t> data) {
    size_t i = 0;
    for (; i + 1 < data.size(); i += 2)
        sum += (uint32_t(data[i]) << 8) | data[i + 1];      // big-endian 16-bit word
    if (i < data.size())
        sum += uint32_t(data[i]) << 8;                       // odd byte: pad with a zero low byte
    return sum;
}

inline uint16_t csum_finish(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);    // fold carries
    return static_cast<uint16_t>(~sum);
}

inline uint16_t internet_checksum(std::span<const uint8_t> data) {
    return csum_finish(csum_add(0, data));
}
// Unit test it! Known vector: the header in the widget above must give 0xb861.
