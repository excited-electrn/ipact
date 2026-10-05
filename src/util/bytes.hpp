#pragma once
#include <cstdint>
#include <span>
#include <arpa/inet.h>

inline uint16_t read_big_endian_16(std::span<const uint8_t> buf, size_t offset) {
	return static_cast<uint16_t>((buf[offset] << 8) | buf[offset + 1]);
}

inline uint32_t read_big_endian_32(std::span<const uint8_t> buf, size_t offset) {
	return  (uint32_t(buf[offset]) << 24) | (uint32_t(buf[offset+1]) << 16) |
			(uint32_t(buf[offset+2]) << 8) | (uint32_t(buf[offset+3]));
}

inline void write_big_endian_16(std::span<uint8_t> buf, size_t offset, uint16_t val) {
	buf[offset] = uint8_t(val >> 8);
	buf[offset + 1] = uint8_t(val);
}

inline void write_big_endian_32(std::span<uint8_t> buf, size_t offset, uint32_t val) {
	buf[offset] = uint8_t(val >> 24);
	buf[offset + 1] = uint8_t(val >> 16);
	buf[offset + 2] = uint8_t(val >> 8);
	buf[offset + 3] = uint8_t(val);
}



