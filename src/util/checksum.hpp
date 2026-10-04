#pragma once
#include <cstdint>
#include <span>

inline uint32_t csum_add(uint32_t sum, std::span<const uint8_t> data) {
	size_t i = 0;
	for (; i+1 < data.size(); i += 2) {
		sum += (uint32_t(data[i]) << 8) | data[i+1]; 
	}

	if (i < data.size()) {
		sum += uint32_t(data[i]) << 8;
	}

	return sum;
}

inline uint16_t csum_finish(uint32_t sum) {
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	return static_cast<uint16_t>(~sum);
}

inline uint16_t internet_checksum(std::span<const uint8_t> data) {
	return csum_finish(csum_add(0, data));
}
