#pragma once
#include <cstdint>
#include <functional>

struct ConnKey {
    uint32_t local_ip;
    uint32_t remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
    bool operator==(const ConnKey&) const = default;
};

template<> struct std::hash<ConnKey> {
    size_t operator()(const ConnKey& k) const noexcept {
        uint64_t a = (uint64_t(k.local_ip) << 32) | k.remote_ip;
        uint64_t b = (uint64_t(k.local_port) << 16) | k.remote_port;
        return std::hash<uint64_t>{}(a * 0x9E3779B97F4A7C15ull ^ b);
    }
};
