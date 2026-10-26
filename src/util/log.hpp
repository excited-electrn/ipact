#pragma once
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

// Debug logging, switched on with the environment variable IPACT_LOG=1 (any value works).
inline bool log_enabled() {
    static const bool on = std::getenv("IPACT_LOG") != nullptr;
    return on;
}
#define LOG(...)                                   \
    do {                                           \
        if (log_enabled()) {                       \
            std::fprintf(stderr, __VA_ARGS__);     \
            std::fputc('\n', stderr);              \
        }                                          \
    } while (0)

// 0x0A000002 -> "10.0.0.2"
inline std::string ip_to_string(uint32_t ip) {
    return std::to_string(ip >> 24) + "." + std::to_string((ip >> 16) & 255) + "." +
           std::to_string((ip >> 8) & 255) + "." + std::to_string(ip & 255);
}
