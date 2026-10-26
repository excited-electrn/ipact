#pragma once
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

// Debug logging, IPACT_LOG=1
inline bool log_enabled() {
    static const bool on = std::getenv("IPACT_LOG") != nullptr;
    return on;
}

#define LOG(...) \
    do { \
        if (log_enabled()) { \
            std::fprintf(stderr, __VA_ARGS__); \
            std::fputc('\n', stderr); \
        } \
    } while (0) \


inline std::string ip_to_string(uint32_t ip) {
    return std::to_string(ip >> 24) + "." + std::to_string((ip >> 16) & 255) + "." + 
            std::to_string((ip >> 8) & 255) + "." + std::to_string(ip & 255);
}
    
