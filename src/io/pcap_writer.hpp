#pragma once
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>

// Classic pcap. LINKTYPE_RAW (101) means "each packet starts with an IPv4/IPv6 header",
// exactly what a TUN device gives us. Fields are written in host byte order and Wireshark
// figures out the endianness from the magic number.
class PcapWriter {
public:
    explicit PcapWriter(const std::string& path) : f_(std::fopen(path.c_str(), "wb")) {
        struct { uint32_t magic = 0xa1b2c3d4; uint16_t major = 2, minor = 4;
                 int32_t tz = 0; uint32_t sigfigs = 0, snaplen = 65535, linktype = 101; } gh;
        if (f_) std::fwrite(&gh, sizeof gh, 1, f_);
    }
    ~PcapWriter() { if (f_) std::fclose(f_); }
    void write(std::span<const uint8_t> pkt) {
        if (!f_) return;
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                      std::chrono::system_clock::now().time_since_epoch()).count();
        struct { uint32_t sec, usec, caplen, len; } rh{
            uint32_t(us / 1'000'000), uint32_t(us % 1'000'000), uint32_t(pkt.size()), uint32_t(pkt.size())};
        std::fwrite(&rh, sizeof rh, 1, f_);
        std::fwrite(pkt.data(), 1, pkt.size(), f_);
        std::fflush(f_);                       // so the file is usable even if we crash
    }
private:
    std::FILE* f_;
};
