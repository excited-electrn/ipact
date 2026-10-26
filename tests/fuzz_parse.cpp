// Layer 3: throw garbage at every parser. The only acceptable outcomes are "no value" or a
// valid result. A crash, a sanitizer report or an endless loop is a bug.
//
// With clang (coverage-guided):
//   clang++ -std=c++20 -fsanitize=fuzzer,address,undefined -Iinclude -Isrc tests/fuzz_parse.cpp -o fuzz_parse
//   ./fuzz_parse -max_total_time=60
// With g++ (random + mutated inputs, no coverage guidance; still catches plenty):
//   g++ -std=c++20 -DFUZZ_STANDALONE -fsanitize=address,undefined -Iinclude -Isrc tests/fuzz_parse.cpp -o fuzz_parse
//   ./fuzz_parse 500000
#include <cstdint>
#include <span>
#include "net/ipv4.hpp"
#include "tcp/header.hpp"
#include "tcp/options.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::span<const uint8_t> pkt(data, size);
    if (auto ip = parse_ipv4(pkt)) {
        if (auto tcp = parse_tcp(ip->h.src, ip->h.dst, ip->payload)) (void)parse_options(tcp->options);
    }
    (void)parse_options(pkt);          // hit the option parser directly: checksums stop random inputs reaching it
    return 0;
}

#ifdef FUZZ_STANDALONE
#include <cstdio>
#include <cstdlib>
#include <random>
#include <vector>

int main(int argc, char** argv) {
    long iterations = argc > 1 ? std::atol(argv[1]) : 200000;
    std::mt19937 rng(12345);
    for (long i = 0; i < iterations; ++i) {
        std::vector<uint8_t> buf(rng() % 80);
        for (auto& b : buf) b = uint8_t(rng());
        if (rng() % 2 && buf.size() >= 20) {                 // make it look like a real packet to get past the first checks
            buf[0] = 0x45;
            buf[2] = 0;
            buf[3] = uint8_t(buf.size());
            buf[9] = 6;
        }
        LLVMFuzzerTestOneInput(buf.data(), buf.size());
    }
    std::printf("%ld inputs, no crashes\n", iterations);
}
#endif
