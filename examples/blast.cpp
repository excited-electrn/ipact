// Send a known pattern as fast as TCP allows, then report the speed.
//   blast <ip> <port> <bytes>
// Set IPACT_CWND_LOG=cwnd.csv to record the congestion window over time (see Phase 12).
// Byte number i of the stream is (i % 251), so the receiver can check it, e.g.
//   python3 -c "import sys; sys.stdout.buffer.write(bytes(i % 251 for i in range(N)))" | cmp - received.bin
#include <algorithm>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "engine.hpp"
#include "util/log.hpp"

static Engine* g_engine = nullptr;

int main(int argc, char** argv) {
    if (argc != 4) { std::fprintf(stderr, "usage: blast <ip> <port> <bytes>\n"); return 1; }
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    unsigned a, b, c, d;
    std::sscanf(argv[1], "%u.%u.%u.%u", &a, &b, &c, &d);
    const uint32_t ip = (a << 24) | (b << 16) | (c << 8) | d;
    const uint16_t port = uint16_t(std::atoi(argv[2]));
    const size_t total = size_t(std::atoll(argv[3]));

    Engine eng(EngineConfig::from_env());
    g_engine = &eng;
    std::signal(SIGINT, [](int) { if (g_engine) g_engine->stop(); });
    TcpLayer& tcp = eng.tcp();

    auto conn = tcp.connect(ip, port);
    Tcb* t = conn.get();
    size_t queued = 0;
    bool closing = false, reported = false;
    Time start{};

    // Keep the send buffer topped up; when everything is queued, close; when it is all acknowledged, report.
    auto pump = [&] {
        while (queued < total) {
            uint8_t buf[4096];
            size_t n = std::min({total - queued, sizeof buf, t->send_buf.free_space()});
            if (n == 0) break;
            for (size_t i = 0; i < n; ++i) buf[i] = uint8_t((queued + i) % 251);
            queued += tcp.send(*t, std::span<const uint8_t>(buf, n));
        }
        if (queued == total && !closing) { closing = true; tcp.close(*t); }
        if (queued == total && t->send_buf.empty() && !reported) {
            reported = true;
            double s = std::chrono::duration<double>(Clock::now() - start).count();
            std::printf("sent %zu bytes in %.2f s = %.2f MB/s\n", total, s, double(total) / s / 1e6);
            std::printf("retransmitted segments: %lu (fast: %lu, timeouts: %lu)\n", (unsigned long)t->stats.retransmits,
                        (unsigned long)t->stats.fast_retransmits, (unsigned long)t->stats.timeouts);
        }
    };
    // Congestion-window recorder: one CSV line (time_ms,cwnd,ssthresh,in_flight) every 5 ms.
    FILE* cwnd_log = nullptr;
    if (const char* f = std::getenv("IPACT_CWND_LOG")) {
        cwnd_log = std::fopen(f, "w");
        std::fprintf(cwnd_log, "time_ms,cwnd,ssthresh,in_flight\n");
    }
    Time last_sample{};
    eng.on_loop = [&] {
        if (!cwnd_log || reported || !t->cc || Clock::now() - last_sample < std::chrono::milliseconds(5)) return;
        last_sample = Clock::now();
        double ms = std::chrono::duration<double, std::milli>(last_sample - start).count();
        uint32_t ss = t->cc->ssthresh();
        std::fprintf(cwnd_log, "%.1f,%u,%u,%u\n", ms, t->cc->cwnd(), ss == UINT32_MAX ? 0u : ss, t->data_in_flight());
    };
    t->on_connected = [&] { start = Clock::now(); std::printf("connected, sending %zu bytes\n", total); pump(); };
    t->on_writable  = pump;
    t->on_closed    = [&](int err) {
        std::printf("closed (%s)\n", err ? std::strerror(err) : "clean");
        if (cwnd_log) std::fclose(cwnd_log);
        eng.stop();
    };
    eng.run();
}
