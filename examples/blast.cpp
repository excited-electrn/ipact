// Send a known pattern as fast as TCP allows, then report the speed.
//   blast <ip> <port> <bytes>
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
        }
    };
    t->on_connected = [&] { start = Clock::now(); std::printf("connected, sending %zu bytes\n", total); pump(); };
    t->on_writable  = pump;
    t->on_closed    = [&](int err) {
        std::printf("closed (%s)\n", err ? std::strerror(err) : "clean");
        eng.stop();
    };
    eng.run();
}