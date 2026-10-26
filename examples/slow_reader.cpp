// Flow-control demo: accept a connection, IGNORE it for a while (so our receive window
// fills up and drops to 0), then read it slowly. Optionally save what arrives to a file.
//   slow_reader [ignore_seconds=5] [output_file]
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include "engine.hpp"
#include "util/log.hpp"

static Engine* g_engine = nullptr;

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    int ignore_s = argc > 1 ? std::atoi(argv[1]) : 5;
    FILE* out = argc > 2 ? std::fopen(argv[2], "wb") : nullptr;

    Engine eng(EngineConfig::from_env());
    g_engine = &eng;
    std::signal(SIGINT, [](int) { if (g_engine) g_engine->stop(); });
    TcpLayer& tcp = eng.tcp();

    Tcb* conn = nullptr;
    size_t total = 0;
    Time start{}, last_read{}, last_print{};

    tcp.listen(9000, [&](const std::shared_ptr<Tcb>& c) {
        conn = c.get();
        start = Clock::now();
        std::printf("accepted; ignoring it for %d s\n", ignore_s);
        c->on_closed = [&](int) {
            std::printf("closed; %zu bytes received in total\n", total);
            conn = nullptr;
            if (out) { std::fclose(out); out = nullptr; }
        };
        // No on_readable: we do NOT read when data arrives. on_loop reads on a schedule instead.
    });

    eng.on_loop = [&] {
        if (!conn) return;
        Time now = Clock::now();
        using std::chrono::milliseconds;
        if (now - last_print > milliseconds(1000)) {
            last_print = now;
            std::printf("t=%2lds  buffered=%6zu  free window=%6zu  total read=%zu\n",
                        long(std::chrono::duration_cast<std::chrono::seconds>(now - start).count()),
                        conn->recv_buf.size(), conn->recv_buf.free_space(), total);
        }
        if (now - start < std::chrono::seconds(ignore_s)) return;
        if (now - last_read < milliseconds(20)) return;      // slow reader: 1 KB every 20 ms = 50 KB/s
        last_read = now;
        uint8_t buf[1024];
        size_t n = tcp.read(*conn, buf);
        total += n;
        if (out && n) std::fwrite(buf, 1, n, out);
        if (conn->fin_received && conn->recv_buf.empty()) tcp.close(*conn);
    };

    std::printf("slow_reader on 10.0.0.2:9000\n");
    eng.run();
}
