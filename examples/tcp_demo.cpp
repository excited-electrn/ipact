#include <csignal>
#include <cstdio>
#include <cstring>

#include "engine.hpp"
#include "util/log.hpp"

static Engine* g_engine = nullptr;

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    Engine eng(EngineConfig::from_env());
    g_engine = &eng;
    std::signal(SIGINT, [](int) {
        if (g_engine) g_engine->stop();
    });
    TcpLayer& tcp = eng.tcp();

    tcp.listen(9000, [&tcp](const std::shared_ptr<Tcb>& c) {
        Tcb* t = c.get();
        std::printf("accepted %s:%u\n", ip_to_string(t->key.remote_ip).c_str(), t->key.remote_port);
        t->on_readable = [t] {
            std::printf("  %zu bytes arrived (discarding)\n", t->recv_buf.size());
            t->recv_buf.consume(t->recv_buf.size());
        };

        t->on_eof = [&tcp, t] {
            std::printf(" peer closed its side, closing ours\n");
            tcp.close(*t);
        };

        t->on_closed = [](int err) {
            std::printf("  connection closed (%s)\n", err ? std::strerror(err) : "clean");
        };
    });

    if (argc == 4 && std::strcmp(argv[1], "connect") == 0) {
        uint32_t a, b, c, d;
        if (std::sscanf(argv[2], "%u.%u.%u.%u", &a, &b, &c, &d) != 4 ||
            a > 255 || b > 255 || c > 255 || d > 255) {
            std::fprintf(stderr, "bad ip: %s\n", argv[2]);
            return 1;
        }
        auto conn = tcp.connect((a << 24) | (b << 16) | (c << 8) | d, uint16_t(std::atoi(argv[3])));
        Tcb* t = conn.get();

        t->on_connected = [&tcp, t] {
            std::printf("connected! closing again\n");
            tcp.close(*t);
        };

        t->on_closed = [](int err) {
            std::printf("client connection closed (%s)\n", err ? std::strerror(err) : "clean");
        };
    }

    std::printf("listening on 10.0.0.2:9000  (Ctrl-C to stop)\n");
    eng.run();
}