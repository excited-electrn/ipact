// Echo server on port 9000: every byte that arrives is sent back.
// Optional:  tcp_demo connect <ip> <port> <text>   connects out, sends <text>, prints the reply.
#include <algorithm>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>
#include "engine.hpp"
#include "util/log.hpp"

static Engine* g_engine = nullptr;

// One Echo object per connection. It moves bytes from the receive buffer to the send buffer,
// but only as many as the send buffer can take, so a slow peer pushes back on its sender.
struct Echo {
    TcpLayer& tcp;
    Tcb*      t;
    bool      peer_done = false;

    void pump() {
        uint8_t buf[4096];
        for (;;) {
            size_t n = std::min({t->send_buf.free_space(), t->recv_buf.size(), sizeof buf});
            if (n == 0) break;
            tcp.read(*t, std::span<uint8_t>(buf, n));
            tcp.send(*t, std::span<const uint8_t>(buf, n));
        }
        if (peer_done && t->recv_buf.empty()) tcp.close(*t);   // everything echoed: say goodbye
    }
};

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);          // flush every line, even when redirected to a file
    Engine eng(EngineConfig::from_env());
    g_engine = &eng;
    std::signal(SIGINT, [](int) { if (g_engine) g_engine->stop(); });
    TcpLayer& tcp = eng.tcp();

    tcp.listen(9000, [&tcp](const std::shared_ptr<Tcb>& c) {
        auto echo = std::make_shared<Echo>(Echo{tcp, c.get()});
        std::printf("accepted %s:%u\n", ip_to_string(c->key.remote_ip).c_str(), c->key.remote_port);
        c->on_readable = [echo] { echo->pump(); };
        c->on_writable = [echo] { echo->pump(); };
        c->on_eof      = [echo] { echo->peer_done = true; echo->pump(); };
        c->on_closed   = [](int err) { std::printf("  closed (%s)\n", err ? std::strerror(err) : "clean"); };
    });

    if (argc == 5 && std::strcmp(argv[1], "connect") == 0) {
        unsigned a, b, c, d;
        std::sscanf(argv[2], "%u.%u.%u.%u", &a, &b, &c, &d);
        auto conn = tcp.connect((a << 24) | (b << 16) | (c << 8) | d, uint16_t(std::atoi(argv[3])));
        Tcb* t = conn.get();
        std::string text = argv[4];
        t->on_connected = [&tcp, t, text] {
            tcp.send(*t, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(text.data()), text.size()));
            tcp.close(*t);                                   // FIN goes out after the data
        };
        t->on_readable = [&tcp, t] {
            uint8_t buf[2048];
            size_t n = tcp.read(*t, buf);
            std::printf("client got: %.*s\n", int(n), reinterpret_cast<char*>(buf));
        };
        t->on_closed = [](int err) { std::printf("client closed (%s)\n", err ? std::strerror(err) : "clean"); };
    }

    std::printf("echo server on 10.0.0.2:9000  (Ctrl-C to stop)\n");
    eng.run();
}