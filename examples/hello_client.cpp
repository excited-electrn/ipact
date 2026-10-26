// Connect to a server, send a line, print the reply.
//   hello_client <ip> <port> <text>      e.g.   hello_client 10.0.0.1 7000 "hello"
// Try a server first:   socat TCP-LISTEN:7000,bind=10.0.0.1,reuseaddr,fork EXEC:cat
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <system_error>
#include "ipact/stack.hpp"

int main(int argc, char** argv) {
    if (argc != 4) { std::fprintf(stderr, "usage: hello_client <ip> <port> <text>\n"); return 1; }
    try {
        ipact::Stack stack;
        ipact::Connection conn = stack.connect(argv[1], uint16_t(std::atoi(argv[2])));
        std::printf("connected to %s\n", conn.peer().c_str());

        conn.send(argv[3], std::strlen(argv[3]));
        char buf[1024];
        size_t n = conn.recv(buf, sizeof buf);
        std::printf("reply (%zu bytes): %.*s\n", n, int(n), buf);
        ipact::ConnectionStats s = conn.stats();
        std::printf("srtt %.2f ms, rto %.0f ms, cwnd %u bytes\n", s.srtt_ms, s.rto_ms, s.cwnd);
        conn.close();
    } catch (const std::system_error& e) {
        std::fprintf(stderr, "error: %s\n", e.what());      // e.g. "connect: Connection refused"
        return 1;
    }
}
