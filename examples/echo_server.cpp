// A multi-client echo server written against the PUBLIC API only: it looks like a socket program.
//   sudo ./build/echo_server      then, from another terminal:   nc 10.0.0.2 9000
#include <cstdio>
#include <system_error>
#include <thread>
#include "ipact/stack.hpp"

int main() {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    ipact::Stack stack;                                   // brings up tun0 and the stack thread
    ipact::Listener listener = stack.listen(9000);
    std::printf("echo server on 10.0.0.2:9000\n");

    for (;;) {
        ipact::Connection conn = listener.accept();
        std::printf("accepted %s\n", conn.peer().c_str());
        std::thread([conn]() mutable {                    // one thread per client keeps the code simple
            try {
                char buf[4096];
                while (size_t n = conn.recv(buf, sizeof buf))   // 0 = the client closed
                    conn.send(buf, n);
            } catch (const std::system_error& e) {
                std::printf("%s: %s\n", conn.peer().c_str(), e.what());
            }
            ipact::ConnectionStats s = conn.stats();
            std::printf("closed %s  (srtt %.2f ms, cwnd %u, %lu retransmits)\n", conn.peer().c_str(), s.srtt_ms, s.cwnd,
                        (unsigned long)s.retransmits);
            conn.close();
        }).detach();
    }
}
