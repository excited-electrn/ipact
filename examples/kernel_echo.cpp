#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>

int main() {
    int srv = socket(AF_INET, SOCK_STREAM, 0);          // 1. create a TCP socket
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(9000);                         // note htons!
    bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof addr);  // 2. claim port 9000
    listen(srv, 16);                                     // 3. become a listener

    for (;;) {
        int c = accept(srv, nullptr, nullptr);           // 4. wait for the handshake to finish
        char buf[4096];
        ssize_t n;
        while ((n = recv(c, buf, sizeof buf, 0)) > 0)    // 5. read bytes
            send(c, buf, static_cast<size_t>(n), 0);     // 6. write them back
        close(c);                                        // 7. FIN
    }
}
