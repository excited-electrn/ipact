# ipact

ipact is a TCP and IPv4 stack written in C++20 for Linux. It sends and receives IP packets through a TUN interface and provides a blocking C++ API for client and server programs.

The project is built for learning how TCP works and for testing network behavior. It includes packet capture, packet loss controls, connection statistics, and tests that run over a simulated network.

## Features

* TCP connection setup, data transfer, graceful close, and connection reset
* Receive buffering and handling of data that arrives out of order
* Flow control, window scaling, delayed acknowledgments, and zero window probes
* Reno congestion control with NewReno recovery
* Retransmission timers, round trip time estimates, timestamps, and selective acknowledgments
* IPv4 packet validation and ICMP echo replies
* A blocking API with listeners, connections, and connection statistics
* PCAP recording and congestion window plots
* Unit tests, network simulation tests, and parser fuzzing

## Requirements

Use Linux with a C++20 compiler, CMake 3.20 or newer, and POSIX threads. Live examples also need access to `/dev/net/tun` and a configured TUN interface. The implementation uses Linux headers and epoll, so a native Windows build is not supported.

Python and Matplotlib are optional and are only needed for plotting congestion window data.

## Build and test

Run these commands from the repository root in a Linux shell.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The tests use memory and a simulated clock. They do not need a TUN interface or root access.

## Run the echo server

Create a persistent TUN interface owned by your current user. Use a different address range if `10.0.0.0/24` is already in use on your machine.

```sh
sudo ip tuntap add dev tun0 mode tun user "$(id -un)"
sudo ip addr add 10.0.0.1/24 dev tun0
sudo ip link set dev tun0 mtu 1500 up
./build/echo_server
```

In another terminal, connect to the stack and type a line.

```sh
nc 10.0.0.2 9000
```

Linux owns `10.0.0.1`. ipact owns `10.0.0.2` inside the program. Assign only `10.0.0.1` to the Linux interface. The program opens the interface but does not configure its address or bring it up.

Run one example at a time on `tun0`. Stop the server with Ctrl+C when finished. See the [setup guide](docs/SETUP.md) for client examples, packet capture, and cleanup.

## Public API

Include `ipact/stack.hpp` and link the CMake target `ipact`.

```cpp
#include "ipact/stack.hpp"

int main() {
    ipact::Stack stack;
    auto listener = stack.listen(9000);

    for (;;) {
        auto connection = listener.accept();
        char buffer[4096];
        while (size_t count = connection.recv(buffer, sizeof buffer)) {
            connection.send(buffer, count);
        }
        connection.close();
    }
}
```

This example serves one client at a time. The included `echo_server` uses a thread for each client. Keep the stack alive while using its listeners and connections. API failures report an error through `std::system_error`.

See the [API guide](docs/API.md) for options, error handling, connection lifetime, and statistics.

## Examples

| Program | Purpose |
| :--- | :--- |
| `echo_server` | Echo server using the public blocking API on port 9000 |
| `hello_client` | Send text to a server using the public API |
| `tcp_demo` | Echo server and optional client using internal callbacks |
| `blast` | Send a known byte pattern and report transfer statistics |
| `slow_reader` | Read slowly to show receive flow control |
| `ping_responder` | Reply to ICMP echo requests through `tun0` |
| `tun_dump` | Print raw packets read from `tun0` |

## Documentation

* [Setup and examples](docs/SETUP.md)
* [Public API](docs/API.md)
* [Architecture](docs/ARCHITECTURE.md)
* [Testing and development](docs/TESTING.md)
* [Project description](PROJECT_DESCRIPTION.md)

## Scope

ipact is an experimental implementation for learning and local testing. It supports IPv4 TCP and ICMP echo. It does not implement IPv6, UDP transport, Ethernet, ARP, IP fragment reassembly, DNS lookup, or TLS. Initial sequence numbers use a fixed random seed by default, and TIME_WAIT is shortened to four seconds for experiments. The public API does not provide listener cancellation or general send and receive timeouts.

## License

ipact is available under the [MIT License](LICENSE).
