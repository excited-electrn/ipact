# Public API

The public header is [`include/ipact/stack.hpp`](../include/ipact/stack.hpp). All public types are in the `ipact` namespace. Headers under `src` are internal and may change as the implementation evolves.

## Link an application

For an application that has this repository in a directory named `ipact`, use the following CMake setup.

```cmake
cmake_minimum_required(VERSION 3.20)
project(example LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_subdirectory(ipact)
add_executable(example main.cpp)
target_link_libraries(example PRIVATE ipact)
```

The repository builds its examples and tests as part of that subdirectory. It does not currently provide an install target or an exported package for `find_package`.

## Stack options

```cpp
#include "ipact/stack.hpp"

ipact::Options options;
options.tun_name = "tun0";
options.local_ip = "10.0.0.2";
options.pcap_path = "session.pcap";
options.connect_timeout_ms = 10000;
ipact::Stack stack(options);
```

| Field | Default | Meaning |
| :--- | :--- | :--- |
| `tun_name` | `tun0` | Interface to open |
| `local_ip` | `10.0.0.2` | IPv4 address handled by the stack |
| `pcap_path` | Empty | Optional capture file path |
| `connect_timeout_ms` | `10000` | Maximum wait for a public API connection attempt |

Constructing a stack opens the TUN interface and starts its event thread. Configure the Linux interface separately as described in the [setup guide](SETUP.md). IPv4 addresses must be numeric strings. Hostname resolution is not provided.

The stack cannot be copied. Keep it alive for every operation on its listeners and connections. Finish application work and join application threads before destroying it. Its destructor stops the event thread and drops protocol state. It does not wait for every graceful close to finish.

## Listeners and connections

| Call | Behavior |
| :--- | :--- |
| `stack.listen(port)` | Register a listener on the stack address and return a listener handle |
| `listener.accept()` | Wait for a completed handshake and return a connection |
| `stack.connect(ip, port)` | Wait for connection setup or an error |
| `connection.send(data, len)` | Wait until all bytes have been accepted into the send buffer |
| `connection.recv(buffer, len)` | Wait for data, EOF, or an error, then return the number of bytes read |
| `connection.close()` | Queue a graceful close and return without waiting for completion |
| `connection.set_nodelay(true)` | Disable Nagle buffering for future small writes |
| `connection.peer()` | Return the remote numeric address and port |
| `connection.stats()` | Return a snapshot of connection statistics |

Use a positive receive buffer length. A receive call may return fewer bytes than requested. With a positive length, zero means that the peer has finished sending and the buffered data has been drained. TCP preserves byte order but does not preserve the boundaries between send calls.

A successful send means that bytes were queued locally. It does not mean that the peer has received or acknowledged them. On an error, some bytes may already have been queued before the exception occurred.

Call `close()` explicitly when finished sending. It sends FIN after queued data has been transmitted, and the stack must continue running to handle acknowledgments and retransmission. Destroying a connection handle does not automatically request a graceful close. A copied connection handle refers to the same connection.

There is no public listener close call or cancellation mechanism for `accept()`. Sending and receiving have no general application timeout. Avoid destroying the stack while an application thread is blocked in an API call. Calls share the engine mutex, but applications should coordinate access when several threads use one connection, especially when closing it.

## Errors

API failures use `std::system_error` with errno style codes. Invalid numeric IPv4 addresses report `EINVAL`. Typical connection errors include `ECONNREFUSED`, `ECONNRESET`, `ETIMEDOUT`, and `EPIPE`. Sending or receiving through an empty connection reports `EBADF`.

```cpp
#include <cstdio>
#include <system_error>
#include "ipact/stack.hpp"

void connect_to_host(ipact::Stack& stack) {
    try {
        auto connection = stack.connect("10.0.0.1", 7000);
        const char text[] = "hello";
        connection.send(text, sizeof(text) - 1);
        char buffer[1024];
        const size_t count = connection.recv(buffer, sizeof buffer);
        std::printf("Received %zu bytes\n", count);
        connection.close();
    } catch (const std::system_error& error) {
        std::fprintf(stderr, "%s\n", error.what());
    }
}
```

The caller owns the stack in this example and must keep it running after this function returns if graceful close is still in progress.

## Statistics

| Field | Unit | Meaning |
| :--- | :--- | :--- |
| `retransmits` | Segments | Total segments retransmitted |
| `fast_retransmits` | Events | Fast retransmit triggers |
| `timeouts` | Events | Retransmission timeouts |
| `cwnd` | Bytes | Current congestion window |
| `ssthresh` | Bytes | Slow start threshold, with zero meaning not yet set |
| `bytes_in_flight` | Bytes | Sent payload that has not yet been acknowledged |
| `srtt_ms` | Milliseconds | Smoothed round trip time |
| `rto_ms` | Milliseconds | Current retransmission timeout |

An empty connection converts to false. Its `peer()` result is empty, and its statistics are zero. A nonempty handle can still refer to a connection that has closed, so the boolean conversion does not indicate protocol state.

Return to the [README](../README.md).
