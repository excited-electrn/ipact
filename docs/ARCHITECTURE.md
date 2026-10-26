# Architecture

ipact separates packet input and output from the TCP protocol. The live engine uses a Linux TUN interface and a real clock. Tests connect protocol instances in memory and supply a simulated clock.

## Packet flow

1. Linux routes an IP packet for the stack address into the TUN interface.
2. `Engine` reads the packet, applies optional packet loss, and records it when capture is enabled.
3. The IPv4 parser checks packet lengths, header checksum, and fragmentation fields.
4. ICMP echo requests go to the echo responder. TCP packets go to `TcpLayer`.
5. The TCP layer checks the segment and updates the matching connection state.
6. Application callbacks or blocking API calls move data through connection buffers.
7. Outgoing TCP or ICMP packets pass through optional packet loss and capture before being written to TUN.

TUN carries IP packets directly. This path does not include Ethernet frames or ARP.

## Source layout

| Path | Responsibility |
| :--- | :--- |
| `include/ipact/stack.hpp` | Public options, handles, and statistics |
| `src/stack.cpp` | Blocking API and event thread lifetime |
| `src/engine.cpp` | TUN event loop, packet dispatch, loss controls, and capture |
| `src/io` | TUN file descriptor and PCAP output |
| `src/net` | IPv4 parsing and construction, plus ICMP echo handling |
| `src/tcp/state_machine.cpp` | Connection setup, state changes, reset, and close |
| `src/tcp/send_path.cpp` | Transmission and acknowledgment processing |
| `src/tcp/receive_path.cpp` | Receive buffering and data ordering |
| `src/tcp/output.cpp` | Segment output and advertised receive windows |
| `src/tcp/timers.cpp` | Retransmission, delayed acknowledgment, persist, and TIME_WAIT |
| `src/tcp/options.cpp` | TCP option negotiation and output |
| `src/tcp/app_api.cpp` | Internal buffer operations |
| `src/tcp/tcb.hpp` | State held for each connection |
| `src/tcp/congestion.hpp` | Congestion control interface and Reno implementation |
| `src/tcp/rtt.hpp` | Round trip time and retransmission timeout estimates |
| `src/util` | Byte queues, byte conversion, checksums, and logging |
| `examples` | Programs that use the public API or internal callbacks |
| `tests` | Unit tests, simulated transfers, and parser fuzzing |
| `tools/plot_cwnd.py` | Plot congestion statistics from CSV |

## Thread model

The public stack owns one event thread. Application threads call the blocking API. Both sides use the same engine mutex when accessing mutable protocol state. Waiting application calls use condition variables, which release the mutex until a callback signals progress.

The event thread waits through epoll without holding the protocol mutex. It then locks the engine, reads ready packets, runs due timers, and invokes internal callbacks. Its wait is capped at 20 milliseconds so that timers armed by an application thread are noticed soon.

Internal callbacks must return promptly. Calling a blocking public API method from an engine callback can prevent the event thread from making progress. Examples such as `tcp_demo`, `blast`, and `slow_reader` instead use the internal buffer API from callbacks.

## Protocol model

`TcpLayer` accepts parsed IPv4 packets and emits complete IP packets through a supplied function. A separate clock function supplies time. `tick()` processes timers, and `next_deadline()` tells the caller when the next timer is due.

Each connection has a transmission control block, or `Tcb`. It holds sequence numbers, send and receive windows, queues, data that arrived out of order, negotiated options, timers, callbacks, and statistics. A connection key contains the local and remote addresses and ports.

Reno starts with a congestion window of ten effective segments. It grows the window during slow start and congestion avoidance. Duplicate acknowledgments can trigger fast retransmit, and NewReno handles partial acknowledgments during recovery. Selective acknowledgments track received ranges so that recovery can focus on missing data.

## Default values

| Setting | Default |
| :--- | :--- |
| Stack IPv4 address | `10.0.0.2` |
| Interface name | `tun0` |
| Send buffer per connection | 256 KiB |
| Receive buffer per connection | 256 KiB |
| Offered MSS | 1460 bytes |
| Window scaling, timestamps, selective acknowledgments | Enabled |
| Delayed acknowledgment interval | 40 milliseconds |
| Initial retransmission timeout | 1000 milliseconds |
| Retransmission timeout range | 200 to 60000 milliseconds |
| Maximum consecutive retransmission retries | 8 |
| TIME_WAIT duration | 4000 milliseconds |

Most protocol settings are internal fields in `TcpConfig`. The public options expose a smaller set of settings. The default packet size assumes a TUN MTU of 1500 bytes. Outgoing packets request no IP fragmentation, and incoming fragments are rejected. Dynamic path MTU discovery is not implemented.

Return to the [README](../README.md).
