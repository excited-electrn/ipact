# Project description

## Short description

ipact is a C++20 TCP and IPv4 stack for Linux with a blocking API, TUN networking, packet capture, and simulated network tests.

## Full description

ipact implements TCP in a user process so that connection setup, reliable delivery, flow control, and congestion control can be studied in code. It connects to Linux through a TUN interface and can exchange data with normal TCP programs on the host.

The stack includes Reno congestion control with NewReno recovery, retransmission timers, selective acknowledgments, timestamps, window scaling, and support for data that arrives out of order. Applications use a small blocking C++ API to listen, connect, send, receive, and inspect connection statistics.

Examples cover echo servers, clients, bulk transfers, slow readers, ICMP echo replies, and packet inspection. Packet loss controls, PCAP output, and congestion window plots help explain how the protocol reacts to changing network conditions. Unit tests, parser fuzzing, and network simulations check behavior without requiring a live interface.

The project is intended for learning, experiments, and local protocol testing. It is written in C++20, built with CMake, and released under the MIT License.

## Suggested repository topics

`cpp` `cpp20` `tcp` `ipv4` `networking` `linux` `tun` `congestion` `pcap` `cmake`
