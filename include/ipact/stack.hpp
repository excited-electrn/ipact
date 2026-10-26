#pragma once
// The public API. Everything else in src/ is internal.
//
//   ipact::Stack stack;                          // starts the TUN device and the stack thread
//   auto listener = stack.listen(9000);
//   ipact::Connection c = listener.accept();     // blocks
//   char buf[1024]; size_t n = c.recv(buf, sizeof buf);
//   c.send(buf, n);
//   c.close();
//
// Calls block, like the socket API. Failures throw std::system_error with an errno code
// (ECONNREFUSED, ECONNRESET, ETIMEDOUT, EPIPE, ...). Keep the Stack alive for as long as
// you use its Listeners and Connections.
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace ipact {

struct Core;                                         // internal: the TUN device, the engine and its thread

struct Options {
    std::string tun_name = "tun0";
    std::string local_ip = "10.0.0.2";
    std::string pcap_path;               // if set, record every packet (open the file in Wireshark)
    int connect_timeout_ms = 10000;
};

// A snapshot of one connection: your own "ss -ti".
struct ConnectionStats {
    uint64_t retransmits = 0, fast_retransmits = 0, timeouts = 0;   // segments resent, and why
    uint32_t cwnd = 0, ssthresh = 0;                                // congestion window (bytes); ssthresh 0 = not yet set
    uint32_t bytes_in_flight = 0;
    double srtt_ms = 0, rto_ms = 0;                                 // smoothed round-trip time, retransmission timeout
};

class Connection {
public:
    Connection() = default;                         // an empty handle; use Listener::accept or Stack::connect
    size_t send(const void* data, size_t len);      // blocks until all `len` bytes are queued for sending
    size_t recv(void* buf, size_t len);             // blocks until at least 1 byte arrived; returns 0 at end of stream
    void close();                                   // graceful close (FIN after the queued data); does not block
    void set_nodelay(bool on);                      // true = send small writes immediately (TCP_NODELAY)
    std::string peer() const;                       // "10.0.0.1:51234"
    ConnectionStats stats() const;
    explicit operator bool() const { return impl_ != nullptr; }

private:
    friend class Stack;
    friend class Listener;
    struct Impl;
    std::shared_ptr<Impl> impl_;
};

class Listener {
public:
    Connection accept();                            // blocks until a client has completed the handshake

private:
    friend class Stack;
    struct Impl;
    std::shared_ptr<Impl> impl_;
};

class Stack {
public:
    explicit Stack(Options options = {});
    ~Stack();
    Stack(const Stack&) = delete;
    Stack& operator=(const Stack&) = delete;

    Listener listen(uint16_t port);
    Connection connect(const std::string& ip, uint16_t port);   // blocks until established or failed

private:
    std::unique_ptr<Core> core_;
};

}  // namespace ipact
