#pragma once
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <unordered_map>
#include <vector>
#include "net/ipv4.hpp"
#include "tcp/header.hpp"
#include "tcp/tcb.hpp"

struct TcpConfig {
    uint32_t local_ip = (10u << 24) | 2;                  // 10.0.0.2: our side of the TUN link
    size_t   send_buf_size = 256 * 1024;
    size_t   recv_buf_size = 256 * 1024;                  // bigger than 64 KB, so window scaling matters
    uint16_t mss = 1460;                                  // what we offer: 1500 (TUN MTU) - 20 IP - 20 TCP
    bool     want_wscale = true;                          // which options we offer / accept
    bool     want_timestamps = true;
    bool     want_sack = true;
    std::chrono::milliseconds time_wait{4000};            // 2*MSL. Real stacks use 60 s; 4 s keeps experiments short.
    std::optional<uint32_t>   fixed_isn;                  // tests: force the initial sequence number
    uint32_t rng_seed = 12345;
    int      max_retries = 8;                             // consecutive timeouts before we give up (ETIMEDOUT)
    std::chrono::milliseconds delayed_ack{40};            // how long we may hold back an ACK (Linux: 40 ms)
};

// The whole TCP protocol, with no knowledge of TUN devices, threads or the real clock.
// Packets come in through on_ip_packet(); packets go out through the `out` function you
// pass to the constructor; time comes from the `clock` function. That makes it testable.
class TcpLayer {
public:
    using SendPacket = std::function<void(std::vector<uint8_t>)>;
    using AcceptFn   = std::function<void(const std::shared_ptr<Tcb>&)>;
    using ClockFn    = std::function<Time()>;

    TcpLayer(TcpConfig cfg, SendPacket out, ClockFn clock = [] { return Clock::now(); });

    // ---- called by the I/O layer ----
    void on_ip_packet(const Ipv4View& ip);          // one incoming IP packet (already parsed)
    void tick();                                    // run every timer that is due
    std::optional<Time> next_deadline() const;      // when should tick() run next?

    // ---- called by the application ----
    void listen(uint16_t port, AcceptFn on_accept);
    std::shared_ptr<Tcb> connect(uint32_t remote_ip, uint16_t remote_port);
    void close(Tcb& t);                             // graceful: send FIN after queued data
    void abort(Tcb& t);                             // hard: send RST, forget everything
    void shutdown();                                // drop every connection and listener silently (the stack is going away)

    // Moving bytes. Both return immediately; neither ever blocks.
    size_t send(Tcb& t, std::span<const uint8_t> data);   // returns how many bytes were accepted
    size_t read(Tcb& t, std::span<uint8_t> out);          // returns 0 if nothing is waiting

    size_t connection_count() const { return conns_.size(); }

private:
    // ---- state_machine.cpp ----
    void passive_open(const Ipv4Header& ip, const TcpView& seg);
    void segment_arrives(Tcb& t, const TcpView& seg);
    void handle_syn_sent(Tcb& t, const TcpView& seg);
    void handle_rst(Tcb& t, const TcpView& seg);
    void handle_fin(Tcb& t, const TcpView& seg);
    bool acceptable(const Tcb& t, const TcpView& seg) const;
    void become_established(Tcb& t);
    void enter_time_wait(Tcb& t);
    void set_state(Tcb& t, State s);
    void destroy(Tcb& t, int err);

    // ---- output.cpp ----
    void emit(Tcb& t, uint32_t seq, uint8_t flags, std::span<const uint8_t> payload = {});
    void send_raw(uint32_t src_ip, uint32_t dst_ip, const TcpHeader& h,
                  std::span<const uint8_t> options, std::span<const uint8_t> payload);
    void send_ack(Tcb& t);
    void send_reset_for(const Ipv4Header& ip, const TcpView& seg);
    uint32_t rcv_window(const Tcb& t) const;
    uint16_t advertised_window(Tcb& t, uint8_t flags);
    void maybe_send_window_update(Tcb& t);

    // ---- timers.cpp ----
    void sent_new(Tcb& t);          // we just sent sequence space for the first time
    void acked_up_to(Tcb& t);       // snd_una just moved forward
    void arm_rto(Tcb& t);
    void stop_rto(Tcb& t);
    void on_rto(Tcb& t);            // the retransmission timer fired
    void retransmit_head(Tcb& t);   // resend the oldest unacknowledged segment
    void arm_delack(Tcb& t);
    void arm_persist(Tcb& t);
    void on_persist(Tcb& t);        // zero-window probe timer fired
    void on_dup_ack(Tcb& t);        // (Phase 12) a duplicate ACK arrived
    void send_hole(Tcb& t, uint32_t start, uint32_t end);   // (Phase 13) retransmit part of [start, end)
    void retransmit_next_hole(Tcb& t);                      // (Phase 13) SACK-driven retransmission

    // ---- options.cpp ----
    std::vector<uint8_t> build_options(const Tcb& t, uint8_t flags);
    void read_peer_options(Tcb& t, const TcpView& seg);
    uint32_t ts_now() const;                        // our timestamp clock: milliseconds

    // ---- send_path.cpp ----
    void try_send(Tcb& t);
    bool process_ack(Tcb& t, const TcpView& seg);
    void update_send_window(Tcb& t, const TcpHeader& h);

    // ---- receive_path.cpp ----
    void process_payload(Tcb& t, const TcpView& seg);

    uint32_t pick_isn();
    Time now() const { return clock_(); }

    TcpConfig cfg_;
    SendPacket out_;
    ClockFn clock_;
    std::mt19937 rng_;
    uint16_t ip_id_ = 1;
    uint16_t next_port_ = 49152;
    std::unordered_map<ConnKey, std::shared_ptr<Tcb>> conns_;
    std::map<uint16_t, AcceptFn> listeners_;
};
