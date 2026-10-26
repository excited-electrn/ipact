#pragma once
#include <chrono>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <vector>
#include "tcp/congestion.hpp"
#include "tcp/conn_key.hpp"
#include "tcp/rtt.hpp"
#include "tcp/seq.hpp"
#include "util/byte_queue.hpp"

enum class State {
    Closed, Listen, SynSent, SynReceived, Established,
    FinWait1, FinWait2, CloseWait, Closing, LastAck, TimeWait
};

inline const char* to_string(State s) {
    switch (s) {
        case State::Closed:      return "CLOSED";
        case State::Listen:      return "LISTEN";
        case State::SynSent:     return "SYN_SENT";
        case State::SynReceived: return "SYN_RECEIVED";
        case State::Established: return "ESTABLISHED";
        case State::FinWait1:    return "FIN_WAIT_1";
        case State::FinWait2:    return "FIN_WAIT_2";
        case State::CloseWait:   return "CLOSE_WAIT";
        case State::Closing:     return "CLOSING";
        case State::LastAck:     return "LAST_ACK";
        case State::TimeWait:    return "TIME_WAIT";
    }
    return "?";
}

using Clock = std::chrono::steady_clock;
using Time  = Clock::time_point;

// Ordering for std::map keys that are sequence numbers. Plain `<` breaks at wrap-around.
struct SeqLess {
    bool operator()(uint32_t a, uint32_t b) const { return seq_lt(a, b); }
};

// Transmission Control Block: everything we know about one connection.
struct Tcb {
    Tcb(size_t send_cap, size_t recv_cap) : send_buf(send_cap), recv_buf(recv_cap) {}

    ConnKey key{};
    State   state   = State::Closed;
    bool    passive = false;      // created by a listener (true) or by connect() (false)
    int     error   = 0;          // errno-style reason if the connection died abnormally

    // ---- send side (RFC 9293 names) ----
    uint32_t iss = 0;             // initial send sequence number (our SYN)
    uint32_t snd_una = 0;         // oldest byte not yet acknowledged
    uint32_t snd_nxt = 0;         // next sequence number we will use
    uint32_t snd_wnd = 0;         // peer's advertised window (already scaled, in bytes)
    uint32_t snd_wl1 = 0;         // seq of the segment that last updated snd_wnd
    uint32_t snd_wl2 = 0;         // ack of the segment that last updated snd_wnd
    uint16_t mss = 536;           // largest payload we send; 536 is the RFC default
    bool     fin_queued = false;  // app called close(): send a FIN once all data is out
    bool     fin_sent   = false;
    uint32_t fin_seq    = 0;      // sequence number our FIN occupies

    // ---- receive side ----
    uint32_t irs = 0;             // initial receive sequence number (their SYN)
    uint32_t rcv_nxt = 0;         // next sequence number we expect from them
    bool     fin_received = false;

    // Window scaling shifts. Both stay 0 (= no scaling) until Phase 13 negotiates them.
    uint8_t snd_wscale = 0;       // shift applied to the windows the peer sends us
    uint8_t rcv_wscale = 0;       // shift the peer applies to the windows we send

    // ---- buffers ----
    ByteQueue send_buf;           // byte 0 of this queue has sequence number snd_una
    ByteQueue recv_buf;           // in-order bytes waiting for the app to read()
    std::map<uint32_t, std::vector<uint8_t>, SeqLess> ooo;   // out-of-order data, by seq (Phase 9)

    // ---- timers ----
    Time timewait_deadline{};

    // ---- retransmission timer and RTT measurement (Phase 10) ----
    RttEstimator rtt;
    bool     rto_armed = false;
    Time     rto_deadline{};
    int      retries = 0;            // consecutive timeouts without progress
    bool     rtt_active = false;     // are we timing a segment right now?
    uint32_t rtt_seq = 0;            // the sample completes when this sequence number is acknowledged
    Time     rtt_start{};

    // ---- flow control and efficiency (Phase 11) ----
    bool     nodelay = false;        // true = TCP_NODELAY: switch Nagle's algorithm off
    uint32_t max_snd_wnd = 0;        // largest window the peer has ever advertised
    uint32_t rcv_adv_edge = 0;       // right edge (rcv_nxt + window) of the window we last advertised
    uint32_t unacked_segs = 0;       // data segments received since we last sent an ACK
    bool     delack_armed = false;   // delayed-ACK timer
    Time     delack_deadline{};
    bool     persist_armed = false;  // zero-window probe timer
    Time     persist_deadline{};
    int      persist_backoff = 0;

    // ---- options (Phase 13) ----
    bool     ws_ok = false, ts_ok = false, sack_ok = false;   // what was negotiated in the handshake
    uint32_t ts_recent = 0;                  // newest TSval from the peer: we echo it back
    uint32_t last_ooo_seq = 0;               // receiver: seq of the newest out-of-order segment (first SACK block)
    std::map<uint32_t, uint32_t, SeqLess> sacked;   // sender: byte ranges [start, end) the peer reports holding
    uint32_t retx_next = 0;                  // sender: hole search during recovery starts here

    // ---- congestion control (Phase 12) ----
    std::unique_ptr<CongestionControl> cc;   // created when the connection becomes ESTABLISHED
    uint32_t dupacks = 0;                    // consecutive duplicate ACKs
    bool     in_recovery = false;            // recovering from a loss?
    bool     recovery_by_timeout = false;    // ...started by a timeout (true) or by 3 duplicate ACKs (false)
    uint32_t recover = 0;                    // recovery ends when this sequence number is acknowledged

    struct Stats { uint64_t retransmits = 0, fast_retransmits = 0, timeouts = 0; } stats;

    // ---- application callbacks (all optional) ----
    std::function<void()>    on_connected;   // active open finished: now ESTABLISHED
    std::function<void()>    on_readable;    // new bytes are waiting in recv_buf
    std::function<void()>    on_writable;    // send_buf has free space again
    std::function<void()>    on_eof;         // peer sent FIN: no more bytes will ever arrive
    std::function<void(int)> on_closed;      // connection is gone; 0 = clean, else errno value

    // Largest payload per segment: the MSS minus the 12 bytes the timestamp option takes.
    uint32_t send_mss() const { return mss - (ts_ok ? 12u : 0u); }

    // How many bytes the congestion controller currently allows in flight.
    uint32_t cwnd() const { return cc ? cc->cwnd() : std::numeric_limits<uint32_t>::max(); }

    // Payload bytes that were sent but are not yet acknowledged.
    // (A FIN uses one sequence number but is not payload, so it is subtracted.)
    uint32_t data_in_flight() const {
        uint32_t f = snd_nxt - snd_una;
        if (fin_sent && f > 0) f -= 1;
        return f;
    }
};
