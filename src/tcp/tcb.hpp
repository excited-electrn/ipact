#pragma once
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <vector>

#include "tcp/conn_key.hpp"
#include "tcp/seq.hpp"
#include "util/bytes_queue.hpp"
#include "tcp/rtt.hpp"

enum class State {
    Closed, Listen, SynSent, SynReceived, Established,
    FinWait1, FinWait2, CloseWait, Closing, LastAck, TimeWait
};

inline const char* to_string(State s) {
    switch (s)
    {
        case State::Closed: return "CLOSED";
        case State::Listen: return "LISTEN";
        case State::SynSent: return "SYN_SENT";
        case State::SynReceived: return "SYN_RECEIVED";
        case State::Established: return "ESTABLISHED";
        case State::FinWait1: return "FIN_WAIT_1";
        case State::FinWait2: return "FIN_WAIT_2";
        case State::CloseWait: return "CLOSE_WAIT";
        case State::Closing: return "CLOSING";
        case State::LastAck: return "LAST_ACK";
        case State::TimeWait: return "TIME_WAIT";
    }

    return "?";
}

using Clock = std::chrono::steady_clock;
using Time  = Clock::time_point;

struct SeqLess {
    bool operator()(uint32_t a, uint32_t b) const {
        return seq_lt(a, b);
    }
};

struct Tcb {
    Tcb(size_t send_cap, size_t recv_cap)
        : send_buf(send_cap)
        , recv_buf(recv_cap)
    {}

    ConnKey key{};
    State state   = State::Closed;
    bool  passive = false;
    int   error   = 0;

    // send side
    uint32_t iss = 0;
    uint32_t snd_una = 0;
    uint32_t snd_nxt = 0;
    uint32_t snd_wnd = 0;
    uint32_t snd_wl1 = 0;
    uint32_t snd_wl2 = 0;
    uint16_t mss = 536;
    bool fin_queued = false;
    bool fin_sent   = false;
    uint32_t fin_seq = 0;

    // receive side
    uint32_t irs = 0;
    uint32_t rcv_nxt = 0;
    bool     fin_received = false;

    // window scaling shifts
    uint8_t snd_wscale = 0;
    uint8_t rcv_wscale = 0;

    // buffers
    ByteQueue send_buf;
    ByteQueue recv_buf;
    std::map<uint32_t, std::vector<uint8_t>, SeqLess> ooo; // out-of-order

    // timers
    Time timewait_deadline{};

    //  retransmission timer and RTT measurement
    RttEstimator rtt;
    bool     rto_armed = false;
    Time     rto_deadline{};
    int      retries = 0;            // consecutive timeouts without progress
    bool     rtt_active = false;     // are we timing a segment right now?
    uint32_t rtt_seq = 0;            // the sample completes when this sequence number is acknowledged
    Time     rtt_start{};

    // flow control and efficiency
    bool     nodelay = false;        // true = TCP_NODELAY: switch Nagle's algorithm off
    uint32_t max_snd_wnd = 0;        // largest window the peer has ever advertised
    uint32_t rcv_adv_edge = 0;       // right edge (rcv_nxt + window) of the window we last advertised
    uint32_t unacked_segs = 0;       // data segments received since we last sent an ACK
    bool     delack_armed = false;   // delayed-ACK timer
    Time     delack_deadline{};
    bool     persist_armed = false;  // zero-window probe timer
    Time     persist_deadline{};
    int      persist_backoff = 0;


    // application callbacks
    std::function<void()>   on_connected;
    std::function<void()>   on_readable;
    std::function<void()>   on_writable;
    std::function<void()>   on_eof;
    std::function<void(int)> on_closed;

    // Payload bytes that were sent but are not yet acknowledged
    uint32_t data_in_flight() const {
        uint32_t f = snd_nxt - snd_una;
        if (fin_sent && f > 0) f -= 1;
        return f;
    }
};