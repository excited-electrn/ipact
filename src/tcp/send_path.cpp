// Everything about sending data and about processing the ACKs we get back.
#include <algorithm>
#include "tcp/options.hpp"
#include "tcp/tcp_layer.hpp"
#include "util/log.hpp"

// Send as much new data as the peer's window allows, then the FIN if the app closed.
void TcpLayer::try_send(Tcb& t) {
    if (t.state != State::Established && t.state != State::CloseWait) return;
    t.max_snd_wnd = std::max(t.max_snd_wnd, t.snd_wnd);

    for (;;) {
        uint32_t in_flight = t.data_in_flight();
        uint32_t unsent    = uint32_t(t.send_buf.size()) - in_flight;
        uint32_t window    = std::min(t.snd_wnd, t.cwnd());          // the peer's limit AND the network's limit
        uint32_t room      = window > in_flight ? window - in_flight : 0;
        uint32_t len       = std::min({unsent, room, t.send_mss()});
        if (len == 0) break;

        // Silly-window avoidance and Nagle (RFC 1122 4.2.3.4, RFC 896). Only send a small
        // segment if it empties our buffer AND nothing is waiting for an ACK (or Nagle is
        // off). Anything else small waits until an ACK arrives and more data can join it.
        bool full_segment   = len >= t.send_mss();
        bool half_window    = uint64_t(len) * 2 >= t.max_snd_wnd;
        bool flushes_buffer = len == unsent;
        bool nagle_ok       = t.nodelay || in_flight == 0 || t.fin_queued;
        if (!(full_segment || half_window || (flushes_buffer && nagle_ok))) break;

        std::vector<uint8_t> payload(len);
        t.send_buf.peek(in_flight, payload);                 // copy; the bytes stay queued until acknowledged
        uint8_t flags = uint8_t(flag::ACK | (len == unsent ? flag::PSH : 0));
        emit(t, t.snd_nxt, flags, payload);
        t.snd_nxt += len;
        sent_new(t);
    }

    bool all_sent = t.send_buf.size() == t.data_in_flight();
    if (t.fin_queued && !t.fin_sent && all_sent) {
        t.fin_seq = t.snd_nxt;
        emit(t, t.snd_nxt, flag::FIN | flag::ACK);
        t.snd_nxt += 1;                                      // a FIN occupies one sequence number
        t.fin_sent = true;
        sent_new(t);
        set_state(t, t.state == State::Established ? State::FinWait1 : State::LastAck);
        t.persist_armed = false;
        return;
    }

    // Data is waiting, nothing is in flight, and we could not send it: the peer's window is
    // (nearly) closed and no ACK is coming to wake us. The persist timer will probe it.
    bool stalled = t.send_buf.size() > 0 && t.data_in_flight() == 0;
    if (stalled && !t.persist_armed) { t.persist_backoff = 0; arm_persist(t); }
    if (!stalled) t.persist_armed = false;
}

// Take the window the peer advertises, but only from segments that are not older than
// the one that set it (RFC 9293 3.10.7.4).
void TcpLayer::update_send_window(Tcb& t, const TcpHeader& h) {
    if (seq_lt(t.snd_wl1, h.seq) || (t.snd_wl1 == h.seq && seq_leq(t.snd_wl2, h.ack))) {
        t.snd_wnd = uint32_t(h.window) << t.snd_wscale;
        t.max_snd_wnd = std::max(t.max_snd_wnd, t.snd_wnd);
        t.snd_wl1 = h.seq;
        t.snd_wl2 = h.ack;
    }
}

// A duplicate ACK says: "something after snd_una arrived, but snd_una itself did not."
void TcpLayer::on_dup_ack(Tcb& t) {
    t.dupacks += 1;
    if (t.in_recovery) {
        if (!t.recovery_by_timeout) t.cc->on_dup_ack_extra();      // window inflation (fast recovery)
        if (t.sack_ok) retransmit_next_hole(t);                    // the SACK info says exactly what is missing
        return;
    }
    if (t.dupacks == 3) {                                          // three in a row: treat it as a loss
        LOG("fast retransmit of seq %u (cwnd %u)", t.snd_una, t.cwnd());
        t.recover = t.snd_nxt;
        t.retx_next = t.snd_una;
        t.in_recovery = true;
        t.recovery_by_timeout = false;
        t.cc->on_dup_ack_threshold(t.data_in_flight());
        t.stats.fast_retransmits += 1;
        retransmit_head(t);
    }
}

// Handle the ACK field of a segment in a synchronized state.
// Returns false if the segment must be dropped (it acknowledges something we never sent).
bool TcpLayer::process_ack(Tcb& t, const TcpView& seg) {
    const TcpHeader& h = seg.h;
    if (seq_gt(h.ack, t.snd_nxt)) {                          // from the future
        send_ack(t);
        return false;
    }
    if (seq_lt(h.ack, t.snd_una)) return true;               // old duplicate: nothing to learn

    uint32_t old_wnd = t.snd_wnd;
    update_send_window(t, h);

    if (h.ack == t.snd_una) {
        // RFC 5681: a duplicate ACK carries no data and no SYN/FIN, arrives while data is
        // outstanding, and does not change the window. With SACK the window rule is dropped:
        // a peer whose buffer is growing changes its window on every ACK, but an ACK that
        // carries SACK blocks is a duplicate no matter what its window says.
        bool same_window = t.snd_wnd == old_wnd || (t.sack_ok && carries_sack(seg.options));
        bool is_dup = seg.payload.empty() && !h.has(flag::SYN) && !h.has(flag::FIN) &&
                      same_window && t.data_in_flight() > 0;
        if (is_dup && t.cc) on_dup_ack(t);
    } else {                                                 // new data acknowledged
        uint32_t acked = h.ack - t.snd_una;
        if (t.fin_sent && seq_gt(h.ack, t.fin_seq)) acked -= 1;   // the FIN is not in send_buf
        t.send_buf.consume(acked);
        t.snd_una = h.ack;
        t.dupacks = 0;
        sack_trim(t.sacked, t.snd_una);
        acked_up_to(t);

        if (t.cc && acked > 0) {
            if (!t.in_recovery) {
                t.cc->on_ack(acked);
            } else if (seq_geq(h.ack, t.recover)) {          // full ACK: recovery is over
                if (!t.recovery_by_timeout) t.cc->on_recovery_exit();
                t.in_recovery = false;
            } else {                                         // partial ACK: there is another hole at snd_una
                if (t.recovery_by_timeout) t.cc->on_ack(acked); else t.cc->on_partial_ack(acked);
                retransmit_head(t);
            }
        }
        if (acked > 0 && t.on_writable) t.on_writable();     // there is room in send_buf again
    }
    try_send(t);                                             // acked data or a bigger window: send more
    return true;
}
