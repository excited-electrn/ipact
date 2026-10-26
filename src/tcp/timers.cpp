// All timers: retransmission (RTO) and TIME_WAIT.
#include <algorithm>
#include <cerrno>
#include "tcp/tcp_layer.hpp"
#include "util/log.hpp"

namespace {
Clock::duration to_clock(RttEstimator::ms d) { return std::chrono::duration_cast<Clock::duration>(d); }
}

void TcpLayer::arm_rto(Tcb& t) {
    t.rto_armed = true;
    t.rto_deadline = now() + to_clock(t.rtt.rto());
}

void TcpLayer::stop_rto(Tcb& t) { t.rto_armed = false; }

void TcpLayer::arm_delack(Tcb& t) {
    if (t.delack_armed) return;                           // already waiting: do not push the deadline back
    t.delack_armed = true;
    t.delack_deadline = now() + std::chrono::duration_cast<Clock::duration>(cfg_.delayed_ack);
}

// Probe delay: the RTO, doubled after every probe, at most 60 s.
void TcpLayer::arm_persist(Tcb& t) {
    auto delay = std::min(t.rtt.rto() * double(1 << t.persist_backoff), RttEstimator::ms(60000));
    t.persist_armed = true;
    t.persist_deadline = now() + to_clock(delay);
}

// The peer's window has been closed for a while and we have data waiting. Send a probe with
// an OLD sequence number: the peer must answer with an ACK, and that ACK carries its window.
void TcpLayer::on_persist(Tcb& t) {
    LOG("persist: probing the peer's window (backoff %d)", t.persist_backoff);
    emit(t, t.snd_una - 1, flag::ACK);
    t.persist_backoff = std::min(t.persist_backoff + 1, 8);
    arm_persist(t);
}

// Called right after we transmit sequence space (SYN, data or FIN) for the FIRST time.
void TcpLayer::sent_new(Tcb& t) {
    if (!t.rto_armed) arm_rto(t);                         // the timer runs whenever something is unacknowledged
    if (!t.rtt_active) {                                  // time one segment at a time
        t.rtt_active = true;
        t.rtt_seq = t.snd_nxt;
        t.rtt_start = now();
    }
}

// Called after snd_una moved forward (new data was acknowledged).
void TcpLayer::acked_up_to(Tcb& t) {
    t.retries = 0;
    t.rtt.reset_backoff();                                // progress: the path works, stop doubling
    if (t.rtt_active && seq_geq(t.snd_una, t.rtt_seq)) {  // the timed segment is acknowledged: one RTT sample
        t.rtt.on_sample(std::chrono::duration_cast<RttEstimator::ms>(now() - t.rtt_start));
        t.rtt_active = false;
    }
    if (t.snd_una == t.snd_nxt) stop_rto(t);              // nothing outstanding: no timer
    else arm_rto(t);                                      // progress: restart the timer for the next segment
}

// Resend the oldest thing the peer has not acknowledged.
void TcpLayer::retransmit_head(Tcb& t) {
    t.rtt_active = false;                                 // Karn's rule: never time a retransmitted segment
    if (t.state == State::SynSent)     { emit(t, t.iss, flag::SYN); return; }
    if (t.state == State::SynReceived) { emit(t, t.iss, flag::SYN | flag::ACK); return; }

    uint32_t in_flight = t.data_in_flight();
    if (in_flight > 0) {
        std::vector<uint8_t> payload(std::min<uint32_t>(in_flight, t.mss));
        t.send_buf.peek(0, payload);                      // byte 0 of send_buf is snd_una
        emit(t, t.snd_una, flag::ACK, payload);
    } else if (t.fin_sent && seq_leq(t.snd_una, t.fin_seq)) {
        emit(t, t.fin_seq, flag::FIN | flag::ACK);
    }
}

void TcpLayer::on_rto(Tcb& t) {
    if (++t.retries > cfg_.max_retries) {
        LOG("rto: giving up after %d retries", t.retries - 1);
        destroy(t, ETIMEDOUT);
        return;
    }
    LOG("rto: timeout #%d, retransmitting seq %u", t.retries, t.snd_una);
    t.rtt.on_timeout();                                   // exponential back-off
    retransmit_head(t);
    arm_rto(t);
}

void TcpLayer::tick() {
    std::vector<std::shared_ptr<Tcb>> all;                // copy: destroy() edits conns_
    for (auto& [key, t] : conns_) all.push_back(t);
    for (auto& t : all) {
        if (t->state == State::Closed) continue;          // destroyed by a callback earlier in this loop
        if (t->state == State::TimeWait) {
            if (now() >= t->timewait_deadline) destroy(*t, 0);
            continue;
        }
        if (t->rto_armed && now() >= t->rto_deadline) on_rto(*t);
        if (t->state == State::Closed) continue;
        if (t->delack_armed && now() >= t->delack_deadline) send_ack(*t);   // emit() clears the flag
        if (t->persist_armed && now() >= t->persist_deadline) on_persist(*t);
    }
}

std::optional<Time> TcpLayer::next_deadline() const {
    std::optional<Time> best;
    auto consider = [&best](Time d) { if (!best || d < *best) best = d; };
    for (auto& [key, t] : conns_) {
        if (t->state == State::TimeWait) { consider(t->timewait_deadline); continue; }
        if (t->rto_armed) consider(t->rto_deadline);
        if (t->delack_armed) consider(t->delack_deadline);
        if (t->persist_armed) consider(t->persist_deadline);
    }
    return best;
}