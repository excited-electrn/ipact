// Everything about data arriving from the peer.
#include <algorithm>
#include "tcp/tcp_layer.hpp"

// Called for every acceptable segment in a state that can receive data.
void TcpLayer::process_payload(Tcb& t, const TcpView& seg) {
    if (t.state != State::Established && t.state != State::FinWait1 && t.state != State::FinWait2) return;
    if (seg.payload.empty()) return;

    uint32_t seq = seg.h.seq;
    std::span<const uint8_t> data = seg.payload;

    // 1. Cut off the front if we already have those bytes (a retransmission that overlaps).
    if (seq_lt(seq, t.rcv_nxt)) {
        uint32_t skip = t.rcv_nxt - seq;
        if (skip >= data.size()) { send_ack(t); return; }    // entirely old: just re-acknowledge
        data = data.subspan(skip);
        seq = t.rcv_nxt;
    }
    // 2. Cut off the tail if it does not fit in our window.
    uint32_t wnd = rcv_window(t);
    uint32_t offset = seq - t.rcv_nxt;                       // gap between what we expect and this data
    if (offset >= wnd) { send_ack(t); return; }
    if (data.size() > wnd - offset) data = data.first(wnd - offset);

    if (seq == t.rcv_nxt) {
        // 3a. In order: append, then pull in any stored data that is now contiguous.
        bool had_holes = !t.ooo.empty();
        size_t n = t.recv_buf.write(data);
        t.rcv_nxt += uint32_t(n);
        while (!t.ooo.empty()) {
            auto it = t.ooo.begin();
            if (seq_gt(it->first, t.rcv_nxt)) break;                         // still a hole
            uint32_t end = it->first + uint32_t(it->second.size());
            if (seq_gt(end, t.rcv_nxt)) {                                    // has bytes we still need
                std::span<const uint8_t> rest(it->second);
                rest = rest.subspan(t.rcv_nxt - it->first);
                t.rcv_nxt += uint32_t(t.recv_buf.write(rest));
            }
            t.ooo.erase(it);
        }
        // ACK policy (RFC 5681): immediately if a hole existed (this may have filled it) or on
        // every second segment; otherwise wait a moment, hoping to piggyback on outgoing data.
        t.unacked_segs += 1;
        if (had_holes || t.unacked_segs >= 2) send_ack(t);
        else arm_delack(t);
        if (t.on_readable) t.on_readable();
    } else {
        // 3b. Out of order: keep it until the hole is filled, and complain immediately with a
        // duplicate ACK that says what we still need.
        auto& slot = t.ooo[seq];
        if (slot.size() < data.size()) slot.assign(data.begin(), data.end());
        t.last_ooo_seq = seq;                                // the first SACK block must contain this segment
        send_ack(t);
    }
}
