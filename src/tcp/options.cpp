// TCP options: offering them in a SYN, agreeing on them, and using them afterwards.
//   MSS ......... largest segment each side wants
//   Window scale  windows larger than 65535
//   Timestamps .. better RTT measurement, echoed back by the peer
//   SACK ........ the receiver reports which out-of-order blocks it holds
#include <algorithm>
#include "tcp/options.hpp"
#include "tcp/tcp_layer.hpp"
#include "util/log.hpp"

uint32_t TcpLayer::ts_now() const {
    return uint32_t(std::chrono::duration_cast<std::chrono::milliseconds>(now().time_since_epoch()).count());
}

// The options to put on a segment we are about to send.
std::vector<uint8_t> TcpLayer::build_options(const Tcb& t, uint8_t flags) {
    if (flags & flag::RST) return {};
    OptionWriter w;

    if (flags & flag::SYN) {
        bool reply = flags & flag::ACK;        // SYN+ACK may only contain what the peer offered AND we accepted
        w.mss(cfg_.mss);
        if (reply ? t.sack_ok : cfg_.want_sack) w.sack_permitted();
        if (reply ? t.ts_ok : cfg_.want_timestamps) w.timestamps(ts_now(), t.ts_recent);
        if (reply ? t.ws_ok : cfg_.want_wscale) { w.nop(); w.wscale(wscale_for(t.recv_buf.capacity())); }
        return w.finish();
    }

    if (t.ts_ok) { w.nop(); w.nop(); w.timestamps(ts_now(), t.ts_recent); }
    if (t.sack_ok && (flags & flag::ACK) && !t.ooo.empty()) {
        // 40 bytes is the maximum: timestamps need 12, so 3 SACK blocks fit; without them, 4.
        auto blocks = make_sack_blocks(t.ooo, t.last_ooo_seq, t.ts_ok ? 3 : 4);
        if (!blocks.empty()) { w.nop(); w.nop(); w.sack(blocks); }
    }
    return w.finish();
}

// Look at the options of a segment we accepted.
void TcpLayer::read_peer_options(Tcb& t, const TcpView& seg) {
    auto parsed = parse_options(seg.options);
    if (!parsed) { LOG("tcp: malformed options ignored"); return; }
    const TcpOptions& o = *parsed;

    if (seg.h.has(flag::SYN)) {
        // Negotiation. An option is in use only if both sides want it.
        t.mss        = o.mss ? std::min<uint16_t>(*o.mss, cfg_.mss) : uint16_t(536);   // no MSS option: RFC default
        t.ws_ok      = cfg_.want_wscale && o.wscale.has_value();
        t.snd_wscale = t.ws_ok ? std::min<uint8_t>(*o.wscale, 14) : uint8_t(0);
        t.rcv_wscale = t.ws_ok ? wscale_for(t.recv_buf.capacity()) : uint8_t(0);
        t.sack_ok    = cfg_.want_sack && o.sack_permitted;
        t.ts_ok      = cfg_.want_timestamps && o.timestamp.has_value();
        if (t.ts_ok) t.ts_recent = o.timestamp->first;
        LOG("options: mss=%u wscale=%s(snd %u, rcv %u) sack=%d timestamps=%d", t.mss, t.ws_ok ? "on" : "off",
            t.snd_wscale, t.rcv_wscale, int(t.sack_ok), int(t.ts_ok));
        return;
    }

    if (t.ts_ok && o.timestamp) {
        auto [tsval, tsecr] = *o.timestamp;
        // Remember the newest TSval to echo it back. (A complete stack would also use it for PAWS.)
        if (seq_leq(seg.h.seq, t.rcv_nxt) && int32_t(tsval - t.ts_recent) >= 0) t.ts_recent = tsval;
        // The peer echoes the TSval we sent, so now - TSecr is a round trip. No Karn's rule needed.
        if (seg.h.has(flag::ACK) && tsecr != 0 && seq_gt(seg.h.ack, t.snd_una)) {
            uint32_t rtt_ms = ts_now() - tsecr;
            if (rtt_ms < 60000) t.rtt.on_sample(RttEstimator::ms(double(rtt_ms)));
        }
    }
    if (t.sack_ok) {
        for (auto& b : o.sack)                                  // only believe blocks that make sense
            if (seq_lt(b.left, b.right) && seq_gt(b.left, t.snd_una) && seq_leq(b.right, t.snd_nxt))
                sack_add(t.sacked, b.left, b.right);
    }
}
