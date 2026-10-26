// Everything that builds and transmits segments lives here.
#include <algorithm>
#include "tcp/tcp_layer.hpp"

// How many more bytes we can accept right now.
uint32_t TcpLayer::rcv_window(const Tcb& t) const {
    return static_cast<uint32_t>(t.recv_buf.free_space());
}

// The window we put in a segment. Silly-window avoidance (RFC 1122 4.2.3.3): when the app
// has only freed a little space, do NOT announce it; keep the old right edge. A bigger
// window is only announced once it grows by at least min(MSS, half the buffer).
uint16_t TcpLayer::advertised_window(Tcb& t, uint8_t flags) {
    uint32_t free_space = rcv_window(t);
    uint32_t wnd = free_space;
    if (!(flags & flag::SYN)) {
        uint32_t promised = seq_gt(t.rcv_adv_edge, t.rcv_nxt) ? t.rcv_adv_edge - t.rcv_nxt : 0;
        uint32_t step = std::min<uint32_t>(t.mss, uint32_t(t.recv_buf.capacity() / 2));
        if (free_space > promised && free_space - promised < step) wnd = promised;   // growth too small
        if (wnd > free_space) wnd = free_space;                                      // never promise more than we have
    }
    uint8_t shift = (flags & flag::SYN) ? 0 : t.rcv_wscale;      // a SYN's window is never scaled
    if (flags & flag::SYN) wnd = std::min<uint32_t>(wnd, 0xFFFF);
    wnd = (wnd >> shift) << shift;                               // the peer can only see multiples of 2^shift
    t.rcv_adv_edge = t.rcv_nxt + wnd;
    return static_cast<uint16_t>(std::min<uint32_t>(wnd >> shift, 0xFFFF));
}

// After the app read data: tell the peer if the window grew enough to be worth a segment.
void TcpLayer::maybe_send_window_update(Tcb& t) {
    if (t.fin_received) return;                              // the peer will not send more anyway
    uint32_t promised = seq_gt(t.rcv_adv_edge, t.rcv_nxt) ? t.rcv_adv_edge - t.rcv_nxt : 0;
    uint32_t step = std::min<uint32_t>(t.mss, uint32_t(t.recv_buf.capacity() / 2));
    if (rcv_window(t) >= promised + step) send_ack(t);
}

// Wrap a TCP segment in an IP packet and hand it to the wire.
void TcpLayer::send_raw(uint32_t src_ip, uint32_t dst_ip, const TcpHeader& h,
                        std::span<const uint8_t> options, std::span<const uint8_t> payload) {
    auto seg = build_tcp(src_ip, dst_ip, h, options, payload);
    out_(build_ipv4(src_ip, dst_ip, IpProto::TCP, seg, ip_id_++));
}

// The one function every normal segment goes through.
void TcpLayer::emit(Tcb& t, uint32_t seq, uint8_t flags, std::span<const uint8_t> payload) {
    TcpHeader h{};
    h.src_port = t.key.local_port;
    h.dst_port = t.key.remote_port;
    h.seq      = seq;
    h.ack      = (flags & flag::ACK) ? t.rcv_nxt : 0;
    h.flags    = flags;
    h.window   = advertised_window(t, flags);
    if (flags & flag::ACK) { t.unacked_segs = 0; t.delack_armed = false; }   // this segment carries the ACK
    auto opts  = build_options(t, flags);
    send_raw(t.key.local_ip, t.key.remote_ip, h, opts, payload);
}

// A bare ACK: "I have everything below rcv_nxt, and this is my window."
void TcpLayer::send_ack(Tcb& t) { emit(t, t.snd_nxt, flag::ACK); }

// A segment arrived for a connection that does not exist: answer with RST (RFC 9293 3.10.7.1).
void TcpLayer::send_reset_for(const Ipv4Header& ip, const TcpView& seg) {
    TcpHeader h{};
    h.src_port = seg.h.dst_port;
    h.dst_port = seg.h.src_port;
    if (seg.h.has(flag::ACK)) {
        h.seq   = seg.h.ack;                       // make the RST look like it came after what they saw
        h.flags = flag::RST;
    } else {
        uint32_t len = uint32_t(seg.payload.size()) + (seg.h.has(flag::SYN) ? 1u : 0u) +
                       (seg.h.has(flag::FIN) ? 1u : 0u);
        h.seq   = 0;
        h.ack   = seg.h.seq + len;
        h.flags = flag::RST | flag::ACK;
    }
    send_raw(ip.dst, ip.src, h, {}, {});
}
