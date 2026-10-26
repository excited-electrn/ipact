#include <algorithm>

#include "tcp_layer.hpp"

uint32_t TcpLayer::rcv_window(const Tcb& t) const {
    return static_cast<uint32_t>(t.recv_buf.free_space());
}

uint16_t TcpLayer::advertised_window(const Tcb& t, uint8_t /*flags*/) const {
    return static_cast<uint16_t>(std::min<uint32_t>(rcv_window(t), 0xFFFF));
}

void TcpLayer::send_raw(uint32_t src_ip, uint32_t dst_ip, const TcpHeader& h,
                   std::span<const uint8_t> options, std::span<const uint8_t> payload) {
    auto seg = build_tcp(src_ip, dst_ip, h, options, payload);
    out_(build_ipv4(src_ip, dst_ip, IpProto::TCP, seg, ip_id++));
}

void TcpLayer::emit(Tcb& t, uint32_t seq, uint8_t flags, std::span<const uint8_t> payload) {
    TcpHeader h{};
    h.src_port = t.key.local_port;
    h.dst_port = t.key.remote_port;
    h.seq = seq;
    h.ack = (flags & flag::ACK) ? t.rcv_nxt : 0;
    h.flags = flags;
    h.window = advertised_window(t, flags);
    auto opts = build_options(t, flags);
    send_raw(t.key.local_ip, t.key.remote_ip, h, opts, payload);
}

void TcpLayer::send_ack(Tcb& t) {
    emit (t, t.snd_nxt, flag::ACK);
}

void TcpLayer::send_reset_for(const Ipv4Header& ip, const TcpView& seg) {
    TcpHeader h{};
    h.src_port = seg.header.dst_port;
    h.dst_port = seg.header.src_port;

    if (seg.header.has(flag::ACK)) {
        h.seq = seg.header.ack;
        h.flags = flag::RST;
    } else {
        uint32_t len = uint32_t(seg.payload.size()) + (seg.header.has(flag::SYN) ? 1u : 0u) + (seg.header.has(flag::FIN) ? 1u : 0u);
        h.seq = 0;
        h.ack = seg.header.seq + len;
        h.flags = flag::RST | flag::ACK;
    }

    send_raw(ip.dst, ip.src, h, {}, {});
}