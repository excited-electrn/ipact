#include "tcp/tcp_layer.hpp"

void TcpLayer::process_payload(Tcb& t, const TcpView& seg) {
    if (t.state != State::Established && t.state != State::FinWait1 && t.state != State::FinWait2) return;
    if (seg.payload.empty()) return;
    if (seg.header.seq == t.rcv_nxt) {
        size_t n = t.recv_buf.write(seg.payload);
        t.rcv_nxt += static_cast<uint32_t>(n);
        if (n > 0 && t.on_readable) t.on_readable();
    }
    send_ack(t);        
}