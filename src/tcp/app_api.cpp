#include "tcp/tcp_layer.hpp"

size_t TcpLayer::send(Tcb& t, std::span<const uint8_t> data) {
    if (t.fin_queued || (t.state != State::Established && t.state != State::CloseWait)) return 0;
    size_t n = t.send_buf.write(data);
    try_send(t);
    return n;
}

size_t TcpLayer::read(Tcb& t, std::span<uint8_t> out) {
    size_t n =  t.recv_buf.read(out);
    if (n > 0 && t.state != State::Closed) maybe_send_window_update(t);
    return n;
}