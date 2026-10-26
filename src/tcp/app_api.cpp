// The two functions an application uses to move bytes.
#include "tcp/tcp_layer.hpp"

// Copy as much of `data` as fits into the send buffer, then try to transmit.
// Returns how many bytes were accepted (less than data.size() when the buffer is full:
// wait for on_writable and offer the rest again).
size_t TcpLayer::send(Tcb& t, std::span<const uint8_t> data) {
    if (t.fin_queued || (t.state != State::Established && t.state != State::CloseWait)) return 0;
    size_t n = t.send_buf.write(data);
    try_send(t);
    return n;
}

// Take bytes out of the receive buffer. Returns 0 if it is empty (check t.fin_received
// to tell "nothing yet" from "the peer is done").
size_t TcpLayer::read(Tcb& t, std::span<uint8_t> out) {
    size_t n = t.recv_buf.read(out);
    if (n > 0 && t.state != State::Closed) maybe_send_window_update(t);
    return n;
}
