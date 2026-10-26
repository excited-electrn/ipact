#include "tcp/tcp_layer.hpp"

std::vector<uint8_t> TcpLayer::build_options(const Tcb& /*t*/, uint8_t /*flags*/) {
    return {};
}

void TcpLayer::read_peer_options(Tcb& /*t*/, const TcpView& /*seg*/) {}