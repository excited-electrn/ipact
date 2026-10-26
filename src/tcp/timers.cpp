#include <algorithm>
#include "tcp/tcp_layer.hpp"

void TcpLayer::tick() {
    std::vector<std::shared_ptr<Tcb>> all;               
    for (auto& [key, t] : conns_) all.push_back(t);
    for (auto& t : all)
        if (t->state == State::TimeWait && now() >= t->timewait_deadline) destroy(*t, 0);
}

std::optional<Time> TcpLayer::next_deadline() const {
    std::optional<Time> best;
    for (auto& [key, t] : conns_)
        if (t->state == State::TimeWait && (!best || t->timewait_deadline < *best)) best = t->timewait_deadline;
    return best;
}

void TcpLayer::sent_new(Tcb&) {}
void TcpLayer::acked_up_to(Tcb&) {}