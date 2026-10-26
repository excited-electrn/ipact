#include <cerrno>
#include "tcp/tcp_layer.hpp"
#include "util/log.hpp"

namespace {
    uint32_t seg_len(const TcpView& s) {
        return uint32_t(s.payload.size()) + (s.header.has(flag::SYN) ? 1u : 0u) + (s.header.has(flag::FIN) ? 1u : 0u);
    }
}

TcpLayer::TcpLayer(TcpConfig cfg, SendPacket out, ClockFn clock)
    : cfg_(std::move(cfg))
    , out_(std::move(out))
    , clock_(std::move(clock))
    , rng_(cfg_.rng_seed)
{}

uint32_t TcpLayer::pick_isn() {
    return cfg_.fixed_isn ? *cfg_.fixed_isn : static_cast<uint32_t>(rng_());
}

void TcpLayer::set_state(Tcb& t, State s) {
    LOG("[%s:%u <-> %s:%u] %s -> %s", ip_to_string(t.key.local_ip).c_str(), t.key.local_port,
        ip_to_string(t.key.remote_ip).c_str(), t.key.remote_port, to_string(t.state), to_string(s));
    t.state = s;
}

void TcpLayer::destroy(Tcb& t, int err) {
    std::shared_ptr<Tcb> keep;
    if (auto it = conns_.find(t.key); it != conns_.end()) {
        keep = it->second;
        conns_.erase(it);
    }
    if (t.state != State::Closed) set_state(t, State::Closed);
    t.error = err;
    auto closed = std::move(t.on_closed);
    t.on_connected = nullptr;
    t.on_readable = nullptr;
    t.on_writable = nullptr;
    t.on_eof = nullptr;
    t.on_closed = nullptr;
    if (closed) closed(err);
}

void TcpLayer::enter_time_wait(Tcb& t) {
    set_state(t, State::TimeWait);
    t.timewait_deadline = now() + std::chrono::duration_cast<Clock::duration>(cfg_.time_wait);
}

void TcpLayer::become_established(Tcb& t) {
    set_state(t, State::Established);
    if (t.passive) {
        auto it = listeners_.find(t.key.local_port);
        if (it != listeners_.end()) {
            auto fn = it->second;
            fn(conns_.at(t.key));
        }
    } else if (t.on_connected) {
        t.on_connected();
    }
}

// application side

void TcpLayer::listen(uint16_t port, AcceptFn on_accept) {
    listeners_[port] = std::move(on_accept);
}

std::shared_ptr<Tcb> TcpLayer::connect(uint32_t remote_ip, uint16_t remote_port) {
    ConnKey key{cfg_.local_ip, remote_ip, 0, remote_port};
    do {
        key.local_port = next_port++;
        if (next_port == 0) next_port = 49152;
    } while (conns_.count(key));

    auto t = std::make_shared<Tcb>(cfg_.send_buf_size, cfg_.recv_buf_size);
    t->key = key;
    t->iss = pick_isn();
    t->snd_una = t->iss;
    t->snd_nxt = t->iss + 1;
    conns_[key] = t;
    set_state(*t, State::SynSent);
    emit(*t, t->iss, flag::SYN);
    sent_new(*t);
    return t;
}

void TcpLayer::close(Tcb& t) {
    switch (t.state)
    {
    case State::SynSent:
        destroy(t, 0);
        break;
    case State::SynReceived:
        abort(t);
        break;
    case State::Established:
    case State::CloseWait:
        t.fin_queued = true;
        try_send(t);
        break;
    default:
        break;
    }
}

void TcpLayer::abort(Tcb& t) {
    if (t.state != State::Closed && t.state != State::SynSent) {
        emit(t, t.snd_nxt, flag::RST | flag::ACK);
    }
    destroy(t, ECONNABORTED);
}


// packets in
void TcpLayer::on_ip_packet(const Ipv4View& ip) {
    auto seg = parse_tcp(ip.header.src, ip.header.dst, ip.payload);
    if (!seg) {
        LOG("TCP: bad segment dropped");
        return;
    }

    ConnKey key{ip.header.dst, ip.header.src, seg->header.dst_port, seg->header.src_port};
    if (auto it = conns_.find(key); it != conns_.end()) {
        auto t = it->second;
        segment_arrives(*t, *seg);
        return;
    }

    if (seg->header.has(flag::RST)) return;
    if (seg->header.has(flag::SYN) && !seg->header.has(flag::ACK) && listeners_.count(seg->header.dst_port)) {
        passive_open(ip.header, *seg);
        return;
    }
    send_reset_for(ip.header, *seg);
}

void TcpLayer::passive_open(const Ipv4Header& ip, const TcpView& seg) {
    auto t = std::make_shared<Tcb>(cfg_.send_buf_size, cfg_.recv_buf_size);
    t->key = ConnKey{ip.dst, ip.src, seg.header.dst_port, seg.header.src_port};
    t->passive = true;
    t->irs = seg.header.seq;
    t->rcv_nxt = seg.header.seq + 1;
    t->iss = pick_isn();
    t->snd_una = t->iss;
    t->snd_nxt = t->iss + 1;
    t->snd_wnd = seg.header.window;
    t->snd_wl1 = seg.header.seq;
    t->snd_wl2 = t->iss;
    read_peer_options(*t, seg);
    conns_[t->key] = t;
    set_state(*t, State::SynReceived);
    emit(*t, t->iss, flag::SYN | flag::ACK);
    sent_new(*t);
}

bool TcpLayer::acceptable(const Tcb& t, const TcpView& seg) const {
    uint32_t len = seg_len(seg);
    uint32_t wnd = rcv_window(t);
    uint32_t seq = seg.header.seq;
    if (len == 0) {
        return (wnd == 0 ? seq == t.rcv_nxt : seq_in_range(seq, t.rcv_nxt, t.rcv_nxt + wnd));
    }
    if (wnd == 0) return false;
    return seq_in_range(seq, t.rcv_nxt, t.rcv_nxt + wnd) || seq_in_range(seq + len - 1, t.rcv_nxt, t.rcv_nxt + wnd);
}

void TcpLayer::handle_syn_sent(Tcb& t, const TcpView& seg) {
    const TcpHeader& h = seg.header;
    bool ack_ok = false;
    if (h.has(flag::ACK)) {
        if (seq_leq(h.ack, t.iss) || seq_gt(h.ack, t.snd_nxt)) {
            if (!h.has(flag::RST)) emit(t, h.ack, flag::RST);
            return;
        }
        ack_ok = true;
    }

    if (h.has(flag::RST)) {
        if (ack_ok) destroy(t, ECONNREFUSED);
        return;
    }

    if (!h.has(flag::SYN)) return;

    t.irs = h.seq;
    t.rcv_nxt = h.seq + 1;
    t.snd_wnd = h.window;
    t.snd_wl1 = h.seq;
    t.snd_wl2 = h.ack;
    read_peer_options(t, seg);

    if (ack_ok) {
        t.snd_una = h.ack;
        acked_up_to(t);
        send_ack(t);
        become_established(t);
    } else {
        set_state(t, State::SynReceived);
        emit(t, t.iss, flag::SYN | flag::ACK);
    }
}

void TcpLayer::handle_rst(Tcb& t, const TcpView& seg) {
    if (t.state == State::TimeWait) return;
    if (seg.header.seq == t.rcv_nxt) destroy(t, ECONNRESET);
    else send_ack(t);
}

void TcpLayer::handle_fin(Tcb& t, const TcpView& seg) {
    if (!seg.header.has(flag::FIN)) return;
    uint32_t fin_at = seg.header.seq + uint32_t(seg.payload.size());
    if (fin_at != t.rcv_nxt) return;
    if (t.state != State::Established &&
        t.state != State::FinWait1 &&
        t.state != State::FinWait2) {
            return;
    }

    t.fin_received = true;
    t.rcv_nxt += 1;
    send_ack(t);
    switch (t.state)
    {
    case State::Established:
        set_state(t, State::CloseWait);
        break;
    case State::FinWait1:
        set_state(t, State::Closing);
        break;
    case State::FinWait2:
        enter_time_wait(t);
        break;
    default:
        break;
    }
    if (t.on_eof) t.on_eof();
}

void TcpLayer::segment_arrives(Tcb& t, const TcpView& seg) {
    const TcpHeader& h = seg.header;
    if (t.state == State::SynSent) {
        handle_syn_sent(t, seg);
        return;
    }

    // Our syn + ack was lost, so they sent the syn again, answer again
    if (t.state == State::SynReceived && h.has(flag::SYN) &&
        !h.has(flag::ACK) &&
        h.seq == t.irs) {
            emit(t, t.iss, flag::SYN | flag::ACK);
            return;
    }

    // 1. is it inside the window?
    if (!acceptable(t, seg)) {
        if (!h.has(flag::RST)) {
            send_ack(t);
            if (t.state == State::TimeWait) enter_time_wait(t);
        }
        return;
    }

    // 2. rst
    if (h.has(flag::RST)) {
        handle_rst(t, seg);
        return;
    }

    // 3. syn inside window of exisiting connectionn
    if (h.has(flag::SYN)) {
        send_ack(t);
        return;
    }

    // 4. Everything here needs ack
    if (!h.has(flag::ACK)) return;

    read_peer_options(t, seg);

    // 5. ack that completes handshake
    if (t.state == State::SynReceived) {
        if (!(seq_lt(t.snd_una, h.ack) &&
              seq_leq(h.ack, t.snd_nxt))) {
                emit(t, h.ack, flag::RST);
                return;
        }

        t.snd_una = h.ack;
        acked_up_to(t);
        update_send_window(t, h);
        become_established(t);
    }

    if (!process_ack(t, seg)) return;

    // did that ack aknowledge our FIN?
    if (t.fin_sent && seq_gt(t.snd_una, t.fin_seq)) {
        if (t.state == State::FinWait1) set_state(t, State::FinWait2);
        else if (t.state == State::FinWait2) enter_time_wait(t);
        else if (t.state == State::LastAck) {
            destroy(t, 0);
            return;
        }
    }

    // 6. data 
    process_payload(t, seg);

    // 7. fin
    handle_fin(t, seg);
}