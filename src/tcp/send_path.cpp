#include "tcp/tcp_layer.hpp"

void TcpLayer::try_send(Tcb& t) {
    if (t.state != State::Established && t.state != State::CloseWait) return;
    if (t.fin_queued && !t.fin_sent) {
        t.fin_seq = t.snd_nxt;
        emit(t, t.snd_nxt, flag::FIN | flag::ACK);
        t.snd_nxt += 1;                                  
        t.fin_sent = true;
        sent_new(t);
        set_state(t, t.state == State::Established ? State::FinWait1 : State::LastAck);
    }
}

void TcpLayer::update_send_window(Tcb& t, const TcpHeader& h) {
    if (seq_lt(t.snd_wl1, h.seq) || (t.snd_wl1 == h.seq && seq_leq(t.snd_wl2, h.ack))) {
        t.snd_wnd = uint32_t(h.window) << t.snd_wscale;
        t.snd_wl1 = h.seq;
        t.snd_wl2 = h.ack;
    }
}

bool TcpLayer::process_ack(Tcb& t, const TcpView& seg) {
    const TcpHeader& h = seg.header;
    if (seq_gt(h.ack, t.snd_nxt)) {        
        send_ack(t);
        return false;
    }
    if (seq_lt(h.ack, t.snd_una)) return true;  
    update_send_window(t, h);
    if (seq_gt(h.ack, t.snd_una)) {
        t.snd_una = h.ack;                       
        acked_up_to(t);
    }
    return true;
}