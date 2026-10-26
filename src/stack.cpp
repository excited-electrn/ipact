// The blocking API on top of the event-driven TcpLayer.
//
// Threads:  one "stack thread" runs Engine::run(). Application threads call send/recv/accept.
// Locking:  every touch of the TcpLayer, from either side, holds engine.mutex().
// Waiting:  an app thread waits on a condition variable (which releases the mutex);
//           the TcpLayer's callbacks, running on the stack thread, notify it.
#include "ipact/stack.hpp"
#include <arpa/inet.h>
#include <condition_variable>
#include <deque>
#include <system_error>
#include <thread>
#include "engine.hpp"
#include "util/log.hpp"

namespace ipact {

namespace {
[[noreturn]] void fail(int err, const char* what) { throw std::system_error(err, std::generic_category(), what); }

uint32_t parse_ip(const std::string& s) {
    in_addr a{};
    if (inet_pton(AF_INET, s.c_str(), &a) != 1) fail(EINVAL, "not an IPv4 address");
    return ntohl(a.s_addr);
}

EngineConfig make_config(const Options& o) {
    EngineConfig c = EngineConfig::from_env();               // keeps the IPACT_* environment knobs working
    c.tun_name = o.tun_name;
    c.tcp.local_ip = parse_ip(o.local_ip);
    if (!o.pcap_path.empty()) c.pcap_path = o.pcap_path;
    return c;
}
}  // namespace

struct Core {
    explicit Core(const Options& o) : options(o), engine(make_config(o)) {
        thread = std::thread([this] { engine.run(); });
    }
    ~Core() {
        engine.stop();
        thread.join();
        std::lock_guard<std::mutex> lock(engine.mutex());
        engine.tcp().shutdown();                              // break the connection <-> callback cycles
    }
    Options options;
    Engine engine;
    std::thread thread;
};

// ------------------------------------------------------------------ Connection

struct Connection::Impl : std::enable_shared_from_this<Connection::Impl> {
    Core* core = nullptr;
    std::shared_ptr<Tcb> tcb;
    std::condition_variable cv;
    bool connected = false;
    bool closed = false;                                     // the TcpLayer has forgotten the connection
    int error = 0;

    std::mutex& mu() { return core->engine.mutex(); }
    TcpLayer& tcp() { return core->engine.tcp(); }

    bool can_send() const {
        return (tcb->state == State::Established || tcb->state == State::CloseWait) && !tcb->fin_queued;
    }

    // Connect the TcpLayer's callbacks to our condition variable. Call with the lock held.
    void hook() {
        auto self = shared_from_this();                      // the callbacks keep us alive; destroy() clears them
        tcb->on_connected = [self] { self->connected = true; self->cv.notify_all(); };
        tcb->on_readable  = [self] { self->cv.notify_all(); };
        tcb->on_writable  = [self] { self->cv.notify_all(); };
        tcb->on_eof       = [self] { self->cv.notify_all(); };
        tcb->on_closed    = [self](int err) { self->closed = true; self->error = err; self->cv.notify_all(); };
    }
};

size_t Connection::send(const void* data, size_t len) {
    if (!impl_) fail(EBADF, "send on an empty Connection");
    Impl& I = *impl_;
    std::unique_lock<std::mutex> lock(I.mu());
    auto* p = static_cast<const uint8_t*>(data);
    size_t done = 0;
    while (done < len) {
        I.cv.wait(lock, [&] { return I.closed || !I.can_send() || I.tcb->send_buf.free_space() > 0; });
        if (I.closed) fail(I.error ? I.error : EPIPE, "send");
        if (!I.can_send()) fail(EPIPE, "send after close");
        done += I.tcp().send(*I.tcb, std::span<const uint8_t>(p + done, len - done));
    }
    return len;
}

size_t Connection::recv(void* buf, size_t len) {
    if (!impl_) fail(EBADF, "recv on an empty Connection");
    Impl& I = *impl_;
    std::unique_lock<std::mutex> lock(I.mu());
    I.cv.wait(lock, [&] { return !I.tcb->recv_buf.empty() || I.tcb->fin_received || I.closed; });
    if (!I.tcb->recv_buf.empty()) return I.tcp().read(*I.tcb, std::span<uint8_t>(static_cast<uint8_t*>(buf), len));
    if (I.error) fail(I.error, "recv");
    return 0;                                                // the peer closed: end of stream
}

void Connection::close() {
    if (!impl_) return;
    std::lock_guard<std::mutex> lock(impl_->mu());
    if (!impl_->closed) impl_->tcp().close(*impl_->tcb);
}

void Connection::set_nodelay(bool on) {
    if (!impl_) return;
    std::lock_guard<std::mutex> lock(impl_->mu());
    impl_->tcb->nodelay = on;
}

std::string Connection::peer() const {
    if (!impl_) return "";
    return ip_to_string(impl_->tcb->key.remote_ip) + ":" + std::to_string(impl_->tcb->key.remote_port);
}

ConnectionStats Connection::stats() const {
    ConnectionStats s;
    if (!impl_) return s;
    std::lock_guard<std::mutex> lock(impl_->mu());
    const Tcb& t = *impl_->tcb;
    s.retransmits = t.stats.retransmits;
    s.fast_retransmits = t.stats.fast_retransmits;
    s.timeouts = t.stats.timeouts;
    s.bytes_in_flight = t.data_in_flight();
    if (t.cc) {
        s.cwnd = t.cc->cwnd();
        s.ssthresh = t.cc->ssthresh() == UINT32_MAX ? 0 : t.cc->ssthresh();
    }
    s.srtt_ms = t.rtt.srtt().count();
    s.rto_ms = t.rtt.rto().count();
    return s;
}

// ------------------------------------------------------------------ Listener

struct Listener::Impl {
    Core* core = nullptr;
    std::condition_variable cv;
    std::deque<Connection> ready;
};

Connection Listener::accept() {
    Impl& L = *impl_;
    std::unique_lock<std::mutex> lock(L.core->engine.mutex());
    L.cv.wait(lock, [&] { return !L.ready.empty(); });
    Connection c = std::move(L.ready.front());
    L.ready.pop_front();
    return c;
}

// ------------------------------------------------------------------ Stack

Stack::Stack(Options options) : core_(std::make_unique<Core>(options)) {}
Stack::~Stack() = default;

Listener Stack::listen(uint16_t port) {
    auto impl = std::make_shared<Listener::Impl>();
    impl->core = core_.get();
    Core* core = core_.get();
    std::lock_guard<std::mutex> lock(core->engine.mutex());
    core->engine.tcp().listen(port, [impl, core](const std::shared_ptr<Tcb>& tcb) {
        // Runs on the stack thread with the lock held, right when the handshake completes.
        auto c = std::make_shared<Connection::Impl>();
        c->core = core;
        c->tcb = tcb;
        c->hook();
        Connection conn;
        conn.impl_ = c;
        impl->ready.push_back(std::move(conn));
        impl->cv.notify_all();
    });
    Listener l;
    l.impl_ = impl;
    return l;
}

Connection Stack::connect(const std::string& ip, uint16_t port) {
    auto impl = std::make_shared<Connection::Impl>();
    impl->core = core_.get();
    std::unique_lock<std::mutex> lock(core_->engine.mutex());
    impl->tcb = core_->engine.tcp().connect(parse_ip(ip), port);
    impl->hook();
    bool done = impl->cv.wait_for(lock, std::chrono::milliseconds(core_->options.connect_timeout_ms),
                                  [&] { return impl->connected || impl->closed; });
    if (!done) {                                             // nobody answered
        core_->engine.tcp().abort(*impl->tcb);
        fail(ETIMEDOUT, "connect");
    }
    if (!impl->connected) fail(impl->error ? impl->error : ECONNABORTED, "connect");   // e.g. ECONNREFUSED
    Connection conn;
    conn.impl_ = impl;
    return conn;
}

}  // namespace ipact
