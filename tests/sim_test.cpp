// Layer 2: deterministic simulation.
//
// Two TcpLayer instances (host A = 10.0.0.1, host B = 10.0.0.2) are connected by an in-memory
// "wire" that can drop, duplicate, delay and reorder packets. Time is a variable we move
// ourselves, so a transfer that takes 10 minutes of network time runs in milliseconds, and
// every run with the same seed behaves identically. A failing seed is a permanent test case.
#include <algorithm>
#include <cerrno>
#include <functional>
#include <map>
#include <optional>
#include <random>
#include "check.hpp"
#include "tcp/tcp_layer.hpp"

namespace {

using std::chrono::milliseconds;
using std::chrono::seconds;

constexpr uint32_t kA = 0x0A000001, kB = 0x0A000002;

uint8_t pattern(size_t i) { return uint8_t((i * 2654435761ull) >> 13); }   // the bytes we transfer

struct Impairment {
    double loss = 0.0;             // probability that a packet vanishes
    double duplicate = 0.0;        // probability that a packet arrives twice
    int delay_ms = 5;              // one-way delay
    int jitter_ms = 0;             // extra random delay 0..jitter: this is what reorders packets
};

class Sim {
public:
    explicit Sim(uint32_t seed, TcpConfig base = {})
        : rng_(seed),
          now_(Time{} + seconds(1000)),
          a_(host_config(base, kA, seed * 2 + 1), [this](std::vector<uint8_t> p) { transmit(0, std::move(p)); }, [this] { return now_; }),
          b_(host_config(base, kB, seed * 2 + 2), [this](std::vector<uint8_t> p) { transmit(1, std::move(p)); }, [this] { return now_; }) {}

    TcpLayer& a() { return a_; }
    TcpLayer& b() { return b_; }
    Time now() const { return now_; }
    Impairment imp;
    std::function<bool(int from, const std::vector<uint8_t>& pkt)> drop_filter;   // scripted losses
    std::function<void()> observer;                                             // called after every event
    std::optional<Time> wake_at;                                                // one extra wake-up for the test
    std::function<void()> on_wake;
    uint64_t packets_sent[2] = {0, 0};

    // Advance time event by event until done() is true. Returns false if time ran out (or stalled).
    bool run(const std::function<bool()>& done, Clock::duration limit) {
        Time end = now_ + limit;
        for (long guard = 0; guard < 20'000'000; ++guard) {
            if (done()) return true;
            std::optional<Time> next;
            auto consider = [&next](std::optional<Time> t) { if (t && (!next || *t < *next)) next = t; };
            if (!queue_.empty()) consider(queue_.begin()->first);
            consider(a_.next_deadline());
            consider(b_.next_deadline());
            consider(wake_at);
            if (!next || *next > end) return done();
            if (*next > now_) now_ = *next;

            while (!queue_.empty() && queue_.begin()->first <= now_) {
                auto [to, pkt] = std::move(queue_.begin()->second);
                queue_.erase(queue_.begin());
                if (auto ip = parse_ipv4(pkt)) (to == 0 ? a_ : b_).on_ip_packet(*ip);
            }
            a_.tick();
            b_.tick();
            if (wake_at && *wake_at <= now_) { wake_at.reset(); if (on_wake) on_wake(); }
            if (observer) observer();
        }
        std::printf("    simulation did not settle (livelock?)\n");
        return false;
    }

private:
    static TcpConfig host_config(TcpConfig c, uint32_t ip, uint32_t seed) {
        c.local_ip = ip;
        c.rng_seed = seed;
        c.time_wait = seconds(120);                  // a realistic 2*MSL: costs nothing with a fake clock
        return c;
    }
    bool chance(double p) { return p > 0 && std::uniform_real_distribution<>(0, 1)(rng_) < p; }

    void transmit(int from, std::vector<uint8_t> pkt) {
        packets_sent[from]++;
        if (drop_filter && drop_filter(from, pkt)) return;
        if (chance(imp.loss)) return;
        int copies = chance(imp.duplicate) ? 2 : 1;
        for (int i = 0; i < copies; ++i) {
            int delay = imp.delay_ms + (imp.jitter_ms ? int(rng_() % unsigned(imp.jitter_ms + 1)) : 0);
            queue_.emplace(now_ + milliseconds(delay), std::make_pair(1 - from, pkt));
        }
    }

    std::mt19937 rng_;
    Time now_;
    std::multimap<Time, std::pair<int, std::vector<uint8_t>>> queue_;     // ordered by delivery time
    TcpLayer a_, b_;
};

// ---------------------------------------------------------------- the application on each host
// A (client) connects to B (server) and uploads `total` pattern bytes, then closes.
// B reads everything, checks it byte by byte, and closes when A is done.
struct Transfer {
    size_t total = 0;
    std::shared_ptr<Tcb> client, server;
    size_t queued = 0, received = 0;
    bool mismatch = false, client_closed = false, server_closed = false;
    bool server_reading = true, peer_done = false, saw_closed_window = false, server_close_called = false;
    int client_err = -1, server_err = -1;

    void server_pump(TcpLayer& tcp) {
        if (!server_reading || !server) return;
        uint8_t buf[2048];
        while (size_t n = tcp.read(*server, buf)) {
            for (size_t i = 0; i < n; ++i) if (buf[i] != pattern(received + i)) mismatch = true;
            received += n;
        }
        if (peer_done && server->recv_buf.empty() && !server_close_called) {
            server_close_called = true;
            tcp.close(*server);
        }
    }
    void client_pump(TcpLayer& tcp) {
        while (queued < total) {
            uint8_t buf[2048];
            size_t n = std::min({total - queued, sizeof buf, client->send_buf.free_space()});
            if (n == 0) break;
            for (size_t i = 0; i < n; ++i) buf[i] = pattern(queued + i);
            queued += tcp.send(*client, std::span<const uint8_t>(buf, n));
        }
        if (queued == total && !client->fin_queued && client->state == State::Established) tcp.close(*client);
    }
    bool ok() const { return received == total && !mismatch && client_err == 0 && server_err == 0; }
};

void start_transfer(Sim& sim, Transfer& x, size_t total, uint16_t port = 80) {
    x.total = total;
    sim.b().listen(port, [&x, &sim](const std::shared_ptr<Tcb>& c) {
        x.server = c;
        c->on_readable = [&x, &sim] { x.server_pump(sim.b()); };
        c->on_eof = [&x, &sim] { x.peer_done = true; x.server_pump(sim.b()); };
        c->on_closed = [&x](int e) { x.server_closed = true; x.server_err = e; };
    });
    x.client = sim.a().connect(kB, port);
    x.client->on_connected = [&x, &sim] { x.client_pump(sim.a()); };
    x.client->on_writable = [&x, &sim] { x.client_pump(sim.a()); };
    x.client->on_closed = [&x](int e) { x.client_closed = true; x.client_err = e; };
}

// Properties that must hold after EVERY event, whatever the network does.
void check_invariants(const Transfer& x) {
    for (const Tcb* t : {x.client.get(), x.server.get()}) {
        if (!t || t->state == State::Closed) continue;
        CHECK(seq_leq(t->snd_una, t->snd_nxt));
        CHECK(t->send_buf.size() <= t->send_buf.capacity());
        CHECK(t->recv_buf.size() <= t->recv_buf.capacity());
        if (t->state == State::Established || t->state == State::CloseWait)
            CHECK(t->data_in_flight() <= t->send_buf.size());
    }
}

// Runs a whole transfer; returns true if it completed correctly.
bool run_transfer(Sim& sim, Transfer& x, size_t total, Clock::duration limit = std::chrono::minutes(30)) {
    start_transfer(sim, x, total);
    sim.observer = [&] {
        check_invariants(x);
        if (x.server && x.server->recv_buf.free_space() < x.server->mss) x.saw_closed_window = true;
    };
    sim.run([&] { return x.client_closed && x.server_closed; }, limit);
    if (!x.ok()) {                                    // say WHAT went wrong: this is what you debug from
        std::printf("    received %zu/%zu bytes, mismatch=%d, client_err=%d (%s), server_err=%d (%s)\n", x.received,
                    total, int(x.mismatch), x.client_err, x.client ? to_string(x.client->state) : "-", x.server_err,
                    x.server ? to_string(x.server->state) : "-");
    }
    return x.ok();
}

}  // namespace

// ============================================================================ scenarios

TEST(sim_clean_transfer) {
    Sim sim(1);
    Transfer x;
    CHECK(run_transfer(sim, x, 300'000));
    CHECK_EQ(x.client->stats.retransmits, 0u);
}

TEST(sim_loss_reordering_and_duplication) {
    for (uint32_t seed = 1; seed <= 12; ++seed) {
        Sim sim(seed);
        sim.imp = {.loss = 0.10, .duplicate = 0.05, .delay_ms = 10, .jitter_ms = 30};
        Transfer x;
        bool ok = run_transfer(sim, x, 120'000);
        if (!ok) std::printf("    failing seed: %u\n", seed);
        CHECK(ok);
    }
}

TEST(sim_very_heavy_loss) {
    for (uint32_t seed = 1; seed <= 4; ++seed) {
        Sim sim(seed);
        sim.imp = {.loss = 0.25, .duplicate = 0.0, .delay_ms = 10, .jitter_ms = 10};
        Transfer x;
        bool ok = run_transfer(sim, x, 40'000);
        if (!ok) std::printf("    failing seed: %u\n", seed);
        CHECK(ok);
    }
}

TEST(sim_sequence_numbers_wrap_around_during_transfer) {
    for (uint32_t seed = 1; seed <= 5; ++seed) {
        TcpConfig cfg;
        cfg.fixed_isn = 0xFFFFFF00u;                 // the very first data crosses 2^32
        Sim sim(seed, cfg);
        sim.imp = {.loss = 0.05, .duplicate = 0.02, .delay_ms = 10, .jitter_ms = 20};
        Transfer x;
        CHECK(run_transfer(sim, x, 100'000));
    }
}

TEST(sim_every_option_combination_works) {
    for (int mask = 0; mask < 8; ++mask) {
        TcpConfig cfg;
        cfg.want_wscale = mask & 1;
        cfg.want_timestamps = mask & 2;
        cfg.want_sack = mask & 4;
        Sim sim(100 + uint32_t(mask), cfg);
        sim.imp = {.loss = 0.05, .duplicate = 0.0, .delay_ms = 10, .jitter_ms = 25};
        Transfer x;
        bool ok = run_transfer(sim, x, 80'000);
        if (!ok) std::printf("    failing option mask: %d\n", mask);
        CHECK(ok);
    }
}

TEST(sim_tiny_buffers_force_flow_control) {
    TcpConfig cfg;
    cfg.send_buf_size = 3000;
    cfg.recv_buf_size = 3000;
    Sim sim(5, cfg);
    sim.imp = {.loss = 0.05, .duplicate = 0.0, .delay_ms = 10, .jitter_ms = 10};
    Transfer x;
    CHECK(run_transfer(sim, x, 60'000));
}

TEST(sim_slow_reader_closes_the_window_and_recovers) {
    Sim sim(3);
    Transfer x;
    start_transfer(sim, x, 400'000);
    x.server_reading = false;                         // B ignores the connection...
    sim.wake_at = sim.now() + seconds(20);
    sim.on_wake = [&] { x.server_reading = true; x.server_pump(sim.b()); };   // ...then starts reading
    // While B is deaf, its read pump is only triggered by the wake-up, so also drain on later events:
    sim.observer = [&] {
        check_invariants(x);
        if (x.server && x.server->recv_buf.free_space() < x.server->mss) x.saw_closed_window = true;
        if (x.server_reading) x.server_pump(sim.b());
    };
    sim.run([&] { return x.client_closed && x.server_closed; }, std::chrono::minutes(10));
    CHECK(x.saw_closed_window);                       // the window really did shrink below one segment (a sender
                                                      // refuses to send smaller runts: silly-window avoidance)
    CHECK(x.ok());
}

TEST(sim_connection_refused) {
    Sim sim(1);
    bool closed = false;
    int err = -1;
    auto c = sim.a().connect(kB, 9999);               // nobody listens on port 9999
    c->on_closed = [&](int e) { closed = true; err = e; };
    sim.run([&] { return closed; }, seconds(5));
    CHECK(closed);
    CHECK_EQ(err, ECONNREFUSED);
}

TEST(sim_lost_syn_and_synack_are_retransmitted) {
    Sim sim(1);
    int syn_dropped = 0, synack_dropped = 0;
    sim.drop_filter = [&](int from, const std::vector<uint8_t>& pkt) {
        auto ip = parse_ipv4(pkt);
        auto seg = parse_tcp(ip->h.src, ip->h.dst, ip->payload);
        if (from == 0 && seg->h.has(flag::SYN) && syn_dropped < 1) { syn_dropped++; return true; }
        if (from == 1 && seg->h.has(flag::SYN) && synack_dropped < 2) { synack_dropped++; return true; }
        return false;
    };
    Transfer x;
    CHECK(run_transfer(sim, x, 5000));
    CHECK_EQ(syn_dropped, 1);
    CHECK_EQ(synack_dropped, 2);
}

TEST(sim_fast_retransmit_after_three_duplicate_acks) {
    Sim sim(1);
    bool dropped = false;
    sim.drop_filter = [&](int from, const std::vector<uint8_t>& pkt) {   // lose exactly the first data segment
        auto ip = parse_ipv4(pkt);
        auto seg = parse_tcp(ip->h.src, ip->h.dst, ip->payload);
        if (from == 0 && !seg->payload.empty() && !dropped) { dropped = true; return true; }
        return false;
    };
    Transfer x;
    CHECK(run_transfer(sim, x, 40'000));
    CHECK(dropped);
    CHECK(x.client->stats.fast_retransmits >= 1);     // three duplicate ACKs triggered the resend...
    CHECK_EQ(x.client->stats.timeouts, 0u);           // ...so the timer never had to fire
}

TEST(sim_blackhole_triggers_backoff_and_then_gives_up) {
    TcpConfig cfg;                                    // default: 8 retries
    Sim sim(1, cfg);
    Transfer x;
    start_transfer(sim, x, 50'000);
    sim.run([&] { return x.client && x.client->state == State::Established && x.queued > 0; }, seconds(5));
    sim.imp.loss = 1.0;                               // the network dies
    Time t0 = sim.now();
    sim.run([&] { return x.client_closed; }, std::chrono::minutes(30));
    double waited = std::chrono::duration<double>(sim.now() - t0).count();
    CHECK(x.client_closed);
    CHECK_EQ(x.client_err, ETIMEDOUT);
    CHECK_EQ(x.client->stats.timeouts, 8u);
    CHECK(waited > 60 && waited < 900);               // exponential back-off: minutes, not milliseconds
}

TEST(sim_simultaneous_close) {
    Sim sim(1);
    bool a_closed = false, b_closed = false;
    int a_err = -1, b_err = -1;
    sim.b().listen(80, [&](const std::shared_ptr<Tcb>& c) {
        c->on_closed = [&](int e) { b_closed = true; b_err = e; };
        sim.b().close(*c);                            // B closes the moment the connection exists...
    });
    auto c = sim.a().connect(kB, 80);
    c->on_connected = [&] { sim.a().close(*c); };     // ...and so does A: the two FINs cross on the wire
    c->on_closed = [&](int e) { a_closed = true; a_err = e; };
    sim.run([&] { return a_closed && b_closed; }, std::chrono::minutes(5));   // includes both TIME_WAIT periods
    CHECK(a_closed && b_closed);
    CHECK_EQ(a_err, 0);
    CHECK_EQ(b_err, 0);
}

TEST(sim_abort_resets_the_peer) {
    Sim sim(1);
    Transfer x;
    start_transfer(sim, x, 1'000'000);
    sim.run([&] { return x.received > 20'000; }, seconds(30));
    sim.a().abort(*x.client);                         // A slams the connection shut with a RST
    sim.run([&] { return x.server_closed; }, seconds(30));
    CHECK(x.server_closed);
    CHECK_EQ(x.server_err, ECONNRESET);
    CHECK_EQ(x.client_err, ECONNABORTED);
}

TEST(sim_hundreds_of_random_seeds) {
    int failures = 0;
    for (uint32_t seed = 1000; seed < 1150; ++seed) {
        Sim sim(seed);
        std::mt19937 r(seed);
        sim.imp = {.loss = double(r() % 25) / 100.0, .duplicate = double(r() % 10) / 100.0,
                   .delay_ms = int(1 + r() % 40), .jitter_ms = int(r() % 60)};
        Transfer x;
        if (!run_transfer(sim, x, 20'000 + r() % 60'000)) {
            std::printf("    failing seed: %u (loss %.2f dup %.2f jitter %d)\n", seed, sim.imp.loss, sim.imp.duplicate, sim.imp.jitter_ms);
            ++failures;
        }
    }
    CHECK_EQ(failures, 0);
}

int main() { return run_all_tests(); }
