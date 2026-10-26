#include "engine.hpp"
#include <fcntl.h>
#include <sys/epoll.h>
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <stdexcept>
#include "util/log.hpp"

// From net/icmp.cpp (Phase 6): builds the echo reply for a ping, if there is one.
std::optional<std::vector<uint8_t>> handle_icmp(const Ipv4View& ip, uint16_t& ip_id_counter);

EngineConfig EngineConfig::from_env() {
    EngineConfig c;
    if (const char* v = std::getenv("IPACT_TUN"))      c.tun_name = v;
    if (const char* v = std::getenv("IPACT_DROP_IN"))  c.drop_in  = std::atof(v);
    if (const char* v = std::getenv("IPACT_DROP_OUT")) c.drop_out = std::atof(v);
    if (const char* v = std::getenv("IPACT_PCAP"))     c.pcap_path = v;
    if (std::getenv("IPACT_NO_SACK"))   c.tcp.want_sack = false;          // experiments: switch options off
    if (std::getenv("IPACT_NO_TS"))     c.tcp.want_timestamps = false;
    if (std::getenv("IPACT_NO_WSCALE")) c.tcp.want_wscale = false;
    return c;
}

Engine::Engine(EngineConfig cfg)
    : cfg_(cfg),
      tun_(cfg.tun_name),
      tcp_(cfg.tcp, [this](std::vector<uint8_t> p) { send_packet(std::move(p)); }),
      rng_(cfg.seed) {
    if (!cfg_.pcap_path.empty()) pcap_ = std::make_unique<PcapWriter>(cfg_.pcap_path);
    ::fcntl(tun_.fd(), F_SETFL, ::fcntl(tun_.fd(), F_GETFL) | O_NONBLOCK);   // read() must never block the loop
    epfd_ = ::epoll_create1(EPOLL_CLOEXEC);
    if (epfd_ < 0) throw std::runtime_error("epoll_create1 failed");
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = tun_.fd();
    ::epoll_ctl(epfd_, EPOLL_CTL_ADD, tun_.fd(), &ev);
}

bool Engine::coin(double probability) {
    return probability > 0.0 && std::uniform_real_distribution<>(0.0, 1.0)(rng_) < probability;
}

// Every packet we transmit goes through here, so this is the place for fake packet loss.
void Engine::send_packet(std::vector<uint8_t> pkt) {
    if (coin(cfg_.drop_out)) {
        LOG("engine: dropped an outgoing packet on purpose");
        return;
    }
    if (pcap_) pcap_->write(pkt);
    tun_.write_packet(pkt);
}

// Read every packet that is waiting and hand each to the right protocol.
void Engine::drain_tun() {
    std::vector<uint8_t> buf(65535);
    for (;;) {
        ssize_t n = tun_.read_packet(buf);
        if (n < 0) break;                                   // EAGAIN: nothing left
        if (coin(cfg_.drop_in)) { LOG("engine: dropped an incoming packet on purpose"); continue; }
        if (pcap_) pcap_->write(std::span<const uint8_t>(buf.data(), size_t(n)));
        auto ip = parse_ipv4(std::span<const uint8_t>(buf.data(), size_t(n)));
        if (!ip || ip->h.dst != cfg_.tcp.local_ip) continue;
        if (ip->h.protocol == uint8_t(IpProto::ICMP)) {
            if (auto reply = handle_icmp(*ip, icmp_ip_id_)) send_packet(std::move(*reply));
        } else if (ip->h.protocol == uint8_t(IpProto::TCP)) {
            tcp_.on_ip_packet(*ip);
        }
    }
}

void Engine::run() {
    while (running_) {
        // Sleep until a packet arrives or the next timer is due, but never longer than 20 ms.
        // (The cap means a timer armed from another thread is noticed within 20 ms.)
        int timeout_ms = 20;
        {
            std::lock_guard<std::mutex> lock(mu_);              // next_deadline() reads connection state
            if (auto d = tcp_.next_deadline()) {
                auto wait = std::chrono::duration_cast<std::chrono::milliseconds>(*d - Clock::now()).count();
                timeout_ms = int(std::clamp<long long>(wait, 0, 20));
            }
        }
        epoll_event ev{};
        int n = ::epoll_wait(epfd_, &ev, 1, timeout_ms);        // sleeping WITHOUT the lock: app threads can work
        if (n < 0 && errno != EINTR) throw std::runtime_error("epoll_wait failed");

        std::lock_guard<std::mutex> lock(mu_);
        if (n > 0) drain_tun();
        tcp_.tick();
        if (on_loop) on_loop();
    }
}
