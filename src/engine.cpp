#include "engine.hpp"
#include "util/log.hpp"

#include <fcntl.h>
#include <sys/epoll.h>
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <stdexcept>

std::optional<std::vector<uint8_t>> handle_icmp(const Ipv4View& ip, uint16_t& ip_id_counter);

EngineConfig EngineConfig::from_env() {
    EngineConfig c;
    if (const char* v = std::getenv("IPACT_TUN")) c.tun_name = v;
    if (const char* v = std::getenv("IPACT_DROP_IN")) c.drop_in = std::atof(v);
    if (const char* v = std::getenv("IPACT_DROP_OUT")) c.drop_out = std::atof(v);
    return c;
}

Engine::Engine(EngineConfig cfg)
    : cfg_(cfg)
    , tun_(cfg.tun_name)
    , tcp_(cfg.tcp, [this](std::vector<uint8_t> p) { send_packet(std::move(p)); })
    , rng_(cfg.seed) {
    int fd = tun_.fd();
    int flags = ::fcntl(fd, F_GETFL);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        throw std::system_error(errno, std::generic_category(), "fcntl O_NONBLOCK");
    }
    epfd_ = ::epoll_create1(EPOLL_CLOEXEC);
    if (epfd_ < 0) {
        throw std::system_error(errno, std::generic_category(), "epoll_create1");
    }
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    ::epoll_ctl(epfd_, EPOLL_CTL_ADD, tun_.fd(), &ev);
}

bool Engine::coin(double probability) {
    return probability > 0.0 && std::uniform_real_distribution<>(0.0, 1.0)(rng_) < probability;
}

void Engine::send_packet(std::vector<uint8_t> pkt) {
    if (coin(cfg_.drop_out)) {
        LOG("engine: dropped an outgoing packet on purpose");
        return;
    }
    tun_.write_packet(pkt);
}

void Engine::drain_tun() {
    std::vector<uint8_t> buf(65535);
    for (;;) {
        ssize_t n = tun_.read_packet(buf);
        if (n < 0) return;
        if (coin(cfg_.drop_in)) {
            LOG("engine: dropped an incoming packet on purpose"); 
            continue;
        }

        auto ip = parse_ipv4(std::span<const uint8_t>(buf.data(), size_t(n)));
        if (!ip || ip->header.dst != cfg_.tcp.local_ip) continue;
        if (ip->header.protocol == uint8_t(IpProto::ICMP)) {
            if (auto reply = handle_icmp(*ip, icmp_ip_id)) send_packet(std::move(*reply));
        } else if (ip->header.protocol == uint8_t(IpProto::TCP)) {
            tcp_.on_ip_packet(*ip);
        }
    }
}

void Engine::run() {
    while (running_) {
        int timeout_ms = 20;
        if (auto d = tcp_.next_deadline()) {
            auto wait = std::chrono::duration_cast<std::chrono::milliseconds>(*d - Clock::now()).count();
            timeout_ms = int(std::clamp<long long>(wait, 0, 20));
        }
        epoll_event ev{};
        int n = ::epoll_wait(epfd_, &ev, 1, timeout_ms);
        if (n < 0 && errno != EINTR) {
            throw std::system_error(errno, std::generic_category(), "epoll_wait failed");
        }
        if (n > 0) drain_tun();
        tcp_.tick();
        if (on_loop) on_loop();
    }
}