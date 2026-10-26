#pragma once
#include <atomic>
#include <functional>
#include <memory>
#include <random>
#include <string>

#include "io/tun_device.hpp"
#include "tcp/tcp_layer.hpp"

// Engine =  a TUN device + IP layer + TCP layer + event loop
struct EngineConfig {
    std::string tun_name = "tun0";
    TcpConfig tcp;
    double drop_in = 0.0; // fake packet loss on packet we receive (0.0 - 1.0)
    double drop_out = 0.0; // fake packet loss on packet we send
    uint32_t seed = 1;

    // Reads IPACT_TUN, IPACT_DROP_IN, IPACT_DROP_OUT from the environment, e.g.
    //   IPACT_DROP_IN=0.05 IPACT_DROP_OUT=0.05 ./build/tcp_demo
    static EngineConfig from_env();
};

class Engine {
public:
    explicit Engine(EngineConfig cfg = {});
    TcpLayer& tcp() { return tcp_; }
    void run();
    void stop() { running_ = false; }

    // Optional: called once per pass of the loop (at least every 20 ms). Handy for demos
    // that need to do something periodically without threads.
    std::function<void()> on_loop;

private:
    void drain_tun();
    void send_packet(std::vector<uint8_t> pkt);
    bool coin(double probability);

    EngineConfig cfg_;
    TunDevice tun_;
    TcpLayer tcp_;
    int epfd_ = -1;
    std::atomic<bool> running_{true};
    uint16_t icmp_ip_id = 1;
    std::mt19937 rng_;
};