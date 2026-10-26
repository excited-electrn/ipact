#pragma once
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include "io/pcap_writer.hpp"
#include "io/tun_device.hpp"
#include "tcp/tcp_layer.hpp"

// Engine = a TUN device + the IP layer + a TcpLayer + the event loop that drives them.
struct EngineConfig {
    std::string tun_name = "tun0";
    TcpConfig   tcp;
    double      drop_in  = 0.0;              // fake packet loss on packets we RECEIVE (0.0 - 1.0)
    double      drop_out = 0.0;              // fake packet loss on packets we SEND
    std::string pcap_path;                   // if set, every packet we send or receive is written here
    uint32_t    seed = 1;

    // Reads IPACT_TUN, IPACT_DROP_IN, IPACT_DROP_OUT from the environment, e.g.
    //   IPACT_DROP_IN=0.05 IPACT_DROP_OUT=0.05 ./build/tcp_demo
    static EngineConfig from_env();
};

class Engine {
public:
    explicit Engine(EngineConfig cfg = {});
    TcpLayer& tcp() { return tcp_; }
    void run();                              // loop until stop() is called
    void stop() { running_ = false; }

    // Phase 14: every access to the TcpLayer (from the loop AND from application threads) holds this lock.
    std::mutex& mutex() { return mu_; }

    // Optional: called once per pass of the loop (at least every 20 ms). Handy for demos
    // that need to do something periodically without threads.
    std::function<void()> on_loop;

private:
    void drain_tun();
    void send_packet(std::vector<uint8_t> pkt);
    bool coin(double probability);           // true with the given probability

    EngineConfig cfg_;
    std::mutex mu_;
    std::unique_ptr<PcapWriter> pcap_;
    TunDevice tun_;
    TcpLayer tcp_;
    int epfd_ = -1;
    std::atomic<bool> running_{true};
    uint16_t icmp_ip_id_ = 1;
    std::mt19937 rng_;
};
