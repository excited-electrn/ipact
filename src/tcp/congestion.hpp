#pragma once
#include <algorithm>
#include <cstdint>
#include <limits>

// A congestion controller decides how many bytes may be in flight (the "cwnd").
// TcpLayer tells it what happened; it answers with a window. Swapping algorithms
// (Reno, CUBIC, ...) means writing another class with these methods.
class CongestionControl {
public:
    virtual ~CongestionControl() = default;
    virtual uint32_t cwnd() const = 0;
    virtual uint32_t ssthresh() const = 0;
    virtual void on_ack(uint32_t acked_bytes) = 0;          // new data acknowledged, not in recovery
    virtual void on_dup_ack_threshold(uint32_t flight) = 0; // 3rd duplicate ACK: a loss; recovery starts
    virtual void on_dup_ack_extra() = 0;                    // more duplicate ACKs during recovery
    virtual void on_partial_ack(uint32_t acked_bytes) = 0;  // recovery continues, but there is another hole
    virtual void on_recovery_exit() = 0;                    // everything outstanding at the loss is acked
    virtual void on_timeout(uint32_t flight) = 0;           // the retransmission timer fired
};

// TCP Reno with NewReno's partial-ACK handling (RFC 5681 + RFC 6582).
class Reno : public CongestionControl {
public:
    explicit Reno(uint32_t mss) : mss_(mss), cwnd_(10 * mss) {}   // initial window: 10 segments (RFC 6928)

    uint32_t cwnd() const override { return cwnd_; }
    uint32_t ssthresh() const override { return ssthresh_; }

    void on_ack(uint32_t acked) override {
        if (cwnd_ < ssthresh_) {
            cwnd_ += std::min(acked, mss_);                          // slow start: roughly doubles every RTT
        } else {
            cwnd_ += std::max<uint32_t>(1, uint32_t(uint64_t(mss_) * mss_ / cwnd_));   // avoidance: +1 MSS per RTT
        }
    }
    void on_dup_ack_threshold(uint32_t flight) override {
        ssthresh_ = std::max(flight / 2, 2 * mss_);                  // halve
        cwnd_ = ssthresh_ + 3 * mss_;                                // +3: the three segments that caused the dup ACKs left the network
    }
    void on_dup_ack_extra() override { cwnd_ += mss_; }              // each dup ACK = one more segment has left the network
    void on_partial_ack(uint32_t acked) override {
        cwnd_ = cwnd_ > acked ? cwnd_ - acked : 0;                   // deflate by what was just acked...
        cwnd_ += mss_;                                               // ...and allow one new segment
    }
    void on_recovery_exit() override { cwnd_ = ssthresh_; }
    void on_timeout(uint32_t flight) override {
        ssthresh_ = std::max(flight / 2, 2 * mss_);
        cwnd_ = mss_;                                                // start over with one segment
    }

private:
    uint32_t mss_;
    uint32_t cwnd_;
    uint32_t ssthresh_ = std::numeric_limits<uint32_t>::max();       // "infinity" until the first loss
};
