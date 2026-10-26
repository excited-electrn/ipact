#pragma once
#include <algorithm>
#include <chrono>
#include <cmath>

// Round-trip-time estimator and retransmission-timeout (RTO) calculator, RFC 6298.
class RttEstimator {
public:
    using ms = std::chrono::duration<double, std::milli>;

    explicit RttEstimator(ms min_rto = ms(200), ms max_rto = ms(60000))
        : min_(min_rto), max_(max_rto), rto_(ms(1000)) {}          // RFC: start with an RTO of 1 second

    // Feed in one measured round trip.
    void on_sample(ms r) {
        if (!have_sample_) {                                       // first sample
            srtt_ = r;
            rttvar_ = r / 2;
            have_sample_ = true;
        } else {                                                   // smooth it (alpha = 1/8, beta = 1/4)
            rttvar_ = 0.75 * rttvar_ + 0.25 * ms(std::abs((srtt_ - r).count()));
            srtt_   = 0.875 * srtt_ + 0.125 * r;
        }
        rto_ = clamp(srtt_ + std::max(ms(1), 4 * rttvar_));        // 1 ms = clock granularity
        backoff_ = 1;                                              // a fresh sample ends the back-off
    }

    // The timer fired: double the timeout (up to 64x) until the peer makes progress.
    void on_timeout() { backoff_ = std::min(backoff_ * 2, 64); }

    // The peer acknowledged new data, so the path is alive again: end the back-off.
    void reset_backoff() { backoff_ = 1; }

    ms rto() const { return clamp(rto_ * backoff_); }
    ms srtt() const { return srtt_; }
    ms rttvar() const { return rttvar_; }
    bool has_sample() const { return have_sample_; }

private:
    ms clamp(ms v) const { return std::min(std::max(v, min_), max_); }

    ms min_, max_;
    ms srtt_{0}, rttvar_{0};
    ms rto_;
    int backoff_ = 1;
    bool have_sample_ = false;
};