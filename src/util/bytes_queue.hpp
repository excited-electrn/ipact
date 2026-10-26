#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <span>

class ByteQueue {
public:
    explicit ByteQueue(size_t capacity = 64 * 1024) 
        : cap_(capacity) 
    {}

    size_t size() const { return q_.size(); }
    size_t capacity() const { return cap_; }
    size_t free_space() const { return cap_ - q_.size(); }
    bool empty() const { return q_.empty(); }

    // Append as many bytes as fit. Returns how many are stored
    size_t write(std::span<const uint8_t> data) {
        size_t n = std::min(data.size(), free_space());
        q_.insert(q_.end(), data.begin(), data.begin() + static_cast<std::ptrdiff_t>(n));
        return n;
    }

    // Copy up tp out.size() bytes with removing
    size_t peek(size_t offset, std::span<uint8_t> out) const {
        if (offset >= q_.size()) return 0;
        size_t n = std::min(out.size(), q_.size() - offset);
        std::copy_n(q_.begin() + static_cast<std::ptrdiff_t>(offset), n, out.begin());
        return n;
    }

    size_t read(std::span<uint8_t> out) {
        size_t n = peek(0, out);
        consume(n);
        return n;
    }

    // Remove n bytes from front
    void consume(size_t n) {
        n = std::min(n, q_.size());
        q_.erase(q_.begin(), q_.begin() + static_cast<std::ptrdiff_t>(n));
    }


private:
    std::deque<uint8_t> q_;
    size_t cap_;
};