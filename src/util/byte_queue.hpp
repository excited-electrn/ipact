#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

// A FIFO of bytes with a fixed capacity, stored in a ring buffer (Phase 14).
// Same interface as the deque version from Phase 8, so nothing else in the project changes.
//
//   storage:  [ . . . H=====T . . . ]      head: first byte, tail: where the next byte goes
//   wrapped:  [ ===T . . . . H===== ]      the data wraps around the end of the array
class ByteQueue {
public:
    explicit ByteQueue(size_t capacity = 64 * 1024) : buf_(capacity) {}

    size_t size() const { return size_; }
    size_t capacity() const { return buf_.size(); }
    size_t free_space() const { return buf_.size() - size_; }
    bool empty() const { return size_ == 0; }

    // Append as many bytes as fit. Returns how many were stored.
    size_t write(std::span<const uint8_t> data) {
        size_t n = std::min(data.size(), free_space());
        size_t tail = (head_ + size_) % cap();
        size_t first = std::min(n, cap() - tail);                   // up to the end of the array...
        std::copy_n(data.begin(), first, buf_.begin() + static_cast<std::ptrdiff_t>(tail));
        std::copy_n(data.begin() + static_cast<std::ptrdiff_t>(first), n - first, buf_.begin());   // ...then the start
        size_ += n;
        return n;
    }
    // Copy up to out.size() bytes, starting `offset` bytes from the front, WITHOUT removing them.
    size_t peek(size_t offset, std::span<uint8_t> out) const {
        if (offset >= size_) return 0;
        size_t n = std::min(out.size(), size_ - offset);
        size_t start = (head_ + offset) % cap();
        size_t first = std::min(n, cap() - start);
        std::copy_n(buf_.begin() + static_cast<std::ptrdiff_t>(start), first, out.begin());
        std::copy_n(buf_.begin(), n - first, out.begin() + static_cast<std::ptrdiff_t>(first));
        return n;
    }
    // Copy bytes out and remove them.
    size_t read(std::span<uint8_t> out) {
        size_t n = peek(0, out);
        consume(n);
        return n;
    }
    // Remove n bytes from the front.
    void consume(size_t n) {
        n = std::min(n, size_);
        head_ = (head_ + n) % cap();
        size_ -= n;
    }

private:
    size_t cap() const { return buf_.empty() ? 1 : buf_.size(); }   // avoids "% 0"
    std::vector<uint8_t> buf_;
    size_t head_ = 0, size_ = 0;
};
