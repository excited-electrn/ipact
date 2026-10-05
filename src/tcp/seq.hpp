#pragma once
#include <cstdint>

constexpr bool seq_lt(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b) < 0;
}

constexpr bool seq_leq(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b) <= 0;
}

constexpr bool seq_gt(uint32_t a, uint32_t b) {
    return seq_lt(b, a);
}

constexpr bool seq_geq(uint32_t a, uint32_t b) {
    return seq_leq(b, a);
}

constexpr bool seq_in_range(uint32_t x, uint32_t lo, uint32_t hi) {
    return static_cast<uint32_t>(x - lo) < static_cast<uint32_t>(hi - lo);
}


/// Tests
static_assert(seq_leq(1, 2));
static_assert(seq_lt(0xFFFFFFF0u, 5));
static_assert(!seq_lt(5, 0xFFFFFFF0u));
static_assert(seq_in_range(3, 0xFFFFFFFEu, 10))