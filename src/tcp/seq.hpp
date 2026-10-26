#pragma once
#include <cstdint>

// Sequence numbers live on a circle of size 2^32. "a is before b" means b is within
// half the circle ahead of a. Subtracting as unsigned wraps correctly; reading the
// result as SIGNED tells us which direction is shorter.
constexpr bool seq_lt(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) < 0; }
constexpr bool seq_leq(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) <= 0; }
constexpr bool seq_gt(uint32_t a, uint32_t b) { return seq_lt(b, a); }
constexpr bool seq_geq(uint32_t a, uint32_t b) { return seq_leq(b, a); }

// Is x in the half-open interval [lo, hi) on the circle?
constexpr bool seq_in_range(uint32_t x, uint32_t lo, uint32_t hi) {
    return static_cast<uint32_t>(x - lo) < static_cast<uint32_t>(hi - lo);
}

// Tests you MUST write:
static_assert( seq_lt(1, 2));
static_assert( seq_lt(0xFFFFFFF0u, 5));        // wrapped: 0xFFFFFFF0 is "before" 5
static_assert(!seq_lt(5, 0xFFFFFFF0u));
static_assert( seq_in_range(3, 0xFFFFFFFEu, 10));
