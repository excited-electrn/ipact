#pragma once
#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <utility>
#include <vector>
#include "tcp/tcb.hpp"
#include "util/bytes.hpp"

// Option kinds (IANA "TCP Option Kind Numbers").
namespace opt {
constexpr uint8_t End = 0, Nop = 1, Mss = 2, WindowScale = 3, SackPermitted = 4, Sack = 5, Timestamps = 8;
}

struct SackBlock { uint32_t left, right; };            // the bytes [left, right) have arrived

struct TcpOptions {
    std::optional<uint16_t> mss;
    std::optional<uint8_t>  wscale;
    bool                    sack_permitted = false;
    std::optional<std::pair<uint32_t, uint32_t>> timestamp;   // (TSval, TSecr)
    std::vector<SackBlock>  sack;
};

// Parse the options area of a segment. Returns nullopt if it is malformed. NEVER trust the length
// byte of an option without checking it against the bytes that are really there.
inline std::optional<TcpOptions> parse_options(std::span<const uint8_t> o) {
    TcpOptions r;
    size_t i = 0;
    while (i < o.size()) {
        uint8_t kind = o[i];
        if (kind == opt::End) break;
        if (kind == opt::Nop) { ++i; continue; }
        if (i + 1 >= o.size()) return std::nullopt;               // kind without a length byte
        size_t len = o[i + 1];
        if (len < 2 || i + len > o.size()) return std::nullopt;   // length lies
        auto body = o.subspan(i + 2, len - 2);
        switch (kind) {
            case opt::Mss:
                if (len != 4) return std::nullopt;
                r.mss = read_be16(body, 0);
                break;
            case opt::WindowScale:
                if (len != 3) return std::nullopt;
                r.wscale = body[0];
                break;
            case opt::SackPermitted:
                if (len != 2) return std::nullopt;
                r.sack_permitted = true;
                break;
            case opt::Timestamps:
                if (len != 10) return std::nullopt;
                r.timestamp = std::make_pair(read_be32(body, 0), read_be32(body, 4));
                break;
            case opt::Sack:
                if ((len - 2) % 8 != 0) return std::nullopt;
                for (size_t b = 0; b < body.size(); b += 8)
                    r.sack.push_back({read_be32(body, b), read_be32(body, b + 4)});
                break;
            default: break;                                       // unknown option: skip it using its length
        }
        i += len;
    }
    return r;
}

// Builds an options area. finish() pads it to a multiple of 4 bytes.
class OptionWriter {
public:
    void nop() { b_.push_back(opt::Nop); }
    void mss(uint16_t v) { b_.insert(b_.end(), {opt::Mss, 4, uint8_t(v >> 8), uint8_t(v)}); }
    void wscale(uint8_t shift) { b_.insert(b_.end(), {opt::WindowScale, 3, shift}); }
    void sack_permitted() { b_.insert(b_.end(), {opt::SackPermitted, 2}); }
    void timestamps(uint32_t tsval, uint32_t tsecr) {
        b_.insert(b_.end(), {opt::Timestamps, 10});
        put32(tsval);
        put32(tsecr);
    }
    void sack(const std::vector<SackBlock>& blocks) {
        b_.insert(b_.end(), {opt::Sack, uint8_t(2 + 8 * blocks.size())});
        for (auto& blk : blocks) { put32(blk.left); put32(blk.right); }
    }
    std::vector<uint8_t> finish() {
        while (b_.size() % 4 != 0) b_.push_back(opt::Nop);
        return std::move(b_);
    }

private:
    void put32(uint32_t v) { b_.insert(b_.end(), {uint8_t(v >> 24), uint8_t(v >> 16), uint8_t(v >> 8), uint8_t(v)}); }
    std::vector<uint8_t> b_;
};

// Does this segment's options area contain SACK blocks?
inline bool carries_sack(std::span<const uint8_t> options) {
    auto o = parse_options(options);
    return o && !o->sack.empty();
}

// The smallest shift that lets a 16-bit field describe a buffer of `capacity` bytes.
inline uint8_t wscale_for(size_t capacity) {
    uint8_t s = 0;
    while ((capacity >> s) > 0xFFFF && s < 14) ++s;
    return s;
}

// ---------------------------------------------------------------- receiver side of SACK
// Turn our out-of-order segments into SACK blocks. The block with the most recently received
// segment goes first (RFC 2018), and at most `max_blocks` are returned.
inline std::vector<SackBlock>
make_sack_blocks(const std::map<uint32_t, std::vector<uint8_t>, SeqLess>& ooo, uint32_t newest_seq, size_t max_blocks) {
    std::vector<SackBlock> merged;
    for (auto& [seq, data] : ooo) {
        uint32_t l = seq, r = seq + uint32_t(data.size());
        if (!merged.empty() && seq_leq(l, merged.back().right)) {
            if (seq_gt(r, merged.back().right)) merged.back().right = r;
        } else {
            merged.push_back({l, r});
        }
    }
    auto newest = std::find_if(merged.begin(), merged.end(), [&](const SackBlock& b) {
        return seq_leq(b.left, newest_seq) && seq_lt(newest_seq, b.right);
    });
    if (newest != merged.end()) std::rotate(merged.begin(), newest, newest + 1);
    if (merged.size() > max_blocks) merged.resize(max_blocks);
    return merged;
}

// ---------------------------------------------------------------- sender side of SACK
// The scoreboard: byte ranges [start, end) the peer told us it holds beyond snd_una.
using SackMap = std::map<uint32_t, uint32_t, SeqLess>;

inline void sack_add(SackMap& m, uint32_t l, uint32_t r) {
    for (auto it = m.begin(); it != m.end();) {                // merge with everything that overlaps or touches
        if (seq_gt(it->first, r)) break;
        if (seq_lt(it->second, l)) { ++it; continue; }
        if (seq_lt(it->first, l)) l = it->first;
        if (seq_gt(it->second, r)) r = it->second;
        it = m.erase(it);
    }
    m[l] = r;
}

// Forget what the cumulative ACK already covers.
inline void sack_trim(SackMap& m, uint32_t snd_una) {
    while (!m.empty() && seq_leq(m.begin()->second, snd_una)) m.erase(m.begin());
    if (!m.empty() && seq_lt(m.begin()->first, snd_una)) {
        uint32_t r = m.begin()->second;
        m.erase(m.begin());
        m[snd_una] = r;
    }
}

struct Hole {
    uint32_t start, end;       // bytes [start, end) are missing at the receiver
    bool below_sacked;         // true if the peer holds data ABOVE this hole (so it is surely lost)
};

// The first missing range at or after `from`, searching up to `limit` (normally snd_nxt).
inline std::optional<Hole> find_hole(const SackMap& m, uint32_t from, uint32_t limit) {
    uint32_t h = from;
    for (auto& [l, r] : m) {
        if (seq_leq(r, h)) continue;                           // entirely behind us
        if (seq_gt(l, h)) return Hole{h, l, true};             // a gap before this SACKed range
        h = r;                                                 // we are inside it: skip over it
    }
    if (seq_lt(h, limit)) return Hole{h, limit, false};
    return std::nullopt;
}
