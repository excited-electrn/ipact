// Layer 1: small, fast tests of the pure building blocks.
#include <deque>
#include <random>
#include "check.hpp"
#include "net/ipv4.hpp"
#include "tcp/header.hpp"
#include "tcp/options.hpp"
#include "tcp/rtt.hpp"
#include "util/byte_queue.hpp"
#include "util/checksum.hpp"

static std::vector<uint8_t> bytes(std::initializer_list<int> v) {
    std::vector<uint8_t> r;
    for (int x : v) r.push_back(uint8_t(x));
    return r;
}

TEST(checksum_known_vectors) {
    // RFC 1071 section 3 example: the sum is 0xddf2, so the checksum is 0x220d.
    CHECK_EQ(internet_checksum(bytes({0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7})), 0x220d);
    // The IPv4 header from the guide's checksum widget, with its checksum field zeroed.
    auto hdr = bytes({0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
                      0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7});
    CHECK_EQ(internet_checksum(hdr), 0xb861);
    // Odd length: the last byte is padded with a zero low byte.
    CHECK_EQ(internet_checksum(bytes({0x01})), 0xfeff);
    // A buffer that includes its own checksum sums to zero.
    hdr[10] = 0xb8; hdr[11] = 0x61;
    CHECK_EQ(internet_checksum(hdr), 0);
}

TEST(sequence_numbers_wrap_around) {
    CHECK(seq_lt(0xFFFFFFF0u, 5u));          // 5 is "after" 0xFFFFFFF0 once the counter wrapped
    CHECK(!seq_lt(5u, 0xFFFFFFF0u));
    CHECK(seq_gt(5u, 0xFFFFFFF0u));
    CHECK(seq_leq(7u, 7u));
    CHECK(seq_in_range(2u, 0xFFFFFFFEu, 10u));   // the range [0xFFFFFFFE, 10) crosses zero
    CHECK(!seq_in_range(10u, 0xFFFFFFFEu, 10u));
    CHECK(!seq_in_range(0xFFFFFFFDu, 0xFFFFFFFEu, 10u));
}

TEST(build_then_parse_roundtrip) {
    const uint32_t src = 0x0A000001, dst = 0x0A000002;
    TcpHeader h{};
    h.src_port = 1234; h.dst_port = 80; h.seq = 0xFFFFFFFF; h.ack = 42;
    h.flags = flag::ACK | flag::PSH; h.window = 5000;
    std::vector<uint8_t> payload = {'h', 'i', '!'};
    auto seg = build_tcp(src, dst, h, payload);
    auto pkt = build_ipv4(src, dst, IpProto::TCP, seg, 7);

    auto ip = parse_ipv4(pkt);
    CHECK(ip.has_value());
    CHECK_EQ(ip->h.src, src);
    auto tcp = parse_tcp(ip->h.src, ip->h.dst, ip->payload);
    CHECK(tcp.has_value());
    CHECK_EQ(tcp->h.seq, 0xFFFFFFFFu);
    CHECK_EQ(tcp->h.window, 5000);
    CHECK(tcp->h.has(flag::PSH));
    CHECK_EQ(tcp->payload.size(), 3u);

    // One flipped bit anywhere must be caught by the checksum.
    auto bad = seg;
    bad[20] ^= 0x01;
    CHECK(!parse_tcp(src, dst, bad).has_value());
}

TEST(parsers_reject_garbage_without_crashing) {
    std::vector<uint8_t> empty, tiny = {0x45, 0, 0}, wrong_version(20, 0);
    CHECK(!parse_ipv4(empty).has_value());
    CHECK(!parse_ipv4(tiny).has_value());
    CHECK(!parse_ipv4(wrong_version).has_value());
    CHECK(!parse_tcp(1, 2, tiny).has_value());
}

TEST(options_parse_build_and_malformed) {
    OptionWriter w;
    w.mss(1460); w.sack_permitted(); w.timestamps(111, 222); w.nop(); w.wscale(7);
    auto bytes_ = w.finish();
    CHECK_EQ(bytes_.size() % 4, 0u);
    auto o = parse_options(bytes_);
    CHECK(o.has_value());
    CHECK_EQ(*o->mss, 1460);
    CHECK_EQ(*o->wscale, 7);
    CHECK(o->sack_permitted);
    CHECK_EQ(o->timestamp->first, 111u);
    CHECK_EQ(o->timestamp->second, 222u);

    CHECK(!parse_options(bytes({2, 4, 5})).has_value());            // MSS cut short
    CHECK(!parse_options(bytes({2})).has_value());                  // kind without a length
    CHECK(!parse_options(bytes({3, 0})).has_value());               // length below 2 (would loop forever)
    CHECK(!parse_options(bytes({3, 200, 1, 1})).has_value());       // length runs past the end
    CHECK(!parse_options(bytes({2, 3, 1})).has_value());            // MSS must be exactly 4 long
    CHECK(parse_options(bytes({99, 4, 0, 0, 1, 1, 1, 1})).has_value());   // unknown option: skipped by length
    CHECK(parse_options({}).has_value());                           // no options is fine

    SackBlock a{1000, 2000}, b{3000, 4000};
    OptionWriter w2; w2.nop(); w2.nop(); w2.sack({a, b});
    auto o2 = parse_options(w2.finish());
    CHECK(o2.has_value() && o2->sack.size() == 2 && o2->sack[1].right == 4000);
}

TEST(byte_queue_behaves_like_a_deque) {
    // The ring buffer must match a trivially-correct model through thousands of random operations,
    // including every wrap-around situation.
    std::mt19937 rng(7);
    ByteQueue q(100);
    std::deque<uint8_t> model;
    uint8_t next = 0;
    for (int step = 0; step < 20000; ++step) {
        switch (rng() % 4) {
            case 0: {                                             // write
                std::vector<uint8_t> data(rng() % 60);
                for (auto& b : data) b = next++;
                size_t n = q.write(data);
                CHECK_EQ(n, std::min(data.size(), 100 - model.size()));
                model.insert(model.end(), data.begin(), data.begin() + long(n));
                break;
            }
            case 1: {                                             // read
                std::vector<uint8_t> out(rng() % 60);
                size_t n = q.read(out);
                for (size_t i = 0; i < n; ++i) { CHECK_EQ(out[i], model.front()); model.pop_front(); }
                break;
            }
            case 2: {                                             // peek at an offset
                size_t off = rng() % 120;
                std::vector<uint8_t> out(rng() % 60);
                size_t n = q.peek(off, out);
                for (size_t i = 0; i < n; ++i) CHECK_EQ(out[i], model[off + i]);
                break;
            }
            case 3: {                                             // consume
                size_t n = rng() % 70;
                q.consume(n);
                model.erase(model.begin(), model.begin() + long(std::min(n, model.size())));
                break;
            }
        }
        CHECK_EQ(q.size(), model.size());
    }
}

TEST(rtt_estimator_follows_rfc6298) {
    using ms = RttEstimator::ms;
    RttEstimator r(ms(200), ms(60000));
    CHECK_EQ(long(r.rto().count()), 1000);                          // initial RTO is 1 s
    r.on_sample(ms(100));                                           // first sample R: SRTT=R, RTTVAR=R/2
    CHECK_EQ(long(r.srtt().count()), 100);
    CHECK_EQ(long(r.rttvar().count()), 50);
    CHECK_EQ(long(r.rto().count()), 300);                           // SRTT + 4*RTTVAR
    r.on_sample(ms(100));                                           // RTTVAR = 0.75*50, RTO = 100 + 4*37.5
    CHECK_EQ(long(r.rto().count()), 250);
    r.on_timeout();
    CHECK_EQ(long(r.rto().count()), 500);                           // back-off doubles
    r.on_timeout();
    CHECK_EQ(long(r.rto().count()), 1000);
    r.reset_backoff();
    CHECK_EQ(long(r.rto().count()), 250);
    RttEstimator fast(ms(200), ms(60000));
    fast.on_sample(ms(1));
    CHECK(fast.rto().count() >= 200);                               // never below the minimum
}

TEST(sack_scoreboard_merge_trim_and_holes) {
    SackMap m;
    sack_add(m, 3000, 4000);
    sack_add(m, 5000, 6000);
    CHECK_EQ(m.size(), 2u);
    sack_add(m, 4000, 5000);                                        // bridges the two ranges
    CHECK_EQ(m.size(), 1u);
    CHECK_EQ(m.begin()->first, 3000u);
    CHECK_EQ(m.begin()->second, 6000u);

    auto hole = find_hole(m, 1000, 8000);                           // [1000, 3000) is missing, data above it
    CHECK(hole && hole->start == 1000 && hole->end == 3000 && hole->below_sacked);
    auto tail = find_hole(m, 3500, 8000);                           // inside the range: next gap is the tail
    CHECK(tail && tail->start == 6000 && tail->end == 8000 && !tail->below_sacked);
    CHECK(!find_hole(m, 3500, 6000).has_value());                   // nothing missing up to 6000

    sack_trim(m, 4500);                                             // cumulative ACK moved into the range
    CHECK_EQ(m.begin()->first, 4500u);
    sack_trim(m, 6000);
    CHECK(m.empty());

    SackMap w;                                                      // the same logic across the 2^32 wrap
    sack_add(w, 0xFFFFFF00u, 0xFFFFFFF0u);
    sack_add(w, 0xFFFFFFF0u, 0x00000010u);
    CHECK_EQ(w.size(), 1u);
    CHECK_EQ(w.begin()->second, 0x10u);
}

TEST(sack_blocks_newest_first_and_limited) {
    std::map<uint32_t, std::vector<uint8_t>, SeqLess> ooo;
    ooo[1000] = std::vector<uint8_t>(100);
    ooo[1100] = std::vector<uint8_t>(100);                          // touches the previous one: one block
    ooo[3000] = std::vector<uint8_t>(50);
    ooo[5000] = std::vector<uint8_t>(50);
    ooo[7000] = std::vector<uint8_t>(50);
    auto blocks = make_sack_blocks(ooo, 3010, 3);
    CHECK_EQ(blocks.size(), 3u);
    CHECK_EQ(blocks[0].left, 3000u);                                // the block with the newest segment is first
    CHECK_EQ(blocks[0].right, 3050u);
    bool merged = false;
    for (auto& b : blocks) if (b.left == 1000 && b.right == 1200) merged = true;
    CHECK(merged);
}

int main() { return run_all_tests(); }
