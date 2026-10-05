#pragma once

#include <cstdint>
#include <algorithm>
#include <optional>
#include <vector>

#include "net/ipv4.hpp"

std::optional<std::vector<uint8_t>> handle_icmp(const Ipv4View& ip, uint16_t& ip_id_counter);