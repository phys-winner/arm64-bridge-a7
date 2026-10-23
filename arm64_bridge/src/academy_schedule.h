// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <ctime>

namespace AcademySchedule {
constexpr int32_t epoch = 1790553600; // Monday, 2026-09-28 00:00 UTC, shared by every installation.
constexpr int32_t week_seconds = 604800;
constexpr int32_t maximum_week = (INT32_MAX - epoch) / week_seconds;
constexpr std::array<int32_t, 16> tracks = {3, 1, 4, 13, 6, 5, 11, 14, 7, 2, 9, 12, 10, 15, 8, 16};
constexpr std::array<int32_t, 80> cars = {
    101,102,176,103,104,105,106,160,107,108,109,110,111,112,113,163,
    161,162,175,114,115,116,117,159,121,122,123,124,125,126,127,128,
    165,825,130,131,132,821,133,134,135,136,137,138,139,801,800,817,
    804,144,145,146,147,148,149,824,819,808,816,818,150,823,151,152,
    153,154,811,155,802,803,156,820,809,167,813,174,157,822,805,158
};
inline int32_t WeekAt(int64_t utc_seconds) {
    const int64_t delta = std::clamp<int64_t>(utc_seconds, epoch,
        int64_t(epoch) + int64_t(maximum_week) * week_seconds - 1) - epoch;
    return int32_t(1 + delta / week_seconds);
}
struct Event { int32_t track, car, start_date, end_date; };
inline int32_t Date(int32_t seconds) {
    const std::time_t value = seconds;
    std::tm utc{};
    gmtime_r(&value, &utc);
    return (utc.tm_year + 1900) * 10000 + (utc.tm_mon + 1) * 100 + utc.tm_mday;
}
inline Event ForWeek(int32_t week) {
    const uint32_t index = uint32_t(std::clamp(week, 1, maximum_week) - 1);
    // Coprime strides visit every car/track; the cycle shift changes their later pairings.
    return {tracks[(9 + index * 7 + index / cars.size()) % tracks.size()],
            cars[(24 + index * 19) % cars.size()],
            Date(epoch + int32_t(index) * week_seconds),
            Date(epoch + (int32_t(index) + 1) * week_seconds)};
}
}
