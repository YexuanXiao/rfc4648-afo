#pragma once

#include <cassert>
#include <concepts>
#include <cstring>
#include <iterator>
#include <type_traits>
#include <utility>

#include "./common.hpp"

namespace bizwen
{
namespace decode_impl
{
namespace table
{
inline constexpr char8_t base64[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 62,   0xFF, 0xFF, 0xFF, 63,   52,   53,   54,   55,   56,   57,   58,   59,   60,
    61,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,    8,    9,    10,
    11,   12,   13,   14,   15,   16,   17,   18,   19,   20,   21,   22,   23,   24,   25,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 26,   27,   28,   29,   30,   31,   32,   33,   34,   35,   36,   37,   38,   39,   40,   41,   42,
    43,   44,   45,   46,   47,   48,   49,   50,   51,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
inline constexpr char8_t base64_url[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x62, 0xFF, 0xFF, 52,   53,   54,   55,   56,   57,   58,   59,   60,
    61,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,    8,    9,    10,
    11,   12,   13,   14,   15,   16,   17,   18,   19,   20,   21,   22,   23,   24,   25,   0xFF, 0xFF, 0xFF, 0xFF,
    63,   0xFF, 26,   27,   28,   29,   30,   31,   32,   33,   34,   35,   36,   37,   38,   39,   40,   41,   42,
    43,   44,   45,   46,   47,   48,   49,   50,   51,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
inline constexpr char8_t base32[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 26,   27,   28,   29,   30,   31,   0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,    8,    9,    10,
    11,   12,   13,   14,   15,   16,   17,   18,   19,   20,   21,   22,   23,   24,   25,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
inline constexpr char8_t base32_lower[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 26,   27,   28,   29,   30,   31,   0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,    8,    9,    10,   11,   12,   13,   14,   15,   16,
    17,   18,   19,   20,   21,   22,   23,   24,   25,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
inline constexpr char8_t base32_mixed[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 26,   27,   28,   29,   30,   31,   0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,    8,    9,    10,
    11,   12,   13,   14,   15,   16,   17,   18,   19,   20,   21,   22,   23,   24,   25,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,    8,    9,    10,   11,   12,   13,   14,   15,   16,
    17,   18,   19,   20,   21,   22,   23,   24,   25,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
inline constexpr char8_t base32_hex[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,    8,
    9,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 10,   11,   12,   13,   14,   15,   16,   17,   18,   19,   20,
    21,   22,   23,   24,   25,   26,   27,   28,   29,   30,   31,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
inline constexpr char8_t base32_hex_lower[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,    8,
    9,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 10,   11,   12,   13,   14,   15,   16,   17,   18,   19,   20,   21,   22,   23,   24,   25,   26,
    27,   28,   29,   30,   31,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
inline constexpr char8_t base32_hex_mixed[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,    8,
    9,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 10,   11,   12,   13,   14,   15,   16,   17,   18,   19,   20,
    21,   22,   23,   24,   25,   26,   27,   28,   29,   30,   31,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 10,   11,   12,   13,   14,   15,   16,   17,   18,   19,   20,   21,   22,   23,   24,   25,   26,
    27,   28,   29,   30,   31,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
inline constexpr char8_t base32_crockford[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,    8,
    9,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 10,   11,   12,   13,   14,   15,   16,   17,   0xFF, 18,   19,
    0xFF, 20,   21,   0xFF, 22,   23,   24,   25,   26,   0xFF, 27,   28,   29,   30,   31,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
inline constexpr char8_t base32_crockford_lower[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,    8,
    9,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 10,   11,   12,   13,   14,   15,   16,   17,   0xFF, 18,   19,   0xFF, 20,   21,   0xFF, 22,   23,
    24,   25,   26,   0xFF, 27,   28,   29,   30,   31,   32,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
inline constexpr char8_t base32_crockford_mixed[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,    8,
    9,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 10,   11,   12,   13,   14,   15,   16,   17,   0xFF, 18,   19,
    0xFF, 20,   21,   0xFF, 22,   23,   24,   25,   26,   0xFF, 27,   28,   29,   30,   31,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 10,   11,   12,   13,   14,   15,   16,   17,   0xFF, 18,   19,   0xFF, 20,   21,   0xFF, 22,   23,
    24,   25,   26,   0xFF, 27,   28,   29,   30,   31,   32,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
inline constexpr char8_t base16[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,    8,
    9,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 10,   11,   12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
inline constexpr char8_t base16_lower[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,    8,
    9,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 10,   11,   12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
inline constexpr char8_t base16_mixed[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,    8,
    9,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 10,   11,   12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 10,   11,   12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
} // namespace table

using table_ref = std::add_lvalue_reference_t<decltype(table::base64)>;

inline constexpr table_ref get_table(rfc4648_kind kind) noexcept
{
    if (kind == rfc4648_kind::base64)
        return table::base64;
    if (kind == rfc4648_kind::base64_url)
        return table::base64_url;
    if (kind == rfc4648_kind::base32)
        return table::base32;
    if (kind == rfc4648_kind::base32_lower)
        return table::base32_lower;
    if (kind == rfc4648_kind::base32_mixed)
        return table::base32_mixed;
    if (kind == rfc4648_kind::base32_hex)
        return table::base32_hex;
    if (kind == rfc4648_kind::base32_hex_lower)
        return table::base32_hex_lower;
    if (kind == rfc4648_kind::base32_hex_mixed)
        return table::base32_hex_mixed;
    if (kind == rfc4648_kind::base32_crockford)
        return table::base32_crockford;
    if (kind == rfc4648_kind::base32_crockford_lower)
        return table::base32_crockford_lower;
    if (kind == rfc4648_kind::base32_crockford_mixed)
        return table::base32_crockford_mixed;
    if (kind == rfc4648_kind::base16)
        return table::base16;
    if (kind == rfc4648_kind::base16_lower)
        return table::base16_lower;
    if (kind == rfc4648_kind::base16_mixed)
        return table::base16_mixed;

    assert(false);
    std::unreachable();
}

template <typename T>
inline constexpr bool valid_stage1(T t) noexcept
{
    using u = std::make_unsigned_t<T>;

    if (sizeof(T) == 1)
        return true;
    else
        return !(u(t) & ~u(0xFF));
}

inline constexpr bool valid_stage2(unsigned char t) noexcept
{
    return t != 0xFF;
}

template <typename T>
inline constexpr bool is_valid(T t, unsigned char u) noexcept
{
    static_assert(!std::is_same_v<unsigned char, T>);
    return valid_stage1(t) && valid_stage2(u);
}

template <typename T>
inline constexpr unsigned char decode_single(T t, table_ref table) noexcept
{
    return table[static_cast<unsigned char>(t)];
}

template <typename Out>
void check_value_write(Out &&out, unsigned char value)
{
    if constexpr (std::indirectly_writable<Out, unsigned char>)
        *out = value;
    else if constexpr (std::indirectly_writable<Out, char>)
        *out = static_cast<char>(value);
    else if constexpr (std::indirectly_writable<Out, std::byte>)
        *out = static_cast<std::byte>(value);
    else
        static_assert(false,
                      "Output iterator cannot be used to write values of type char, unsigned char, or std::byte.");
}

struct decode_status_b64_b32
{
    // base64
    // 1      2      3      4
    // XXXXXX XXXXXX XXXXXX XXXXXX
    // XXXXXX XX
    //          XXXX XXXX
    //                   XX XXXXXX
    // base32
    // 1     2     3     4     5     6     7     8
    // XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX
    // XXXXX XXX
    //          XX XXXXX X
    //                    XXXX XXXX
    //                             X XXXXX XX
    //                                       XXX XXXXX
    alignas(int) unsigned char sig_{}; // 0 - 4, 0 - 8
    alignas(int) unsigned char buf_;

    // If sig is not 0 at the end of decoding, then buf_ must be 0 and discarded.

    template <typename C, typename Out>
    bool write_b64(C c, Out &first, table_ref table)
    {
        auto res = decode_single(c, table);

        if (!is_valid(c, res))
            return false;

        ++sig_;

        if (sig_ == 1)
        {
            buf_ = res << 2;
        }
        else if (sig_ == 2)
        {
            check_value_write(first, buf_ | res >> 4);
            ++first;
            buf_ = res << 4;
        }
        else if (sig_ == 3)
        {
            check_value_write(first, buf_ | (res >> 2));
            ++first;
            buf_ = res << 6;
        }
        else if (sig_ == 4)
        {
            check_value_write(first, buf_ | res);
            ++first;
            // NB: reset sig
            sig_ = 0;
        }
        else
        {
            std::unreachable();
        }

        return true;
    }

    template <typename In>
    void eat_equal_sign_b64(In &begin, In &end) noexcept
    {
        static_assert(std::is_pointer_v<In>);

        if (sig_ == 3)
        {
            if (begin != end && *begin == '=')
                ++begin;
        }
        else if (sig_ == 2)
        {
            if (begin != end && *begin == '=')
                ++begin;
            if (begin != end && *begin == '=')
                ++begin;
        }
    }

    template <typename C, typename Out>
    bool write_b32(C c, Out &first, table_ref table)
    {
        auto res = decode_single(c, table);

        if (!is_valid(c, res))
            return false;

        ++sig_;

        if (sig_ == 1)
        {
            buf_ = res << 3;
        }
        else if (sig_ == 2)
        {
            check_value_write(first, buf_ | res >> 2);
            ++first;
            buf_ = res << 6;
        }
        else if (sig_ == 3)
        {
            buf_ |= res << 1;
        }
        else if (sig_ == 4)
        {
            check_value_write(first, buf_ | res >> 4);
            ++first;
            buf_ = res << 4;
        }
        else if (sig_ == 5)
        {
            check_value_write(first, buf_ | res >> 1);
            ++first;
            buf_ = res << 7;
        }
        else if (sig_ == 6)
        {
            buf_ |= res << 2;
        }
        else if (sig_ == 7)
        {
            check_value_write(first, buf_ | res >> 3);
            ++first;
            buf_ = res << 5;
        }
        else if (sig_ == 8)
        {
            check_value_write(first, buf_ | res);
            ++first;
            // NB: reset sig
            sig_ = 0;
        }
        else
        {
            std::unreachable();
        }

        return true;
    }

    template <typename In>
    void eat_equal_sign_b32(In &begin, In &end) noexcept
    {
        static_assert(std::is_pointer_v<In>);

        if (sig_ == 2 | sig_ == 4 | sig_ == 5 | sig_ == 7)
        {
            for (std::size_t i{}; i != (8 - sig_); ++i)
            {
                if (begin != end)
                {
                    if (*begin == '=')
                        ++begin;
                    else
                        return;
                }
                else
                {
                    return;
                }
            }
        }
    }
};

template <typename In, typename Out>
inline constexpr In decode_impl_b32(In begin, In end, Out &first, table_ref table, bool padding)
{
    static_assert(std::is_pointer_v<In>);

    decode_status_b64_b32 status{};

    for (; begin != end; ++begin)
    {
        if (!status.write_b64(*begin, first, table))
            break;
    }

    if (padding)
    {
        status.eat_equal_sign_b32(begin, end);
    }

    return begin;
}

template <typename In, typename Out>
inline constexpr In decode_impl_b64(In begin, In end, Out &first, table_ref table, bool padding)
{
    static_assert(std::is_pointer_v<In>);

    decode_status_b64_b32 status{};

    for (; begin != end; ++begin)
    {
        if (!status.write_b64(*begin, first, table))
            break;
    }

    if (padding)
    {
        status.eat_equal_sign_b64(begin, end);
    }

    return begin;
}

template <typename In, typename Out>
inline constexpr In decode_impl_b64_ctx(detail::sig_ref sig, detail::buf_ref buf, In begin, In end, Out &first,
                                        table_ref table)
{
    static_assert(std::is_pointer_v<In>);

    decode_status_b64_b32 status{sig, buf[0]};

    for (; begin != end; ++begin)
    {
        if (!status.write_b64(*begin, first, table))
            break;
    }

    sig = status.sig_;
    buf[0] = status.buf_;

    return begin;
}

template <typename In, typename Out>
inline constexpr In decode_impl_b32_ctx(detail::sig_ref sig, detail::buf_ref buf, In begin, In end, Out &first,
                                        table_ref table)
{
    static_assert(std::is_pointer_v<In>);

    decode_status_b64_b32 status{sig, buf[0]};

    for (; begin != end; ++begin)
    {
        if (!status.write_b32(*begin, first, table))
            break;
    }

    sig = status.sig_;
    buf[0] = status.buf_;

    return begin;
}

template <typename In>
inline constexpr void decode_impl_b64_ctx(detail::sig_ref sig, detail::buf_ref buf, In &begin, In &end,
                                          bool padding) noexcept
{
    auto sig_ = sig;
    sig = 0;

    if (padding)
    {
        decode_status_b64_b32 status{sig_, buf[0]};
        status.eat_equal_sign_b64(begin, end);
    }
}

template <typename In>
inline constexpr void decode_impl_b32_ctx(detail::sig_ref sig, detail::buf_ref buf, In &begin, In &end,
                                          bool padding) noexcept
{
    auto sig_ = sig;
    sig = 0;

    if (padding)
    {
        decode_status_b64_b32 status{sig_, buf[0]};
        status.eat_equal_sign_b32(begin, end);
    }
}

template <typename In, typename Out>
inline constexpr In decode_impl_b16(In begin, In end, Out &first, table_ref table)
{
    static_assert(std::is_pointer_v<In>);

    while (end - begin > 1)
    {
        auto c0 = *begin;
        auto res0 = decode_single(c0, table);

        if (!is_valid(c0, res0))
            return begin;

        ++begin;

        auto c1 = *begin;
        auto res1 = decode_single(c1, table);

        if (!is_valid(c1, res1))
            return begin;

        ++begin;

        check_value_write(first, (res0 << 4) | res1);
        ++first;
    }

    if (end != begin)
    {
        auto c = *begin;
        auto res = decode_single(c, table);

        if (!is_valid(c, res))
            return begin;

        ++begin;

        check_value_write(first, res << 4);
        ++first;
    }

    return begin;
}

template <typename In, typename Out>
inline constexpr In decode_impl_b16_ctx(detail::sig_ref sig, detail::buf_ref buf, In begin, In end, Out &first,
                                        table_ref table)
{
    static_assert(std::is_pointer_v<In>);

    for (; begin != end; ++begin)
    {
        auto c = *begin;
        auto res = decode_single(c, table);

        if (!is_valid(c, res))
            break;

        ++sig;

        if (sig == 1)
        {
            buf[0] = res << 4;
            sig = 1;
        }
        else if (sig == 2)
        {
            check_value_write(first, buf[0] | res);
            ++first;
            sig = 0;
        }
        else
        {
            std::unreachable();
        }
    }

    return begin;
}

struct rfc4648_decode_fn
{
    template <typename In, typename Out>
    static inline constexpr rfc4648_decode_result<In, Out> operator()(In begin, In end, Out first,
                                                                      rfc4648_kind kind = rfc4648_kind::base64,
                                                                      bool padding = true)
    {
        using in_char = std::iterator_traits<In>::value_type;

        static_assert(std::contiguous_iterator<In>);
        static_assert(std::is_same_v<in_char, char> || std::is_same_v<in_char, wchar_t> ||
                      std::is_same_v<in_char, char8_t> || std::is_same_v<in_char, char16_t> ||
                      std::is_same_v<in_char, char32_t>);

        auto begin_ptr = detail::to_address_const(begin);
        auto end_ptr = detail::to_address_const(end);

        decltype(begin_ptr) last_ptr = {};

        if (detail::get_family(kind) == rfc4648_kind::base64)
            last_ptr = decode_impl::decode_impl_b64(begin_ptr, end_ptr, first, decode_impl::get_table(kind), padding);
        if (detail::get_family(kind) == rfc4648_kind::base32)
            last_ptr = decode_impl::decode_impl_b32(begin_ptr, end_ptr, first, decode_impl::get_table(kind), padding);
        ;
        if (detail::get_family(kind) == rfc4648_kind::base16)
            last_ptr = decode_impl::decode_impl_b16(begin_ptr, end_ptr, first, decode_impl::get_table(kind));
        ;

        return {begin + (last_ptr - begin_ptr), std::move(first)};
    }

    template <typename R, typename Out>
    static inline constexpr auto operator()(R &&r, Out first, rfc4648_kind kind = rfc4648_kind::base64,
                                            bool padding = true)
    {
        return operator()(std::ranges::begin(r), std::ranges::end(r), first, kind, padding);
    }

    template <typename In, typename Out>
    static inline constexpr rfc4648_decode_result<In, Out> operator()(rfc4648_context &ctx, In begin, In end, Out first,
                                                                      rfc4648_kind kind = rfc4648_kind::base64)
    {
        using in_char = std::iterator_traits<In>::value_type;

        static_assert(std::contiguous_iterator<In>);
        static_assert(std::is_same_v<in_char, char> || std::is_same_v<in_char, wchar_t> ||
                      std::is_same_v<in_char, char8_t> || std::is_same_v<in_char, char16_t> ||
                      std::is_same_v<in_char, char32_t>);

        auto begin_ptr = detail::to_address_const(begin);
        auto end_ptr = detail::to_address_const(end);

        decltype(begin_ptr) last_ptr = {};

        if (detail::get_family(kind) == rfc4648_kind::base64)
            last_ptr = decode_impl::decode_impl_b64_ctx(ctx.sig_, ctx.buf_, begin_ptr, end_ptr, first,
                                                        decode_impl::get_table(kind));
        if (detail::get_family(kind) == rfc4648_kind::base32)
            last_ptr = decode_impl::decode_impl_b32_ctx(ctx.sig_, ctx.buf_, begin_ptr, end_ptr, first,
                                                        decode_impl::get_table(kind));
        ;
        if (detail::get_family(kind) == rfc4648_kind::base16)
            last_ptr = decode_impl::decode_impl_b16_ctx(ctx.sig_, ctx.buf_, begin_ptr, end_ptr, first,
                                                        decode_impl::get_table(kind));
        ;

        return {begin + (last_ptr - begin_ptr), std::move(first)};
    }

    template <typename R, typename Out>
    static inline constexpr auto operator()(rfc4648_context &ctx, R &&r, Out first,
                                            rfc4648_kind kind = rfc4648_kind::base64)
    {
        return operator()(ctx, std::ranges::begin(r), std::ranges::end(r), first, kind);
    }

    template <typename In>
    static inline constexpr In operator()(rfc4648_context &ctx, In begin, In end,
                                          rfc4648_kind kind = rfc4648_kind::base64, bool padding = true)
    {
        using in_char = std::iterator_traits<In>::value_type;

        static_assert(std::contiguous_iterator<In>);
        static_assert(std::is_same_v<in_char, char> || std::is_same_v<in_char, wchar_t> ||
                      std::is_same_v<in_char, char8_t> || std::is_same_v<in_char, char16_t> ||
                      std::is_same_v<in_char, char32_t>);

        auto begin_ptr = detail::to_address_const(begin);
        auto end_ptr = detail::to_address_const(end);

        decltype(begin_ptr) last_ptr = begin_ptr;

        if (detail::get_family(kind) == rfc4648_kind::base64)
            decode_impl::decode_impl_b64_ctx(ctx.sig_, ctx.buf_, last_ptr, end_ptr, padding);
        if (detail::get_family(kind) == rfc4648_kind::base32)
            decode_impl::decode_impl_b32_ctx(ctx.sig_, ctx.buf_, last_ptr, end_ptr, padding);
        // no effect when family is base16 and CHAR_BIT is 8

        return {begin + (last_ptr - begin_ptr)};
    }
};
} // namespace decode_impl

inline constexpr decode_impl::rfc4648_decode_fn rfc4648_decode;
} // namespace bizwen
