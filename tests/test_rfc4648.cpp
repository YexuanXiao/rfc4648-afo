#include "decode.hpp"
#include "encode.hpp"
#include "tests/generated_vectors.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace
{
using rfc4648_test_vectors::vector;

template <typename Ptr>
struct sized_input_sentinel
{
    Ptr last{};
};

template <typename Ptr>
constexpr bool operator==(Ptr it, sized_input_sentinel<Ptr> s) noexcept
{
    return it == s.last;
}

template <typename Ptr>
constexpr bool operator==(sized_input_sentinel<Ptr> s, Ptr it) noexcept
{
    return it == s.last;
}

template <typename Ptr>
constexpr std::ptrdiff_t operator-(sized_input_sentinel<Ptr> s, Ptr it) noexcept
{
    return s.last - it;
}

template <typename Ptr>
constexpr std::ptrdiff_t operator-(Ptr it, sized_input_sentinel<Ptr> s) noexcept
{
    return it - s.last;
}

template <typename Ptr>
struct sized_sentinel_range
{
    Ptr first{};
    sized_input_sentinel<Ptr> last{};

    constexpr Ptr begin() const noexcept
    {
        return first;
    }

    constexpr sized_input_sentinel<Ptr> end() const noexcept
    {
        return last;
    }
};

[[nodiscard]] constexpr bool encoding_supported(bizwen::rfc4648_kind kind) noexcept
{
    return !(kind == bizwen::rfc4648_kind::base32_mixed || kind == bizwen::rfc4648_kind::base32_hex_mixed ||
             kind == bizwen::rfc4648_kind::base32_crockford_mixed || kind == bizwen::rfc4648_kind::base16_mixed);
}

[[nodiscard]] std::string invert_ascii_alpha_case(std::string_view s)
{
    std::string out{s};
    for (char &c : out)
    {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
        else if (c >= 'a' && c <= 'z')
            c = static_cast<char>(c - 'a' + 'A');
    }
    return out;
}

void check_vector_once(vector const &v)
{
    std::span<unsigned char const> input{v.input, v.input_size};
    std::string_view expected = v.encoded;

    if (encoding_supported(v.kind))
    {
        std::string encoded(expected.size(), '\0');
        auto encoded_end = bizwen::rfc4648_encode(input.begin(), input.end(), encoded.begin(), v.kind, v.padding);
        assert(encoded_end == encoded.end());
        assert(encoded == expected);

        std::string encoded_range(expected.size(), '\0');
        auto encoded_range_end = bizwen::rfc4648_encode(input, encoded_range.begin(), v.kind, v.padding);
        assert(encoded_range_end == encoded_range.end());
        assert(encoded_range == expected);

        std::string encoded_sentinel(expected.size(), '\0');
        auto const *begin_ptr = input.data();
        sized_input_sentinel<unsigned char const *> end_sentinel{begin_ptr + static_cast<std::ptrdiff_t>(input.size())};
        auto encoded_sentinel_end = bizwen::rfc4648_encode(begin_ptr, end_sentinel, encoded_sentinel.begin(), v.kind, v.padding);
        assert(encoded_sentinel_end == encoded_sentinel.end());
        assert(encoded_sentinel == expected);

        std::string encoded_sentinel_range(expected.size(), '\0');
        sized_sentinel_range<unsigned char const *> rng{begin_ptr, end_sentinel};
        auto encoded_sentinel_range_end = bizwen::rfc4648_encode(rng, encoded_sentinel_range.begin(), v.kind, v.padding);
        assert(encoded_sentinel_range_end == encoded_sentinel_range.end());
        assert(encoded_sentinel_range == expected);

        assert(bizwen::rfc4648_encode_length(input.size(), v.kind) >= expected.size());
    }

    assert(bizwen::rfc4648_decode_length(expected.size(), v.kind) >= input.size());

    std::vector<unsigned char> decoded(input.size());
    auto [end1, out1] = bizwen::rfc4648_decode(expected.begin(), expected.end(), decoded.begin(), v.kind, v.padding);
    assert(end1 == expected.end());
    assert(out1 == decoded.end());
    assert(std::equal(decoded.begin(), decoded.end(), input.begin(), input.end()));

    std::vector<unsigned char> decoded_range(input.size());
    auto [end2, out2] = bizwen::rfc4648_decode(expected, decoded_range.begin(), v.kind, v.padding);
    assert(end2 == expected.end());
    assert(out2 == decoded_range.end());
    assert(std::equal(decoded_range.begin(), decoded_range.end(), input.begin(), input.end()));

    std::vector<unsigned char> decoded_sentinel(input.size());
    auto const *decode_begin = expected.data();
    sized_input_sentinel<char const *> decode_end{decode_begin + static_cast<std::ptrdiff_t>(expected.size())};
    auto [end3, out3] = bizwen::rfc4648_decode(decode_begin, decode_end, decoded_sentinel.begin(), v.kind, v.padding);
    assert(end3 == decode_begin + static_cast<std::ptrdiff_t>(expected.size()));
    assert(out3 == decoded_sentinel.end());
    assert(std::equal(decoded_sentinel.begin(), decoded_sentinel.end(), input.begin(), input.end()));

    std::vector<unsigned char> decoded_sentinel_range(input.size());
    sized_sentinel_range<char const *> decode_rng{decode_begin, decode_end};
    auto [end4, out4] = bizwen::rfc4648_decode(decode_rng, decoded_sentinel_range.begin(), v.kind, v.padding);
    assert(end4 == decode_begin + static_cast<std::ptrdiff_t>(expected.size()));
    assert(out4 == decoded_sentinel_range.end());
    assert(std::equal(decoded_sentinel_range.begin(), decoded_sentinel_range.end(), input.begin(), input.end()));
}

void check_vector_with_context(vector const &v)
{
    std::span<unsigned char const> input{v.input, v.input_size};
    std::string_view expected = v.encoded;

    if (encoding_supported(v.kind))
    {
        std::string encoded(expected.size(), '\0');
        bizwen::rfc4648_context ctx;

        auto out = encoded.begin();
        auto const *p = input.data();
        auto n = input.size();

        auto n1 = std::min<std::size_t>(1, n);
        auto n2 = std::min<std::size_t>(2, n - n1);

        out = bizwen::rfc4648_encode(ctx, p, p + n1, out, v.kind);
        out = bizwen::rfc4648_encode(ctx, p + n1, p + n1 + n2, out, v.kind);
        out = bizwen::rfc4648_encode(ctx, p + n1 + n2, p + n, out, v.kind);
        out = bizwen::rfc4648_encode(ctx, out, v.kind, v.padding);

        assert(out == encoded.end());
        assert(encoded == expected);
    }

        {
            std::vector<unsigned char> decoded(input.size());
            bizwen::rfc4648_context ctx;

            auto out = decoded.begin();

        auto const *begin = expected.data();
        auto const *end = begin + static_cast<std::ptrdiff_t>(expected.size());

        auto first_pad = expected.find('=');
        if (first_pad == std::string_view::npos)
            first_pad = expected.size();

        auto c1 = std::min<std::size_t>(1, first_pad);
        auto c2 = std::min<std::size_t>(2, first_pad - c1);

        auto const *mid1 = begin + static_cast<std::ptrdiff_t>(c1);
        auto const *mid2 = mid1 + static_cast<std::ptrdiff_t>(c2);

        auto [it1, out1] = bizwen::rfc4648_decode(ctx, begin, sized_input_sentinel<char const *>{mid1}, out, v.kind);
        assert(it1 == mid1);
        std::tie(it1, out1) =
            bizwen::rfc4648_decode(ctx, it1, sized_input_sentinel<char const *>{mid2}, out1, v.kind);
        assert(it1 == mid2);
        auto [it3, out3] = bizwen::rfc4648_decode(ctx, it1, sized_input_sentinel<char const *>{end}, out1, v.kind);

        auto it4 = bizwen::rfc4648_decode(ctx, it3, sized_input_sentinel<char const *>{end}, v.kind, v.padding);
        assert(it4 == end);

            assert(out3 == decoded.end());
            assert(std::equal(decoded.begin(), decoded.end(), input.begin(), input.end()));
        }
}

void check_mixed_decode(bizwen::rfc4648_kind kind, bool padding, std::string_view encoded,
                        std::span<unsigned char const> expected_plain)
{
    std::string flipped = invert_ascii_alpha_case(encoded);
    if (flipped == encoded)
        return;

    std::vector<unsigned char> decoded(expected_plain.size());
    auto [end, out] = bizwen::rfc4648_decode(flipped.begin(), flipped.end(), decoded.begin(), kind, padding);
    assert(end == flipped.end());
    assert(out == decoded.end());
    assert(std::equal(decoded.begin(), decoded.end(), expected_plain.begin(), expected_plain.end()));
}
} // namespace

int main()
{
    for (vector const &v : rfc4648_test_vectors::vectors)
    {
        check_vector_once(v);
        check_vector_with_context(v);

        std::span<unsigned char const> input{v.input, v.input_size};

        if (v.kind == bizwen::rfc4648_kind::base32_mixed || v.kind == bizwen::rfc4648_kind::base32_hex_mixed ||
            v.kind == bizwen::rfc4648_kind::base32_crockford_mixed || v.kind == bizwen::rfc4648_kind::base16_mixed)
        {
            check_mixed_decode(v.kind, v.padding, v.encoded, input);
        }
    }

    // Base64-url must round-trip '-' and '_' correctly.
    {
        std::array<unsigned char, 2> data{0xFB, 0xFF};
        std::string encoded(4, '\0');
        bizwen::rfc4648_encode(data.begin(), data.end(), encoded.begin(), bizwen::rfc4648_kind::base64_url, true);
        assert(encoded.find('-') != std::string::npos || encoded.find('_') != std::string::npos);

        std::array<unsigned char, 2> decoded{};
        auto [end, out] =
            bizwen::rfc4648_decode(encoded.begin(), encoded.end(), decoded.begin(), bizwen::rfc4648_kind::base64_url, true);
        assert(end == encoded.end());
        assert(out == decoded.end());
        assert(decoded == data);
    }

    // Crockford lower/mixed must reject non-alphabet junk.
    {
        std::string_view junk = "{";
        std::array<unsigned char, 8> out{};
        auto [end1, _] =
            bizwen::rfc4648_decode(junk.begin(), junk.end(), out.begin(), bizwen::rfc4648_kind::base32_crockford_lower, true);
        assert(end1 == junk.begin());
        auto [end2, __] =
            bizwen::rfc4648_decode(junk.begin(), junk.end(), out.begin(), bizwen::rfc4648_kind::base32_crockford_mixed, true);
        assert(end2 == junk.begin());
    }

    return 0;
}
