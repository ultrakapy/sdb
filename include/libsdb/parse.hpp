#ifndef SDB_PARSE_HPP
#define SDB_PARSE_HPP

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <array>
#include <system_error>
#include <cerrno>

#include <fast_float/fast_float.h>

#include <libsdb/error.hpp>

namespace sdb {
  template <class I>
  std::optional<I> to_integral(std::string_view sv, int base = 10) {
    auto begin = sv.begin();
    if (base == 16 and sv.size() > 1 and
        begin[0] == '0' and begin[1] == 'x') {
      begin += 2;
    }

    I ret;
    auto result = std::from_chars(begin, sv.end(), ret, base);

    if (result.ec != std::errc() || result.ptr != sv.end()) {
      return std::nullopt;
    }
    return ret;
  }

  template<>
  inline std::optional<std::byte> to_integral(std::string_view sv, int base) {
    auto uint8 = to_integral<std::uint8_t>(sv, base);
    if (uint8) return static_cast<std::byte>(*uint8);
    return std::nullopt;
  }

  template <std::size_t N>
  auto parse_vector(std::string_view text) {
    auto invalid = [] { sdb::error::send("Invalid format"); };

    std::array<std::byte, N> bytes;
    const char* c = text.data();

    if (*c++ != '[') invalid();
    for (auto i = 0; i < N - 1; ++i) {
      bytes[i] = to_integral<std::byte>({ c, 4 }, 16).value();
      c += 4;
      if (*c++ != ',') invalid();
    }

    bytes[N - 1] = to_integral<std::byte>({ c, 4 }, 16).value();
    c += 4;

    if (*c++ != ']') invalid();
    if (c != text.end()) invalid();

    return bytes;
  }


  template <class F>
  std::optional<F> to_float(std::string_view sv) {
    if (sv.empty()) return std::nullopt;

    F ret{};

    if constexpr (std::is_same_v<F, long double>) {
      // Use strtold for long double (GCC 9 compatible)
      // GCC 9 / libstdc++ lacks std::from_chars for long double.
      // We must emulate strict behavior using strtold.

      // Enforce no leading whitespace (match from_chars behavior)
      if (std::isspace(static_cast<unsigned char>(sv.front()))) {
        return std::nullopt;
      }

      // Allocation is unavoidable for strtold (needs null-term)
      std::string temp(sv);  // strtold needs null-terminated string
      char* end;
      errno = 0;

      // Note: strtold is locale-dependent.
      // If this runs in non-C locales, this might fail on '.'
      ret = std::strtold(temp.c_str(), &end);

      // Check for range errors and ensure full string consumption
      if (errno == 0 && end == temp.c_str() + temp.size()) {
        return ret;
      }
      return std::nullopt;
    } else {
      // Use fast_float for float and double (GCC 9 compatible)
      auto result = fast_float::from_chars(sv.data(), sv.data() + sv.size(), ret);

      // require success and full consumption of the input range, otherwise return nullopt
      if (result.ec == std::errc() && result.ptr == sv.data() + sv.size()) {
        return ret;
      }

      return std::nullopt;
    }
  }
}

#endif
