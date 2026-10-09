// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <span>
#include <array>
#include <chrono>
#include <vector>
#include <string>
#include <memory>        // unique_ptr, shared_ptr
#include <utility>       // pair
#include <cstddef>       // size_t, nullptr_t, byte
#include <cstdint>       // uint{8,16,32,64}_t
#include <istream>
#include <ostream>
#include <optional>
#include <functional>    // function, reference_wrapper
#include <string_view>

#include <ios>           // ios_base::failure
#include <exception>     // exception
#include <stdexcept>     // logic_error, invalid_argument, runtime_error
#include <system_error>

namespace obe
{
  // Commonly-used types.
  //
  using std::int8_t;
  using std::int16_t;
  using std::int32_t;
  using std::int64_t;

  using std::uint8_t;
  using std::uint16_t;
  using std::uint32_t;
  using std::uint64_t;

  using std::size_t;
  using std::nullptr_t;

  using std::pair;
  using std::string;
  using std::string_view;
  using std::function;
  using std::reference_wrapper;

  using std::unique_ptr;
  using std::shared_ptr;
  using std::weak_ptr;

  using std::span;
  using std::array;
  using std::vector;

  using strings = vector<string>;
  using cstrings = vector<const char*>;

  // Raw protocol data. Demonware structures are byte-oriented, so we
  // use uint8_t, which converts to and from the wire values without casts,
  // for both owned buffers and views.
  //
  using bytes = vector<uint8_t>;

  using std::istream;
  using std::ostream;

  // Exceptions. While <exception> is included, there is no using for
  // std::exception -- use qualified.
  //
  using std::logic_error;
  using std::invalid_argument;
  using std::runtime_error;
  using std::system_error;
  using io_error = std::ios_base::failure;

  using std::generic_category;

  // <optional>
  //
  using std::optional;
  using std::nullopt;

  // <chrono>
  //
  using std::chrono::system_clock;
  using timestamp = system_clock::time_point;
  using duration = system_clock::duration;

  // Demonware identifiers.
  //
  // These are distinct types so that one cannot be passed where another is
  // expected. Construct them with braces (title_id {v}) and get the value
  // with std::to_underlying().
  //
  enum class title_id: uint32_t {};
  enum class user_id: uint64_t {};
  enum class license_id: uint64_t {};
}
