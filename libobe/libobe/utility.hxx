// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <format>
#include <concepts>    // convertible_to, same_as
#include <memory>      // make_shared(), make_unique()
#include <string>      // to_string()
#include <utility>     // move(), forward(), declval(), make_pair(),
                       // to_underlying()
#include <type_traits> // remove_cvref_t
#include <iterator>    // make_move_iterator()
#include <algorithm>   // *

#include <libobe/types.hxx>
#include <libobe/contract.hxx>

namespace obe
{
  using std::move;
  using std::forward;
  using std::declval;

  using std::make_pair;
  using std::make_shared;
  using std::make_unique;
  using std::make_move_iterator;
  using std::to_string;
  using std::to_underlying;

  // The argument formattable with std::format().
  //
  template <typename T>
  concept formattable_argument =
    std::formattable<std::remove_cvref_t<T>, char>;

  // Invalid external input (a message, a ticket, etc). The description is
  // formatted from the arguments, for example:
  //
  // throw invalid_input ("invalid {}: object expected", what);
  //
  class invalid_input: public invalid_argument
  {
  public:
    template <formattable_argument... A>
    explicit
    invalid_input (std::format_string<A...> f, A&&... a)
      : invalid_argument (std::format (f, std::forward<A> (a)...)) {}
  };

  // The enumerations with the to_string() function returning the
  // enumerator's name (found by the argument-dependent lookup).
  //
  template <typename T>
  concept named_enum = std::is_enum_v<T> && requires (T v)
  {
    {to_string (v)} -> std::convertible_to<const char*>;
  };

  // The formatting context that produces characters (see the formatter of
  // the named enumerations below).
  //
  template <typename C>
  concept char_format_context = std::same_as<typename C::char_type, char>;
}

namespace std
{
  // Format the named enumerations as their names.
  //
  // Note that format() must accept any context since formattable checks it
  // against an unspecified one.
  //
  template <obe::named_enum T>
  struct formatter<T, char>: formatter<string_view>
  {
    template <obe::char_format_context C>
    auto
    format (T v, C& c) const
    {
      return formatter<string_view>::format (to_string (v), c);
    }
  };
}

#include <libobe/version.hxx>
