// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

namespace obe
{
  template <formattable_argument... A>
  void bit_parser::
  fail (std::format_string<A...> f, A&&... a) const
  {
    throw bit_parsing (name_,
                       position_,
                       std::format (f, std::forward<A> (a)...));
  }
}
