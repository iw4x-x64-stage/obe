// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

namespace obe
{
  void tiger::
  append (std::unsigned_integral auto v)
  {
    uint8_t b[sizeof (v)];

    for (size_t i (0); i != sizeof (v); ++i)
      b[i] = static_cast<uint8_t> (v >> (i * 8));

    append (span (b));
  }
}
