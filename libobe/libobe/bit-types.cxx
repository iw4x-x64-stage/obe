// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/bit-types.hxx>

using namespace std;

namespace obe
{
  const char*
  to_string (bit_type t) noexcept
  {
    switch (t)
    {
      case bit_type::none:             return "no type";
      case bit_type::boolean:          return "bool";
      case bit_type::char8:            return "char8";
      case bit_type::uchar8:           return "uchar8";
      case bit_type::wchar16:          return "wchar16";
      case bit_type::int16:            return "int16";
      case bit_type::uint16:           return "uint16";
      case bit_type::int32:            return "int32";
      case bit_type::uint32:           return "uint32";
      case bit_type::int64:            return "int64";
      case bit_type::uint64:           return "uint64";
      case bit_type::ranged_int32:     return "ranged int32";
      case bit_type::ranged_uint32:    return "ranged uint32";
      case bit_type::float32:          return "float32";
      case bit_type::float64:          return "float64";
      case bit_type::ranged_float32:   return "ranged float32";
      case bit_type::string:           return "string";
      case bit_type::ustring:          return "unsigned string";
      case bit_type::multibyte_string: return "multibyte string";
      case bit_type::blob:             return "blob";
      case bit_type::full_type:        return "full type";
    }

    return "unknown type";
  }
}
