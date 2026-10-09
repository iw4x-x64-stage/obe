// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <format>
#include <string>
#include <concepts> // same_as

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/address.hpp>

#include <libobe/utility.hxx> // char_format_context

namespace obe
{
  // The internet protocols whose endpoints we format (see below).
  //
  template <typename P>
  concept internet_protocol = std::same_as<P, boost::asio::ip::tcp> ||
                              std::same_as<P, boost::asio::ip::udp>;
}

namespace std
{
  // Format the TCP and UDP endpoints the way their operator<< prints them,
  // for example, 127.0.0.1:3074 or [::1]:3074. As for the named
  // enumerations, the format specification applies to the whole.
  //
  template <obe::internet_protocol P>
  struct formatter<boost::asio::ip::basic_endpoint<P>, char>:
    formatter<string_view>
  {
    auto
    format (const boost::asio::ip::basic_endpoint<P>& e,
            obe::char_format_context auto& c) const
    {
      const boost::asio::ip::address a (e.address ());
      const string s (a.is_v6 ()
                      ? std::format ("[{}]:{}", a.to_string (), e.port ())
                      : std::format ("{}:{}", a.to_string (), e.port ()));

      return formatter<string_view>::format (s, c);
    }
  };
}
