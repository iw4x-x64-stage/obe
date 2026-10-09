// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <print>
#include <format>
#include <string>
#include <cstdint>
#include <sstream>
#include <iostream>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/address.hpp>

#include <libobe/endpoint.hxx>

#undef NDEBUG
#include <cassert>

using namespace std;

namespace asio = boost::asio;

// Usage: argv[0]
//
// Read endpoints from stdin, one per line, and print each formatted with
// std::format() to stdout, one per line:
//
// tcp|udp <address> <port> [<specification>]
//
// The specification is the format specification of the replacement field
// (for example, >20 for {:>20}). Also verify that the result matches the
// endpoint's operator<< when the specification is absent.
//
int
main ()
{
  for (string l; getline (cin, l); )
  {
    istringstream is (l);

    string p, a, s;
    uint16_t n;
    is >> p >> a >> n >> s;
    assert (!is.bad ());

    const asio::ip::address ad (asio::ip::make_address (a));

    // Format the endpoint and check it against operator<<.
    //
    auto print = [&s] (const auto& e)
    {
      const string r (vformat ("{:" + s + '}', make_format_args (e)));

      if (s.empty ())
      {
        ostringstream os;
        os << e;
        assert (r == os.str ());
      }

      println ("{}", r);
    };

    if (p == "tcp")
      print (asio::ip::tcp::endpoint (ad, n));
    else if (p == "udp")
      print (asio::ip::udp::endpoint (ad, n));
    else
    {
      println (cerr, "error: unknown protocol '{}'", p);
      return 1;
    }
  }
}
