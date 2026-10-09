// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <map>
#include <set>
#include <print>
#include <chrono>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>   // memcpy()
#include <sstream>
#include <iostream>
#include <exception> // exception_ptr, rethrow_exception()
#include <stdexcept> // invalid_argument

#include <boost/asio/buffer.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <libobe/service.hxx>
#include <libobe/service-bandwidth.hxx>

#undef NDEBUG
#include <cassert>

using namespace std;
using namespace obe;

namespace asio = boost::asio;

using asio::use_awaitable;
using asio::ip::udp;

using namespace asio::experimental::awaitable_operators;

static const title_id title {1234};

static uint32_t
load_uint32 (const uint8_t* p)
{
  uint32_t r (0);
  for (size_t i (0); i != 4; ++i)
    r |= static_cast<uint32_t> (p[i]) << (i * 8);
  return r;
}

static uint16_t
load_uint16 (const uint8_t* p)
{
  return static_cast<uint16_t> (p[0] | p[1] << 8);
}

static bytes
parse_hex (const string& s)
{
  if (s.size () % 2 != 0)
    throw invalid_argument ("odd number of hex digits");

  bytes r;
  for (size_t i (0); i != s.size (); i += 2)
    r.push_back (static_cast<uint8_t> (stoul (s.substr (i, 2), nullptr, 16)));
  return r;
}

// The client side of a connection's test.
//
struct client
{
  udp::socket   socket;
  udp::endpoint server;
  array<uint8_t, 8> token;
  uint32_t      packet_size;
};

// Usage: argv[0] [--max-tests <n>] [--public-address <addr>]
//                [--public-port <port>]
//
// Create the bandwidth service bound to 127.0.0.1 (any port) with 32-byte
// packets, 4 packets each way, 100ms upload and download, 1000ms download
// timeout, 50ms download linger, and 200ms upload linger. Then play the
// clients according to the commands read from stdin, one per line:
//
// request <connection> <type> [<gateway address>]
//
//   Request the test (the gateway address is 127.0.0.1 by default) and
//   print 'accepted' followed by the offered address or 'rejected <code>'.
//   The other parameters are verified to be the settings above (and the
//   port to be ours or the public one).
//
// upload <connection> <sequence>...
//
//   Send the packets with the sequence numbers.
//
// download <connection>
//
//   Receive the packets until all of them arrive or none arrive for a
//   second and print 'received' followed by their sequence numbers in the
//   order received.
//
// finalize <connection>
//
//   Finalize the test and print 'results' followed by the bytes received
//   and the average, lowest, and highest sequence numbers (the period is
//   verified to be positive) or 'rejected <code>'.
//
// task <connection> <hex>
//
//   Send the raw operation 1 parameters and print the reply in hex or
//   'error <code>: <description>'.
//
// disconnect <connection>
//
//   Notify the service that the connection closed.
//
int
main (int argc, char* argv[])
{
  bandwidth_settings s;
  s.packet_size       = 32;
  s.packet_count      = 4;
  s.upload_duration   = chrono::milliseconds (100);
  s.download_duration = chrono::milliseconds (100);
  s.download_timeout  = chrono::milliseconds (1000);
  s.download_linger   = chrono::milliseconds (50);
  s.upload_linger     = chrono::milliseconds (200);

  for (int i (1); i != argc; ++i)
  {
    const string o (argv[i]);

    if (i + 1 == argc)
    {
      println (cerr, "error: missing {} value", o);
      return 1;
    }

    const string v (argv[++i]);

    if (o == "--max-tests")
      s.max_tests = stoul (v);
    else if (o == "--public-address")
      s.public_address = asio::ip::make_address_v4 (v);
    else if (o == "--public-port")
      s.public_port = static_cast<uint16_t> (stoul (v));
    else
    {
      println (cerr, "error: unknown option '{}'", o);
      return 1;
    }
  }

  asio::io_context ctx;

  bandwidth_service svc (
    ctx.get_executor (),
    udp::endpoint (asio::ip::make_address ("127.0.0.1"), 0),
    s);

  const uint16_t port (s.public_port != 0
                       ? s.public_port
                       : svc.endpoint ().port ());

  map<uint64_t, client> clients;

  // Handle the task, returning the reply or nullopt if it failed (in which
  // case print the error).
  //
  auto handle = [&svc] (uint64_t c,
                        const asio::ip::address& a,
                        bytes in) -> awaitable<optional<bytes>>
  {
    const lsg_identity id {user_id {c}, title, license_id {0}, c, a};

    bytes out;
    try
    {
      co_await svc.handle (id, 1, in, out);
    }
    catch (const task_error& e)
    {
      println ("error {}: {}", to_underlying (e.code), e.what ());
      co_return nullopt;
    }

    co_return out;
  };

  // Print the rejection and return true if the reply is one.
  //
  auto rejected = [] (const bytes& r)
  {
    if (r.empty () || r[0] != 1)
      return false;

    assert (r.size () == 3);
    println ("rejected {}", load_uint16 (r.data () + 1));
    return true;
  };

  auto command = [&ctx, &svc, &clients, &handle, &rejected, &s, port]
                 (const string& l) -> awaitable<void>
  {
    istringstream is (l);
    string k;
    uint64_t c;
    is >> k >> c;

    if (is.fail ())
      throw invalid_argument ("invalid line '" + l + "'");

    if (k == "request")
    {
      unsigned int t;
      string a ("127.0.0.1");
      is >> t;
      if (!(is >> a))
        a = "127.0.0.1";

      optional<bytes> r (
        co_await handle (c,
                         asio::ip::make_address (a),
                         bytes {0, static_cast<uint8_t> (t)}));

      if (!r || rejected (*r))
        co_return;

      assert (r->size () == 1 + 7 * 4 + 2 + 4 + 8 && (*r)[0] == 0);

      const uint8_t* p (r->data () + 1);

      uint32_t v[7];
      for (uint32_t& x: v)
      {
        x = load_uint32 (p);
        p += 4;
      }

      assert (load_uint16 (p) == port);
      p += 2;

      asio::ip::address_v4::bytes_type ab;
      memcpy (ab.data (), p, ab.size ());
      p += 4;

      const asio::ip::address_v4 sa (ab);

      assert (v[0] == s.packet_size                &&
              v[1] == s.packet_count               &&
              v[2] == s.start_delay.count ()       &&
              v[3] == s.upload_duration.count ()   &&
              v[4] == s.download_timeout.count ()  &&
              v[5] == s.download_duration.count () &&
              v[6] == s.download_linger.count ());

      println ("accepted {}", sa.to_string ());

      // Set up the client, sending to the actual endpoint even if a public
      // one is offered.
      //
      client cl {
        udp::socket (ctx, udp::endpoint (asio::ip::address_v4::loopback (), 0)),
        svc.endpoint (),
        {},
        v[0]};
      memcpy (cl.token.data (), p, cl.token.size ());

      clients.insert_or_assign (c, move (cl));
    }
    else if (k == "upload")
    {
      client& cl (clients.at (c));

      bytes b (cl.packet_size, 0xcc);
      memcpy (b.data () + 4, cl.token.data (), cl.token.size ());

      for (uint32_t n; is >> n; )
      {
        for (size_t i (0); i != 4; ++i)
          b[i] = static_cast<uint8_t> (n >> (i * 8));

        cl.socket.send_to (asio::buffer (b), cl.server);
      }
    }
    else if (k == "download")
    {
      client& cl (clients.at (c));

      string r ("received");
      bytes b (65536);

      for (set<uint32_t> ss; ss.size () != 4; )
      {
        udp::endpoint e;
        asio::steady_timer t (ctx, chrono::seconds (1));

        auto v (co_await (
          cl.socket.async_receive_from (asio::buffer (b),
                                        e,
                                        asio::as_tuple (use_awaitable)) ||
          t.async_wait (asio::as_tuple (use_awaitable))));

        if (v.index () == 1)
          break;

        const auto [ec, sz] (get<0> (v));
        assert (!ec);
        assert (e == cl.server && sz == cl.packet_size);
        assert (memcmp (b.data () + 4, cl.token.data (), 8) == 0);

        const uint32_t n (load_uint32 (b.data ()));
        ss.insert (n);
        r += format (" {}", n);
      }

      println ("{}", r);
    }
    else if (k == "finalize")
    {
      // The finalize marker followed by the (zero) download results.
      //
      bytes f (21, 0);
      f[0] = 1;

      optional<bytes> r (
        co_await handle (c, asio::ip::make_address ("127.0.0.1"), move (f)));

      if (!r || rejected (*r))
        co_return;

      assert (r->size () == 1 + 5 * 4 && (*r)[0] == 0);

      const uint8_t* p (r->data () + 1);
      assert (load_uint32 (p + 4) != 0);

      println ("results {} {} {} {}",
               load_uint32 (p),
               load_uint32 (p + 8),
               load_uint32 (p + 12),
               load_uint32 (p + 16));
    }
    else if (k == "task")
    {
      string h;
      is >> h;

      if (optional<bytes> r = co_await handle (
            c, asio::ip::make_address ("127.0.0.1"), parse_hex (h)))
      {
        string x;
        for (uint8_t b: *r)
          x += format ("{:02x}", b);

        println ("reply {}", x);
      }
    }
    else if (k == "disconnect")
      svc.disconnect (
        lsg_identity {user_id {c}, title, license_id {0}, c, {}});
    else
      throw invalid_argument ("unknown command '" + k + "'");
  };

  // Run the commands and the service until they are done.
  //
  exception_ptr ep;
  asio::co_spawn (ctx, svc.run (), asio::detached);

  auto read = [&command, &svc] () -> awaitable<void>
  {
    for (string l; getline (cin, l); )
    {
      if (!l.empty ())
        co_await command (l);
    }

    svc.close ();
  };

  auto finish = [&ep, &svc] (exception_ptr e)
  {
    ep = move (e);
    svc.close ();
  };

  asio::co_spawn (ctx, read, finish);

  ctx.run ();

  if (ep)
  {
    try
    {
      rethrow_exception (ep);
    }
    catch (const std::exception& e)
    {
      println (cerr, "error: {}", e.what ());
      return 1;
    }
  }
}
