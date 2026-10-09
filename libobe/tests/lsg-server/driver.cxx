// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <print>
#include <chrono>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>   // to_underlying()
#include <iostream>
#include <exception>
#include <stdexcept> // runtime_error

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <libobe/frame.hxx>
#include <libobe/ticket.hxx>
#include <libobe/service.hxx>
#include <libobe/lsg-server.hxx>
#include <libobe/lsg-registry.hxx>
#include <libobe/bit-parser.hxx>
#include <libobe/bit-serializer.hxx>
#include <libobe/frame-cipher.hxx>

#undef NDEBUG
#include <cassert>

using namespace std;
using namespace obe;

namespace asio = boost::asio;

using asio::awaitable;
using asio::use_awaitable;
using asio::ip::tcp;

static const title_id title {1234};

// Bit service 50: operation 1 takes uint32 and returns it incremented,
// operation 2 fails with access denied. The handler suspends before
// replying, the way a service waiting for a database would.
//
class increment_service: public service
{
public:
  virtual kind_type
  kind () const noexcept override {return kind_type::bit;}

  virtual awaitable<void>
  handle (const lsg_identity& id,
          uint8_t op,
          bit_parser& in,
          bit_serializer& out) override
  {
    assert (id.title == title);

    co_await asio::post (co_await asio::this_coro::executor, use_awaitable);

    if (op == 2)
      throw task_error (lsg_error::access_denied, "operation {} denied", op);

    out.next_uint32 (in.next_uint32 () + 1);
  }
};

// Bit service 51: operation 1 takes the uint32 value and count and pushes
// the value to the client's user count times, operation 2 takes the uint32
// size and pushes a message of that many bytes. Both return the number of
// pushes queued, summed over the user's connections. Print the
// disconnects.
//
class push_service: public service
{
public:
  explicit
  push_service (lsg_registry& r): registry_ (r) {}

  virtual kind_type
  kind () const noexcept override {return kind_type::bit;}

  virtual awaitable<void>
  handle (const lsg_identity& id,
          uint8_t op,
          bit_parser& in,
          bit_serializer& out) override
  {
    // Note that the handler doesn't suspend between the pushes, so the
    // session cannot drain its queue in the meantime.
    //
    size_t r (0);
    if (op == 1)
    {
      bytes p;
      bit_serializer (p).next_uint32 (in.next_uint32 ());

      for (uint32_t n (in.next_uint32 ()); n != 0; --n)
        r += registry_.push (id.title, id.user, p);
    }
    else
      r = registry_.push (id.title, id.user, bytes (in.next_uint32 ()));

    out.next_uint32 (static_cast<uint32_t> (r));
    co_return;
  }

  virtual void
  disconnect (const lsg_identity& id) noexcept override
  {
    println ("disconnect {}", id.connection);
  }

private:
  lsg_registry& registry_;
};

// Byte service 18: echo the length-prefixed input reversed. Note that the
// input of an encrypted task has the padding at the end, which is why the
// byte task formats are self-delimiting.
//
class reverse_service: public service
{
public:
  virtual kind_type
  kind () const noexcept override {return kind_type::byte;}

  virtual awaitable<void>
  handle (const lsg_identity&,
          uint8_t,
          span<const uint8_t> in,
          bytes& out) override
  {
    if (in.empty () || in[0] > in.size () - 1)
      throw task_error (lsg_error::parameter_parse_error, "invalid input");

    const span<const uint8_t> d (in.subspan (1, in[0]));

    out.push_back (in[0]);
    out.insert (out.end (), d.rbegin (), d.rend ());

    co_return;
  }
};

// The game client side of the gateway connection (the reverse of
// frame_parser and frame_serializer).
//
class client
{
public:
  explicit
  client (tcp::socket s): socket_ (move (s)) {}

  awaitable<void>
  prelude (uint32_t version)
  {
    bytes b;
    for (uint32_t v: {version, 0x10000U})
      for (size_t i (0); i != 4; ++i)
        b.push_back (static_cast<uint8_t> (v >> (i * 8)));

    co_await asio::async_write (socket_, asio::buffer (b), use_awaitable);
  }

  // Send the handshake (plain) and switch to the session key.
  //
  awaitable<void>
  handshake (title_id t,
             uint32_t seed,
             const ticket_data& ticket,
             const session_key& k)
  {
    bytes p {7};
    {
      bit_serializer s (p);
      s.next_uint32 (to_underlying (t));
      s.next_uint32 (seed);
      s.next_bytes (ticket);
    }

    co_await send (p);

    cipher_.emplace (k);
    seed_ = seed;
  }

  // Send a bit task.
  //
  template <typename F>
    requires invocable<F, bit_serializer&>
  awaitable<void>
  bit_task (uint8_t service, uint8_t op, F params)
  {
    bytes p {service};
    {
      bit_serializer s (p);
      s.next_uint8 (op);
      params (s);
      s.next_type (bit_type::none);
    }

    co_await send (p);
  }

  awaitable<void>
  byte_task (uint8_t service, uint8_t op, span<const uint8_t> d)
  {
    bytes p {service, op};
    p.insert (p.end (), d.begin (), d.end ());
    co_await send (p);
  }

  // Send the frame, encrypted if the seed is non-zero.
  //
  awaitable<void>
  send (span<const uint8_t> p)
  {
    bytes b;
    auto append32 = [&b] (uint32_t v)
    {
      for (size_t i (0); i != 4; ++i)
        b.push_back (static_cast<uint8_t> (v >> (i * 8)));
    };

    if (!cipher_ || seed_ == 0)
    {
      append32 (static_cast<uint32_t> (p.size () + 1));
      b.push_back (0);
      b.insert (b.end (), p.begin (), p.end ());
    }
    else
    {
      // MAC, payload, and padding (the seed's low byte).
      //
      const size_t n ((p.size () + 11) & ~static_cast<size_t> (7));

      bytes pt (4);
      pt.insert (pt.end (), p.begin (), p.end ());
      pt.resize (n, static_cast<uint8_t> (seed_));

      const frame_cipher::mac_type m (
        cipher_->authenticate (span (pt).subspan (5)));
      copy (m.begin (), m.end (), pt.begin ());

      cipher_->encrypt (seed_, pt);

      append32 (static_cast<uint32_t> (n + 5));
      b.push_back (1);
      append32 (seed_++);
      b.insert (b.end (), pt.begin (), pt.end ());
    }

    co_await asio::async_write (socket_, asio::buffer (b), use_awaitable);
  }

  // Receive the next frame and print it. Return false on EOF.
  //
  awaitable<bool>
  receive ()
  {
    array<uint8_t, 4> h;
    auto [ec, n] (co_await asio::async_read (socket_,
                                             asio::buffer (h),
                                             asio::as_tuple (use_awaitable)));
    if (ec == asio::error::eof)
    {
      println ("closed");
      co_return false;
    }

    if (ec)
      throw boost::system::system_error (ec);

    const uint32_t size (h[0] | h[1] << 8 | h[2] << 16 |
                         static_cast<uint32_t> (h[3]) << 24);

    if (size == 0)
    {
      println ("keepalive");
      co_return true;
    }

    bytes f (size);
    co_await asio::async_read (socket_, asio::buffer (f), use_awaitable);

    // Decode the frame into the type and payload.
    //
    uint8_t type;
    bytes p;
    if (f[0] == 0)
    {
      type = f[1];
      p.assign (f.begin () + 2, f.end ());
    }
    else
    {
      assert (cipher_);

      const uint32_t seed (f[1] | f[2] << 8 | f[3] << 16 |
                           static_cast<uint32_t> (f[4]) << 24);

      bytes pt (f.begin () + 5, f.end ());
      cipher_->decrypt (seed, pt);

      assert (pt[0] == 0xef && pt[1] == 0xbe && pt[2] == 0xad && pt[3] == 0xde);

      type = pt[4];
      p.assign (pt.begin () + 5, pt.end ());
    }

    // Print it.
    //
    print ("{} {}",
           f[0] == 0 ? "plain" : "encrypted",
           static_cast<frame_type> (type));

    switch (static_cast<frame_type> (type))
    {
      case frame_type::connection_id:
      {
        bit_parser in (p, "reply");
        print (" {}", in.next_uint64 ());
        break;
      }
      case frame_type::error:
      {
        bit_parser in (p, "reply");
        print (" {}", in.next_uint32 ());
        break;
      }
      case frame_type::task_reply:
      {
        bit_parser in (p, "reply");
        print (" tx {}", in.next_uint64 ());

        const uint32_t e (in.next_uint32 ());
        print (" error {}", e);

        if (e == 0)
        {
          print (" op {}", in.next_uint8 ());
          print (" value {}", in.next_uint32 ());
        }
        break;
      }
      case frame_type::service_reply:
      {
        uint64_t tx (0);
        for (size_t i (0); i != 8; ++i)
          tx |= static_cast<uint64_t> (p[i]) << (i * 8);

        // The data is length-prefixed (see reverse_service) since the
        // payload has the padding at the end.
        //
        print (" tx {} data", tx);
        for (size_t i (0); i != p[8]; ++i)
          print (" {}", p[9 + i]);
        break;
      }
      case frame_type::push:
      {
        bit_parser in (p, "push");
        print (" value {}", in.next_uint32 ());
        break;
      }
    }

    println ();
    co_return true;
  }

  tcp::socket&
  socket () {return socket_;}

private:
  tcp::socket            socket_;
  optional<frame_cipher> cipher_;
  uint32_t               seed_ = 0;
};

// Usage: argv[0] <scenario>
//
// Run the gateway server on the loopback interface, connect to it, play the
// scenario, and print the frames the client receives, one per line, as well
// as the disconnects seen by the services. The server diagnostics go to
// stderr.
//
// The scenarios:
//
// encrypted   Handshake with encryption and send a sequence of tasks.
// plain       As above but without encryption, a single task.
// push        Handshake and send a task that pushes a message back.
// oversized   As above but the message exceeds the client's capacity.
// full        As above but push more messages than the send queue takes.
// reset       Handshake and reset the connection.
// empty       Handshake without encryption (an encrypted frame always
//             has the padding) and send an empty task frame.
// expired     Handshake with an expired ticket.
// title       Handshake for a different title than the ticket's.
// forged      Handshake with a ticket from a different sealer.
// service     Send a task frame instead of the handshake.
// untyped     Send a handshake with an untyped bit buffer.
// truncated   Send a handshake that ends before its title.
// version     Send a prelude with an unsupported version.
// idle        Handshake and then wait for the keepalive and the idle
//             timeout.
//
int
main (int argc, char* argv[])
{
  if (argc != 2)
  {
    println (cerr, "usage: {} <scenario>", argv[0]);
    return 1;
  }

  const string scenario (argv[1]);

  ticket_key k1 {}, k2 {};
  k2[0] = 1;

  const ticket_sealer sealer (k1), forger (k2);

  lsg_registry registry;

  increment_service inc;
  push_service push (registry);
  reverse_service rev;
  const service_map services {{50, inc}, {51, push}, {18, rev}};

  lsg_settings settings;
  if (scenario == "idle")
  {
    settings.keepalive_interval = chrono::milliseconds (100);
    settings.idle_timeout = chrono::milliseconds (250);
  }
  else if (scenario == "full")
    settings.send_queue_size = 2;

  asio::io_context ctx;
  lsg_server server (ctx.get_executor (),
                     tcp::endpoint (asio::ip::address_v4::loopback (), 0),
                     sealer,
                     services,
                     registry,
                     settings);

  asio::co_spawn (ctx, server.run (), asio::detached);

  // Play the scenario.
  //
  auto play = [&server, &scenario, &sealer, &forger] () -> awaitable<void>
  {
    tcp::socket s (co_await asio::this_coro::executor);
    co_await s.async_connect (server.endpoint (), use_awaitable);

    client c (move (s));

    if (scenario == "version")
    {
      co_await c.prelude (179);
      while (co_await c.receive ()) ;
      co_return;
    }

    co_await c.prelude (frame_prelude::current_version);

    // Send a malformed handshake (plain since we have no key yet) and wait
    // for the error.
    //
    if (scenario == "service" || scenario == "untyped" ||
        scenario == "truncated")
    {
      const bytes p (scenario == "service" ? bytes {50, 1}  :
                     scenario == "untyped" ? bytes {7, 0}   :
                                             bytes {7, 1});
      co_await c.send (p);

      while (co_await c.receive ()) ;
      co_return;
    }

    // Issue the ticket.
    //
    const timestamp now (system_clock::now ());
    const session_key key (generate_session_key ());

    server_ticket t {title,
                     now,
                     now + chrono::hours (1),
                     license_id {2},
                     user_id {3},
                     key};

    if (scenario == "expired")
      t.expires = now - chrono::seconds (1);

    const ticket_data d ((scenario == "forged" ? forger : sealer).seal (t));
    const title_id ht (scenario == "title" ? title_id {4321} : title);
    const uint32_t seed (scenario == "plain" || scenario == "empty" ? 0 : 100);

    co_await c.handshake (ht, seed, d, key);

    if (!co_await c.receive ()) // Connection id or error.
      co_return;

    // Close abortively (RST instead of FIN) so that the server's read
    // fails instead of seeing the end of the stream.
    //
    if (scenario == "reset")
    {
      c.socket ().set_option (tcp::socket::linger (true, 0));
      c.socket ().close ();
      co_return;
    }

    if (scenario == "empty")
    {
      co_await c.send (bytes ());

      while (co_await c.receive ()) ;
      co_return;
    }

    if (scenario == "push" || scenario == "full")
    {
      // Push the value once, or four times with the queue of two, and
      // receive the queued pushes and the reply. Note that the transmitter
      // waiting for a message takes the first one without it occupying
      // the queue, so the fourth push is the one dropped.
      //
      const bool f (scenario == "full");

      co_await c.bit_task (51, 1, [f] (bit_serializer& s)
      {
        s.next_uint32 (7);
        s.next_uint32 (f ? 4 : 1);
      });

      for (size_t i (f ? 4 : 2); i != 0; --i)
        co_await c.receive ();

      c.socket ().close ();
      co_return;
    }

    if (scenario == "oversized")
    {
      // Push a message as large as the receive capacity the prelude
      // announces, which leaves no room for the frame around it.
      //
      co_await c.bit_task (51, 2, [] (bit_serializer& s)
      {
        s.next_uint32 (0x10000);
      });

      co_await c.receive (); // Reply.

      c.socket ().close ();
      co_return;
    }

    if (scenario == "encrypted" || scenario == "plain")
    {
      auto u32 = [] (uint32_t v)
      {
        return [v] (bit_serializer& s) {s.next_uint32 (v);};
      };

      co_await c.bit_task (50, 1, u32 (41));

      if (scenario == "encrypted")
      {
        // Error, unknown service, parameter type mismatch, byte task.
        //
        co_await c.bit_task (50, 2, u32 (0));
        co_await c.bit_task (99, 1, u32 (0));
        co_await c.bit_task (50, 1, [] (bit_serializer& s)
        {
          s.next_string ("41");
        });

        const uint8_t b[] = {3, 1, 2, 3};
        co_await c.byte_task (18, 1, b);
      }

      for (size_t i (scenario == "encrypted" ? 5 : 1); i != 0; --i)
        co_await c.receive ();

      c.socket ().close ();
      co_return;
    }

    // Wait for whatever comes until the server closes the connection.
    //
    while (co_await c.receive ()) ;
  };

  int r (0);
  asio::co_spawn (ctx, play (), [&server, &r] (exception_ptr e)
  {
    if (e)
    {
      try
      {
        rethrow_exception (e);
      }
      catch (const std::exception& x)
      {
        println (cerr, "error: {}", x.what ());
      }
      r = 1;
    }

    server.close ();
  });

  ctx.run ();
  return r;
}
