// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/service-bandwidth.hxx>

#include <print>
#include <limits>  // numeric_limits
#include <cstdio>  // stderr
#include <cstring> // memcpy()

#include <openssl/rand.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <libobe/openssl.hxx>

using namespace std;

namespace obe
{
  namespace asio = boost::asio;

  using asio::use_awaitable;
  using asio::ip::address_v4;

  using namespace asio::experimental::awaitable_operators;

  // The largest UDP payload over IPv4.
  //
  static const uint32_t max_packet_size (65507);

  // The interval at which we send the download packets that are due. The
  // client sends its packets once per frame, so this is in the same
  // ballpark.
  //
  static const chrono::milliseconds send_interval (10);

  static void
  append_uint16 (bytes& b, uint16_t v)
  {
    b.push_back (static_cast<uint8_t> (v));
    b.push_back (static_cast<uint8_t> (v >> 8));
  }

  static void
  append_uint32 (bytes& b, uint32_t v)
  {
    for (size_t i (0); i != 4; ++i)
      b.push_back (static_cast<uint8_t> (v >> (i * 8)));
  }

  static void
  store_uint32 (uint8_t* p, uint32_t v)
  {
    for (size_t i (0); i != 4; ++i)
      p[i] = static_cast<uint8_t> (v >> (i * 8));
  }

  static uint32_t
  load_uint32 (const uint8_t* p)
  {
    uint32_t r (0);
    for (size_t i (0); i != 4; ++i)
      r |= static_cast<uint32_t> (p[i]) << (i * 8);
    return r;
  }

  // Serialize the duration in milliseconds (see the constructor for the
  // range).
  //
  static void
  append_milliseconds (bytes& b, chrono::milliseconds d)
  {
    append_uint32 (b, static_cast<uint32_t> (d.count ()));
  }

  // Serialize the rejection with the error code.
  //
  static void
  reject (bytes& b, lsg_error e)
  {
    b.push_back (1);
    append_uint16 (b, static_cast<uint16_t> (to_underlying (e)));
  }

  bandwidth_service::
  bandwidth_service (const asio::any_io_executor& x,
                     const udp::endpoint& e,
                     bandwidth_settings s)
    : socket_ (x, e),
      settings_ (move (s))
  {
    // Note that the client takes the durations as uint32 milliseconds.
    //
    auto valid = [] (chrono::milliseconds d)
    {
      return d.count () >= 0 &&
             d.count () <= numeric_limits<uint32_t>::max ();
    };

    LIBOBE_PRE (settings_.packet_size >= 12 &&
                settings_.packet_size <= max_packet_size);
    LIBOBE_PRE (settings_.packet_count != 0);
    LIBOBE_PRE (valid (settings_.start_delay));
    LIBOBE_PRE (valid (settings_.upload_duration) &&
                settings_.upload_duration.count () != 0);
    LIBOBE_PRE (valid (settings_.download_duration) &&
                settings_.download_duration.count () != 0);
    LIBOBE_PRE (valid (settings_.download_timeout) &&
                settings_.download_timeout.count () != 0);
    LIBOBE_PRE (valid (settings_.download_linger));
    LIBOBE_PRE (settings_.upload_linger.count () >= 0);

    // We send the download packets as they become due and drop those that
    // don't fit into the socket buffer, as the network would.
    //
    socket_.non_blocking (true);
  }

  bandwidth_service::udp::endpoint bandwidth_service::
  endpoint () const
  {
    return socket_.local_endpoint ();
  }

  void bandwidth_service::
  close ()
  {
    boost::system::error_code ec;
    socket_.close (ec);
  }

  awaitable<void> bandwidth_service::
  run ()
  {
    bytes b (max_packet_size);

    for (;;)
    {
      udp::endpoint e;
      auto [ec, n] (
        co_await socket_.async_receive_from (asio::buffer (b),
                                             e,
                                             asio::as_tuple (use_awaitable)));

      if (ec == asio::error::operation_aborted || !socket_.is_open ())
        co_return;

      // The receive errors are about a single datagram (for example, the
      // ICMP port unreachable for one of ours, which some systems report
      // on the next receive), so we carry on.
      //
      if (ec)
        continue;

      receive (span (b.data (), n), e);
    }
  }

  awaitable<void> bandwidth_service::
  handle (const lsg_identity& id,
          uint8_t op,
          span<const uint8_t> in,
          bytes& out)
  {
    if (op != 1)
      throw task_error (lsg_error::service_not_available,
                        "bandwidth operation {} not supported", op);

    if (in.empty ())
      throw task_error (lsg_error::parameter_parse_error,
                        "empty bandwidth test request");

    switch (in[0])
    {
      case 0:  co_await request (id, in, out);  break;
      case 1:  co_await finalize (id, in, out); break;
      default: throw task_error (lsg_error::parameter_parse_error,
                                 "invalid bandwidth test request {}", in[0]);
    }
  }

  void bandwidth_service::
  disconnect (const lsg_identity& id) noexcept
  {
    drop (id.connection);
  }

  void bandwidth_service::
  drop (uint64_t c) noexcept
  {
    if (auto i = connections_.find (c); i != connections_.end ())
    {
      tests_.erase (i->second);
      connections_.erase (i);
    }
  }

  awaitable<void> bandwidth_service::
  request (const lsg_identity& id, span<const uint8_t> in, bytes& out)
  {
    if (in.size () < 2)
      throw task_error (lsg_error::parameter_parse_error,
                        "missing bandwidth test type");

    const uint8_t type (in[1]);

    if (type > 1)
      throw task_error (lsg_error::parameter_parse_error,
                        "invalid bandwidth test type {}", type);

    // Figure out the address the client should send its packets to.
    //
    const asio::ip::address& ga (id.address);

    optional<address_v4> a (settings_.public_address);
    if (!a)
    {
      if (ga.is_v4 ())
        a = ga.to_v4 ();
      else if (ga.is_v6 () && ga.to_v6 ().is_v4_mapped ())
        a = asio::ip::make_address_v4 (asio::ip::v4_mapped, ga.to_v6 ());
    }

    if (!a || a->is_unspecified ())
    {
      println (stderr,
               "warning: no IPv4 address to offer bandwidth test to "
               "connection {}",
               id.connection);

      reject (out, lsg_error::bandwidth_test_try_again);
      co_return;
    }

    // The client only requests another test once it is done with the
    // previous one (which it may have abandoned), so replace it.
    //
    drop (id.connection);

    if (tests_.size () >= settings_.max_tests)
    {
      reject (out, lsg_error::bandwidth_test_try_again);
      co_return;
    }

    // Generate the token and the packet we send.
    //
    token_type t;
    do
    {
      if (RAND_bytes (t.data (), static_cast<int> (t.size ())) != 1)
        throw_crypto_error ("unable to generate bandwidth test token");
    }
    while (tests_.contains (t));

    test x;
    x.connection = id.connection;
    x.download   = type == 1;
    x.packet.resize (settings_.packet_size);
    x.first      = steady::now ();
    x.last       = x.first;
    x.completion = make_unique<asio::steady_timer> (
      socket_.get_executor (), steady::time_point::max ());

    memcpy (x.packet.data () + 4, t.data (), t.size ());

    if (RAND_bytes (x.packet.data () + 12,
                    static_cast<int> (x.packet.size () - 12)) != 1)
      throw_crypto_error ("unable to generate bandwidth test packet");

    tests_.emplace (t, move (x));
    connections_.emplace (id.connection, t);

    // Reply with the test parameters.
    //
    const uint16_t port (settings_.public_port != 0
                         ? settings_.public_port
                         : socket_.local_endpoint ().port ());

    out.push_back (0);
    append_uint32       (out, settings_.packet_size);
    append_uint32       (out, settings_.packet_count);
    append_milliseconds (out, settings_.start_delay);
    append_milliseconds (out, settings_.upload_duration);
    append_milliseconds (out, settings_.download_timeout);
    append_milliseconds (out, settings_.download_duration);
    append_milliseconds (out, settings_.download_linger);
    append_uint16       (out, port);

    const address_v4::bytes_type ab (a->to_bytes ());
    out.insert (out.end (), ab.begin (), ab.end ());
    out.insert (out.end (), t.begin (), t.end ());
  }

  awaitable<void> bandwidth_service::
  finalize (const lsg_identity& id, span<const uint8_t> in, bytes& out)
  {
    // We don't use the client's download results but make sure they are
    // there.
    //
    if (in.size () < 21)
      throw task_error (lsg_error::parameter_parse_error,
                        "missing bandwidth test download results");

    auto i (connections_.find (id.connection));
    if (i == connections_.end ())
    {
      reject (out, lsg_error::bandwidth_test_not_started);
      co_return;
    }

    const token_type t (i->second);

    // The client finalizes right after sending its last packet, so some may
    // still be on their way. Wait for them unless we already have the last
    // one, until none arrive for a while.
    //
    // Note that the test may go away while we wait (the connection closes).
    //
    for (;;)
    {
      auto j (tests_.find (t));
      if (j == tests_.end ())
      {
        reject (out, lsg_error::bandwidth_test_not_started);
        co_return;
      }

      const test& x (j->second);
      const steady::time_point d (x.last + settings_.upload_linger);

      if (x.complete || steady::now () >= d)
        break;

      co_await wait (t, d);
    }

    const test& x (tests_.find (t)->second);

    if (x.packets < 2)
    {
      drop (id.connection);
      reject (out, lsg_error::bandwidth_test_socket_error);
      co_return;
    }

    const chrono::milliseconds::rep p (
      chrono::duration_cast<chrono::milliseconds> (x.last - x.first).count ());

    const uint64_t um (numeric_limits<uint32_t>::max ());

    out.push_back (0);
    append_uint32 (out, static_cast<uint32_t> (min (x.received, um)));
    append_uint32 (out,
                   static_cast<uint32_t> (
                     clamp<chrono::milliseconds::rep> (p, 1, um)));
    append_uint32 (out, static_cast<uint32_t> (x.total / x.packets));
    append_uint32 (out, x.lowest);
    append_uint32 (out, x.highest);

    drop (id.connection);
  }

  awaitable<void> bandwidth_service::
  wait (const token_type& t, steady::time_point d)
  {
    auto i (tests_.find (t));
    if (i == tests_.end () || i->second.complete)
      co_return;

    // Note that if the test goes away, then its timer's wait completes as
    // cancelled.
    //
    asio::steady_timer dt (socket_.get_executor (), d);

    co_await (
      i->second.completion->async_wait (asio::as_tuple (use_awaitable)) ||
      dt.async_wait (asio::as_tuple (use_awaitable)));
  }

  void bandwidth_service::
  receive (span<const uint8_t> p, const udp::endpoint& e)
  {
    // Find the test, ignoring anything that doesn't belong to one (stray
    // datagrams, the late packets of a finalized test, etc).
    //
    if (p.size () < 12)
      return;

    token_type t;
    memcpy (t.data (), p.data () + 4, t.size ());

    auto i (tests_.find (t));
    if (i == tests_.end () || p.size () != settings_.packet_size)
      return;

    test& x (i->second);
    const uint32_t s (load_uint32 (p.data ()));

    if (s >= settings_.packet_count)
      return;

    // The download goes where the first packet came from, so we stick to
    // it. Only the client knows the token, so the packets from elsewhere
    // mean its NAT mapping changed mid-test, which we treat as a loss.
    //
    if (x.client && *x.client != e)
      return;

    // Account for the packet.
    //
    const steady::time_point now (steady::now ());

    if (x.packets == 0)
    {
      x.client  = e;
      x.first   = now;
      x.lowest  = s;
      x.highest = s;

      if (x.download)
        asio::co_spawn (socket_.get_executor (), send (t), asio::detached);
    }
    else
    {
      x.received += p.size () + 8;
      x.lowest    = min (x.lowest, s);
      x.highest   = max (x.highest, s);
    }

    ++x.packets;
    x.total += s;
    x.last   = now;

    if (s == settings_.packet_count - 1 && !x.complete)
    {
      x.complete = true;
      x.completion->cancel ();
    }
  }

  awaitable<void> bandwidth_service::
  send (token_type t)
  {
    // Wait for the upload to complete or, if its last packet is lost, for
    // as long as it should take plus a quarter of the time the client waits
    // for our first packet.
    //
    {
      auto i (tests_.find (t));
      if (i == tests_.end ())
        co_return;

      co_await wait (t,
                     i->second.first +
                     settings_.upload_duration +
                     settings_.download_timeout / 4);
    }

    // Send the packets, spreading them over the download duration.
    //
    // Note that the test may go away between the sends (the client gives up
    // or the connection closes).
    //
    const uint32_t n (settings_.packet_count);
    const steady::duration dd (settings_.download_duration);
    const steady::time_point b (steady::now ());

    asio::steady_timer st (socket_.get_executor ());

    for (uint32_t s (0); s != n; )
    {
      auto i (tests_.find (t));
      if (i == tests_.end ())
        co_return;

      test& x (i->second);

      // The number of packets due, starting with the first one right away.
      //
      const steady::duration el (steady::now () - b);
      const uint32_t due (
        el >= dd
        ? n
        : min (n,
               static_cast<uint32_t> (
                 static_cast<uint64_t> (n) * el.count () / dd.count ()) + 1));

      for (; s != due; ++s)
      {
        store_uint32 (x.packet.data (), s);

        boost::system::error_code ec;
        socket_.send_to (asio::buffer (x.packet), *x.client, 0, ec);
      }

      if (s == n)
        break;

      st.expires_after (send_interval);
      co_await st.async_wait (asio::as_tuple (use_awaitable));
    }
  }
}
